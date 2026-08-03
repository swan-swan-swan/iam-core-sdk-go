package redis_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	redisadapter "github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session/sessiontest"
	"github.com/testcontainers/testcontainers-go"
	rediscontainer "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestRedisConformance(t *testing.T) {
	for _, image := range []string{"redis:6.2-alpine", "redis:7.4-alpine"} {
		t.Run(image, func(t *testing.T) {
			container, err := rediscontainer.Run(t.Context(), image)
			if err != nil {
				t.Fatal("start Redis container:", err)
			}
			testcontainers.CleanupContainer(t, container)

			endpoint, err := container.ConnectionString(t.Context())
			if err != nil {
				t.Fatal("get Redis connection string:", err)
			}
			options, err := redisOptions(endpoint)
			if err != nil {
				t.Fatal("parse Redis connection string:", err)
			}
			client := goredis.NewClient(options)
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Error("close Redis client:", err)
				}
			})
			if err := client.Ping(t.Context()).Err(); err != nil {
				t.Fatal("ping Redis:", err)
			}

			sessiontest.Run(t, func(t testing.TB, clock *sessiontest.Clock) session.Backend {
				t.Helper()
				prefix := integrationPrefix(t.Name())
				codec, err := redisadapter.NewAESGCMCodec(redisadapter.Key{
					ID:    "integration",
					Bytes: bytes.Repeat([]byte{1}, 32),
				}, nil)
				if err != nil {
					t.Fatal("create Redis codec:", err)
				}
				backend, err := redisadapter.New(client, redisadapter.Options{
					Prefix: prefix,
					Codec:  codec,
					Clock:  clock,
					Random: rand.Reader,
				})
				if err != nil {
					t.Fatal("create Redis backend:", err)
				}
				return &logicalLeaseBackend{
					Backend:   backend,
					client:    client,
					prefix:    prefix,
					clock:     clock,
					deadlines: make(map[string]time.Time),
				}
			})

			t.Run("raw Redis lease expiry", func(t *testing.T) {
				testRawRedisLeaseExpiry(t, client)
			})
		})
	}
}

// logicalLeaseBackend maps the conformance clock's instantaneous Advance onto
// physical expiry of only the corresponding real Redis lease key. It then
// delegates acquisition to the published adapter, so Redis executes the real
// lease Lua against the real Session and metadata.
type logicalLeaseBackend struct {
	session.Backend
	client *goredis.Client
	prefix string
	clock  *sessiontest.Clock

	mu        sync.Mutex
	deadlines map[string]time.Time
}

func TestLogicalLeaseBackendPreservesDelegateConcurrency(t *testing.T) {
	clock := new(sessiontest.Clock)
	clock.Set(time.Unix(1, 0))
	probe := newAcquireProbeBackend()
	backend := &logicalLeaseBackend{
		Backend:   probe,
		clock:     clock,
		deadlines: make(map[string]time.Time),
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := backend.AcquireRefreshLease(context.Background(), "session", time.Minute)
			results <- err
		}()
	}

	<-probe.entered
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	concurrent := false
	select {
	case <-probe.entered:
		concurrent = true
	case <-timer.C:
	}
	close(probe.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal("delegate acquisition failed:", err)
		}
	}
	if !concurrent || probe.maxInFlight.Load() != 2 {
		t.Fatalf("maximum delegate acquisitions in flight = %d, want 2", probe.maxInFlight.Load())
	}
}

func TestLogicalLeaseBackendDoesNotBlockCanceledDelegate(t *testing.T) {
	clock := new(sessiontest.Clock)
	clock.Set(time.Unix(1, 0))
	probe := newAcquireProbeBackend()
	backend := &logicalLeaseBackend{
		Backend:   probe,
		clock:     clock,
		deadlines: make(map[string]time.Time),
	}
	first := make(chan error, 1)
	go func() {
		_, err := backend.AcquireRefreshLease(context.Background(), "session", time.Minute)
		first <- err
	}()
	<-probe.entered

	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() {
		_, err := backend.AcquireRefreshLease(ctx, "session", time.Minute)
		second <- err
	}()
	cancel()

	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	returnedBeforeRelease := false
	var secondErr error
	select {
	case secondErr = <-second:
		returnedBeforeRelease = true
	case <-timer.C:
	}
	close(probe.release)
	if err := <-first; err != nil {
		t.Fatal("first delegate acquisition failed:", err)
	}
	if !returnedBeforeRelease {
		secondErr = <-second
	}
	if !errors.Is(secondErr, context.Canceled) {
		t.Fatal("canceled delegate returned the wrong error")
	}
	if !returnedBeforeRelease {
		t.Fatal("canceled delegate waited for an unrelated acquisition")
	}
}

type acquireProbeBackend struct {
	session.Backend
	entered     chan struct{}
	release     chan struct{}
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
}

func newAcquireProbeBackend() *acquireProbeBackend {
	return &acquireProbeBackend{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
}

func (b *acquireProbeBackend) AcquireRefreshLease(
	ctx context.Context,
	_ string,
	_ time.Duration,
) (session.Lease, error) {
	inFlight := b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	for {
		maximum := b.maxInFlight.Load()
		if inFlight <= maximum || b.maxInFlight.CompareAndSwap(maximum, inFlight) {
			break
		}
	}
	b.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.release:
		return probeLease{}, nil
	}
}

type probeLease struct{}

func (probeLease) Valid(context.Context) bool    { return true }
func (probeLease) Release(context.Context) error { return nil }

func (b *logicalLeaseBackend) AcquireRefreshLease(
	ctx context.Context,
	sessionID string,
	duration time.Duration,
) (session.Lease, error) {
	b.mu.Lock()
	expire := false
	if deadline, ok := b.deadlines[sessionID]; ok && !b.clock.Now().Before(deadline) {
		delete(b.deadlines, sessionID)
		expire = true
	}
	b.mu.Unlock()

	if expire {
		if err := b.client.PExpire(ctx, leaseKey(b.prefix, sessionID), 0).Err(); err != nil {
			return nil, err
		}
	}
	lease, err := b.Backend.AcquireRefreshLease(ctx, sessionID, duration)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.deadlines[sessionID] = b.clock.Now().Add(duration)
	b.mu.Unlock()
	return lease, nil
}

func testRawRedisLeaseExpiry(t *testing.T, client *goredis.Client) {
	t.Helper()
	clock := new(sessiontest.Clock)
	now := time.Now().UTC().Truncate(time.Millisecond)
	clock.Set(now)
	codec, err := redisadapter.NewAESGCMCodec(redisadapter.Key{
		ID:    "raw-expiry",
		Bytes: bytes.Repeat([]byte{2}, 32),
	}, nil)
	if err != nil {
		t.Fatal("create raw Redis codec:", err)
	}
	backend, err := redisadapter.New(client, redisadapter.Options{
		Prefix: integrationPrefix(t.Name()),
		Codec:  codec,
		Clock:  clock,
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatal("create raw Redis backend:", err)
	}
	item := &session.Session{
		ID:            "raw-expiry-session",
		Version:       1,
		CreatedAt:     now,
		UpdatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(time.Minute),
		IdleExpiresAt: now.Add(time.Minute),
	}
	if err := backend.Create(t.Context(), item); err != nil {
		t.Fatal("create raw Redis Session:", err)
	}
	lease, err := backend.AcquireRefreshLease(t.Context(), item.ID, 100*time.Millisecond)
	if err != nil {
		t.Fatal("acquire short raw Redis lease:", err)
	}
	if !lease.Valid(t.Context()) {
		t.Fatal("short raw Redis lease was not initially valid")
	}
	waitForLeaseExpiry(t, lease)
	current, err := backend.AcquireRefreshLease(t.Context(), item.ID, 5*time.Second)
	if err != nil {
		t.Fatal("reacquire after raw Redis lease expiry:", err)
	}
	if !current.Valid(t.Context()) {
		t.Fatal("reacquired raw Redis lease was not valid")
	}

	next := *item
	next.Version = 2
	next.UpdatedAt = now.Add(time.Second)
	if err := backend.CompareAndSwapWithLease(t.Context(), lease, item.ID, 1, &next); !errors.Is(err, session.ErrLeaseLost) {
		t.Fatal("raw Redis accepted a mutation with a physically expired lease")
	}
	if err := lease.Release(t.Context()); !errors.Is(err, session.ErrLeaseLost) {
		t.Fatal("raw Redis released a physically expired lease")
	}
	stored, err := backend.Get(t.Context(), item.ID)
	if err != nil {
		t.Fatal("get Session after stale lease operations:", err)
	}
	if stored.Version != 1 {
		t.Fatal("stale lease operation changed the Session")
	}
	if !current.Valid(t.Context()) {
		t.Fatal("stale lease operation invalidated the current lease")
	}
	if err := current.Release(t.Context()); err != nil {
		t.Fatal("release reacquired raw Redis lease:", err)
	}
}

func waitForLeaseExpiry(t *testing.T, lease session.Lease) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	defer ticker.Stop()
	for lease.Valid(t.Context()) {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("raw Redis lease did not expire within the bounded poll")
		}
	}
}

func TestRedisOptionsSanitizesMalformedEndpoint(t *testing.T) {
	const (
		username = "endpoint-user-secret"
		password = "endpoint-password-secret"
		endpoint = "redis://" + username + ":" + password + "@localhost/%zz"
	)
	_, err := redisOptions(endpoint)
	if !errors.Is(err, errInvalidEndpoint) {
		t.Fatal("malformed endpoint returned the wrong error classification")
	}
	for _, secret := range []string{endpoint, username, password, "%zz"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("malformed endpoint error exposed input material")
		}
	}
}

func redisOptions(endpoint string) (*goredis.Options, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, errInvalidEndpoint
	}
	if parsed.Scheme != "redis" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errInvalidEndpoint
	}

	database := 0
	if path := strings.TrimPrefix(parsed.EscapedPath(), "/"); path != "" {
		database, err = strconv.Atoi(path)
		if err != nil || database < 0 {
			return nil, errInvalidEndpoint
		}
	}
	username := ""
	password := ""
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	return &goredis.Options{
		Addr:     parsed.Host,
		Username: username,
		Password: password,
		DB:       database,
	}, nil
}

var errInvalidEndpoint = errors.New("invalid Redis endpoint")

func integrationPrefix(name string) string {
	digest := sha256.Sum256([]byte(name))
	return "integration:" + hex.EncodeToString(digest[:])
}

func leaseKey(prefix, sessionID string) string {
	digest := sha256.Sum256([]byte(sessionID))
	return prefix + ":lease:{" + hex.EncodeToString(digest[:]) + "}"
}
