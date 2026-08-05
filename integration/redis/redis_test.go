package redis_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	redisadapter "github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session/sessiontest"
	"github.com/testcontainers/testcontainers-go"
	rediscontainer "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestRedisConformance(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

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
			client.AddHook(rejectLuaHook{})
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
					Backend: backend,
					prefix:  prefix,
					clock:   clock,
					records: make(map[string]logicalLeaseRecord),
					readIdentity: func(ctx context.Context, key string) (leaseIdentity, error) {
						return readRedisLeaseIdentity(ctx, client, key)
					},
					expireIdentity: func(
						ctx context.Context,
						key string,
						identity leaseIdentity,
					) (bool, error) {
						return expireRedisLeaseIdentity(ctx, client, key, identity)
					},
				}
			})

			t.Run("raw Redis lease expiry", func(t *testing.T) {
				testRawRedisLeaseExpiry(t, client)
			})
		})
	}
}

type rejectLuaHook struct{}

func (rejectLuaHook) DialHook(next goredis.DialHook) goredis.DialHook {
	return next
}

func (rejectLuaHook) ProcessHook(next goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		if err := rejectLuaCommand(cmd); err != nil {
			return err
		}
		return next(ctx, cmd)
	}
}

func (rejectLuaHook) ProcessPipelineHook(next goredis.ProcessPipelineHook) goredis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []goredis.Cmder) error {
		for _, cmd := range cmds {
			if err := rejectLuaCommand(cmd); err != nil {
				return err
			}
		}
		return next(ctx, cmds)
	}
}

func rejectLuaCommand(cmd goredis.Cmder) error {
	switch strings.ToLower(cmd.Name()) {
	case "eval", "evalsha", "script":
		return fmt.Errorf("forbidden Redis command: %s", cmd.Name())
	default:
		return nil
	}
}

type leaseIdentity struct {
	owner      string
	fence      string
	generation string
	expiresAt  string
}

func (i leaseIdentity) valid() bool {
	return i.owner != "" && i.fence != "" && i.generation != ""
}

type logicalLeaseRecord struct {
	identity leaseIdentity
	deadline time.Time
}

type leaseIdentityReader func(context.Context, string) (leaseIdentity, error)
type leaseConditionalExpirer func(context.Context, string, leaseIdentity) (bool, error)

// logicalLeaseBackend maps the conformance clock's instantaneous Advance onto
// conditional physical expiry of only the exact real Redis lease it recorded.
// It then delegates acquisition to the published adapter, so Redis executes the
// real native lease transaction against the real Session and metadata.
type logicalLeaseBackend struct {
	session.Backend
	prefix string
	clock  *sessiontest.Clock

	readIdentity   leaseIdentityReader
	expireIdentity leaseConditionalExpirer

	mu      sync.Mutex
	records map[string]logicalLeaseRecord
}

type logicalLease struct {
	backend   *logicalLeaseBackend
	delegate  session.Lease
	sessionID string
	identity  leaseIdentity
	deadline  time.Time
}

func (l *logicalLease) Valid(ctx context.Context) bool {
	return l != nil && l.backend != nil && l.delegate != nil &&
		l.backend.clock.Now().Before(l.deadline) && l.delegate.Valid(ctx)
}

func (l *logicalLease) Release(ctx context.Context) error {
	if l == nil || l.backend == nil || l.delegate == nil || !l.backend.clock.Now().Before(l.deadline) {
		return session.ErrLeaseLost
	}
	err := l.delegate.Release(ctx)
	if err == nil {
		l.backend.forgetLogicalLease(l.sessionID, l.identity)
	}
	return err
}

func TestLogicalLeaseBackendPreservesDelegateConcurrency(t *testing.T) {
	clock := new(sessiontest.Clock)
	clock.Set(time.Unix(1, 0))
	probe := newAcquireProbeBackend(2)
	identity := testLeaseIdentity("delegate-concurrency")
	backend := &logicalLeaseBackend{
		Backend: probe,
		clock:   clock,
		records: make(map[string]logicalLeaseRecord),
		readIdentity: func(context.Context, string) (leaseIdentity, error) {
			return identity, nil
		},
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
	probe := newAcquireProbeBackend(2)
	identity := testLeaseIdentity("delegate-cancel")
	backend := &logicalLeaseBackend{
		Backend: probe,
		clock:   clock,
		records: make(map[string]logicalLeaseRecord),
		readIdentity: func(context.Context, string) (leaseIdentity, error) {
			return identity, nil
		},
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

func TestLogicalLeaseBackendCannotExpireReplacementLease(t *testing.T) {
	clock := new(sessiontest.Clock)
	clock.Set(time.Unix(2, 0))
	l1 := testLeaseIdentity("l1")
	l2 := testLeaseIdentity("l2")
	state := &leaseIdentityState{current: l1}
	if err := (&stateLease{state: state, identity: l1}).Release(context.Background()); err != nil {
		t.Fatal("release first lease:", err)
	}

	expireStarted := make(chan struct{})
	resumeExpire := make(chan struct{})
	var expireCalls atomic.Int32
	backend := &logicalLeaseBackend{
		Backend: &identityBackend{state: state, next: l2},
		prefix:  "test",
		clock:   clock,
		records: map[string]logicalLeaseRecord{
			"session": {identity: l1, deadline: time.Unix(1, 0)},
		},
		readIdentity: state.read,
		expireIdentity: func(ctx context.Context, key string, identity leaseIdentity) (bool, error) {
			if expireCalls.Add(1) == 1 {
				close(expireStarted)
				select {
				case <-resumeExpire:
				case <-ctx.Done():
					return false, ctx.Err()
				}
			}
			return state.expire(ctx, key, identity)
		},
	}

	first := make(chan error, 1)
	go func() {
		_, err := backend.AcquireRefreshLease(context.Background(), "session", time.Minute)
		first <- err
	}()
	<-expireStarted

	current, err := backend.AcquireRefreshLease(context.Background(), "session", time.Minute)
	if err != nil {
		t.Fatal("acquire replacement lease:", err)
	}
	assertLogicalLeaseRecord(t, backend, "session", l2)
	close(resumeExpire)
	if err := <-first; !errors.Is(err, session.ErrConflict) {
		t.Fatal("resumed stale acquisition returned the wrong error")
	}
	if got := state.identity(); got != l2 {
		t.Fatal("stale logical expiry deleted the replacement lease")
	}
	assertLogicalLeaseRecord(t, backend, "session", l2)
	if !current.Valid(context.Background()) {
		t.Fatal("replacement lease was invalidated")
	}
}

func TestLogicalLeaseBackendRetainsFailedExpiryForRetry(t *testing.T) {
	clock := new(sessiontest.Clock)
	clock.Set(time.Unix(2, 0))
	l1 := testLeaseIdentity("retry-l1")
	l2 := testLeaseIdentity("retry-l2")
	state := &leaseIdentityState{current: l1}
	var expireCalls atomic.Int32
	delegate := &identityBackend{state: state, next: l2}
	backend := &logicalLeaseBackend{
		Backend: delegate,
		prefix:  "test",
		clock:   clock,
		records: map[string]logicalLeaseRecord{
			"session": {identity: l1, deadline: time.Unix(1, 0)},
		},
		readIdentity: state.read,
		expireIdentity: func(ctx context.Context, key string, identity leaseIdentity) (bool, error) {
			switch expireCalls.Add(1) {
			case 1, 2:
				return false, ctx.Err()
			case 3:
				return false, errors.New("conditional-expiry-sensitive-detail")
			default:
				return state.expire(ctx, key, identity)
			}
		},
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := backend.AcquireRefreshLease(canceled, "session", time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatal("conditional expiry did not preserve cancellation")
	}
	assertLogicalLeaseRecord(t, backend, "session", l1)

	deadline, deadlineCancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer deadlineCancel()
	if _, err := backend.AcquireRefreshLease(deadline, "session", time.Minute); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("conditional expiry did not preserve deadline expiry")
	}
	assertLogicalLeaseRecord(t, backend, "session", l1)

	if _, err := backend.AcquireRefreshLease(context.Background(), "session", time.Minute); !errors.Is(err, errLogicalLeaseBridge) {
		t.Fatal("conditional expiry returned the wrong fixed error")
	} else if strings.Contains(err.Error(), "sensitive-detail") {
		t.Fatal("conditional expiry error exposed backend detail")
	}
	assertLogicalLeaseRecord(t, backend, "session", l1)

	current, err := backend.AcquireRefreshLease(context.Background(), "session", time.Minute)
	if err != nil {
		t.Fatal("retry conditional expiry:", err)
	}
	if delegate.calls.Load() != 1 {
		t.Fatalf("delegate acquisition calls = %d, want 1", delegate.calls.Load())
	}
	if expireCalls.Load() != 4 {
		t.Fatalf("conditional expiry calls = %d, want 4", expireCalls.Load())
	}
	assertLogicalLeaseRecord(t, backend, "session", l2)
	if !current.Valid(context.Background()) {
		t.Fatal("retried acquisition returned an invalid lease")
	}
}

func TestLogicalLeaseBackendExpiredCallersRemainConcurrent(t *testing.T) {
	const contenders = 8
	clock := new(sessiontest.Clock)
	clock.Set(time.Unix(2, 0))
	l1 := testLeaseIdentity("concurrent-l1")
	l2 := testLeaseIdentity("concurrent-l2")
	state := &leaseIdentityState{current: l1}
	probe := newAcquireProbeBackend(contenders)
	var deletions atomic.Int32
	backend := &logicalLeaseBackend{
		Backend: probe,
		prefix:  "test",
		clock:   clock,
		records: map[string]logicalLeaseRecord{
			"session": {identity: l1, deadline: time.Unix(1, 0)},
		},
		readIdentity: func(context.Context, string) (leaseIdentity, error) { return l2, nil },
		expireIdentity: func(ctx context.Context, key string, identity leaseIdentity) (bool, error) {
			deleted, err := state.expire(ctx, key, identity)
			if deleted {
				deletions.Add(1)
			}
			return deleted, err
		},
	}

	results := make(chan error, contenders)
	for range contenders {
		go func() {
			_, err := backend.AcquireRefreshLease(context.Background(), "session", time.Minute)
			results <- err
		}()
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for range contenders {
		select {
		case <-probe.entered:
		case <-timer.C:
			close(probe.release)
			t.Fatal("expired callers did not enter the delegate concurrently")
		}
	}
	close(probe.release)
	for range contenders {
		if err := <-results; err != nil {
			t.Fatal("expired caller delegate failed:", err)
		}
	}
	if deletions.Load() != 1 {
		t.Fatalf("conditional lease deletions = %d, want 1", deletions.Load())
	}
	if probe.maxInFlight.Load() != contenders {
		t.Fatalf("maximum delegate acquisitions in flight = %d, want %d", probe.maxInFlight.Load(), contenders)
	}
	assertLogicalLeaseRecord(t, backend, "session", l2)
}

func TestLogicalLeaseBackendCleansGrantWhenIdentityReadFails(t *testing.T) {
	clock := new(sessiontest.Clock)
	clock.Set(time.Unix(1, 0))
	identity := testLeaseIdentity("untracked")
	state := &leaseIdentityState{}
	backend := &logicalLeaseBackend{
		Backend: &identityBackend{state: state, next: identity},
		prefix:  "test",
		clock:   clock,
		records: make(map[string]logicalLeaseRecord),
		readIdentity: func(context.Context, string) (leaseIdentity, error) {
			return leaseIdentity{}, errors.New("identity-reader-sensitive-detail")
		},
		expireIdentity: state.expire,
	}

	lease, err := backend.AcquireRefreshLease(context.Background(), "session", time.Minute)
	if lease != nil {
		t.Fatal("identity read failure returned an untracked lease")
	}
	if !errors.Is(err, errLogicalLeaseBridge) {
		t.Fatal("identity read failure returned the wrong fixed error")
	}
	if strings.Contains(err.Error(), "sensitive-detail") {
		t.Fatal("identity read failure exposed backend detail")
	}
	if state.identity() != (leaseIdentity{}) {
		t.Fatal("identity read failure left the granted lease live")
	}
	if state.releaseCalls.Load() != 1 || !state.releaseHadDeadline.Load() {
		t.Fatal("identity read failure did not use one bounded cleanup Release")
	}
	backend.mu.Lock()
	tracked := len(backend.records)
	backend.mu.Unlock()
	if tracked != 0 {
		t.Fatal("identity read failure recorded a lease")
	}
}

func assertLogicalLeaseRecord(
	t *testing.T,
	backend *logicalLeaseBackend,
	sessionID string,
	want leaseIdentity,
) {
	t.Helper()
	backend.mu.Lock()
	record, ok := backend.records[sessionID]
	backend.mu.Unlock()
	if !ok || record.identity != want {
		t.Fatal("logical lease record did not match the expected stable identity")
	}
}

func testLeaseIdentity(suffix string) leaseIdentity {
	return leaseIdentity{
		owner:      "owner-" + suffix,
		fence:      "fence-" + suffix,
		generation: "generation-" + suffix,
		expiresAt:  "expires-" + suffix,
	}
}

type leaseIdentityState struct {
	mu                 sync.Mutex
	current            leaseIdentity
	releaseCalls       atomic.Int32
	releaseHadDeadline atomic.Bool
}

func (s *leaseIdentityState) identity() leaseIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

func (s *leaseIdentityState) read(context.Context, string) (leaseIdentity, error) {
	return s.identity(), nil
}

func (s *leaseIdentityState) expire(
	ctx context.Context,
	_ string,
	want leaseIdentity,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != want {
		return false, nil
	}
	s.current = leaseIdentity{}
	return true, nil
}

type identityBackend struct {
	session.Backend
	state *leaseIdentityState
	next  leaseIdentity
	calls atomic.Int32
}

func (b *identityBackend) AcquireRefreshLease(
	ctx context.Context,
	_ string,
	_ time.Duration,
) (session.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.calls.Add(1)
	b.state.mu.Lock()
	defer b.state.mu.Unlock()
	if b.state.current != (leaseIdentity{}) {
		return nil, session.ErrConflict
	}
	b.state.current = b.next
	return &stateLease{state: b.state, identity: b.next}, nil
}

type stateLease struct {
	state    *leaseIdentityState
	identity leaseIdentity
}

func (l *stateLease) Valid(context.Context) bool {
	return l.state.identity() == l.identity
}

func (l *stateLease) Release(ctx context.Context) error {
	l.state.releaseCalls.Add(1)
	if _, ok := ctx.Deadline(); ok {
		l.state.releaseHadDeadline.Store(true)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	if l.state.current != l.identity {
		return session.ErrLeaseLost
	}
	l.state.current = leaseIdentity{}
	return nil
}

type acquireProbeBackend struct {
	session.Backend
	entered     chan struct{}
	release     chan struct{}
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
}

func newAcquireProbeBackend(capacity int) *acquireProbeBackend {
	return &acquireProbeBackend{
		entered: make(chan struct{}, capacity),
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

var errLogicalLeaseBridge = errors.New("Redis integration lease bridge failed")

func (b *logicalLeaseBackend) AcquireRefreshLease(
	ctx context.Context,
	sessionID string,
	duration time.Duration,
) (session.Lease, error) {
	b.mu.Lock()
	record, expire := b.records[sessionID]
	expire = expire && !b.clock.Now().Before(record.deadline)
	b.mu.Unlock()

	if expire {
		if b.expireIdentity == nil {
			return nil, errLogicalLeaseBridge
		}
		if _, err := b.expireIdentity(ctx, leaseKey(b.prefix, sessionID), record.identity); err != nil {
			return nil, logicalLeaseBridgeError(err)
		}
		b.mu.Lock()
		if current, ok := b.records[sessionID]; ok && current.identity == record.identity {
			delete(b.records, sessionID)
		}
		b.mu.Unlock()
	}
	lease, err := b.Backend.AcquireRefreshLease(ctx, sessionID, duration)
	if err != nil {
		return nil, err
	}
	if lease == nil || b.readIdentity == nil {
		cleanupGrantedLease(lease)
		return nil, errLogicalLeaseBridge
	}
	identity, err := b.readIdentity(ctx, leaseKey(b.prefix, sessionID))
	if err != nil || !identity.valid() {
		cleanupGrantedLease(lease)
		return nil, logicalLeaseBridgeError(err)
	}
	b.mu.Lock()
	if b.records == nil {
		b.records = make(map[string]logicalLeaseRecord)
	}
	deadline := b.clock.Now().Add(duration)
	b.records[sessionID] = logicalLeaseRecord{
		identity: identity,
		deadline: deadline,
	}
	b.mu.Unlock()
	return &logicalLease{
		backend:   b,
		delegate:  lease,
		sessionID: sessionID,
		identity:  identity,
		deadline:  deadline,
	}, nil
}

func (b *logicalLeaseBackend) CompareAndSwapWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
	logical, ok := b.unwrapLogicalLease(lease, id)
	if !ok {
		return b.Backend.CompareAndSwapWithLease(ctx, lease, id, expectedVersion, next)
	}
	if !b.clock.Now().Before(logical.deadline) {
		return b.Backend.CompareAndSwapWithLease(ctx, nil, id, expectedVersion, next)
	}
	err := b.Backend.CompareAndSwapWithLease(ctx, logical.delegate, id, expectedVersion, next)
	if err == nil {
		b.forgetLogicalLease(id, logical.identity)
	}
	return err
}

func (b *logicalLeaseBackend) DeleteWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
) error {
	logical, ok := b.unwrapLogicalLease(lease, id)
	if !ok {
		return b.Backend.DeleteWithLease(ctx, lease, id, expectedVersion)
	}
	if !b.clock.Now().Before(logical.deadline) {
		return b.Backend.DeleteWithLease(ctx, nil, id, expectedVersion)
	}
	err := b.Backend.DeleteWithLease(ctx, logical.delegate, id, expectedVersion)
	if err == nil {
		b.forgetLogicalLease(id, logical.identity)
	}
	return err
}

func (b *logicalLeaseBackend) unwrapLogicalLease(candidate session.Lease, id string) (*logicalLease, bool) {
	lease, ok := candidate.(*logicalLease)
	return lease, ok && lease != nil && lease.backend == b && lease.sessionID == id && lease.delegate != nil
}

func (b *logicalLeaseBackend) forgetLogicalLease(id string, identity leaseIdentity) {
	b.mu.Lock()
	if current, ok := b.records[id]; ok && current.identity == identity {
		delete(b.records, id)
	}
	b.mu.Unlock()
}

func logicalLeaseBridgeError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return errLogicalLeaseBridge
	}
}

func cleanupGrantedLease(lease session.Lease) {
	if lease == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = lease.Release(ctx)
}

func readRedisLeaseIdentity(
	ctx context.Context,
	client goredis.UniversalClient,
	key string,
) (leaseIdentity, error) {
	values, err := client.HMGet(ctx, key, "owner", "fence", "generation").Result()
	if err != nil {
		return leaseIdentity{}, err
	}
	if len(values) != 3 {
		return leaseIdentity{}, errLogicalLeaseBridge
	}
	owner, ownerOK := redisLeaseText(values[0])
	fence, fenceOK := redisLeaseText(values[1])
	generation, generationOK := redisLeaseText(values[2])
	identity := leaseIdentity{
		owner:      owner,
		fence:      fence,
		generation: generation,
	}
	if !ownerOK || !fenceOK || !generationOK || !identity.valid() {
		return leaseIdentity{}, errLogicalLeaseBridge
	}
	return identity, nil
}

func expireRedisLeaseIdentity(
	ctx context.Context,
	client goredis.UniversalClient,
	key string,
	identity leaseIdentity,
) (bool, error) {
	for range 16 {
		deleted := false
		err := client.Watch(ctx, func(tx *goredis.Tx) error {
			values, err := tx.HMGet(ctx, key, "owner", "fence", "generation").Result()
			if err != nil {
				return err
			}
			if len(values) != 3 {
				return errLogicalLeaseBridge
			}
			owner, ownerOK := redisLeaseText(values[0])
			fence, fenceOK := redisLeaseText(values[1])
			generation, generationOK := redisLeaseText(values[2])
			if !ownerOK || !fenceOK || !generationOK ||
				owner != identity.owner || fence != identity.fence || generation != identity.generation {
				return nil
			}
			_, err = tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
				pipe.Del(ctx, key)
				return nil
			})
			deleted = err == nil
			return err
		}, key)
		switch {
		case errors.Is(err, goredis.TxFailedErr):
			continue
		case err != nil:
			return false, err
		default:
			return deleted, nil
		}
	}
	return false, goredis.TxFailedErr
}

func redisLeaseText(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, value != ""
	case []byte:
		return string(value), len(value) != 0
	default:
		return "", false
	}
}

func testRawRedisLeaseExpiry(t *testing.T, client goredis.UniversalClient) {
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
