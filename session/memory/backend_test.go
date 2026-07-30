package memory

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/sessiontest"
)

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

type blockingClock struct {
	mu      sync.Mutex
	now     time.Time
	started chan struct{}
	release chan struct{}
}

func (c *blockingClock) Now() time.Time {
	c.mu.Lock()
	now := c.now
	started := c.started
	release := c.release
	c.started = nil
	c.release = nil
	c.mu.Unlock()
	if started != nil {
		close(started)
		<-release
	}
	return now
}

func (c *blockingClock) Arm() (<-chan struct{}, chan<- struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started = make(chan struct{})
	c.release = make(chan struct{})
	return c.started, c.release
}

func (c *blockingClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

type blockingReader struct {
	started chan struct{}
	release chan struct{}
}

func (r *blockingReader) Read(buffer []byte) (int, error) {
	select {
	case <-r.started:
	default:
		close(r.started)
	}
	<-r.release
	for index := range buffer {
		buffer[index] = byte(index)
	}
	return len(buffer), nil
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func TestBackendConformance(t *testing.T) {
	sessiontest.Run(t, func(t *testing.T) session.Backend {
		t.Helper()
		return New(Options{})
	})
}

func TestNewNormalizesTypedNilOptionalCollaborators(t *testing.T) {
	var clock *mutableClock
	var random *bytes.Reader
	backend := New(Options{Clock: clock, Random: random})
	if backend == nil || backend.clock == nil || backend.random == nil {
		t.Fatalf("backend retained typed nil collaborators: %#v", backend)
	}
	lock, err := backend.Lock(t.Context(), "typed-nil-options", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Unlock(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestBackendUsesInjectedClockForExpiryAndPrune(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	backend := New(Options{Clock: clock, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 256))})
	ctx := context.Background()

	if err := backend.Create(ctx, &session.Session{ID: "session-expiry", Version: 1, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := backend.Create(ctx, &session.Session{ID: "session-idle", Version: 1, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := backend.PutFlow(ctx, &session.Flow{ID: "flow-expiry", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	lock, err := backend.Lock(ctx, "lock-expiry", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	clock.Advance(time.Minute)
	backend.Prune()

	for _, id := range []string{"session-expiry", "session-idle"} {
		if _, err := backend.Get(ctx, id); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("get %q error = %v", id, err)
		}
	}
	if _, err := backend.ConsumeFlow(ctx, "flow-expiry"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("consume error = %v", err)
	}
	if lock.Valid(ctx) {
		t.Fatal("pruned lock remains valid")
	}
	if err := lock.Unlock(ctx); !errors.Is(err, session.ErrLockLost) {
		t.Fatalf("unlock error = %v", err)
	}
	replacement, err := backend.Lock(ctx, "lock-expiry", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBackendExpiredAccessReturnsExpiredThenNotFoundWithInjectedClock(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	backend := New(Options{Clock: clock})
	ctx := context.Background()
	item := &session.Session{ID: "session-expiry", Version: 1, ExpiresAt: now.Add(time.Minute)}
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	flow := &session.Flow{ID: "flow-expiry", ExpiresAt: now.Add(time.Minute)}
	if err := backend.PutFlow(ctx, flow); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Minute)

	if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrExpired) {
		t.Fatalf("first get error = %v", err)
	}
	if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("second get error = %v", err)
	}
	if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrExpired) {
		t.Fatalf("first consume error = %v", err)
	}
	if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("second consume error = %v", err)
	}
}

func TestBackendRandomFailureDoesNotCreateLockOrExposeIdentifier(t *testing.T) {
	backend := New(Options{Random: io.LimitReader(strings.NewReader("short"), 5)})
	ctx := context.Background()
	secretID := "raw-session-lock-id"
	if _, err := backend.Lock(ctx, secretID, time.Minute); err == nil {
		t.Fatal("expected random source error")
	} else if strings.Contains(err.Error(), secretID) || strings.Contains(err.Error(), "short") {
		t.Fatalf("error exposed sensitive value: %v", err)
	}

	backend.random = bytes.NewReader(bytes.Repeat([]byte{2}, 64))
	lock, err := backend.Lock(ctx, secretID, time.Minute)
	if err != nil {
		t.Fatalf("failed lock left partial state: %v", err)
	}
	if err := lock.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBackendLockTokenUsesThirtyTwoRandomBytes(t *testing.T) {
	backend := New(Options{Random: bytes.NewReader(bytes.Repeat([]byte{9}, 32))})
	lock, err := backend.Lock(context.Background(), "session-lock", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	owned, ok := lock.(*ownedLock)
	if !ok {
		t.Fatalf("lock type = %T", lock)
	}
	raw, err := base64.RawURLEncoding.DecodeString(owned.token)
	if err != nil {
		t.Fatalf("token is not raw URL base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("random token bytes = %d", len(raw))
	}
}

func TestBackendExpiredCASRemovesSession(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	backend := New(Options{Clock: clock})
	ctx := context.Background()
	item := &session.Session{ID: "session-cas-expiry", Version: 1, ExpiresAt: now.Add(time.Minute)}
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	next := *item
	next.Version = 2
	next.ExpiresAt = now.Add(time.Hour)
	clock.Advance(time.Minute)

	if err := backend.CompareAndSwap(ctx, item.ID, 1, &next); !errors.Is(err, session.ErrExpired) {
		t.Fatalf("first cas error = %v", err)
	}
	if err := backend.CompareAndSwap(ctx, item.ID, 1, &next); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("second cas error = %v", err)
	}
}

func TestBackendClockReadsAreSerializedWithStateDecisions(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		operation func(*Backend) func()
	}{
		{name: "create", operation: func(backend *Backend) func() {
			return func() {
				_ = backend.Create(context.Background(), &session.Session{
					ID: "create", Version: 1, ExpiresAt: now.Add(time.Hour),
				})
			}
		}},
		{name: "get", operation: func(backend *Backend) func() {
			_ = backend.Create(context.Background(), &session.Session{
				ID: "get", Version: 1, ExpiresAt: now.Add(time.Hour),
			})
			return func() { _, _ = backend.Get(context.Background(), "get") }
		}},
		{name: "compare and swap", operation: func(backend *Backend) func() {
			_ = backend.Create(context.Background(), &session.Session{
				ID: "cas", Version: 1, ExpiresAt: now.Add(time.Hour),
			})
			return func() {
				_ = backend.CompareAndSwap(context.Background(), "cas", 1, &session.Session{
					ID: "cas", Version: 2, ExpiresAt: now.Add(time.Hour),
				})
			}
		}},
		{name: "put flow", operation: func(backend *Backend) func() {
			return func() {
				_ = backend.PutFlow(context.Background(), &session.Flow{
					ID: "put-flow", ExpiresAt: now.Add(time.Hour),
				})
			}
		}},
		{name: "consume flow", operation: func(backend *Backend) func() {
			_ = backend.PutFlow(context.Background(), &session.Flow{
				ID: "consume-flow", ExpiresAt: now.Add(time.Hour),
			})
			return func() { _, _ = backend.ConsumeFlow(context.Background(), "consume-flow") }
		}},
		{name: "lock", operation: func(backend *Backend) func() {
			return func() { _, _ = backend.Lock(context.Background(), "lock", time.Hour) }
		}},
		{name: "lock valid", operation: func(backend *Backend) func() {
			lock, _ := backend.Lock(context.Background(), "valid", time.Hour)
			return func() { _ = lock.Valid(context.Background()) }
		}},
		{name: "unlock", operation: func(backend *Backend) func() {
			lock, _ := backend.Lock(context.Background(), "unlock", time.Hour)
			return func() { _ = lock.Unlock(context.Background()) }
		}},
		{name: "prune", operation: func(backend *Backend) func() {
			return backend.Prune
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &blockingClock{now: now}
			backend := New(Options{
				Clock:  clock,
				Random: bytes.NewReader(bytes.Repeat([]byte{1}, 512)),
			})
			operation := test.operation(backend)
			started, release := clock.Arm()
			done := make(chan struct{})
			go func() {
				defer close(done)
				operation()
			}()
			<-started

			acquired := make(chan struct{})
			go func() {
				backend.mu.Lock()
				clock.Advance(2 * time.Hour)
				close(acquired)
				backend.mu.Unlock()
			}()
			select {
			case <-acquired:
				close(release)
				<-done
				t.Fatal("state lock was available while clock decision was in progress")
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			<-done
			<-acquired
		})
	}
}

func TestBackendLockRandomReadDoesNotHoldStateMutex(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	reader := &blockingReader{started: make(chan struct{}), release: make(chan struct{})}
	backend := New(Options{Clock: &mutableClock{now: now}, Random: reader})
	ctx := context.Background()
	if err := backend.Create(ctx, &session.Session{
		ID: "readable", Version: 1, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	lockResult := make(chan error, 1)
	go func() {
		_, err := backend.Lock(ctx, "lock-random", time.Hour)
		lockResult <- err
	}()
	<-reader.started

	getResult := make(chan error, 1)
	go func() {
		_, err := backend.Get(ctx, "readable")
		getResult <- err
	}()
	select {
	case err := <-getResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		close(reader.release)
		<-lockResult
		t.Fatal("blocking random reader held state mutex")
	}
	close(reader.release)
	if err := <-lockResult; err != nil {
		t.Fatal(err)
	}
}
