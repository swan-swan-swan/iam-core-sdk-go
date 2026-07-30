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
