package sessiontest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

var epoch = time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)

type Clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *Clock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *Clock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

type Factory func(testing.TB, *Clock) session.Backend

func Run(t *testing.T, factory Factory) {
	t.Helper()

	t.Run("flow is consumed exactly once", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		flow := fullFlow("flow-once", clock.Now().Add(time.Minute))
		mustNoError(t, backend.PutFlow(context.Background(), flow))

		const contenders = 16
		var wait sync.WaitGroup
		results := make(chan error, contenders)
		for range contenders {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := backend.ConsumeFlow(context.Background(), flow.ID)
				results <- err
			}()
		}
		wait.Wait()
		close(results)

		var consumed, missing int
		for err := range results {
			switch {
			case err == nil:
				consumed++
			case errors.Is(err, session.ErrNotFound):
				missing++
			default:
				t.Fatal("ConsumeFlow returned an unexpected error classification")
			}
		}
		if consumed != 1 || missing != contenders-1 {
			t.Fatalf("consumed = %d, missing = %d", consumed, missing)
		}
	})

	t.Run("flow expiry uses an exclusive boundary", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()

		expired := fullFlow("flow-put-expired", clock.Now())
		if err := backend.PutFlow(ctx, expired); !errors.Is(err, session.ErrExpired) {
			t.Fatal("PutFlow returned the wrong error for an expired Flow")
		}

		flow := fullFlow("flow-consume-expired", clock.Now().Add(time.Minute))
		mustNoError(t, backend.PutFlow(ctx, flow))
		clock.Advance(time.Minute)
		if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrExpired) {
			t.Fatal("ConsumeFlow returned the wrong error for an expired Flow")
		}
		if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatal("ConsumeFlow returned the wrong error for a removed Flow")
		}
	})

	t.Run("flow input and output are defensive copies", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		flow := fullFlow("flow-copy", clock.Now().Add(time.Minute))
		mustNoError(t, backend.PutFlow(ctx, flow))
		flow.State = "mutated"
		flow.CodeVerifier = "mutated"

		got, err := backend.ConsumeFlow(ctx, flow.ID)
		mustNoError(t, err)
		if got == flow {
			t.Fatal("ConsumeFlow returned the caller's Flow pointer")
		}
		if got.State != "state-original" || got.CodeVerifier != "verifier-original" {
			t.Fatal("stored Flow changed after the caller mutated its input")
		}
	})

	t.Run("flow and session IDs are trim-validated opaque values", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()

		invalid := backend.PutFlow(ctx, fullFlow(" \t\n", clock.Now().Add(time.Minute)))
		if invalid == nil {
			t.Fatal("PutFlow accepted a whitespace-only ID")
		}
		assertInvalidClass := func(operation string, err error) {
			t.Helper()
			if err == nil {
				t.Fatalf("%s accepted a whitespace-only ID", operation)
			}
			if err != invalid {
				t.Fatalf("%s returned a different invalid-input class", operation)
			}
		}
		_, err := backend.ConsumeFlow(ctx, " \t\n")
		assertInvalidClass("ConsumeFlow", err)
		assertInvalidClass("Create", backend.Create(ctx, fullSession(" \t\n", clock.Now())))
		_, err = backend.Get(ctx, " \t\n")
		assertInvalidClass("Get", err)
		next := fullSession(" \t\n", clock.Now())
		next.Version = 2
		assertInvalidClass("CompareAndSwap", backend.CompareAndSwap(ctx, " \t\n", 1, next))
		assertInvalidClass("Delete", backend.Delete(ctx, " \t\n"))
		_, err = backend.AcquireRefreshLease(ctx, " \t\n", time.Minute)
		assertInvalidClass("AcquireRefreshLease", err)
		assertInvalidClass("CompareAndSwapWithLease", backend.CompareAndSwapWithLease(ctx, nil, " \t\n", 1, next))
		assertInvalidClass("DeleteWithLease", backend.DeleteWithLease(ctx, nil, " \t\n", 1))

		opaqueID := " opaque-flow-id "
		flow := fullFlow(opaqueID, clock.Now().Add(time.Minute))
		mustNoError(t, backend.PutFlow(ctx, flow))
		consumed, err := backend.ConsumeFlow(ctx, opaqueID)
		mustNoError(t, err)
		if consumed.ID != opaqueID {
			t.Fatal("Flow ID was trimmed instead of preserved as opaque")
		}
		opaqueID = " opaque-session-id "
		item := fullSession(opaqueID, clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		stored, err := backend.Get(ctx, opaqueID)
		mustNoError(t, err)
		if stored.ID != opaqueID {
			t.Fatal("Session ID was trimmed instead of preserved as opaque")
		}
	})

	t.Run("zero Flow expiry is invalid input", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		invalid := backend.PutFlow(ctx, fullFlow(" \t\n", clock.Now().Add(time.Minute)))
		if invalid == nil {
			t.Fatal("whitespace-only Flow ID was accepted")
		}
		zeroExpiry := fullFlow("flow-zero-expiry", time.Time{})
		if err := backend.PutFlow(ctx, zeroExpiry); err != invalid {
			t.Fatal("zero Flow expiry did not use the invalid-input error class")
		}
		if _, err := backend.ConsumeFlow(ctx, zeroExpiry.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatal("zero-expiry Flow mutated backend state")
		}
	})

	t.Run("session create and get make deep defensive copies", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-copy", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		mutateSession(item)

		first, err := backend.Get(ctx, item.ID)
		mustNoError(t, err)
		assertOriginalSession(t, first, 1)
		mutateSession(first)

		second, err := backend.Get(ctx, item.ID)
		mustNoError(t, err)
		assertOriginalSession(t, second, 1)
	})

	t.Run("session copies preserve initialized empty Groups", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-empty-groups", clock.Now())
		item.Auth.Groups = []string{}
		mustNoError(t, backend.Create(ctx, item))

		stored, err := backend.Get(ctx, item.ID)
		mustNoError(t, err)
		if stored.Auth.Groups == nil || len(stored.Auth.Groups) != 0 {
			t.Fatal("stored Groups was not preserved as an initialized empty slice")
		}
		next := fullSession(item.ID, clock.Now())
		next.Version = 2
		next.Auth.Groups = []string{}
		mustNoError(t, backend.CompareAndSwap(ctx, item.ID, item.Version, next))
		stored, err = backend.Get(ctx, item.ID)
		mustNoError(t, err)
		if stored.Auth.Groups == nil || len(stored.Auth.Groups) != 0 {
			t.Fatal("updated Groups was not preserved as an initialized empty slice")
		}
	})

	t.Run("session create rejects duplicate and expired state", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-create", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		replacement := fullSession(item.ID, clock.Now())
		replacement.Tokens.AccessToken = "replacement"
		if err := backend.Create(ctx, replacement); !errors.Is(err, session.ErrConflict) {
			t.Fatal("Create returned the wrong error for a duplicate Session")
		}
		stored, err := backend.Get(ctx, item.ID)
		mustNoError(t, err)
		if stored.Tokens.AccessToken != "access-original" {
			t.Fatal("duplicate create replaced the session")
		}

		absolute := fullSession("session-absolute-expired", clock.Now())
		absolute.ExpiresAt = clock.Now()
		if err := backend.Create(ctx, absolute); !errors.Is(err, session.ErrExpired) {
			t.Fatal("Create returned the wrong error at absolute expiry")
		}
		idle := fullSession("session-idle-expired", clock.Now())
		idle.IdleExpiresAt = clock.Now()
		if err := backend.Create(ctx, idle); !errors.Is(err, session.ErrExpired) {
			t.Fatal("Create returned the wrong error at idle expiry")
		}
	})

	t.Run("session writes require initial version and idle expiry", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		for _, version := range []uint64{0, 2} {
			item := fullSession(fmt.Sprintf("session-invalid-version-%d", version), clock.Now())
			item.Version = version
			if err := backend.Create(ctx, item); err == nil {
				t.Fatalf("Create accepted initial version %d", version)
			}
			if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrNotFound) {
				t.Fatalf("invalid initial version %d mutated state", version)
			}
		}

		missingIdle := fullSession("session-missing-idle", clock.Now())
		missingIdle.IdleExpiresAt = time.Time{}
		if err := backend.Create(ctx, missingIdle); err == nil {
			t.Fatal("Create accepted zero IdleExpiresAt")
		}
		if _, err := backend.Get(ctx, missingIdle.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatal("zero IdleExpiresAt create mutated state")
		}

		item := fullSession("session-update-missing-idle", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		next := fullSession(item.ID, clock.Now())
		next.Version = 2
		next.IdleExpiresAt = time.Time{}
		if err := backend.CompareAndSwap(ctx, item.ID, item.Version, next); err == nil {
			t.Fatal("CompareAndSwap accepted zero IdleExpiresAt")
		}
		stored, err := backend.Get(ctx, item.ID)
		mustNoError(t, err)
		if stored.Version != 1 {
			t.Fatal("invalid replacement mutated Session")
		}
		lease, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		mustNoError(t, err)
		if err := backend.CompareAndSwapWithLease(ctx, lease, item.ID, item.Version, next); err == nil {
			t.Fatal("CompareAndSwapWithLease accepted zero IdleExpiresAt")
		}
		if !lease.Valid(ctx) {
			t.Fatal("invalid leased replacement changed lease ownership")
		}
		mustNoError(t, lease.Release(ctx))
	})

	t.Run("session compare and swap is versioned and atomic", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-cas", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		next := fullSession(item.ID, clock.Now())
		next.Version = 2
		next.Tokens.AccessToken = "access-next"

		const contenders = 16
		var wait sync.WaitGroup
		results := make(chan error, contenders)
		for range contenders {
			wait.Add(1)
			go func() {
				defer wait.Done()
				results <- backend.CompareAndSwap(ctx, item.ID, 1, next)
			}()
		}
		wait.Wait()
		close(results)

		var swapped, conflicts int
		for err := range results {
			switch {
			case err == nil:
				swapped++
			case errors.Is(err, session.ErrConflict):
				conflicts++
			default:
				t.Fatal("CompareAndSwap returned an unexpected error classification")
			}
		}
		if swapped != 1 || conflicts != contenders-1 {
			t.Fatalf("swapped = %d, conflicts = %d", swapped, conflicts)
		}
		stored, err := backend.Get(ctx, item.ID)
		mustNoError(t, err)
		if stored.Version != 2 {
			t.Fatalf("stored Session version = %d, want 2", stored.Version)
		}
		if stored.Tokens.AccessToken != "access-next" {
			t.Fatal("stored access token did not match the successful replacement")
		}
	})

	t.Run("session compare and swap enforces IDs versions and copies", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-cas-invariants", clock.Now())
		mustNoError(t, backend.Create(ctx, item))

		badID := fullSession(item.ID, clock.Now())
		badID.Version = 2
		if err := backend.CompareAndSwap(ctx, "other", 1, badID); err == nil {
			t.Fatal("CAS accepted a different argument ID")
		}
		badPayload := fullSession("other", clock.Now())
		badPayload.Version = 2
		if err := backend.CompareAndSwap(ctx, item.ID, 1, badPayload); err == nil {
			t.Fatal("CAS accepted a different payload ID")
		}
		badVersion := fullSession(item.ID, clock.Now())
		badVersion.Version = 3
		if err := backend.CompareAndSwap(ctx, item.ID, 1, badVersion); err == nil {
			t.Fatal("CAS accepted a skipped payload version")
		}

		next := fullSession(item.ID, clock.Now())
		next.Version = 2
		mustNoError(t, backend.CompareAndSwap(ctx, item.ID, 1, next))
		mutateSession(next)
		stored, err := backend.Get(ctx, item.ID)
		mustNoError(t, err)
		assertOriginalSession(t, stored, 2)
	})

	t.Run("session expiry is reported once and removes state", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-expiry", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		clock.Set(item.IdleExpiresAt)
		if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrExpired) {
			t.Fatal("Get returned the wrong error for an expired Session")
		}
		if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatal("Get returned the wrong error for a removed Session")
		}
	})

	t.Run("delete is idempotent", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-delete", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		mustNoError(t, backend.Delete(ctx, item.ID))
		mustNoError(t, backend.Delete(ctx, item.ID))
		if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatal("Get returned the wrong error for a deleted Session")
		}
	})

	t.Run("refresh leases are mutually exclusive and releasable", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-lease", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		lease, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		mustNoError(t, err)
		if !lease.Valid(ctx) {
			t.Fatal("fresh lease is invalid")
		}
		if _, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute); !errors.Is(err, session.ErrConflict) {
			t.Fatal("AcquireRefreshLease returned the wrong error for live ownership")
		}
		mustNoError(t, lease.Release(ctx))
		if lease.Valid(ctx) {
			t.Fatal("released lease is valid")
		}
		second, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		mustNoError(t, err)
		mustNoError(t, second.Release(ctx))
	})

	t.Run("expired lease is rejected at the expiry boundary", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-expired-lease", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		lease, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		mustNoError(t, err)
		clock.Advance(time.Minute)
		if lease.Valid(ctx) {
			t.Fatal("lease remained valid at ExpiresAt")
		}
		next := fullSession(item.ID, clock.Now())
		next.Version = 2
		if err := backend.CompareAndSwapWithLease(ctx, lease, item.ID, 1, next); !errors.Is(err, session.ErrLeaseLost) {
			t.Fatal("leased CAS returned the wrong error for an expired Lease")
		}
		if err := backend.DeleteWithLease(ctx, lease, item.ID, 1); !errors.Is(err, session.ErrLeaseLost) {
			t.Fatal("leased delete returned the wrong error for an expired Lease")
		}
		if err := lease.Release(ctx); !errors.Is(err, session.ErrLeaseLost) {
			t.Fatal("Release returned the wrong error for an expired Lease")
		}
	})

	t.Run("new fencing token rejects a stale lease", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-fence", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		stale, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		mustNoError(t, err)
		clock.Advance(time.Minute)
		current, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		mustNoError(t, err)
		if err := stale.Release(ctx); !errors.Is(err, session.ErrLeaseLost) {
			t.Fatal("Release returned the wrong error for a stale Lease")
		}
		if !current.Valid(ctx) {
			t.Fatal("stale release invalidated current lease")
		}
		next := fullSession(item.ID, clock.Now())
		next.Version = 2
		if err := backend.CompareAndSwapWithLease(ctx, stale, item.ID, 1, next); !errors.Is(err, session.ErrLeaseLost) {
			t.Fatal("leased CAS returned the wrong error for a stale Lease")
		}
		mustNoError(t, backend.CompareAndSwapWithLease(ctx, current, item.ID, 1, next))
		mustNoError(t, current.Release(ctx))
	})

	t.Run("leased compare and swap validates session and deep copies", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		first := fullSession("session-lease-first", clock.Now())
		second := fullSession("session-lease-second", clock.Now())
		mustNoError(t, backend.Create(ctx, first))
		mustNoError(t, backend.Create(ctx, second))
		lease, err := backend.AcquireRefreshLease(ctx, first.ID, time.Minute)
		mustNoError(t, err)

		wrong := fullSession(second.ID, clock.Now())
		wrong.Version = 2
		if err := backend.CompareAndSwapWithLease(ctx, lease, second.ID, 1, wrong); !errors.Is(err, session.ErrLeaseLost) {
			t.Fatal("leased CAS returned the wrong error for a cross-Session Lease")
		}
		next := fullSession(first.ID, clock.Now())
		next.Version = 2
		mustNoError(t, backend.CompareAndSwapWithLease(ctx, lease, first.ID, 1, next))
		mutateSession(next)
		stored, err := backend.Get(ctx, first.ID)
		mustNoError(t, err)
		assertOriginalSession(t, stored, 2)
		mustNoError(t, lease.Release(ctx))
	})

	t.Run("delete with lease checks version and invalidates lease", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-delete-lease", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		lease, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		mustNoError(t, err)
		if err := backend.DeleteWithLease(ctx, lease, item.ID, 2); !errors.Is(err, session.ErrConflict) {
			t.Fatal("leased delete returned the wrong error for a version conflict")
		}
		if !lease.Valid(ctx) {
			t.Fatal("version conflict invalidated lease")
		}
		mustNoError(t, backend.DeleteWithLease(ctx, lease, item.ID, 1))
		if lease.Valid(ctx) {
			t.Fatal("successful delete left lease valid")
		}
		if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatal("Get returned the wrong error after leased deletion")
		}
	})

	t.Run("concurrent refresh acquisition has one owner", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		item := fullSession("session-concurrent-lease", clock.Now())
		mustNoError(t, backend.Create(ctx, item))

		const contenders = 32
		var wait sync.WaitGroup
		results := make(chan leaseResult, contenders)
		for range contenders {
			wait.Add(1)
			go func() {
				defer wait.Done()
				lease, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
				results <- leaseResult{lease: lease, err: err}
			}()
		}
		wait.Wait()
		close(results)

		var owner session.Lease
		var acquired, conflicts int
		for result := range results {
			switch {
			case result.err == nil:
				acquired++
				owner = result.lease
			case errors.Is(result.err, session.ErrConflict):
				conflicts++
			default:
				t.Fatal("AcquireRefreshLease returned an unexpected error classification")
			}
		}
		if acquired != 1 || conflicts != contenders-1 {
			t.Fatalf("acquired = %d, conflicts = %d", acquired, conflicts)
		}
		if owner == nil || !owner.Valid(ctx) {
			t.Fatal("winning lease is not valid")
		}
		mustNoError(t, owner.Release(ctx))
	})

	t.Run("refresh lease requires a live session", func(t *testing.T) {
		backend, clock := newBackend(t, factory)
		ctx := context.Background()
		if _, err := backend.AcquireRefreshLease(ctx, "missing", time.Minute); !errors.Is(err, session.ErrNotFound) {
			t.Fatal("AcquireRefreshLease returned the wrong error for a missing Session")
		}
		item := fullSession("session-acquire-expired", clock.Now())
		mustNoError(t, backend.Create(ctx, item))
		clock.Set(item.ExpiresAt)
		if _, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute); !errors.Is(err, session.ErrExpired) {
			t.Fatal("AcquireRefreshLease returned the wrong error for an expired Session")
		}
		if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatal("AcquireRefreshLease did not remove the expired Session")
		}
	})

	for name, makeContext := range map[string]func() (context.Context, context.CancelFunc){
		"canceled contexts stop every operation before mutation": func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		},
		"expired deadlines stop every operation before mutation": func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Unix(1, 0))
		},
	} {
		t.Run(name, func(t *testing.T) {
			backend, clock := newBackend(t, factory)
			ctx, cancel := makeContext()
			defer cancel()
			want := ctx.Err()
			background := context.Background()

			flow := fullFlow("flow-context", clock.Now().Add(time.Minute))
			if err := backend.PutFlow(ctx, flow); !errors.Is(err, want) {
				t.Fatalf("PutFlow error = %v, want %v", err, want)
			}
			if _, err := backend.ConsumeFlow(background, flow.ID); !errors.Is(err, session.ErrNotFound) {
				t.Fatal("canceled PutFlow mutated state")
			}
			mustNoError(t, backend.PutFlow(background, flow))
			if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, want) {
				t.Fatalf("ConsumeFlow error = %v, want %v", err, want)
			}
			if _, err := backend.ConsumeFlow(background, flow.ID); err != nil {
				t.Fatal("canceled ConsumeFlow removed state")
			}

			item := fullSession("session-context", clock.Now())
			if err := backend.Create(ctx, item); !errors.Is(err, want) {
				t.Fatalf("Create error = %v, want %v", err, want)
			}
			if _, err := backend.Get(background, item.ID); !errors.Is(err, session.ErrNotFound) {
				t.Fatal("canceled Create mutated state")
			}
			mustNoError(t, backend.Create(background, item))
			if _, err := backend.Get(ctx, item.ID); !errors.Is(err, want) {
				t.Fatalf("Get error = %v, want %v", err, want)
			}

			next := fullSession(item.ID, clock.Now())
			next.Version = 2
			if err := backend.CompareAndSwap(ctx, item.ID, item.Version, next); !errors.Is(err, want) {
				t.Fatalf("CompareAndSwap error = %v, want %v", err, want)
			}
			stored, err := backend.Get(background, item.ID)
			mustNoError(t, err)
			if stored.Version != 1 {
				t.Fatal("canceled CompareAndSwap mutated state")
			}
			if _, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute); !errors.Is(err, want) {
				t.Fatalf("AcquireRefreshLease error = %v, want %v", err, want)
			}
			lease, err := backend.AcquireRefreshLease(background, item.ID, time.Minute)
			mustNoError(t, err)
			if lease.Valid(ctx) {
				t.Fatal("Lease.Valid returned true after context completion")
			}
			if err := backend.CompareAndSwapWithLease(ctx, lease, item.ID, item.Version, next); !errors.Is(err, want) {
				t.Fatalf("CompareAndSwapWithLease error = %v, want %v", err, want)
			}
			if err := backend.DeleteWithLease(ctx, lease, item.ID, item.Version); !errors.Is(err, want) {
				t.Fatalf("DeleteWithLease error = %v, want %v", err, want)
			}
			if err := lease.Release(ctx); !errors.Is(err, want) {
				t.Fatalf("Lease.Release error = %v, want %v", err, want)
			}
			if !lease.Valid(background) {
				t.Fatal("canceled leased operation changed lease ownership")
			}
			mustNoError(t, lease.Release(background))

			if err := backend.Delete(ctx, item.ID); !errors.Is(err, want) {
				t.Fatalf("Delete error = %v, want %v", err, want)
			}
			if _, err := backend.Get(background, item.ID); err != nil {
				t.Fatal("canceled Delete removed state")
			}
		})
	}
}

type leaseResult struct {
	lease session.Lease
	err   error
}

func newBackend(t testing.TB, factory Factory) (session.Backend, *Clock) {
	t.Helper()
	clock := &Clock{now: epoch}
	return factory(t, clock), clock
}

func fullFlow(id string, expiresAt time.Time) *session.Flow {
	return &session.Flow{
		ID:           id,
		State:        "state-original",
		Nonce:        "nonce-original",
		CodeVerifier: "verifier-original",
		ClientID:     "client-original",
		RedirectURL:  "https://client.example/callback",
		ReturnTo:     "/dashboard",
		CreatedAt:    epoch,
		ExpiresAt:    expiresAt,
	}
}

func fullSession(id string, now time.Time) *session.Session {
	return &session.Session{
		ID:      id,
		Version: 1,
		Tokens: session.TokenSet{
			AccessToken:       "access-original",
			TokenType:         "Bearer",
			RefreshToken:      "refresh-original",
			IDToken:           "id-original",
			AccessTokenExpiry: now.Add(10 * time.Minute),
			GrantedScopes:     []string{"openid", "profile"},
		},
		Auth:          sessionAuth(now),
		CreatedAt:     now,
		UpdatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(2 * time.Hour),
		IdleExpiresAt: now.Add(time.Hour),
	}
}

func sessionAuth(now time.Time) (auth core.AuthContext) {
	auth.Subject = "subject-original"
	auth.Issuer = "https://issuer.example"
	auth.Audience = []string{"client-original"}
	auth.TokenID = "token-id-original"
	auth.IssuedAt = now
	auth.NotBefore = now
	auth.ExpiresAt = now.Add(10 * time.Minute)
	auth.Scopes = []string{"openid", "profile"}
	auth.Groups = []string{"group-original"}
	auth.Username = "username-original"
	auth.DisplayName = "display-original"
	auth.Email = "user@example.com"
	auth.DecisionID = "decision-original"
	auth.ReasonCode = "reason-original"
	auth.TraceID = "trace-original"
	return auth
}

func mutateSession(item *session.Session) {
	item.Tokens.AccessToken = "mutated"
	item.Tokens.GrantedScopes[0] = "mutated"
	item.Auth.Subject = "mutated"
	item.Auth.Audience[0] = "mutated"
	item.Auth.Scopes[0] = "mutated"
	item.Auth.Groups[0] = "mutated"
}

func assertOriginalSession(t testing.TB, item *session.Session, version uint64) {
	t.Helper()
	if item.Version != version {
		t.Fatalf("Session version = %d, want %d", item.Version, version)
	}
	if item.Tokens.AccessToken != "access-original" {
		t.Fatal("Session access token changed through an aliased copy")
	}
	if item.Tokens.GrantedScopes[0] != "openid" {
		t.Fatal("Session granted scopes changed through an aliased copy")
	}
	if item.Auth.Subject != "subject-original" {
		t.Fatal("Session authentication subject changed through an aliased copy")
	}
	if item.Auth.Audience[0] != "client-original" {
		t.Fatal("Session authentication audience changed through an aliased copy")
	}
	if item.Auth.Scopes[0] != "openid" {
		t.Fatal("Session authentication scopes changed through an aliased copy")
	}
	if item.Auth.Groups[0] != "group-original" {
		t.Fatal("Session authentication groups changed through an aliased copy")
	}
}

func mustNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal("backend returned an unexpected error")
	}
}
