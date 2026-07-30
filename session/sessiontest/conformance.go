package sessiontest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

type Factory func(t *testing.T) session.Backend

func Run(t *testing.T, factory Factory) {
	t.Helper()

	t.Run("session create get and deep copy", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := fullSession("session-copy", time.Now().Add(time.Hour))
		if err := backend.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		mutateSession(item)

		first, err := backend.Get(ctx, "session-copy")
		if err != nil {
			t.Fatal(err)
		}
		assertSessionOriginal(t, first)
		mutateSession(first)

		second, err := backend.Get(ctx, "session-copy")
		if err != nil {
			t.Fatal(err)
		}
		assertSessionOriginal(t, second)
	})

	t.Run("duplicate session create is rejected without replacement", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := fullSession("session-duplicate", time.Now().Add(time.Hour))
		if err := backend.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		replacement := fullSession(item.ID, time.Now().Add(2*time.Hour))
		replacement.TokenSet.AccessToken = "replacement-access"
		if err := backend.Create(ctx, replacement); !errors.Is(err, session.ErrVersionConflict) {
			t.Fatalf("error = %v", err)
		}
		stored, err := backend.Get(ctx, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.TokenSet.AccessToken != "access-original" {
			t.Fatal("duplicate create replaced stored session")
		}
	})

	t.Run("session compare and swap is atomic", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := fullSession("session-cas", time.Now().Add(time.Hour))
		if err := backend.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		next := fullSession(item.ID, item.ExpiresAt)
		next.Version = 2
		next.TokenSet.AccessToken = "access-next"

		const contenders = 16
		var group sync.WaitGroup
		results := make(chan error, contenders)
		for range contenders {
			group.Add(1)
			go func() {
				defer group.Done()
				results <- backend.CompareAndSwap(ctx, item.ID, 1, next)
			}()
		}
		group.Wait()
		close(results)

		var successes, conflicts int
		for err := range results {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, session.ErrVersionConflict):
				conflicts++
			default:
				t.Fatalf("unexpected error = %v", err)
			}
		}
		if successes != 1 || conflicts != contenders-1 {
			t.Fatalf("successes = %d, conflicts = %d", successes, conflicts)
		}
		stored, err := backend.Get(ctx, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Version != 2 || stored.TokenSet.AccessToken != "access-next" {
			t.Fatalf("stored version/token = %d/%q", stored.Version, stored.TokenSet.AccessToken)
		}
	})

	t.Run("compare and swap enforces id and next version", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := fullSession("session-cas-invariants", time.Now().Add(time.Hour))
		if err := backend.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name string
			id   string
			want *session.Session
		}{
			{name: "different argument id", id: "different-session", want: func() *session.Session {
				next := fullSession(item.ID, item.ExpiresAt)
				next.Version = 2
				return next
			}()},
			{name: "different payload id", id: item.ID, want: func() *session.Session {
				next := fullSession("different-session", item.ExpiresAt)
				next.Version = 2
				return next
			}()},
			{name: "same version", id: item.ID, want: fullSession(item.ID, item.ExpiresAt)},
			{name: "skipped version", id: item.ID, want: func() *session.Session {
				next := fullSession(item.ID, item.ExpiresAt)
				next.Version = 3
				return next
			}()},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				if err := backend.CompareAndSwap(ctx, test.id, 1, test.want); err == nil {
					t.Fatal("expected validation error")
				}
			})
		}
		stored, err := backend.Get(ctx, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Version != 1 {
			t.Fatalf("version = %d", stored.Version)
		}
	})

	t.Run("compare and swap copies input and output", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := fullSession("session-cas-copy", time.Now().Add(time.Hour))
		if err := backend.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		next := fullSession(item.ID, item.ExpiresAt)
		next.Version = 2
		if err := backend.CompareAndSwap(ctx, item.ID, 1, next); err != nil {
			t.Fatal(err)
		}
		mutateSession(next)
		stored, err := backend.Get(ctx, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		assertSessionOriginal(t, stored)
		if stored.Version != 2 {
			t.Fatalf("version = %d", stored.Version)
		}
	})

	t.Run("expired sessions are reported once and removed", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := fullSession("session-expired", time.Now().Add(-time.Hour))
		if err := backend.Create(ctx, item); !errors.Is(err, session.ErrExpired) {
			t.Fatalf("create error = %v", err)
		}

		item.ExpiresAt = time.Now().Add(time.Hour)
		item.IdleExpiresAt = time.Now().Add(-time.Second)
		if err := backend.Create(ctx, item); !errors.Is(err, session.ErrExpired) {
			t.Fatalf("idle-expired create error = %v", err)
		}
	})

	t.Run("session expiry on access is removed", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := fullSession("session-access-expiry", time.Now().Add(30*time.Millisecond))
		if err := backend.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		eventually(t, time.Second, func() bool {
			_, err := backend.Get(ctx, item.ID)
			return errors.Is(err, session.ErrExpired) || errors.Is(err, session.ErrNotFound)
		})
		if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("second get error = %v", err)
		}
	})

	t.Run("delete is idempotent", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := fullSession("session-delete", time.Now().Add(time.Hour))
		if err := backend.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		if err := backend.Delete(ctx, item.ID); err != nil {
			t.Fatal(err)
		}
		if err := backend.Delete(ctx, item.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.Get(ctx, item.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("get error = %v", err)
		}
	})

	t.Run("flow is consumed exactly once atomically", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		flow := fullFlow("flow-once", time.Now().Add(time.Minute))
		if err := backend.PutFlow(ctx, flow); err != nil {
			t.Fatal(err)
		}

		const contenders = 16
		var group sync.WaitGroup
		type result struct {
			flow *session.Flow
			err  error
		}
		results := make(chan result, contenders)
		for range contenders {
			group.Add(1)
			go func() {
				defer group.Done()
				got, err := backend.ConsumeFlow(ctx, flow.ID)
				results <- result{flow: got, err: err}
			}()
		}
		group.Wait()
		close(results)

		var successes, missing int
		for result := range results {
			switch {
			case result.err == nil:
				successes++
				if result.flow == nil || result.flow.State != "state-original" {
					t.Fatal("successful consume returned wrong flow")
				}
			case errors.Is(result.err, session.ErrNotFound):
				missing++
			default:
				t.Fatalf("unexpected error = %v", result.err)
			}
		}
		if successes != 1 || missing != contenders-1 {
			t.Fatalf("successes = %d, missing = %d", successes, missing)
		}
	})

	t.Run("duplicate flow put is rejected without replacement", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		flow := fullFlow("flow-duplicate", time.Now().Add(time.Minute))
		if err := backend.PutFlow(ctx, flow); err != nil {
			t.Fatal(err)
		}
		replacement := fullFlow(flow.ID, flow.ExpiresAt)
		replacement.State = "state-replacement"
		if err := backend.PutFlow(ctx, replacement); !errors.Is(err, session.ErrVersionConflict) {
			t.Fatalf("put error = %v", err)
		}
		stored, err := backend.ConsumeFlow(ctx, flow.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.State != "state-original" {
			t.Fatal("duplicate put replaced flow")
		}
	})

	t.Run("flow storage and consume deep copy", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		flow := fullFlow("flow-copy", time.Now().Add(time.Minute))
		if err := backend.PutFlow(ctx, flow); err != nil {
			t.Fatal(err)
		}
		flow.State = "mutated-state"
		stored, err := backend.ConsumeFlow(ctx, "flow-copy")
		if err != nil {
			t.Fatal(err)
		}
		if stored.State != "state-original" {
			t.Fatalf("state = %q", stored.State)
		}
		stored.State = "mutated-return"
		if _, err := backend.ConsumeFlow(ctx, "flow-copy"); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("second consume error = %v", err)
		}
	})

	t.Run("expired flows are reported once and removed", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		expired := fullFlow("flow-already-expired", time.Now().Add(-time.Second))
		if err := backend.PutFlow(ctx, expired); !errors.Is(err, session.ErrExpired) {
			t.Fatalf("put error = %v", err)
		}

		flow := fullFlow("flow-access-expiry", time.Now().Add(30*time.Millisecond))
		if err := backend.PutFlow(ctx, flow); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, flow.ExpiresAt.Add(20*time.Millisecond), time.Second)
		if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrExpired) &&
			!errors.Is(err, session.ErrNotFound) {
			t.Fatalf("first consume error = %v", err)
		}
		if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("second consume error = %v", err)
		}
	})

	t.Run("lock enforces ownership and stale owners cannot unlock", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		first, err := backend.Lock(ctx, "session-lock", 30*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if !first.Valid(ctx) {
			t.Fatal("first lock must be valid")
		}
		if _, err := backend.Lock(ctx, "session-lock", time.Second); !errors.Is(err, session.ErrLocked) {
			t.Fatalf("second lock error = %v", err)
		}
		eventually(t, time.Second, func() bool { return !first.Valid(ctx) })

		second, err := backend.Lock(ctx, "session-lock", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := first.Unlock(ctx); !errors.Is(err, session.ErrLockLost) {
			t.Fatalf("stale unlock error = %v", err)
		}
		if !second.Valid(ctx) {
			t.Fatal("stale owner unlocked replacement")
		}
		if err := second.Unlock(ctx); err != nil {
			t.Fatal(err)
		}
		if second.Valid(ctx) {
			t.Fatal("unlocked lock is valid")
		}
		if err := second.Unlock(ctx); !errors.Is(err, session.ErrLockLost) {
			t.Fatalf("second unlock error = %v", err)
		}
	})

	t.Run("lock acquisition is atomic", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		const contenders = 16
		var group sync.WaitGroup
		type result struct {
			lock session.Lock
			err  error
		}
		results := make(chan result, contenders)
		for range contenders {
			group.Add(1)
			go func() {
				defer group.Done()
				lock, err := backend.Lock(ctx, "session-lock-atomic", time.Minute)
				results <- result{lock: lock, err: err}
			}()
		}
		group.Wait()
		close(results)

		var successes, locked int
		var owner session.Lock
		for result := range results {
			switch {
			case result.err == nil:
				successes++
				owner = result.lock
			case errors.Is(result.err, session.ErrLocked):
				locked++
			default:
				t.Fatalf("unexpected error = %v", result.err)
			}
		}
		if successes != 1 || locked != contenders-1 {
			t.Fatalf("successes = %d, locked = %d", successes, locked)
		}
		if err := owner.Unlock(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid inputs fail without exposing identifiers", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		secretID := "raw-secret-identifier"
		valid := fullSession(secretID, time.Now().Add(time.Hour))
		cases := []struct {
			name string
			call func() error
		}{
			{name: "nil session", call: func() error { return backend.Create(ctx, nil) }},
			{name: "blank session id", call: func() error {
				item := fullSession(" ", time.Now().Add(time.Hour))
				return backend.Create(ctx, item)
			}},
			{name: "zero session version", call: func() error {
				item := fullSession(secretID, time.Now().Add(time.Hour))
				item.Version = 0
				return backend.Create(ctx, item)
			}},
			{name: "blank get id", call: func() error { _, err := backend.Get(ctx, " "); return err }},
			{name: "nil cas session", call: func() error {
				return backend.CompareAndSwap(ctx, secretID, 1, nil)
			}},
			{name: "zero cas version", call: func() error {
				return backend.CompareAndSwap(ctx, secretID, 0, valid)
			}},
			{name: "overflow cas version", call: func() error {
				next := *valid
				next.Version = 0
				return backend.CompareAndSwap(ctx, secretID, ^uint64(0), &next)
			}},
			{name: "blank delete id", call: func() error { return backend.Delete(ctx, " ") }},
			{name: "nil flow", call: func() error { return backend.PutFlow(ctx, nil) }},
			{name: "blank flow id", call: func() error {
				return backend.PutFlow(ctx, fullFlow(" ", time.Now().Add(time.Minute)))
			}},
			{name: "blank consume id", call: func() error {
				_, err := backend.ConsumeFlow(ctx, " ")
				return err
			}},
			{name: "blank lock id", call: func() error {
				_, err := backend.Lock(ctx, " ", time.Second)
				return err
			}},
			{name: "zero lock duration", call: func() error {
				_, err := backend.Lock(ctx, secretID, 0)
				return err
			}},
			{name: "negative lock duration", call: func() error {
				_, err := backend.Lock(ctx, secretID, -time.Second)
				return err
			}},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				err := test.call()
				if err == nil {
					t.Fatal("expected error")
				}
				if strings.Contains(err.Error(), secretID) {
					t.Fatalf("error exposed identifier: %v", err)
				}
			})
		}
	})
}

func waitUntil(t *testing.T, deadline time.Time, timeout time.Duration) {
	t.Helper()
	waitDeadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if time.Now().After(waitDeadline) {
			t.Fatal("deadline was not reached before timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

func fullSession(id string, expiry time.Time) *session.Session {
	return &session.Session{
		ID:      id,
		Version: 1,
		TokenSet: oidc.TokenSet{
			AccessToken:       "access-original",
			TokenType:         "Bearer",
			RefreshToken:      "refresh-original",
			IDToken:           "id-original",
			AccessTokenExpiry: expiry.Add(-time.Minute),
		},
		Identity: oidc.Identity{
			Subject:     "subject-original",
			Username:    "username-original",
			Email:       "original@example.test",
			DisplayName: "Display Original",
			Roles:       []string{"role-original"},
			Scopes:      []string{"scope-original"},
			ExtraClaims: map[string]json.RawMessage{
				"nested": json.RawMessage(`{"value":["original"]}`),
			},
		},
		GrantedScopes:       []string{"granted-original"},
		CreatedAt:           expiry.Add(-2 * time.Hour),
		UpdatedAt:           expiry.Add(-time.Hour),
		LastSeenAt:          expiry.Add(-time.Minute),
		ExpiresAt:           expiry,
		IdentityValidatedAt: expiry.Add(-time.Minute),
	}
}

func mutateSession(item *session.Session) {
	item.TokenSet.AccessToken = "access-mutated"
	item.Identity.Roles[0] = "role-mutated"
	item.Identity.Scopes[0] = "scope-mutated"
	item.Identity.ExtraClaims["nested"][10] = 'X'
	item.Identity.ExtraClaims["added"] = json.RawMessage(`"added"`)
	item.GrantedScopes[0] = "granted-mutated"
}

func assertSessionOriginal(t *testing.T, item *session.Session) {
	t.Helper()
	if item.TokenSet.AccessToken != "access-original" ||
		item.Identity.Roles[0] != "role-original" ||
		item.Identity.Scopes[0] != "scope-original" ||
		string(item.Identity.ExtraClaims["nested"]) != `{"value":["original"]}` ||
		item.Identity.ExtraClaims["added"] != nil ||
		item.GrantedScopes[0] != "granted-original" {
		t.Fatal("session was not deeply copied")
	}
}

func fullFlow(id string, expiry time.Time) *session.Flow {
	return &session.Flow{
		ID:        id,
		State:     "state-original",
		Nonce:     "nonce-original",
		ReturnTo:  "/return",
		CreatedAt: expiry.Add(-time.Minute),
		ExpiresAt: expiry,
	}
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("condition was not met before timeout")
		}
		time.Sleep(time.Millisecond)
	}
}
