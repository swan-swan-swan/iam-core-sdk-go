package bff

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz"
)

var _ httpauthz.SessionResolver = (*Client)(nil)

func TestBFFSessionClonePreservesInitializedEmptyGroups(t *testing.T) {
	item := &session.Session{
		Tokens: session.TokenSet{GrantedScopes: []string{}},
		Auth:   core.AuthContext{Audience: []string{}, Scopes: []string{}, Groups: []string{}},
	}

	cloned := cloneSessionState(item)
	if cloned == nil || cloned.Tokens.GrantedScopes == nil || cloned.Auth.Audience == nil ||
		cloned.Auth.Scopes == nil || cloned.Auth.Groups == nil {
		t.Fatal("BFF Session clone collapsed an initialized empty slice to nil")
	}
	credential := credentialFromSession(cloned)
	if credential.Auth.Groups == nil {
		t.Fatal("credential clone collapsed initialized empty Groups to nil")
	}
}

type countingSessionBackend struct {
	session.Backend
	getCalls atomic.Int32
	casCalls atomic.Int32
}

func (b *countingSessionBackend) Get(ctx context.Context, id string) (*session.Session, error) {
	b.getCalls.Add(1)
	return b.Backend.Get(ctx, id)
}

func (b *countingSessionBackend) CompareAndSwap(
	ctx context.Context,
	id string,
	version uint64,
	next *session.Session,
) error {
	b.casCalls.Add(1)
	return b.Backend.CompareAndSwap(ctx, id, version, next)
}

func TestResolveSessionPresentOnlyParsesConfiguredCookieShape(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	counting := &countingSessionBackend{Backend: backend}
	client.backend = counting

	missing := requestWithSessionCookie(item.ID)
	missing.Header.Del("Cookie")
	if present, err := client.SessionPresent(missing); err != nil || present {
		t.Fatalf("missing SessionPresent()=%v/%v", present, err)
	}
	if present, err := client.SessionPresent(requestWithSessionCookie(item.ID)); err != nil || !present {
		t.Fatalf("valid SessionPresent()=%v/%v", present, err)
	}
	malformed := requestWithSessionCookie(item.ID)
	malformed.Header.Set("Cookie", "__Host-portal_session=bad/value")
	if present, err := client.SessionPresent(malformed); err == nil || !present {
		t.Fatalf("malformed SessionPresent()=%v/%v", present, err)
	}
	duplicate := requestWithSessionCookie(item.ID)
	duplicate.Header.Set("Cookie", "__Host-portal_session=one; __Host-portal_session=two")
	if present, err := client.SessionPresent(duplicate); err == nil || !present {
		t.Fatalf("duplicate SessionPresent()=%v/%v", present, err)
	}
	for _, raw := range []string{
		"__Host-portal_session=\"unterminated",
		"__Host-portal_session",
		"other=value; __Host-portal_session=bad value",
	} {
		request := requestWithSessionCookie(item.ID)
		request.Header["Cookie"] = []string{raw}
		if present, err := client.SessionPresent(request); err == nil || !present {
			t.Fatalf("raw malformed credential %q SessionPresent()=%v/%v", raw, present, err)
		}
	}
	if counting.getCalls.Load() != 0 || counting.casCalls.Load() != 0 || issuer.RefreshCalls() != 0 {
		t.Fatalf("SessionPresent caused stateful work: get=%d cas=%d refresh=%d", counting.getCalls.Load(), counting.casCalls.Load(), issuer.RefreshCalls())
	}
}

func TestResolveSessionMissingCookieIsNotPresentAndDoesNotLoad(t *testing.T) {
	client, backend, _ := newRefreshTestClient(t)
	counting := &countingSessionBackend{Backend: backend}
	client.backend = counting
	request := requestWithSessionCookie("unused")
	request.Header.Del("Cookie")
	credential, present, err := client.ResolveSession(request)
	if err != nil || present || !reflect.DeepEqual(credential, core.Credential{}) || counting.getCalls.Load() != 0 {
		t.Fatalf("ResolveSession()=%#v/%v/%v loads=%d", credential, present, err, counting.getCalls.Load())
	}
}

func TestResolveSessionUpdatesLastSeenAndIdleExpiryThroughCAS(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	before := seedValidSession(t, backend)
	issuer.Clock.Advance(10 * time.Second)
	credential, present, err := client.ResolveSession(requestWithSessionCookie(before.ID))
	if err != nil || !present {
		t.Fatalf("ResolveSession()=%#v/%v/%v", credential, present, err)
	}
	after, err := backend.Get(t.Context(), before.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := refreshTestNow.Add(10 * time.Second)
	if after.Version != before.Version+1 || !after.LastSeenAt.Equal(now) ||
		!after.IdleExpiresAt.Equal(now.Add(30*time.Minute)) || !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatalf("touched session=%#v", after)
	}
	access, tokenErr := credential.Tokens.AccessToken(t.Context())
	if tokenErr != nil || access != before.Tokens.AccessToken || credential.Source != core.CredentialSession ||
		credential.SessionID != before.ID || credential.Auth.Subject != before.Auth.Subject {
		t.Fatal("ResolveSession returned an invalid session credential")
	}
}

type conflictingTouchBackend struct {
	session.Backend
	once     sync.Once
	casCalls atomic.Int32
}

func (b *conflictingTouchBackend) CompareAndSwap(
	ctx context.Context,
	id string,
	version uint64,
	next *session.Session,
) error {
	b.casCalls.Add(1)
	injected := false
	b.once.Do(func() {
		current, err := b.Backend.Get(ctx, id)
		if err != nil {
			return
		}
		winner := cloneSessionForTest(current)
		winner.Version = current.Version + 1
		winner.Tokens.AccessToken = "winner-access-token-sensitive"
		winner.Auth.DisplayName = "Concurrent Winner"
		if b.Backend.CompareAndSwap(ctx, id, current.Version, winner) == nil {
			injected = true
		}
	})
	if injected {
		return session.ErrConflict
	}
	return b.Backend.CompareAndSwap(ctx, id, version, next)
}

func TestResolveSessionCASConflictReloadsNewerSessionWithoutOverwriting(t *testing.T) {
	client, backend, _ := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	conflicting := &conflictingTouchBackend{Backend: backend}
	client.backend = conflicting
	credential, present, err := client.ResolveSession(requestWithSessionCookie(item.ID))
	if err != nil || !present {
		t.Fatalf("ResolveSession()=%#v/%v/%v", credential, present, err)
	}
	stored, err := backend.Get(t.Context(), item.ID)
	if err != nil || stored.Tokens.AccessToken != "winner-access-token-sensitive" || stored.Auth.DisplayName != "Concurrent Winner" {
		t.Fatal("resolver overwrote the concurrently committed winner")
	}
	access, tokenErr := credential.Tokens.AccessToken(t.Context())
	if tokenErr != nil || access != "winner-access-token-sensitive" || conflicting.casCalls.Load() > 4 {
		t.Fatalf("credential/cas = redacted/%v/%d", tokenErr, conflicting.casCalls.Load())
	}
}

func TestResolveSessionTokenSourceCapturesImmutableFinalAccessToken(t *testing.T) {
	client, backend, _ := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	credential, present, err := client.ResolveSession(requestWithSessionCookie(item.ID))
	if err != nil || !present {
		t.Fatalf("ResolveSession() present=%v err=%v", present, err)
	}
	current, err := backend.Get(t.Context(), item.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacement := cloneSessionForTest(current)
	replacement.Version++
	replacement.Tokens.AccessToken = "later-access-token-sensitive"
	replacement.Auth.Groups[0] = "later-group"
	if err := backend.CompareAndSwap(t.Context(), current.ID, current.Version, replacement); err != nil {
		t.Fatal(err)
	}
	credential.Auth.Groups[0] = "caller-mutation"
	access, err := credential.Tokens.AccessToken(t.Context())
	if err != nil || access != item.Tokens.AccessToken {
		t.Fatalf("captured token changed: redacted/%v", err)
	}
	stored, err := backend.Get(t.Context(), item.ID)
	if err != nil || stored.Auth.Groups[0] != "later-group" {
		t.Fatal("credential AuthContext aliased backend session state")
	}
}

func TestResolveSessionRejectsExpiryAtEqualityAndDeletesExpiredState(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	issuer.Clock.Advance(30 * time.Minute)
	_, present, err := client.ResolveSession(requestWithSessionCookie(item.ID))
	if !present || !errors.Is(err, core.ErrUnauthenticated) {
		t.Fatalf("ResolveSession() present=%v err=%v", present, err)
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("expired session was not deleted: %v", err)
	}
}

func TestResolveSessionRejectsMissingAuthenticatedFields(t *testing.T) {
	tests := map[string]func(*session.Session){
		"subject":      func(item *session.Session) { item.Auth.Subject = "" },
		"access token": func(item *session.Session) { item.Tokens.AccessToken = "" },
		"token type":   func(item *session.Session) { item.Tokens.TokenType = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, backend, _ := newRefreshTestClient(t)
			item := refreshSessionFixture([]string{"ops"}, []string{"openid", "groups"})
			item.Tokens.AccessTokenExpiry = refreshTestNow.Add(10 * time.Minute)
			mutate(item)
			if err := backend.Create(t.Context(), item); err != nil {
				t.Fatal(err)
			}
			if _, present, err := client.ResolveSession(requestWithSessionCookie(item.ID)); !present || !errors.Is(err, core.ErrUnauthenticated) {
				t.Fatalf("ResolveSession() present=%v err=%v", present, err)
			}
		})
	}
}

func TestResolveSessionPreservesCanceledRequestContext(t *testing.T) {
	client, backend, _ := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request := requestWithSessionCookie(item.ID).WithContext(ctx)
	if _, present, err := client.ResolveSession(request); !present || !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveSession() present=%v err=%v", present, err)
	}
}
