package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

func TestAuthenticateCookieOnlyUsesSessionIdentity(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	request := credentialRequest(t, true, "")

	got, err := harness.service.Authenticate(request)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got.Source != CredentialSession || got.SessionID != "session-1" ||
		got.AccessToken != "session-token" || got.Identity.Subject != "user-1" {
		t.Fatalf("credential = %#v", got)
	}
	if harness.oidc.userInfoCalls.Load() != 0 {
		t.Fatalf("UserInfo calls = %d", harness.oidc.userInfoCalls.Load())
	}
	stored, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil || stored.Version != 2 || !stored.LastSeenAt.Equal(fixedNow) ||
		!stored.IdleExpiresAt.Equal(fixedNow.Add(time.Hour)) {
		t.Fatalf("stored = %#v, error = %v", stored, err)
	}
}

func TestAuthenticateBearerOnlyAlwaysUsesOnlineUserInfo(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	for range 2 {
		got, err := harness.service.Authenticate(credentialRequest(t, false, "Bearer api-token"))
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		if got.Source != CredentialBearer || got.SessionID != "" ||
			got.AccessToken != "api-token" || got.Identity.Subject != "user-1" {
			t.Fatalf("credential = %#v", got)
		}
	}
	if harness.oidc.userInfoCalls.Load() != 2 {
		t.Fatalf("UserInfo calls = %d", harness.oidc.userInfoCalls.Load())
	}
}

func TestAuthenticateSameCookieAndBearerUsesSessionRules(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	got, err := harness.service.Authenticate(credentialRequest(t, true, "Bearer session-token"))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got.Source != CredentialSession || got.SessionID != "session-1" ||
		harness.oidc.userInfoCalls.Load() != 0 {
		t.Fatalf("credential = %#v, UserInfo calls = %d", got, harness.oidc.userInfoCalls.Load())
	}
}

func TestAuthenticateRejectsDifferentCookieAndBearerTokens(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	request := credentialRequest(t, true, "Bearer different-token")

	_, err := harness.service.Authenticate(request)
	assertSDKKind(t, err, sdkerr.KindCredentialConflict)
	if harness.oidc.userInfoCalls.Load() != 0 || harness.oidc.tokenCalls.Load() != 0 {
		t.Fatalf("UserInfo calls = %d, token calls = %d",
			harness.oidc.userInfoCalls.Load(), harness.oidc.tokenCalls.Load())
	}
}

func TestAuthenticateRejectsMalformedOrAmbiguousBearer(t *testing.T) {
	tests := map[string]func(*http.Request){
		"lowercase scheme": func(r *http.Request) { r.Header.Set("Authorization", "bearer token") },
		"empty token":      func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"double space":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer  token") },
		"tab":              func(r *http.Request) { r.Header.Set("Authorization", "Bearer token\tvalue") },
		"unicode space":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer token\u00a0value") },
		"unicode control":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer token\u0085value") },
		"comma":            func(r *http.Request) { r.Header.Set("Authorization", "Bearer token,other") },
		"other scheme":     func(r *http.Request) { r.Header.Set("Authorization", "Basic token") },
		"duplicate": func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer token-1")
			r.Header.Add("Authorization", "Bearer token-2")
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newCredentialHarness(t, nil, nil)
			request := httptest.NewRequest(http.MethodGet, "/assets", nil)
			setup(request)
			_, err := harness.service.Authenticate(request)
			assertSDKKind(t, err, sdkerr.KindUnauthenticated)
			if harness.oidc.userInfoCalls.Load() != 0 {
				t.Fatalf("UserInfo calls = %d", harness.oidc.userInfoCalls.Load())
			}
		})
	}
}

func TestAuthenticateRejectsDuplicateSessionCookies(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/assets", nil)
	request.AddCookie(&http.Cookie{Name: harness.service.sessionCookie.Name, Value: "session-1"})
	request.AddCookie(&http.Cookie{Name: harness.service.sessionCookie.Name, Value: "session-2"})

	_, err := harness.service.Authenticate(request)
	assertSDKKind(t, err, sdkerr.KindUnauthenticated)
}

func TestAuthenticateAllowsMissingCookieWithBearer(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	got, err := harness.service.Authenticate(credentialRequest(t, false, "Bearer api-token"))
	if err != nil || got.Source != CredentialBearer || got.Identity.Subject != "user-1" {
		t.Fatalf("credential = %#v, error = %v", got, err)
	}
}

func TestAuthenticateFailsClosedForExpiredMissingAndBackendError(t *testing.T) {
	tests := map[string]func(*credentialHarness){
		"expired": func(h *credentialHarness) {
			h.service.clock = fixedClock{fixedNow.Add(3 * time.Hour)}
		},
		"missing": func(h *credentialHarness) {
			if err := h.backend.Delete(t.Context(), "session-1"); err != nil {
				t.Fatal(err)
			}
		},
		"backend": func(h *credentialHarness) {
			h.service.backend = &getErrorBackend{
				Backend: h.backend,
				err:     errors.New("redis session=session-1 token=session-token"),
			}
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newCredentialHarness(t, nil, nil)
			setup(harness)
			_, err := harness.service.Authenticate(credentialRequest(t, true, ""))
			if name == "backend" {
				assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
			} else {
				assertSDKKind(t, err, sdkerr.KindUnauthenticated)
			}
			if stringsContainAny(err.Error(), "session-1", "session-token", "redis") {
				t.Fatalf("error leaked backend data: %v", err)
			}
		})
	}
}

func TestAuthenticateRefreshesSessionInsideWindow(t *testing.T) {
	harness := newCredentialHarness(t, func(item *session.Session) {
		item.TokenSet.AccessTokenExpiry = fixedNow.Add(30 * time.Second)
		item.TokenSet.RefreshToken = "refresh-original"
		item.TokenSet.IDToken = "id-original"
	}, nil)
	harness.oidc.mu.Lock()
	harness.oidc.includeRefreshIDToken = false
	harness.oidc.mu.Unlock()

	got, err := harness.service.Authenticate(credentialRequest(t, true, ""))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got.AccessToken != "access-refreshed" || harness.oidc.tokenCalls.Load() != 1 {
		t.Fatalf("credential = %#v, token calls = %d", got, harness.oidc.tokenCalls.Load())
	}
}

func TestAuthenticateRechecksIdentityAtConfiguredInterval(t *testing.T) {
	harness := newCredentialHarness(t, func(item *session.Session) {
		item.IdentityValidatedAt = fixedNow.Add(-30 * time.Second)
		item.Identity.Username = "old-name"
	}, nil)

	got, err := harness.service.Authenticate(credentialRequest(t, true, ""))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if harness.oidc.userInfoCalls.Load() != 1 || got.Identity.Username != "alice" {
		t.Fatalf("credential = %#v, UserInfo calls = %d", got, harness.oidc.userInfoCalls.Load())
	}
	stored, getErr := harness.backend.Get(t.Context(), "session-1")
	if getErr != nil || !stored.IdentityValidatedAt.Equal(fixedNow) || stored.Version != 2 ||
		stored.Identity.Username != "alice" {
		t.Fatalf("stored = %#v, error = %v", stored, getErr)
	}
}

func TestAuthenticateDoesNotRecheckBeforeInterval(t *testing.T) {
	harness := newCredentialHarness(t, func(item *session.Session) {
		item.IdentityValidatedAt = fixedNow.Add(-29 * time.Second)
	}, nil)
	if _, err := harness.service.Authenticate(credentialRequest(t, true, "")); err != nil {
		t.Fatal(err)
	}
	if harness.oidc.userInfoCalls.Load() != 0 {
		t.Fatalf("UserInfo calls = %d", harness.oidc.userInfoCalls.Load())
	}
}

func TestAuthenticateRejectsUserInfoSubjectMismatchAndDeactivation(t *testing.T) {
	t.Run("subject mismatch", func(t *testing.T) {
		harness := newCredentialHarness(t, func(item *session.Session) {
			item.IdentityValidatedAt = fixedNow.Add(-time.Minute)
		}, nil)
		harness.oidc.mu.Lock()
		harness.oidc.userInfoSubject = "different-user"
		harness.oidc.mu.Unlock()
		_, err := harness.service.Authenticate(credentialRequest(t, true, ""))
		assertSDKKind(t, err, sdkerr.KindUnauthenticated)
	})
	t.Run("deactivated", func(t *testing.T) {
		harness := newCredentialHarness(t, func(item *session.Session) {
			item.IdentityValidatedAt = fixedNow.Add(-time.Minute)
		}, nil)
		harness.oidc.mu.Lock()
		harness.oidc.userInfoStatus = http.StatusUnauthorized
		harness.oidc.mu.Unlock()
		_, err := harness.service.Authenticate(credentialRequest(t, true, ""))
		assertSDKKind(t, err, sdkerr.KindUnauthenticated)
	})
}

func TestAuthenticateTouchCASConflictReturnsSafeWinner(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := cloneTestSession(baseline)
	winner.Version++
	winner.LastSeenAt = fixedNow
	winner.IdleExpiresAt = fixedNow.Add(time.Hour)
	var casCalls atomic.Int32
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		casFunc: func(ctx context.Context, id string, expected uint64, _ *session.Session) error {
			casCalls.Add(1)
			if err := harness.backend.CompareAndSwap(ctx, id, expected, winner); err != nil {
				t.Fatal(err)
			}
			return session.ErrVersionConflict
		},
	}

	got, err := harness.service.Authenticate(credentialRequest(t, true, ""))
	if err != nil || got.Identity.Subject != "user-1" || casCalls.Load() != 1 {
		t.Fatalf("credential = %#v, error = %v, CAS calls = %d", got, err, casCalls.Load())
	}
}

func TestAuthenticateRecheckCASConflictReturnsValidatedWinner(t *testing.T) {
	harness := newCredentialHarness(t, func(item *session.Session) {
		item.IdentityValidatedAt = fixedNow.Add(-time.Minute)
	}, nil)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := cloneTestSession(baseline)
	winner.Version++
	winner.Identity.Username = "winner-name"
	winner.IdentityValidatedAt = fixedNow
	winner.LastSeenAt = fixedNow
	winner.IdleExpiresAt = fixedNow.Add(time.Hour)
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		casFunc: func(ctx context.Context, id string, expected uint64, _ *session.Session) error {
			if err := harness.backend.CompareAndSwap(ctx, id, expected, winner); err != nil {
				t.Fatal(err)
			}
			return session.ErrVersionConflict
		},
	}

	got, err := harness.service.Authenticate(credentialRequest(t, true, ""))
	if err != nil || got.Identity.Username != "winner-name" {
		t.Fatalf("credential = %#v, error = %v", got, err)
	}
}

func TestAuthenticateCASConflictRejectsUnsafeWinner(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		casFunc: func(context.Context, string, uint64, *session.Session) error {
			return session.ErrVersionConflict
		},
	}
	_, err := harness.service.Authenticate(credentialRequest(t, true, ""))
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
}

func TestAuthenticateCASConflictRejectsWinnerWithDifferentSubject(t *testing.T) {
	harness := newCredentialHarness(t, nil, nil)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := cloneTestSession(baseline)
	winner.Version++
	winner.Identity.Subject = "different-user"
	winner.LastSeenAt = fixedNow
	winner.IdleExpiresAt = fixedNow.Add(time.Hour)
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		casFunc: func(ctx context.Context, id string, expected uint64, _ *session.Session) error {
			if err := harness.backend.CompareAndSwap(ctx, id, expected, winner); err != nil {
				t.Fatal(err)
			}
			return session.ErrVersionConflict
		},
	}

	_, err = harness.service.Authenticate(credentialRequest(t, true, ""))
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
}

func TestAuthenticateDoesNotMoveLastSeenOrIdleExpiryBackward(t *testing.T) {
	harness := newCredentialHarness(t, func(item *session.Session) {
		item.LastSeenAt = fixedNow.Add(time.Minute)
		item.IdleExpiresAt = fixedNow.Add(90 * time.Minute)
	}, nil)
	got, err := harness.service.Authenticate(credentialRequest(t, true, ""))
	if err != nil {
		t.Fatal(err)
	}
	stored, getErr := harness.backend.Get(t.Context(), got.SessionID)
	if getErr != nil || !stored.LastSeenAt.Equal(fixedNow.Add(time.Minute)) ||
		!stored.IdleExpiresAt.Equal(fixedNow.Add(90*time.Minute)) ||
		!stored.ExpiresAt.Equal(fixedNow.Add(2*time.Hour)) {
		t.Fatalf("stored = %#v, error = %v", stored, getErr)
	}
}

func TestSessionTouchDeadlineCapsAtAbsoluteExpiryWithoutOverflow(t *testing.T) {
	nearMaximum := time.Date(9999, time.December, 31, 23, 0, 0, 0, time.UTC)
	absolute := nearMaximum.Add(30 * time.Minute)
	if got := sessionTouchDeadline(nearMaximum, time.Duration(1<<63-1), absolute, time.Time{}); !got.Equal(absolute) {
		t.Fatalf("deadline = %v, want %v", got, absolute)
	}
}

func TestAuthenticateReturnsDefensiveIdentityCopies(t *testing.T) {
	harness := newCredentialHarness(t, func(item *session.Session) {
		item.Identity.ExtraClaims = map[string]json.RawMessage{"tenant": json.RawMessage(`"tenant-1"`)}
	}, nil)
	got, err := harness.service.Authenticate(credentialRequest(t, true, ""))
	if err != nil {
		t.Fatal(err)
	}
	got.Identity.Roles[0] = "mutated"
	got.Identity.Scopes[0] = "mutated"
	got.Identity.ExtraClaims["tenant"][1] = 'X'

	stored, getErr := harness.backend.Get(t.Context(), "session-1")
	if getErr != nil || stored.Identity.Roles[0] != "role-1" ||
		stored.Identity.Scopes[0] != "openid" ||
		string(stored.Identity.ExtraClaims["tenant"]) != `"tenant-1"` {
		t.Fatalf("stored = %#v, error = %v", stored, getErr)
	}
}

type credentialHarness struct {
	*testHarness
}

func newCredentialHarness(
	t *testing.T,
	mutateSession func(*session.Session),
	mutateConfig func(*Config),
) *credentialHarness {
	t.Helper()
	harness := newTestHarness(t, func(config *Config, _ *testHarness) {
		config.IdentityRecheckInterval = 30 * time.Second
		config.RefreshBeforeExpiry = time.Minute
		config.SessionIdleTTL = time.Hour
		if mutateConfig != nil {
			mutateConfig(config)
		}
	})
	item := &session.Session{
		ID:      "session-1",
		Version: 1,
		TokenSet: oidc.TokenSet{
			AccessToken:       "session-token",
			TokenType:         "Bearer",
			RefreshToken:      "refresh-original",
			IDToken:           "id-original",
			AccessTokenExpiry: fixedNow.Add(time.Hour),
		},
		Identity: oidc.Identity{
			Subject:  "user-1",
			Username: "old-name",
			Roles:    []string{"role-1"},
			Scopes:   []string{"openid"},
		},
		GrantedScopes:       []string{"openid"},
		CreatedAt:           fixedNow.Add(-time.Hour),
		UpdatedAt:           fixedNow.Add(-time.Hour),
		LastSeenAt:          fixedNow.Add(-time.Minute),
		ExpiresAt:           fixedNow.Add(2 * time.Hour),
		IdleExpiresAt:       fixedNow.Add(30 * time.Minute),
		IdentityValidatedAt: fixedNow.Add(-time.Second),
	}
	if mutateSession != nil {
		mutateSession(item)
	}
	seedSession(t, harness.backend, item)
	return &credentialHarness{testHarness: harness}
}

func credentialRequest(t *testing.T, withCookie bool, authorization string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/assets", nil)
	if withCookie {
		request.AddCookie(&http.Cookie{Name: "__Host-iam_core_session", Value: "session-1"})
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	return request
}

type getErrorBackend struct {
	session.Backend
	err error
}

func (b *getErrorBackend) Get(context.Context, string) (*session.Session, error) {
	return nil, b.err
}
