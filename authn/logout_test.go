package authn

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

func TestLogoutDeletesSessionBeforeOneRemoteCallWithRetainedTokens(t *testing.T) {
	harness := newLogoutHarness(t, false, nil)
	var deletedBeforeRemote atomic.Bool
	harness.oidc.mu.Lock()
	harness.oidc.logoutCheck = func() {
		_, err := harness.backend.Get(context.Background(), "session-1")
		deletedBeforeRemote.Store(errors.Is(err, session.ErrNotFound))
	}
	harness.oidc.mu.Unlock()

	if err := harness.service.Logout(t.Context(), "session-1"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if !deletedBeforeRemote.Load() || harness.oidc.logoutCalls.Load() != 1 {
		t.Fatalf("deleted before remote = %v, logout calls = %d",
			deletedBeforeRemote.Load(), harness.oidc.logoutCalls.Load())
	}
	harness.oidc.mu.Lock()
	access := harness.oidc.lastLogoutAccessToken
	idHint := harness.oidc.lastLogoutIDTokenHint
	harness.oidc.mu.Unlock()
	if access != "Bearer access-logout-secret" || idHint != "id-logout-secret" {
		t.Fatalf("logout credentials = access %q id hint %q", access, idHint)
	}
	if _, err := harness.backend.Get(t.Context(), "session-1"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("session was recreated: %v", err)
	}
}

func TestLogoutAbsentOrExpiredSessionIsIdempotent(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		harness := newLogoutHarness(t, false, nil)
		if err := harness.backend.Delete(t.Context(), "session-1"); err != nil {
			t.Fatal(err)
		}
		if err := harness.service.Logout(t.Context(), "session-1"); err != nil {
			t.Fatalf("Logout() error = %v", err)
		}
		if harness.oidc.logoutCalls.Load() != 0 {
			t.Fatalf("logout calls = %d", harness.oidc.logoutCalls.Load())
		}
	})
	t.Run("expired", func(t *testing.T) {
		harness := newLogoutHarness(t, false, nil)
		harness.service.backend = &logoutBackend{Backend: harness.backend, getErr: session.ErrExpired}
		if err := harness.service.Logout(t.Context(), "session-1"); err != nil {
			t.Fatalf("Logout() error = %v", err)
		}
		if harness.oidc.logoutCalls.Load() != 0 {
			t.Fatalf("logout calls = %d", harness.oidc.logoutCalls.Load())
		}
	})
}

func TestLogoutBackendReadFailureStillDeletesLocally(t *testing.T) {
	harness := newLogoutHarness(t, false, nil)
	harness.service.backend = &logoutBackend{
		Backend: harness.backend,
		getErr:  errors.New("redis token=access-logout-secret session=session-1"),
	}

	err := harness.service.Logout(t.Context(), "session-1")
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
	if stringsContainAny(err.Error(), "redis", "access-logout-secret", "session-1") {
		t.Fatalf("error leaked backend data: %v", err)
	}
	if _, getErr := harness.backend.Get(t.Context(), "session-1"); !errors.Is(getErr, session.ErrNotFound) {
		t.Fatalf("local session remains: %v", getErr)
	}
	if harness.oidc.logoutCalls.Load() != 0 {
		t.Fatalf("logout calls = %d", harness.oidc.logoutCalls.Load())
	}
}

func TestLogoutDeleteFailureSkipsRemoteCall(t *testing.T) {
	harness := newLogoutHarness(t, false, nil)
	harness.service.backend = &logoutBackend{
		Backend:   harness.backend,
		deleteErr: errors.New("redis delete session=session-1"),
	}
	err := harness.service.Logout(t.Context(), "session-1")
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
	if harness.oidc.logoutCalls.Load() != 0 {
		t.Fatalf("logout calls = %d", harness.oidc.logoutCalls.Load())
	}
}

func TestLogoutRemoteFailureReturnsErrorAndNeverRestoresSession(t *testing.T) {
	harness := newLogoutHarness(t, false, nil)
	harness.oidc.mu.Lock()
	harness.oidc.logoutStatus = http.StatusServiceUnavailable
	harness.oidc.mu.Unlock()

	err := harness.service.Logout(t.Context(), "session-1")
	assertSDKKind(t, err, sdkerr.KindIAMUnavailable)
	if harness.oidc.logoutCalls.Load() != 1 {
		t.Fatalf("logout calls = %d", harness.oidc.logoutCalls.Load())
	}
	if _, getErr := harness.backend.Get(t.Context(), "session-1"); !errors.Is(getErr, session.ErrNotFound) {
		t.Fatalf("session was restored: %v", getErr)
	}
}

func TestLogoutHandlerClearsCookieUnconditionally(t *testing.T) {
	tests := map[string]func(*logoutHarness, *http.Request){
		"success": func(*logoutHarness, *http.Request) {},
		"absent": func(h *logoutHarness, request *http.Request) {
			request.Header.Del("Cookie")
			if err := h.backend.Delete(context.Background(), "session-1"); err != nil {
				t.Fatal(err)
			}
		},
		"remote failure": func(h *logoutHarness, _ *http.Request) {
			h.oidc.mu.Lock()
			h.oidc.logoutStatus = http.StatusServiceUnavailable
			h.oidc.mu.Unlock()
		},
		"backend failure": func(h *logoutHarness, _ *http.Request) {
			h.service.backend = &logoutBackend{
				Backend:   h.backend,
				deleteErr: errors.New("backend unavailable"),
			}
		},
		"duplicate cookie": func(_ *logoutHarness, request *http.Request) {
			request.AddCookie(&http.Cookie{Name: "__Host-iam_core_session", Value: "session-2"})
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newLogoutHarness(t, false, nil)
			request := credentialRequest(t, true, "")
			setup(harness, request)
			recorder := httptest.NewRecorder()

			harness.service.LogoutHandler().ServeHTTP(recorder, request)

			assertSessionCookieCleared(t, recorder, harness.service.sessionCookie.Name)
			if name == "success" || name == "absent" {
				if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 {
					t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
				}
			} else if recorder.Code != http.StatusServiceUnavailable ||
				recorder.Body.String() != "Service Unavailable\n" {
				t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestLogoutHandlerRemoteFailurePolicyAndSafeObservation(t *testing.T) {
	for _, remoteFailureIsSuccess := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "success"}[remoteFailureIsSuccess], func(t *testing.T) {
			hooks := &recordingHooks{}
			var logs bytes.Buffer
			harness := newLogoutHarness(t, remoteFailureIsSuccess, func(config *Config) {
				config.Hooks = hooks
				config.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
			})
			harness.oidc.mu.Lock()
			harness.oidc.logoutStatus = http.StatusServiceUnavailable
			harness.oidc.mu.Unlock()
			recorder := httptest.NewRecorder()

			harness.service.LogoutHandler().ServeHTTP(recorder, credentialRequest(t, true, ""))

			wantStatus := http.StatusServiceUnavailable
			if remoteFailureIsSuccess {
				wantStatus = http.StatusNoContent
			}
			if recorder.Code != wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, wantStatus)
			}
			events := hooks.Events()
			if len(events) != 1 || events[0].Operation != "authn.logout" ||
				events[0].Outcome != "remote_error" {
				t.Fatalf("events = %#v", events)
			}
			for _, secret := range []string{
				"session-1",
				"access-logout-secret",
				"id-logout-secret",
				"remote_error_description",
			} {
				if strings.Contains(logs.String(), secret) {
					t.Fatalf("logs exposed %q: %s", secret, logs.String())
				}
			}
		})
	}
}

func TestLogoutHandlerNeverRecreatesAfterRemoteFailure(t *testing.T) {
	harness := newLogoutHarness(t, true, nil)
	harness.oidc.mu.Lock()
	harness.oidc.logoutStatus = http.StatusServiceUnavailable
	harness.oidc.mu.Unlock()
	recorder := httptest.NewRecorder()
	harness.service.LogoutHandler().ServeHTTP(recorder, credentialRequest(t, true, ""))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	if _, err := harness.backend.Get(t.Context(), "session-1"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("session was recreated: %v", err)
	}
}

type logoutHarness struct {
	*testHarness
}

func newLogoutHarness(
	t *testing.T,
	remoteFailureIsSuccess bool,
	mutateConfig func(*Config),
) *logoutHarness {
	t.Helper()
	harness := newTestHarness(t, func(config *Config, _ *testHarness) {
		config.LogoutRemoteFailureIsSuccess = remoteFailureIsSuccess
		if mutateConfig != nil {
			mutateConfig(config)
		}
	})
	seedSession(t, harness.backend, &session.Session{
		ID:      "session-1",
		Version: 1,
		TokenSet: oidc.TokenSet{
			AccessToken:       "access-logout-secret",
			TokenType:         "Bearer",
			RefreshToken:      "refresh-logout-secret",
			IDToken:           "id-logout-secret",
			AccessTokenExpiry: fixedNow.Add(time.Hour),
		},
		Identity:            oidc.Identity{Subject: "user-1"},
		CreatedAt:           fixedNow.Add(-time.Hour),
		UpdatedAt:           fixedNow.Add(-time.Hour),
		LastSeenAt:          fixedNow.Add(-time.Minute),
		ExpiresAt:           fixedNow.Add(2 * time.Hour),
		IdleExpiresAt:       fixedNow.Add(time.Hour),
		IdentityValidatedAt: fixedNow.Add(-time.Minute),
	})
	return &logoutHarness{testHarness: harness}
}

type logoutBackend struct {
	session.Backend
	getErr    error
	deleteErr error
}

func (b *logoutBackend) Get(ctx context.Context, id string) (*session.Session, error) {
	if b.getErr != nil {
		return nil, b.getErr
	}
	return b.Backend.Get(ctx, id)
}

func (b *logoutBackend) Delete(ctx context.Context, id string) error {
	if b.deleteErr != nil {
		return b.deleteErr
	}
	return b.Backend.Delete(ctx, id)
}

type recordingHooks struct {
	mu     sync.Mutex
	events []observability.Event
}

func (h *recordingHooks) Observe(_ context.Context, event observability.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
}

func (h *recordingHooks) Events() []observability.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]observability.Event(nil), h.events...)
}

func assertSessionCookieCleared(t *testing.T, recorder *httptest.ResponseRecorder, name string) {
	t.Helper()
	result := recorder.Result()
	t.Cleanup(func() { _ = result.Body.Close() })
	cookies := result.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value == "" && cookie.MaxAge < 0 &&
			cookie.Path == "/" && cookie.HttpOnly && cookie.SameSite == http.SameSiteLaxMode {
			return
		}
	}
	t.Fatalf("cleared %s cookie not found: %#v", name, cookies)
}
