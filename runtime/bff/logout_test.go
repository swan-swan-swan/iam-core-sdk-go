package bff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
)

func TestLocalLogoutNeverCallsEndSession(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	response := serveWithCookie(t, client.LocalLogoutHandler(), item.ID)
	if response.Code != http.StatusNoContent || issuer.EndSessionCalls() != 0 {
		t.Fatalf("status=%d calls=%d", response.Code, issuer.EndSessionCalls())
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("local session remained after logout: %v", err)
	}
	assertSessionCookieCleared(t, response, client.sessionCookie.Name)
}

func TestLocalLogoutWithoutCookieIsIdempotentAndClearsCookie(t *testing.T) {
	client, _, issuer := newRefreshTestClient(t)
	response := httptest.NewRecorder()
	client.LocalLogoutHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/logout", nil))
	if response.Code != http.StatusNoContent || issuer.EndSessionCalls() != 0 {
		t.Fatalf("status=%d calls=%d", response.Code, issuer.EndSessionCalls())
	}
	assertSessionCookieCleared(t, response, client.sessionCookie.Name)
}

func TestCentralLogoutDeletesLocalBeforeRemoteFailure(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	issuer.EndSessionStatus = http.StatusServiceUnavailable
	var observedDeleted atomic.Bool
	issuer.EndSessionHook = func() {
		_, err := backend.Get(context.Background(), item.ID)
		observedDeleted.Store(errors.Is(err, session.ErrNotFound))
	}
	response := serveWithCookie(t, client.CentralLogoutHandler(), item.ID)
	if response.Code != http.StatusServiceUnavailable || issuer.EndSessionCalls() != 1 {
		t.Fatalf("status=%d calls=%d", response.Code, issuer.EndSessionCalls())
	}
	if !observedDeleted.Load() {
		t.Fatal("remote end-session began before local state was deleted")
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("session restored: %v", err)
	}
	assertSessionCookieCleared(t, response, client.sessionCookie.Name)
}

func TestCentralLogoutUsesPriorTokensInExactSingleRequest(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	response := serveWithCookie(t, client.CentralLogoutHandler(), item.ID)
	issuer.mu.Lock()
	method := issuer.lastEndSessionMethod
	authorization := issuer.lastEndSessionAuthorization
	hint := issuer.lastEndSessionIDTokenHint
	rawQuery := issuer.lastEndSessionRawQuery
	issuer.mu.Unlock()
	if response.Code != http.StatusNoContent || issuer.EndSessionCalls() != 1 || method != http.MethodGet ||
		authorization != "Bearer "+item.Tokens.AccessToken || hint != item.Tokens.IDToken ||
		strings.Count(rawQuery, "id_token_hint=") != 1 {
		t.Fatal("central logout request did not match the frozen end-session contract")
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("local session remained: %v", err)
	}
}

func TestCentralLogoutRejectsRedirectWithoutFollowingOrRestoring(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	issuer.EndSessionRedirect = true
	response := serveWithCookie(t, client.CentralLogoutHandler(), item.ID)
	issuer.mu.Lock()
	targetCalls := issuer.endSessionTargetCalls
	issuer.mu.Unlock()
	if response.Code != http.StatusBadRequest || issuer.EndSessionCalls() != 1 || targetCalls != 0 {
		t.Fatalf("status=%d calls=%d target=%d", response.Code, issuer.EndSessionCalls(), targetCalls)
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("session restored after redirect rejection: %v", err)
	}
}

func TestCentralLogoutBoundsAndSanitizesRemoteResponse(t *testing.T) {
	tests := map[string]func(*refreshIssuer){
		"oversized success": func(issuer *refreshIssuer) {
			issuer.EndSessionStatus = http.StatusOK
			issuer.EndSessionContentType = "application/json"
			issuer.EndSessionBody = `{"padding":"` + strings.Repeat("x", maxOAuthResponseBytes+1) + `"}`
		},
		"hostile unavailable": func(issuer *refreshIssuer) {
			issuer.EndSessionStatus = http.StatusServiceUnavailable
			issuer.EndSessionContentType = "application/json"
			issuer.EndSessionBody = `{"message":"access-token-old-sensitive id-token-old-sensitive hostile"}`
		},
	}
	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			client, backend, issuer := newRefreshTestClient(t)
			item := seedValidSession(t, backend)
			configure(issuer)
			response := serveWithCookie(t, client.CentralLogoutHandler(), item.ID)
			if issuer.EndSessionCalls() != 1 {
				t.Fatalf("end-session calls=%d", issuer.EndSessionCalls())
			}
			if name == "oversized success" && response.Code != http.StatusBadRequest {
				t.Fatalf("oversized success status=%d", response.Code)
			}
			if name == "hostile unavailable" && response.Code != http.StatusServiceUnavailable {
				t.Fatalf("unavailable status=%d", response.Code)
			}
			for _, secret := range []string{"access-token-old-sensitive", "id-token-old-sensitive", "hostile"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatal("central logout exposed a remote secret")
				}
			}
			if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
				t.Fatalf("session restored after remote failure: %v", err)
			}
		})
	}
}

func TestCentralLogoutMissingPriorTokenDeletesLocallyWithoutRemoteCall(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := refreshSessionFixture([]string{"ops"}, []string{"openid"})
	item.Tokens.AccessTokenExpiry = refreshTestNow.Add(10 * time.Minute)
	item.Tokens.IDToken = ""
	if err := backend.Create(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	response := serveWithCookie(t, client.CentralLogoutHandler(), item.ID)
	if response.Code != http.StatusBadRequest || issuer.EndSessionCalls() != 0 {
		t.Fatalf("status=%d calls=%d", response.Code, issuer.EndSessionCalls())
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("invalid session remained after central logout: %v", err)
	}
}

func TestCentralLogoutOmitsBearerWhenPriorAccessTokenIsMissing(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := refreshSessionFixture([]string{"ops"}, []string{"openid"})
	item.Tokens.AccessToken = ""
	item.Tokens.AccessTokenExpiry = refreshTestNow.Add(10 * time.Minute)
	if err := backend.Create(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	response := serveWithCookie(t, client.CentralLogoutHandler(), item.ID)
	issuer.mu.Lock()
	authorization := issuer.lastEndSessionAuthorization
	hint := issuer.lastEndSessionIDTokenHint
	issuer.mu.Unlock()
	if response.Code != http.StatusNoContent || issuer.EndSessionCalls() != 1 || authorization != "" || hint != item.Tokens.IDToken {
		t.Fatalf("status=%d calls=%d authorization=%q hint=%q", response.Code, issuer.EndSessionCalls(), authorization, hint)
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("invalid session remained after central logout: %v", err)
	}
}

func TestCentralLogoutPreservesCancellationWhileReadingRemoteResponse(t *testing.T) {
	client, backend, _ := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	started := make(chan struct{})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       &canceledResponseBody{ctx: request.Context(), started: started},
			Request:    request,
		}, nil
	})}
	ctx, cancel := context.WithCancel(t.Context())
	request := httptest.NewRequest(http.MethodPost, "/logout", nil).WithContext(ctx)
	request.AddCookie(&http.Cookie{Name: client.sessionCookie.Name, Value: item.ID})
	result := make(chan error, 1)
	go func() {
		result <- client.centralLogout(httptest.NewRecorder(), request)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("central logout did not begin reading the remote response")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("centralLogout() error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled end-session response read did not return")
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("central logout restored local state after cancellation: %v", err)
	}
}

type deleteFailingBackend struct{ session.Backend }

func (b *deleteFailingBackend) Delete(context.Context, string) error {
	return errors.New("backend detail containing session-refresh-test")
}

func TestCentralLogoutDeleteFailureClearsCookieAndDoesNotCallRemote(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedValidSession(t, backend)
	client.backend = &deleteFailingBackend{Backend: backend}
	response := serveWithCookie(t, client.CentralLogoutHandler(), item.ID)
	if response.Code != http.StatusServiceUnavailable || issuer.EndSessionCalls() != 0 ||
		strings.Contains(response.Body.String(), item.ID) {
		t.Fatalf("status=%d calls=%d body=%q", response.Code, issuer.EndSessionCalls(), response.Body.String())
	}
	assertSessionCookieCleared(t, response, client.sessionCookie.Name)
}

func assertSessionCookieCleared(t *testing.T, response *httptest.ResponseRecorder, name string) {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name && cookie.Value == "" && cookie.MaxAge < 0 {
			return
		}
	}
	t.Fatalf("session cookie %q was not cleared", name)
}
