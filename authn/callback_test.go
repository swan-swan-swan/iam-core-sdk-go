package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

func TestCallbackMissingFlowCookieClearsFlowAndCreatesNoSession(t *testing.T) {
	harness := newTestHarness(t, nil)
	response := httptest.NewRecorder()
	harness.service.CallbackHandler().ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/auth/callback?state=s&code=c", nil),
	)
	if response.Code != http.StatusBadRequest || harness.backend.createCount.Load() != 0 {
		t.Fatalf("status=%d create calls=%d", response.Code, harness.backend.createCount.Load())
	}
	assertFlowCleared(t, response)
}

func TestCompleteCallbackNilRequestDoesNotPanic(t *testing.T) {
	service, _ := newTestService(t)
	response := httptest.NewRecorder()
	if _, err := service.CompleteCallback(response, nil); err == nil {
		t.Fatal("CompleteCallback(nil request) returned nil error")
	}
	assertFlowCleared(t, response)
}

func TestCallbackStateMismatchConsumesFlowBeforeProviderError(t *testing.T) {
	harness, flowCookie := callbackHarness(t, "expected-state", "expected-nonce", "/assets")
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/callback?state=attacker-state&error=access_denied&code=attacker-code",
		nil,
	)
	request.AddCookie(flowCookie)
	response := httptest.NewRecorder()
	_, err := harness.service.CompleteCallback(response, request)
	if err == nil || harness.backend.consumeCount.Load() != 1 ||
		harness.backend.createCount.Load() != 0 || harness.oidc.tokenCalls.Load() != 0 {
		t.Fatalf("error=%v consumes=%d creates=%d tokenCalls=%d", err, harness.backend.consumeCount.Load(), harness.backend.createCount.Load(), harness.oidc.tokenCalls.Load())
	}
	assertFlowCleared(t, response)
	if _, consumeErr := harness.backend.ConsumeFlow(context.Background(), flowCookie.Value); !errors.Is(consumeErr, session.ErrNotFound) {
		t.Fatalf("flow was not consumed: %v", consumeErr)
	}
}

func TestCallbackProviderErrorCreatesNoSession(t *testing.T) {
	harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/")
	request := httptest.NewRequest(http.MethodGet, "/auth/callback?state=state-1&error=access_denied", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	harness.service.CallbackHandler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || harness.backend.createCount.Load() != 0 ||
		harness.oidc.tokenCalls.Load() != 0 {
		t.Fatalf("status=%d creates=%d tokenCalls=%d", response.Code, harness.backend.createCount.Load(), harness.oidc.tokenCalls.Load())
	}
	assertFlowCleared(t, response)
}

func TestCallbackNonceMismatchCreatesNoSession(t *testing.T) {
	harness, cookie := callbackHarness(t, "state-1", "expected-nonce", "/")
	harness.oidc.mu.Lock()
	harness.oidc.nonce = "wrong-nonce"
	harness.oidc.mu.Unlock()
	response := executeCallback(harness.service, cookie, "state-1", "code-1")
	if response.Code != http.StatusUnauthorized || harness.backend.createCount.Load() != 0 ||
		harness.oidc.tokenCalls.Load() != 1 || harness.oidc.userInfoCalls.Load() != 0 {
		t.Fatalf("status=%d creates=%d token=%d userinfo=%d", response.Code, harness.backend.createCount.Load(), harness.oidc.tokenCalls.Load(), harness.oidc.userInfoCalls.Load())
	}
	assertFlowCleared(t, response)
}

func TestCallbackMissingIDTokenCreatesNoSession(t *testing.T) {
	harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/")
	harness.oidc.mu.Lock()
	harness.oidc.includeIDToken = false
	harness.oidc.mu.Unlock()
	response := executeCallback(harness.service, cookie, "state-1", "code-1")
	if response.Code != http.StatusUnauthorized || harness.backend.createCount.Load() != 0 ||
		harness.oidc.userInfoCalls.Load() != 0 {
		t.Fatalf("status=%d creates=%d userinfo=%d", response.Code, harness.backend.createCount.Load(), harness.oidc.userInfoCalls.Load())
	}
	assertFlowCleared(t, response)
}

func TestCallbackUserInfoSubjectMismatchCreatesNoSession(t *testing.T) {
	harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/")
	harness.oidc.mu.Lock()
	harness.oidc.nonce = "nonce-1"
	harness.oidc.userInfoSubject = "different-user"
	harness.oidc.mu.Unlock()
	response := executeCallback(harness.service, cookie, "state-1", "code-1")
	if response.Code != http.StatusUnauthorized || harness.backend.createCount.Load() != 0 ||
		harness.oidc.tokenCalls.Load() != 1 || harness.oidc.userInfoCalls.Load() != 1 {
		t.Fatalf("status=%d creates=%d token=%d userinfo=%d", response.Code, harness.backend.createCount.Load(), harness.oidc.tokenCalls.Load(), harness.oidc.userInfoCalls.Load())
	}
	assertFlowCleared(t, response)
}

func TestCallbackSuccessCreatesFreshSessionAndRedirectsStoredReturnTo(t *testing.T) {
	harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/assets?q=one#fragment")
	harness.oidc.mu.Lock()
	harness.oidc.nonce = "nonce-1"
	harness.oidc.mu.Unlock()
	request := httptest.NewRequest(http.MethodGet, "/auth/callback?state=state-1&code=code-1", nil)
	request.AddCookie(cookie)
	request.AddCookie(&http.Cookie{Name: "__Host-iam_core_session", Value: "attacker-fixed-id"})
	response := httptest.NewRecorder()
	harness.service.CallbackHandler().ServeHTTP(response, request)

	if response.Code != http.StatusFound ||
		response.Header().Get("Location") != "/assets?q=one#fragment" {
		t.Fatalf("status=%d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if response.Body.Len() != 0 {
		t.Fatalf("redirect body exposed return_to: %q", response.Body.String())
	}
	if harness.oidc.tokenCalls.Load() != 1 || harness.oidc.userInfoCalls.Load() != 1 ||
		harness.backend.createCount.Load() != 1 {
		t.Fatalf("token=%d userinfo=%d creates=%d", harness.oidc.tokenCalls.Load(), harness.oidc.userInfoCalls.Load(), harness.backend.createCount.Load())
	}
	created := harness.backend.LastSession()
	if created == nil || created.ID == "" || created.ID == "attacker-fixed-id" ||
		created.Version != 1 || !created.CreatedAt.Equal(fixedNow) ||
		!created.UpdatedAt.Equal(fixedNow) || !created.LastSeenAt.Equal(fixedNow) ||
		!created.IdentityValidatedAt.Equal(fixedNow) ||
		!created.ExpiresAt.Equal(fixedNow.Add(7*24*time.Hour)) ||
		!created.IdleExpiresAt.Equal(fixedNow.Add(8*time.Hour)) ||
		created.TokenSet.AccessToken != "access-secret" ||
		created.Identity.Subject != "user-1" ||
		len(created.GrantedScopes) != 2 {
		t.Fatalf("created session = %#v", created)
	}
	sessionCookie := findResponseCookie(response, "__Host-iam_core_session")
	if sessionCookie == nil || sessionCookie.Value != created.ID || !sessionCookie.Secure ||
		!sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %#v", sessionCookie)
	}
	assertFlowCleared(t, response)
}

func TestCallbackCreateFailureSetsNoSessionCookie(t *testing.T) {
	harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/")
	harness.backend.createErr = errors.New("database secret")
	harness.oidc.mu.Lock()
	harness.oidc.nonce = "nonce-1"
	harness.oidc.mu.Unlock()
	response := executeCallback(harness.service, cookie, "state-1", "code-1")
	if response.Code != http.StatusServiceUnavailable ||
		findResponseCookie(response, "__Host-iam_core_session") != nil ||
		strings.Contains(response.Body.String(), "database secret") {
		t.Fatalf("status=%d sessionCookie=%#v body=%q", response.Code, findResponseCookie(response, "__Host-iam_core_session"), response.Body.String())
	}
	assertFlowCleared(t, response)
}

func TestCallbackRandomSessionIDFailureCreatesNoSession(t *testing.T) {
	harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/")
	harness.random.failCall = harness.random.calls + 1
	harness.oidc.mu.Lock()
	harness.oidc.nonce = "nonce-1"
	harness.oidc.mu.Unlock()
	response := executeCallback(harness.service, cookie, "state-1", "code-1")
	if response.Code != http.StatusServiceUnavailable || harness.backend.createCount.Load() != 0 ||
		findResponseCookie(response, "__Host-iam_core_session") != nil {
		t.Fatalf("status=%d creates=%d headers=%#v", response.Code, harness.backend.createCount.Load(), response.Header())
	}
	assertFlowCleared(t, response)
}

func TestCallbackRejectsMissingOrDuplicateParametersAfterConsumingFlow(t *testing.T) {
	tests := []string{
		"/auth/callback?code=code-1",
		"/auth/callback?state=state-1",
		"/auth/callback?state=state-1&state=state-1&code=code-1",
		"/auth/callback?state=state-1&code=one&code=two",
		"/auth/callback?state=state-1&error=one&error=two",
		"/auth/callback?state=state-1&error=denied&code=code-1",
	}
	for _, target := range tests {
		t.Run(url.QueryEscape(target), func(t *testing.T) {
			harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/")
			request := httptest.NewRequest(http.MethodGet, target, nil)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			harness.service.CallbackHandler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest && response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if harness.backend.consumeCount.Load() != 1 || harness.backend.createCount.Load() != 0 ||
				harness.oidc.tokenCalls.Load() != 0 {
				t.Fatalf("consume=%d create=%d token=%d", harness.backend.consumeCount.Load(), harness.backend.createCount.Load(), harness.oidc.tokenCalls.Load())
			}
			assertFlowCleared(t, response)
		})
	}
}

func TestCallbackDuplicateAndExpiredFlowCreateNoSession(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/")
		harness.oidc.mu.Lock()
		harness.oidc.nonce = "nonce-1"
		harness.oidc.mu.Unlock()
		first := executeCallback(harness.service, cookie, "state-1", "code-1")
		second := executeCallback(harness.service, cookie, "state-1", "code-1")
		if first.Code != http.StatusFound || second.Code != http.StatusBadRequest ||
			harness.backend.createCount.Load() != 1 || harness.oidc.tokenCalls.Load() != 1 {
			t.Fatalf("first=%d second=%d creates=%d token=%d", first.Code, second.Code, harness.backend.createCount.Load(), harness.oidc.tokenCalls.Load())
		}
		assertFlowCleared(t, second)
	})
	t.Run("expired", func(t *testing.T) {
		harness := newTestHarness(t, nil)
		flow := &session.Flow{
			ID: "expired-flow", State: "state-1", Nonce: "nonce-1", ReturnTo: "/",
			CreatedAt: fixedNow.Add(-time.Hour), ExpiresAt: fixedNow,
		}
		harness.backend.lastFlow = flow
		harness.backend.consumeErr = session.ErrExpired
		request := httptest.NewRequest(http.MethodGet, "/auth/callback?state=state-1&code=code", nil)
		request.AddCookie(&http.Cookie{Name: "__Host-iam_core_flow", Value: flow.ID})
		response := httptest.NewRecorder()
		harness.service.CallbackHandler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || harness.backend.createCount.Load() != 0 {
			t.Fatalf("status=%d creates=%d", response.Code, harness.backend.createCount.Load())
		}
		assertFlowCleared(t, response)
	})
}

func TestConcurrentCallbackHasOneWinner(t *testing.T) {
	harness, cookie := callbackHarness(t, "state-1", "nonce-1", "/")
	harness.oidc.mu.Lock()
	harness.oidc.nonce = "nonce-1"
	harness.oidc.mu.Unlock()
	var wait sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses <- executeCallback(harness.service, cookie, "state-1", "code-1").Code
		}()
	}
	wait.Wait()
	close(statuses)
	found, rejected := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusFound:
			found++
		case http.StatusBadRequest:
			rejected++
		}
	}
	if found != 1 || rejected != 1 || harness.backend.createCount.Load() != 1 ||
		harness.oidc.tokenCalls.Load() != 1 {
		t.Fatalf("found=%d rejected=%d creates=%d token=%d", found, rejected, harness.backend.createCount.Load(), harness.oidc.tokenCalls.Load())
	}
}

func TestCallbackFlowClearPreservesCookieScope(t *testing.T) {
	harness := newTestHarness(t, func(config *Config, _ *testHarness) {
		config.FlowCookie = http.Cookie{
			Name: "__Host-custom-flow", Path: "/", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
	})
	response := httptest.NewRecorder()
	harness.service.CallbackHandler().ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/auth/callback?state=s&code=c", nil),
	)
	cookie := findResponseCookie(response, "__Host-custom-flow")
	if cookie == nil || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure ||
		!cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode ||
		cookie.MaxAge != -1 || !cookie.Expires.Before(fixedNow) {
		t.Fatalf("clear cookie = %#v", cookie)
	}
}

func callbackHarness(t *testing.T, state, nonce, returnTo string) (*testHarness, *http.Cookie) {
	t.Helper()
	harness := newTestHarness(t, nil)
	flow := &session.Flow{
		ID:        "flow-id",
		State:     state,
		Nonce:     nonce,
		ReturnTo:  returnTo,
		CreatedAt: fixedNow,
		ExpiresAt: fixedNow.Add(10 * time.Minute),
	}
	if err := harness.backend.PutFlow(context.Background(), flow); err != nil {
		t.Fatal(err)
	}
	return harness, &http.Cookie{Name: "__Host-iam_core_flow", Value: flow.ID}
}

func executeCallback(service *Service, cookie *http.Cookie, state, code string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code),
		nil,
	)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	service.CallbackHandler().ServeHTTP(response, request)
	return response
}

func assertFlowCleared(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	cookie := findResponseCookie(response, "__Host-iam_core_flow")
	if cookie == nil || cookie.Value != "" || cookie.MaxAge != -1 ||
		!cookie.Expires.Before(fixedNow) || cookie.Path != "/" ||
		!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("flow clear cookie = %#v headers=%#v", cookie, response.Header())
	}
}

func findResponseCookie(response *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
