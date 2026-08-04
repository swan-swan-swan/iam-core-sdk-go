package bff

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

func TestCallbackExchangeUsesExactFormOnceAndNoAmbientHeaders(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	_ = completeLogin(t, client, issuer)
	form := issuer.LastTokenForm()
	wantNames := []string{"client_id", "client_secret", "code", "code_verifier", "grant_type", "redirect_uri"}
	gotNames := make([]string, 0, len(form))
	for name, values := range form {
		gotNames = append(gotNames, name)
		if len(values) != 1 || values[0] == "" {
			t.Fatalf("form field %q has invalid cardinality or an empty value", name)
		}
	}
	slices.Sort(gotNames)
	if !slices.Equal(gotNames, wantNames) || form.Get("grant_type") != "authorization_code" ||
		form.Get("code") != testCode || form.Get("client_id") != testClientID ||
		form.Get("client_secret") != testClientSecret || form.Get("redirect_uri") != issuer.Server.URL+"/callback" ||
		len(form.Get("code_verifier")) != 43 || issuer.TokenCalls.Load() != 1 {
		t.Fatalf("exchange form fields or call count are incorrect: fields=%v calls=%d", gotNames, issuer.TokenCalls.Load())
	}
	tokenHeader, userInfoHeader := issuer.LastHeaders()
	if tokenHeader.Get("Content-Type") != "application/x-www-form-urlencoded" || tokenHeader.Get("Accept") != "application/json" ||
		tokenHeader.Get("Cookie") != "" || tokenHeader.Get("Authorization") != "" {
		t.Fatal("token request headers are incorrect")
	}
	if userInfoHeader.Get("Authorization") != "Bearer "+issuer.IssuedAccessToken() || userInfoHeader.Get("Accept") != "application/json" ||
		userInfoHeader.Get("Cookie") != "" {
		t.Fatal("userinfo request headers are incorrect")
	}
}

func TestCallbackRejectsTokenRedirectWithoutFollowing(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.TokenRedirect = true
	attempt := beginLogin(t, client, issuer, "/")
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if response.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 1 {
		t.Fatalf("redirect response was followed or misclassified: status=%d calls=%d", response.Code, issuer.TokenCalls.Load())
	}
}

func TestCallbackRejectsUserInfoRedirectWithoutReachingTarget(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.UserInfoRedirect = true
	attempt := beginLogin(t, client, issuer, "/")
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if response.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != 1 || issuer.UserInfoTargetCalls.Load() != 0 {
		t.Fatalf("UserInfo redirect was followed or misclassified: status=%d target=%d", response.Code, issuer.UserInfoTargetCalls.Load())
	}
}

func TestCallbackDoesNotRetryTokenFailures(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.TokenStatus = http.StatusServiceUnavailable
	issuer.TokenError = "temporarily_unavailable"
	attempt := beginLogin(t, client, issuer, "/")
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if response.Code != http.StatusServiceUnavailable || issuer.TokenCalls.Load() != 1 {
		t.Fatalf("status=%d calls=%d", response.Code, issuer.TokenCalls.Load())
	}
}

func TestBFFRemoteOperationsUseFiniteTimeoutsWithoutCancelingCaller(t *testing.T) {
	client, _, _ := newBFFTestClient(t)
	client.tokenTimeout = 10 * time.Millisecond
	client.userInfoTimeout = 10 * time.Millisecond
	client.endSessionTimeout = 10 * time.Millisecond
	var calls int
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}

	tests := []struct {
		name string
		call func(context.Context) error
	}{
		{name: "authorization code token exchange", call: func(ctx context.Context) error {
			_, err := client.exchange(ctx, testCode, strings.Repeat("A", 43))
			return err
		}},
		{name: "userinfo", call: func(ctx context.Context) error {
			_, err := client.loadUserInfo(ctx, testAccessToken)
			return err
		}},
		{name: "end session", call: func(ctx context.Context) error {
			return client.endSession(ctx, testAccessToken, "id-token-sensitive")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			caller := context.Background()
			started := time.Now()
			err := test.call(caller)
			if !errors.Is(err, core.ErrUnavailable) {
				t.Fatalf("operation error = %#v, want sanitized IAM unavailable", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("operation timeout took %s", elapsed)
			}
			if caller.Err() != nil {
				t.Fatalf("operation timeout canceled caller: %v", caller.Err())
			}
		})
	}
	if calls != len(tests) {
		t.Fatalf("remote calls = %d, want %d single attempts", calls, len(tests))
	}
}

func TestAuthorizationCodeExchangePreservesSecretProviderContextErrors(t *testing.T) {
	for name, providerErr := range map[string]error{
		"canceled": context.Canceled,
		"deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			secret := "wrapped-provider-secret-" + name
			wrapped := fmt.Errorf("%s: %w", secret, providerErr)
			client.clientSecret = SecretProviderFunc(func(context.Context) (string, error) { return "", wrapped })
			_, err := client.exchange(context.Background(), testCode, strings.Repeat("A", 43))
			if err != providerErr || strings.Contains(err.Error(), secret) || issuer.TokenCalls.Load() != 0 {
				t.Fatalf("exchange did not normalize provider context error or issued a request: calls=%d", issuer.TokenCalls.Load())
			}
		})
	}

	client, _, issuer := newBFFTestClient(t)
	secret := "secret-provider-cause-sensitive"
	client.clientSecret = SecretProviderFunc(func(context.Context) (string, error) { return "", errors.New(secret) })
	_, err := client.exchange(context.Background(), testCode, strings.Repeat("A", 43))
	var typed *core.Error
	if !errors.As(err, &typed) || typed.Kind != core.KindInvalidConfig || strings.Contains(err.Error(), secret) || issuer.TokenCalls.Load() != 0 {
		t.Fatalf("provider failure = %#v calls=%d, want sanitized invalid config", err, issuer.TokenCalls.Load())
	}
}

func TestCallbackHandlerDoesNotExposeWrappedSecretProviderContextError(t *testing.T) {
	config, _, issuer := newBFFTestConfig(t)
	secret := "callback-provider-wrapper-sensitive"
	config.ClientSecret = SecretProviderFunc(func(context.Context) (string, error) {
		return "", fmt.Errorf("%s: %w", secret, context.Canceled)
	})
	client, err := New(config)
	if err != nil {
		t.Fatal("construct BFF client")
	}
	attempt := beginLogin(t, client, issuer, "/")
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), secret) || issuer.TokenCalls.Load() != 0 {
		t.Fatalf("callback provider wrapper leaked or issued a request: status=%d calls=%d", response.Code, issuer.TokenCalls.Load())
	}
}

func TestCallbackPreservesUnavailableStatusWithMalformedErrorBody(t *testing.T) {
	tests := map[string]func(*bffIssuer){
		"token": func(issuer *bffIssuer) {
			issuer.TokenStatus = http.StatusServiceUnavailable
			issuer.TokenContentType = "text/plain"
			issuer.TokenBody = testCode
		},
		"userinfo": func(issuer *bffIssuer) {
			issuer.UserInfoStatus = http.StatusServiceUnavailable
			issuer.UserInfoContentType = "text/plain"
			issuer.UserInfoBody = testCode
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			mutate(issuer)
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), testCode) {
				t.Fatalf("unavailable response was misclassified or leaked its body: status=%d", response.Code)
			}
		})
	}
}

func TestCallbackMapsOAuthErrorsWithoutExposingDescriptions(t *testing.T) {
	tests := []struct {
		name, oauthError string
		status, wantHTTP int
	}{
		{"invalid grant", "invalid_grant", http.StatusBadRequest, http.StatusUnauthorized},
		{"invalid client", "invalid_client", http.StatusUnauthorized, http.StatusUnauthorized},
		{"access denied", "access_denied", http.StatusBadRequest, http.StatusUnauthorized},
		{"temporarily unavailable", "temporarily_unavailable", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
		{"server error", "server_error", http.StatusInternalServerError, http.StatusServiceUnavailable},
		{"unknown", "future_error", http.StatusBadRequest, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			issuer.TokenStatus, issuer.TokenError = test.status, test.oauthError
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != test.wantHTTP || strings.Contains(response.Body.String(), testCode) || issuer.TokenCalls.Load() != 1 {
				t.Fatalf("OAuth error was misclassified or leaked: status=%d calls=%d", response.Code, issuer.TokenCalls.Load())
			}
		})
	}
}

func TestCallbackRejectsOversizedAndMalformedProtocolBodies(t *testing.T) {
	tests := map[string]func(*bffIssuer){
		"oversized token": func(issuer *bffIssuer) {
			issuer.TokenBody = `{"padding":"` + strings.Repeat("x", maxOAuthResponseBytes+1) + `"}`
		},
		"token content type":  func(issuer *bffIssuer) { issuer.TokenContentType = "text/plain"; issuer.TokenBody = `{}` },
		"token trailing json": func(issuer *bffIssuer) { issuer.TokenBody = `{} {}` },
		"token duplicate key": func(issuer *bffIssuer) { issuer.TokenBody = `{"access_token":"a","access_token":"b"}` },
		"oversized userinfo": func(issuer *bffIssuer) {
			issuer.UserInfoBody = `{"padding":"` + strings.Repeat("x", maxOAuthResponseBytes+1) + `"}`
		},
		"userinfo content type":  func(issuer *bffIssuer) { issuer.UserInfoContentType = "text/plain"; issuer.UserInfoBody = `{}` },
		"userinfo trailing json": func(issuer *bffIssuer) { issuer.UserInfoBody = `{} {}` },
		"userinfo duplicate key": func(issuer *bffIssuer) { issuer.UserInfoBody = `{"sub":"a","sub":"b"}` },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			mutate(issuer)
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != http.StatusBadRequest && response.Code != http.StatusServiceUnavailable {
				t.Fatalf("malformed protocol response status=%d", response.Code)
			}
		})
	}
}

type recordingObserver struct {
	mu     sync.Mutex
	events []core.Event
}

func (o *recordingObserver) Observe(_ context.Context, event core.Event) {
	o.mu.Lock()
	o.events = append(o.events, event)
	o.mu.Unlock()
}

func (o *recordingObserver) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return fmt.Sprint(o.events)
}

func TestCallbackErrorsObserverAndLoggerNeverContainSecrets(t *testing.T) {
	config, backend, issuer := newBFFTestConfig(t)
	observer := &recordingObserver{}
	var logs bytes.Buffer
	config.Observer = observer
	config.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	attempt := beginLogin(t, client, issuer, "/")
	flow := backend.LastFlow()
	issuer.IDTokenNonce = "wrong-nonce-sensitive"
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	combined := logs.String() + observer.String() + response.Body.String()
	secrets := map[string]string{
		"code": testCode, "client secret": testClientSecret,
		"access token": issuer.IssuedAccessToken(), "id token": issuer.IssuedIDToken(), "refresh token": testRefreshToken,
		"flow id": flow.ID, "state": flow.State, "nonce": flow.Nonce, "verifier": flow.CodeVerifier, "cookie": attempt.Flow.Value,
	}
	for name, secret := range secrets {
		if strings.Contains(combined, secret) {
			t.Fatalf("%s leaked through callback diagnostics", name)
		}
	}
	if response.Code != http.StatusUnauthorized || issuer.TokenCalls.Load() != 1 {
		t.Fatalf("status=%d token calls=%d", response.Code, issuer.TokenCalls.Load())
	}
	if !strings.Contains(logs.String(), `"operation":"bff.callback"`) || !strings.Contains(observer.String(), "bff.callback") {
		t.Fatal("sanitized callback observability event was not emitted")
	}
}

func TestOAuthErrorClassificationsAreStableAndSanitized(t *testing.T) {
	tests := []struct {
		oauth  string
		status int
		kind   core.Kind
		reason core.Reason
		retry  bool
	}{
		{"invalid_grant", http.StatusBadRequest, core.KindUnauthenticated, core.ReasonInvalidGrant, false},
		{"access_denied", http.StatusBadRequest, core.KindForbidden, core.ReasonAccessDenied, false},
		{"temporarily_unavailable", http.StatusServiceUnavailable, core.KindIAMUnavailable, core.ReasonTemporarilyUnavailable, true},
		{"server_error", http.StatusInternalServerError, core.KindIAMUnavailable, "", true},
		{"unknown_" + testCode, http.StatusBadRequest, core.KindProtocol, "", false},
	}
	for index, test := range tests {
		err := oauthEndpointError("bff.exchange", test.status, test.oauth)
		var typed *core.Error
		if !errors.As(err, &typed) || typed.Kind != test.kind || typed.Reason != test.reason || typed.Retryable != test.retry ||
			typed.Operation != "bff.exchange" || strings.Contains(typed.Error(), testCode) {
			t.Fatalf("oauthEndpointError case %d has incorrect sanitized classification: %#v", index, err)
		}
	}
}
