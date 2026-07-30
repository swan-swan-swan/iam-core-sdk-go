package oidc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
)

func TestTokenEndpointHTTPStatusTakesPrecedenceOverMalformedBody(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		kind        sdkerr.Kind
		retryable   bool
	}{
		{"empty 503", http.StatusServiceUnavailable, "application/json", "", sdkerr.KindIAMUnavailable, true},
		{"non-json 500", http.StatusInternalServerError, "text/plain", "hostile-secret", sdkerr.KindIAMUnavailable, true},
		{"oversized 502", http.StatusBadGateway, "application/json", strings.Repeat("x", (1<<20)+1), sdkerr.KindIAMUnavailable, true},
		{"malformed 429", http.StatusTooManyRequests, "application/json", "{", sdkerr.KindIAMUnavailable, true},
		{"malformed 401", http.StatusUnauthorized, "application/json", "{", sdkerr.KindUnauthenticated, false},
		{"malformed 403", http.StatusForbidden, "application/json", "{", sdkerr.KindForbidden, false},
		{"malformed 400", http.StatusBadRequest, "application/json", "{", sdkerr.KindProtocol, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeOIDCServer(t)
			fake.setRawTokenResponse(test.status, test.contentType, test.body)
			client, err := New(t.Context(), Config{
				IssuerURL:      fake.Server.URL,
				ClientID:       "client-1",
				SecretProvider: StaticSecret("secret-1"),
				RedirectURL:    "https://app.example/callback",
				Scopes:         []string{"openid"},
				HTTPClient:     fake.Server.Client(),
				Timeout:        time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Refresh(t.Context(), "refresh-secret")
			var typed *sdkerr.Error
			if !errors.As(err, &typed) || typed.Kind != test.kind ||
				typed.Retryable != test.retryable || typed.HTTPStatus != test.status ||
				typed.Cause != nil || strings.Contains(err.Error(), "hostile-secret") ||
				fake.TokenCalls.Load() != 1 {
				t.Fatalf("error = %#v, calls = %d", err, fake.TokenCalls.Load())
			}
		})
	}
}

func TestTokenEndpointAuthoritativeStatusCannotBeOverriddenByOAuthBody(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		kind   sdkerr.Kind
		retry  bool
	}{
		{"429 invalid grant", http.StatusTooManyRequests, `{"error":"invalid_grant"}`, sdkerr.KindIAMUnavailable, true},
		{"500 invalid client", http.StatusInternalServerError, `{"error":"invalid_client"}`, sdkerr.KindIAMUnavailable, true},
		{"401 access denied", http.StatusUnauthorized, `{"error":"access_denied"}`, sdkerr.KindUnauthenticated, false},
		{"403 invalid grant", http.StatusForbidden, `{"error":"invalid_grant"}`, sdkerr.KindForbidden, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeOIDCServer(t)
			fake.setRawTokenResponse(test.status, "application/json", test.body)
			client, err := New(t.Context(), Config{
				IssuerURL:      fake.Server.URL,
				ClientID:       "client-1",
				SecretProvider: StaticSecret("secret-1"),
				RedirectURL:    "https://app.example/callback",
				Scopes:         []string{"openid"},
				HTTPClient:     fake.Server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Refresh(t.Context(), "refresh-secret")
			var typed *sdkerr.Error
			if !errors.As(err, &typed) || typed.Kind != test.kind ||
				typed.Retryable != test.retry || typed.Reason != "" ||
				errors.Is(err, sdkerr.ErrInvalidGrant) {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}

func TestExchangeUsesClientSecretInFormAndDoesNotRetry(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	_, err := client.Exchange(context.Background(), "code-1")
	if err != nil {
		t.Fatal(err)
	}
	if fake.TokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d", fake.TokenCalls.Load())
	}
	if fake.LastTokenForm.Get("client_secret") != "secret-1" {
		t.Fatal("client_secret was not sent in form")
	}
}

func TestExchangeUsesCurrentSecretAndExpectedForm(t *testing.T) {
	fake := newFakeOIDCServer(t)
	var calls atomic.Int32
	client, err := New(t.Context(), Config{
		IssuerURL: fake.Server.URL,
		ClientID:  "client-1",
		SecretProvider: SecretProviderFunc(func(context.Context) (string, error) {
			if calls.Add(1) == 1 {
				return "rotated-secret-1", nil
			}
			return "rotated-secret-2", nil
		}),
		RedirectURL: "https://app.example/callback",
		Scopes:      []string{"openid"},
		HTTPClient:  fake.Server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.Exchange(t.Context(), "code-1"); err != nil {
		t.Fatalf("first Exchange() error = %v", err)
	}
	first := fake.tokenForm()
	if _, err := client.Exchange(t.Context(), "code-2"); err != nil {
		t.Fatalf("second Exchange() error = %v", err)
	}
	second := fake.tokenForm()
	if first.Get("client_secret") != "rotated-secret-1" || second.Get("client_secret") != "rotated-secret-2" {
		t.Fatalf("secrets = first %q second %q", first.Get("client_secret"), second.Get("client_secret"))
	}
	if second.Get("grant_type") != "authorization_code" || second.Get("client_id") != "client-1" ||
		second.Get("code") != "code-2" || second.Get("redirect_uri") != "https://app.example/callback" {
		t.Fatalf("form = %#v", second)
	}
}

func TestExchangeReturnsTokenSet(t *testing.T) {
	client, _ := newTestClientAndServer(t)
	tokens, err := client.Exchange(t.Context(), "code-1")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if tokens.AccessToken != "access-1" || tokens.TokenType != "Bearer" ||
		tokens.RefreshToken != "refresh-2" || tokens.IDToken == "" {
		t.Fatalf("tokens = %#v", tokens)
	}
	if tokens.AccessTokenExpiry.IsZero() {
		t.Fatal("access token expiry was not populated")
	}
}

func TestRefreshUsesFormOnceAndPreservesOmittedRefreshToken(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	fake.setTokenResponse(http.StatusOK, map[string]any{
		"access_token": "access-2",
		"token_type":   "Bearer",
		"expires_in":   1800,
	}, "")
	tokens, err := client.Refresh(t.Context(), "refresh-original")
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if fake.TokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d", fake.TokenCalls.Load())
	}
	form := fake.tokenForm()
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-original" ||
		form.Get("client_secret") != "secret-1" {
		t.Fatalf("form = %#v", form)
	}
	if tokens.RefreshToken != "refresh-original" {
		t.Fatalf("refresh token = %q", tokens.RefreshToken)
	}
}

func TestRefreshRejectsNullRefreshTokenReplacement(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	fake.setTokenResponse(http.StatusOK, map[string]any{
		"access_token":  "access-2",
		"token_type":    "Bearer",
		"expires_in":    1800,
		"refresh_token": nil,
	}, "")
	tokens, err := client.Refresh(t.Context(), "refresh-original")
	if err == nil {
		t.Fatalf("tokens = %#v, want protocol error", tokens)
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindProtocol {
		t.Fatalf("error = %#v", err)
	}
}

func TestExchangeRejectsExpiresInOverflow(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	fake.setTokenResponse(http.StatusOK, map[string]any{
		"access_token": "access-2",
		"token_type":   "Bearer",
		"expires_in":   int64(math.MaxInt64),
	}, "")
	tokens, err := client.Exchange(t.Context(), "code-1")
	if err == nil {
		t.Fatalf("tokens = %#v, want protocol error", tokens)
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindProtocol {
		t.Fatalf("error = %#v", err)
	}
}

func TestTokenMethodsRejectEmptySubmittedValuesBeforeRequest(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	if _, err := client.Exchange(t.Context(), "  "); err == nil {
		t.Fatal("expected empty code error")
	}
	if _, err := client.Refresh(t.Context(), ""); err == nil {
		t.Fatal("expected empty refresh token error")
	}
	if calls := fake.TokenCalls.Load(); calls != 0 {
		t.Fatalf("token calls = %d", calls)
	}
}

func TestTokenErrorIsRedactedAndCarriesCorrelation(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	fake.setTokenResponse(http.StatusBadRequest, map[string]any{
		"error":             "invalid_grant",
		"error_description": "hostile code-1 secret-1 refresh-original",
		"request_id":        "request-body",
		"trace_id":          "trace-safe",
	}, "request-header")
	_, err := client.Exchange(t.Context(), "code-1")
	if err == nil {
		t.Fatal("expected token error")
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if typed.Kind != sdkerr.KindUnauthenticated || typed.RequestID != "request-header" || typed.TraceID != "trace-safe" {
		t.Fatalf("error = %#v", typed)
	}
	if typed.Reason != sdkerr.ReasonInvalidGrant || !errors.Is(err, sdkerr.ErrInvalidGrant) {
		t.Fatalf("invalid_grant classification = %#v", typed)
	}
	if typed.Cause != nil {
		t.Fatalf("error cause = %v", typed.Cause)
	}
	for _, secret := range []string{"hostile", "code-1", "secret-1", "refresh-original"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error exposed %q: %v", secret, err)
		}
	}
}

func TestTokenEndpointClassifiesOnlyExactInvalidGrant(t *testing.T) {
	for name, code := range map[string]string{
		"invalid client":  "invalid_client",
		"near match":      "invalid-grant",
		"hostile unknown": "invalid_grant token=secret",
	} {
		t.Run(name, func(t *testing.T) {
			client, fake := newTestClientAndServer(t)
			fake.setTokenResponse(http.StatusBadRequest, map[string]any{
				"error":             code,
				"error_description": "hostile refresh-original secret-1",
			}, "")
			_, err := client.Refresh(t.Context(), "refresh-original")
			if err == nil {
				t.Fatal("expected token error")
			}
			typed, ok := err.(*sdkerr.Error)
			if !ok || typed.Reason != "" || errors.Is(err, sdkerr.ErrInvalidGrant) {
				t.Fatalf("error = %#v", err)
			}
			for _, forbidden := range []string{code, "hostile", "refresh-original", "secret-1"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("error exposed %q: %v", forbidden, err)
				}
			}
		})
	}
}

func TestSanitizeErrorPreservesOnlyAllowlistedReason(t *testing.T) {
	valid := &sdkerr.Error{
		Kind:      sdkerr.KindUnauthenticated,
		Operation: "transport.response",
		Reason:    sdkerr.ReasonInvalidGrant,
	}
	if got := sanitizeError("oidc.refresh", valid); got.Reason != sdkerr.ReasonInvalidGrant {
		t.Fatalf("allowlisted reason = %q", got.Reason)
	}

	hostile := &sdkerr.Error{
		Kind:      sdkerr.KindUnauthenticated,
		Operation: "transport.response",
		Reason:    "invalid_grant token=secret",
	}
	got := sanitizeError("oidc.refresh", hostile)
	if got.Reason != "" || strings.Contains(got.Error(), "secret") {
		t.Fatalf("unsafe sanitized error = %#v", got)
	}
}

func TestTokenErrorDropsCorrelationContainingSubmittedValues(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	fake.setTokenResponse(http.StatusBadRequest, map[string]any{
		"error":      "invalid_grant",
		"request_id": "request-code-1",
		"trace_id":   "trace-secret-1",
	}, "")
	_, err := client.Exchange(t.Context(), "code-1")
	if err == nil {
		t.Fatal("expected token error")
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if typed.RequestID != "" || typed.TraceID != "" {
		t.Fatalf("unsafe correlation = request %q trace %q", typed.RequestID, typed.TraceID)
	}
}

func TestIAMEnvelopeErrorIsRedacted(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	fake.setTokenResponse(http.StatusInternalServerError, map[string]any{
		"code":       50001,
		"message":    "hostile-secret",
		"request_id": "request-safe",
		"trace_id":   "trace-safe",
	}, "")
	_, err := client.Refresh(t.Context(), "refresh-original")
	if err == nil {
		t.Fatal("expected token error")
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if typed.Kind != sdkerr.KindIAMUnavailable || !typed.Retryable ||
		typed.RequestID != "request-safe" || typed.TraceID != "trace-safe" {
		t.Fatalf("error = %#v", typed)
	}
	if typed.Cause != nil || strings.Contains(err.Error(), "hostile-secret") {
		t.Fatalf("unsafe error = %#v", typed)
	}
}

func TestSecretProviderFailureIsSanitizedAndSkipsRequest(t *testing.T) {
	fake := newFakeOIDCServer(t)
	client, err := New(t.Context(), Config{
		IssuerURL: fake.Server.URL,
		ClientID:  "client-1",
		SecretProvider: SecretProviderFunc(func(context.Context) (string, error) {
			return "", errors.New("vault exposed client-secret")
		}),
		RedirectURL: "https://app.example/callback",
		Scopes:      []string{"openid"},
		HTTPClient:  fake.Server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.Exchange(t.Context(), "code-1")
	if err == nil {
		t.Fatal("expected secret provider error")
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Cause != nil {
		t.Fatalf("error = %#v", err)
	}
	if strings.Contains(err.Error(), "vault") || strings.Contains(err.Error(), "client-secret") {
		t.Fatalf("unsafe error = %v", err)
	}
	if calls := fake.TokenCalls.Load(); calls != 0 {
		t.Fatalf("token calls = %d", calls)
	}
}

func TestTokenLoggingDoesNotContainCredentialsOrProtocolData(t *testing.T) {
	fake := newFakeOIDCServer(t)
	var logs bytes.Buffer
	client, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
		Logger:         slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fake.setTokenResponse(http.StatusBadRequest, map[string]any{
		"error":             "invalid_grant",
		"error_description": "hostile-description",
	}, "")
	_, _ = client.Exchange(t.Context(), "code-1")
	for _, forbidden := range []string{"secret-1", "code-1", "invalid_grant", "hostile-description"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("logs exposed %q: %s", forbidden, logs.String())
		}
	}
}
