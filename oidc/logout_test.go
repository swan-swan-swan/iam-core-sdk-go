package oidc

import (
	"net/http"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
)

func TestLogoutSendsEncodedIDTokenHintAndBearerExactlyOnce(t *testing.T) {
	var method, authorization, hint, rawQuery string
	client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, request *http.Request) {
		method = request.Method
		authorization = request.Header.Get("Authorization")
		hint = request.URL.Query().Get("id_token_hint")
		rawQuery = request.URL.RawQuery
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusNoContent)
	})
	idTokenHint := "header.payload+/= id-token-secret&admin=true"
	if err := client.Logout(t.Context(), "access-token-secret", idTokenHint); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if calls.Load() != 1 || method != http.MethodGet || authorization != "Bearer access-token-secret" ||
		hint != idTokenHint || strings.Contains(rawQuery, "admin=true") {
		t.Fatalf(
			"calls=%d method=%q authorization=%q hint=%q query=%q",
			calls.Load(),
			method,
			authorization,
			hint,
			rawQuery,
		)
	}
}

func TestLogoutOmitsBearerWhenAccessTokenIsEmpty(t *testing.T) {
	var authorization string
	client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{}`))
	})
	if err := client.Logout(t.Context(), "", "id-token-hint"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if calls.Load() != 1 || authorization != "" {
		t.Fatalf("calls=%d authorization=%q", calls.Load(), authorization)
	}
}

func TestLogoutAcceptsAny2xxStatus(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(status)
			})
			if err := client.Logout(t.Context(), "", "id-token-hint"); err != nil {
				t.Fatalf("Logout() error = %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d", calls.Load())
			}
		})
	}
}

func TestLogoutAcceptsEmpty204WithoutContentType(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	if err := client.Logout(t.Context(), "", "id-token-hint"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestLogoutRejectsEmptyIDTokenHintWithoutRequest(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected request")
	})
	err := client.Logout(t.Context(), "access-token-secret", " \t")
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindInvalidConfig || typed.Cause != nil || calls.Load() != 0 {
		t.Fatalf("error=%#v calls=%d", err, calls.Load())
	}
}

func TestLogoutMapsAndSanitizesIAMEnvelopeError(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "request-safe")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{
			"code":40101,
			"message":"hostile id-token-secret access-token-secret",
			"request_id":"request-body",
			"trace_id":"trace-safe"
		}`))
	})
	err := client.Logout(t.Context(), "access-token-secret", "id-token-secret")
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindUnauthenticated || typed.Cause != nil ||
		typed.RequestID != "request-safe" || typed.TraceID != "trace-safe" || calls.Load() != 1 {
		t.Fatalf("error=%#v calls=%d", err, calls.Load())
	}
	for _, secret := range []string{"hostile", "id-token-secret", "access-token-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error exposed %q: %v", secret, err)
		}
	}
}

func TestLogout5xxIsRetryableWithoutSDKRetry(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = writer.Write([]byte(`{"message":"hostile-response-secret"}`))
	})
	err := client.Logout(t.Context(), "access-token-secret", "id-token-secret")
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindIAMUnavailable || !typed.Retryable || typed.Cause != nil ||
		calls.Load() != 1 {
		t.Fatalf("error=%#v calls=%d", err, calls.Load())
	}
}

func TestLogoutStatusMappingPrecedesTransportResponseErrors(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		wantKind    sdkerr.Kind
		wantRetry   bool
	}{
		{
			name:     "401 missing content type",
			status:   http.StatusUnauthorized,
			wantKind: sdkerr.KindUnauthenticated,
		},
		{
			name:        "503 non JSON",
			status:      http.StatusServiceUnavailable,
			contentType: "text/plain",
			wantKind:    sdkerr.KindIAMUnavailable,
			wantRetry:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
				if test.contentType != "" {
					writer.Header().Set("Content-Type", test.contentType)
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte("hostile-id-token-secret-access-token-secret"))
			})
			err := client.Logout(t.Context(), "access-token-secret", "id-token-secret")
			typed, ok := err.(*sdkerr.Error)
			if !ok || typed.Kind != test.wantKind || typed.Retryable != test.wantRetry ||
				typed.Cause != nil || calls.Load() != 1 {
				t.Fatalf("error=%#v calls=%d", err, calls.Load())
			}
			if strings.Contains(err.Error(), "hostile") || strings.Contains(err.Error(), "token-secret") {
				t.Fatalf("unsafe error = %v", err)
			}
		})
	}
}

func TestLogoutRejectsNonJSON2xx(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("hostile-id-token-secret"))
	})
	err := client.Logout(t.Context(), "access-token-secret", "id-token-secret")
	assertProtocolErrorIsRedacted(t, err, "hostile", "id-token-secret", "access-token-secret")
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestLogoutRejectsMalformedJSON2xx(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"hostile":"id-token-secret"`))
	})
	err := client.Logout(t.Context(), "access-token-secret", "id-token-secret")
	assertProtocolErrorIsRedacted(t, err, "hostile", "id-token-secret", "access-token-secret")
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestLogoutDropsCorrelationContainingSubmittedValues(t *testing.T) {
	client, _ := newTask4EndpointClient(t, "end_session_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "request-tenant-1")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"trace_id":"trace-access-token-secret"}`))
	})
	err := client.Logout(t.Context(), "access-token-secret", "id-token-secret")
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.RequestID != "" || typed.TraceID != "" || typed.Cause != nil {
		t.Fatalf("error = %#v", err)
	}
}
