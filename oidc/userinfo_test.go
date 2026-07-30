package oidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
)

func newUserInfoClient(t *testing.T, responseBody string) *Client {
	t.Helper()
	client, _ := newTask4EndpointClient(t, "userinfo_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(responseBody))
	})
	return client
}

func newTask4EndpointClient(
	t *testing.T,
	discoveryEndpoint string,
	handler http.HandlerFunc,
) (*Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		handler(writer, request)
	}))
	t.Cleanup(endpoint.Close)

	fake := newFakeOIDCServer(t)
	fake.overrideDiscoveryEndpoint(discoveryEndpoint, endpoint.URL+"/endpoint?tenant=tenant-1")
	client, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid", "profile", "email", "roles"},
		HTTPClient:     http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client, &calls
}

func TestUserInfoPreservesUnknownClaims(t *testing.T) {
	client := newUserInfoClient(t, `{
		"sub":"op_usr_0123456789abcdefgjk",
		"username":"alice",
		"roles":["platform_dev"],
		"organization_code":"ops"
	}`)
	identity, err := client.UserInfo(t.Context(), "access-token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != task4Subject {
		t.Fatalf("subject = %q", identity.Subject)
	}
	if string(identity.ExtraClaims["organization_code"]) != `"ops"` {
		t.Fatalf("extra claims = %#v", identity.ExtraClaims)
	}
}

func TestUserInfoExtractsKnownFieldsAndConfiguredScopes(t *testing.T) {
	client := newUserInfoClient(t, `{
		"sub":"op_usr_0123456789abcdefgjk",
		"username":"alice",
		"email":"alice@example.test",
		"display_name":"Alice",
		"roles":["platform_dev"],
		"scope":"hostile unverified",
		"organization_code":{"value":"ops"}
	}`)
	identity, err := client.UserInfo(t.Context(), "access-token")
	if err != nil {
		t.Fatalf("UserInfo() error = %v", err)
	}
	if identity.Username != "alice" || identity.Email != "alice@example.test" ||
		identity.DisplayName != "Alice" || len(identity.Roles) != 1 || identity.Roles[0] != "platform_dev" {
		t.Fatalf("identity = %#v", identity)
	}
	wantScopes := []string{"openid", "profile", "email", "roles"}
	if strings.Join(identity.Scopes, " ") != strings.Join(wantScopes, " ") {
		t.Fatalf("scopes = %#v", identity.Scopes)
	}
	for _, known := range []string{"sub", "username", "email", "display_name", "roles"} {
		if _, ok := identity.ExtraClaims[known]; ok {
			t.Fatalf("known claim %q remained in extra claims", known)
		}
	}
	if string(identity.ExtraClaims["scope"]) != `"hostile unverified"` ||
		string(identity.ExtraClaims["organization_code"]) != `{"value":"ops"}` {
		t.Fatalf("extra claims = %#v", identity.ExtraClaims)
	}
}

func TestUserInfoReturnsDefensiveCopies(t *testing.T) {
	client := newUserInfoClient(t, `{
		"sub":"op_usr_0123456789abcdefgjk",
		"roles":["platform_dev"],
		"organization_code":"ops"
	}`)
	first, err := client.UserInfo(t.Context(), "access-token")
	if err != nil {
		t.Fatalf("first UserInfo() error = %v", err)
	}
	first.Roles[0] = "mutated"
	first.Scopes[0] = "mutated"
	first.ExtraClaims["organization_code"][1] = 'X'

	second, err := client.UserInfo(t.Context(), "access-token")
	if err != nil {
		t.Fatalf("second UserInfo() error = %v", err)
	}
	if second.Roles[0] != "platform_dev" || second.Scopes[0] != "openid" ||
		string(second.ExtraClaims["organization_code"]) != `"ops"` {
		t.Fatalf("second identity aliased first: %#v", second)
	}
}

func TestUserInfoSendsOneBearerGET(t *testing.T) {
	var method, authorization, rawQuery string
	client, calls := newTask4EndpointClient(t, "userinfo_endpoint", func(writer http.ResponseWriter, request *http.Request) {
		method = request.Method
		authorization = request.Header.Get("Authorization")
		rawQuery = request.URL.RawQuery
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"sub":"` + task4Subject + `"}`))
	})
	if _, err := client.UserInfo(t.Context(), "access-token-secret"); err != nil {
		t.Fatalf("UserInfo() error = %v", err)
	}
	if calls.Load() != 1 || method != http.MethodGet || authorization != "Bearer access-token-secret" ||
		rawQuery != "tenant=tenant-1" {
		t.Fatalf("calls=%d method=%q authorization=%q query=%q", calls.Load(), method, authorization, rawQuery)
	}
}

func TestUserInfoRejectsEmptyAccessTokenWithoutRequest(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "userinfo_endpoint", func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected request")
	})
	_, err := client.UserInfo(t.Context(), " \t")
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindInvalidConfig || typed.Cause != nil || calls.Load() != 0 {
		t.Fatalf("error=%#v calls=%d", err, calls.Load())
	}
}

func TestUserInfo401IAMEnvelopeMapsToErrUnauthenticated(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "userinfo_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "request-safe")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{
			"code":40101,
			"message":"hostile access-token-secret",
			"request_id":"request-body",
			"trace_id":"trace-safe"
		}`))
	})
	_, err := client.UserInfo(t.Context(), "access-token-secret")
	if !errors.Is(err, sdkerr.ErrUnauthenticated) {
		t.Fatalf("error = %#v", err)
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindUnauthenticated || typed.Cause != nil ||
		typed.RequestID != "request-safe" || typed.TraceID != "trace-safe" || calls.Load() != 1 {
		t.Fatalf("error=%#v calls=%d", err, calls.Load())
	}
	if strings.Contains(err.Error(), "hostile") || strings.Contains(err.Error(), "access-token-secret") {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestUserInfo5xxIsRetryableWithoutSDKRetry(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "userinfo_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"message":"hostile-response-secret"}`))
	})
	_, err := client.UserInfo(t.Context(), "access-token-secret")
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindIAMUnavailable || !typed.Retryable || typed.Cause != nil || calls.Load() != 1 {
		t.Fatalf("error=%#v calls=%d", err, calls.Load())
	}
	if strings.Contains(err.Error(), "hostile-response-secret") || strings.Contains(err.Error(), "access-token-secret") {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestUserInfo5xxMappingPrecedesBodyDecoding(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "userinfo_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "request-tenant-1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`"hostile-response-secret"`))
	})
	_, err := client.UserInfo(t.Context(), "access-token-secret")
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindIAMUnavailable || !typed.Retryable || typed.Cause != nil ||
		typed.RequestID != "" || calls.Load() != 1 {
		t.Fatalf("error=%#v calls=%d", err, calls.Load())
	}
}

func TestUserInfoMalformed2xxAndMissingSubjectAreProtocolErrors(t *testing.T) {
	for name, body := range map[string]string{
		"malformed":        `{"sub":`,
		"wrong known type": `{"sub":"` + task4Subject + `","roles":"platform_dev"}`,
		"missing subject":  `{"username":"alice"}`,
	} {
		t.Run(name, func(t *testing.T) {
			client, calls := newTask4EndpointClient(t, "userinfo_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(body))
			})
			_, err := client.UserInfo(t.Context(), "access-token-secret")
			assertProtocolErrorIsRedacted(t, err, "access-token-secret", body)
			if calls.Load() != 1 {
				t.Fatalf("calls = %d", calls.Load())
			}
		})
	}
}

func TestUserInfoBoundsResponseBody(t *testing.T) {
	client, calls := newTask4EndpointClient(t, "userinfo_endpoint", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"sub":"` + strings.Repeat("x", 1<<20) + `"}`))
	})
	_, err := client.UserInfo(t.Context(), "access-token-secret")
	assertProtocolErrorIsRedacted(t, err, "access-token-secret")
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}
