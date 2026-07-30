package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
)

func TestNewRejectsIssuerMismatch(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.OverrideDiscoveryIssuer("https://different.example")
	_, err := New(context.Background(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid", "profile"},
		HTTPClient:     fake.Server.Client(),
	})
	if err == nil {
		t.Fatal("expected issuer mismatch")
	}
	if fake.DiscoveryCalls.Load() != 1 {
		t.Fatalf("discovery calls = %d", fake.DiscoveryCalls.Load())
	}
}

func TestNewAcceptsOnlyTrailingSlashIssuerNormalization(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.OverrideDiscoveryIssuer(fake.Server.URL + "/")
	client, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client.Metadata().Issuer != fake.Server.URL+"/" {
		t.Fatalf("issuer = %q", client.Metadata().Issuer)
	}
}

func TestNewDoesNotNormalizeIssuerWhitespace(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.OverrideDiscoveryIssuer(" " + fake.Server.URL)
	_, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
	})
	if err == nil {
		t.Fatal("expected issuer whitespace mismatch")
	}
}

func TestNewDoesNotRewriteDiscoveredEndpointHost(t *testing.T) {
	fake := newFakeOIDCServer(t)
	endpoint := "https://tokens.example/oidc/token"
	fake.overrideDiscoveryEndpoint("token_endpoint", endpoint)
	client, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client.Metadata().TokenEndpoint != endpoint {
		t.Fatalf("token endpoint = %q", client.Metadata().TokenEndpoint)
	}
}

func TestNewPreservesDiscoveredEndpointQuery(t *testing.T) {
	fake := newFakeOIDCServer(t)
	endpoint := fake.Server.URL + "/oidc/token?tenant=tenant-1"
	fake.overrideDiscoveryEndpoint("token_endpoint", endpoint)
	client, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client.Metadata().TokenEndpoint != endpoint {
		t.Fatalf("token endpoint = %q", client.Metadata().TokenEndpoint)
	}
}

func TestNewObservesIssuerMismatchAsError(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.OverrideDiscoveryIssuer("https://different.example")
	hooks := &recordingHooks{}
	_, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
		Hooks:          hooks,
	})
	if err == nil {
		t.Fatal("expected issuer mismatch")
	}
	events := hooks.events()
	if len(events) != 1 || events[0].Operation != "oidc.discovery" || events[0].Outcome != "error" {
		t.Fatalf("events = %#v", events)
	}
}

func TestNewRejectsInsecureNonLoopbackIssuer(t *testing.T) {
	_, err := New(t.Context(), Config{
		IssuerURL:      "http://iam.example/tenant?credential=issuer-secret",
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     http.DefaultClient,
	})
	if err == nil {
		t.Fatal("expected insecure issuer rejection")
	}
	if strings.Contains(err.Error(), "issuer-secret") {
		t.Fatalf("error exposed issuer query: %v", err)
	}
}

func TestNewRejectsMissingRequiredEndpoint(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.overrideDiscoveryEndpoint("userinfo_endpoint", "")
	_, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
	})
	if err == nil {
		t.Fatal("expected missing endpoint rejection")
	}
}

func TestNewRequiresOpenIDScope(t *testing.T) {
	fake := newFakeOIDCServer(t)
	_, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"profile"},
		HTTPClient:     fake.Server.Client(),
	})
	if err == nil {
		t.Fatal("expected openid scope rejection")
	}
}

func TestNewDiscoveryErrorsAreSanitized(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.Server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "request-safe")
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = writer.Write([]byte(`{"message":"hostile-secret","request_id":"request-safe","trace_id":"trace-safe"}`))
	})
	_, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
	})
	if err == nil {
		t.Fatal("expected discovery error")
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if typed.RequestID != "request-safe" || typed.TraceID != "trace-safe" {
		t.Fatalf("correlation = request %q trace %q", typed.RequestID, typed.TraceID)
	}
	if typed.Cause != nil || strings.Contains(err.Error(), "hostile-secret") {
		t.Fatalf("unsafe error = %#v", typed)
	}
}

func TestNewBoundsDiscoveryResponse(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.Server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"issuer":"` + strings.Repeat("x", 1<<20) + `"}`))
	})
	_, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.Server.Client(),
	})
	if err == nil {
		t.Fatal("expected bounded discovery error")
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindProtocol || typed.Cause != nil {
		t.Fatalf("error = %#v", err)
	}
}

func TestAuthCodeURLContainsStateNonceAndScopes(t *testing.T) {
	client := newTestClient(t)
	raw := client.AuthCodeURL("state-1", "nonce-1")
	values, _ := url.Parse(raw)
	query := values.Query()
	if query.Get("state") != "state-1" || query.Get("nonce") != "nonce-1" {
		t.Fatalf("query = %#v", query)
	}
	if query.Get("response_type") != "code" || query.Get("scope") != "openid profile email roles" {
		t.Fatalf("query = %#v", query)
	}
}

func TestAuthCodeURLRequiresStateAndNonce(t *testing.T) {
	client := newTestClient(t)
	if got := client.AuthCodeURL("", "nonce-1"); got != "" {
		t.Fatalf("URL with empty state = %q", got)
	}
	if got := client.AuthCodeURL("state-1", ""); got != "" {
		t.Fatalf("URL with empty nonce = %q", got)
	}
}

type recordingHooks struct {
	mu       sync.Mutex
	observed []observability.Event
}

func (hooks *recordingHooks) Observe(_ context.Context, event observability.Event) {
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	hooks.observed = append(hooks.observed, event)
}

func (hooks *recordingHooks) events() []observability.Event {
	hooks.mu.Lock()
	defer hooks.mu.Unlock()
	return append([]observability.Event(nil), hooks.observed...)
}
