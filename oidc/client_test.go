package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
)

func TestNewResolvesIndependentTimeoutBuckets(t *testing.T) {
	for _, test := range []struct {
		name              string
		legacy            time.Duration
		discoveryJWKS     time.Duration
		tokenUserInfo     time.Duration
		wantDiscoveryJWKS time.Duration
		wantTokenUserInfo time.Duration
	}{
		{
			name:              "dedicated defaults",
			wantDiscoveryJWKS: 5 * time.Second,
			wantTokenUserInfo: 10 * time.Second,
		},
		{
			name:              "legacy fallback",
			legacy:            2 * time.Second,
			wantDiscoveryJWKS: 2 * time.Second,
			wantTokenUserInfo: 2 * time.Second,
		},
		{
			name:              "dedicated values override legacy",
			legacy:            2 * time.Second,
			discoveryJWKS:     3 * time.Second,
			tokenUserInfo:     4 * time.Second,
			wantDiscoveryJWKS: 3 * time.Second,
			wantTokenUserInfo: 4 * time.Second,
		},
		{
			name:              "partial dedicated value uses legacy for other bucket",
			legacy:            2 * time.Second,
			discoveryJWKS:     3 * time.Second,
			wantDiscoveryJWKS: 3 * time.Second,
			wantTokenUserInfo: 2 * time.Second,
		},
		{
			name:              "partial dedicated value uses default for other bucket",
			tokenUserInfo:     4 * time.Second,
			wantDiscoveryJWKS: 5 * time.Second,
			wantTokenUserInfo: 4 * time.Second,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeOIDCServer(t)
			client, err := New(t.Context(), Config{
				IssuerURL:            fake.Server.URL,
				ClientID:             "client-1",
				SecretProvider:       StaticSecret("secret-1"),
				RedirectURL:          "https://app.example/callback",
				Scopes:               []string{"openid"},
				HTTPClient:           fake.Server.Client(),
				Timeout:              test.legacy,
				DiscoveryJWKSTimeout: test.discoveryJWKS,
				TokenUserInfoTimeout: test.tokenUserInfo,
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if client.discoveryJWKSTimeout != test.wantDiscoveryJWKS {
				t.Fatalf("discovery/JWKS timeout = %v, want %v", client.discoveryJWKSTimeout, test.wantDiscoveryJWKS)
			}
			if client.tokenUserInfoTimeout != test.wantTokenUserInfo {
				t.Fatalf("token/UserInfo timeout = %v, want %v", client.tokenUserInfoTimeout, test.wantTokenUserInfo)
			}
		})
	}
}

func TestNewRejectsNegativeTimeoutBucketsBeforeDiscovery(t *testing.T) {
	for _, test := range []Config{
		{Timeout: -time.Nanosecond},
		{DiscoveryJWKSTimeout: -time.Nanosecond},
		{TokenUserInfoTimeout: -time.Nanosecond},
	} {
		fake := newFakeOIDCServer(t)
		test.IssuerURL = fake.Server.URL
		test.ClientID = "client-1"
		test.SecretProvider = StaticSecret("secret-1")
		test.RedirectURL = "https://app.example/callback"
		test.Scopes = []string{"openid"}
		test.HTTPClient = fake.Server.Client()
		client, err := New(t.Context(), test)
		if err == nil || client != nil {
			t.Fatalf("New(%#v) = %#v, %v", test, client, err)
		}
		if fake.DiscoveryCalls.Load() != 0 {
			t.Fatalf("discovery calls = %d", fake.DiscoveryCalls.Load())
		}
	}
}

func TestIndependentTimeoutBucketsAreWiredToTheirOperations(t *testing.T) {
	const (
		discoveryJWKS = 2 * time.Minute
		tokenUserInfo = 4 * time.Minute
	)
	fake := newFakeOIDCServer(t)
	base := fake.Server.Client().Transport
	var mu sync.Mutex
	remaining := make(map[string]time.Duration)
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Errorf("%s request has no deadline", request.URL.Path)
		} else {
			mu.Lock()
			remaining[request.URL.Path] = time.Until(deadline)
			mu.Unlock()
		}
		return base.RoundTrip(request)
	})}
	client, err := New(t.Context(), Config{
		IssuerURL:            fake.Server.URL,
		ClientID:             "client-1",
		SecretProvider:       StaticSecret("secret-1"),
		RedirectURL:          "https://app.example/callback",
		Scopes:               []string{"openid"},
		HTTPClient:           httpClient,
		DiscoveryJWKSTimeout: discoveryJWKS,
		TokenUserInfoTimeout: tokenUserInfo,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.Exchange(t.Context(), "code-1"); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if _, err := client.UserInfo(t.Context(), "access-token"); err == nil {
		t.Fatal("UserInfo unexpectedly succeeded against missing test route")
	}
	if err := client.Logout(t.Context(), "access-token", "id-token"); err == nil {
		t.Fatal("Logout unexpectedly succeeded against missing test route")
	}
	if _, err := client.verifier.Verify(t.Context(), fake.signIDToken(t)); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/.well-known/openid-configuration", "/oidc/jwks"} {
		assertRemainingTimeout(t, path, remaining[path], discoveryJWKS)
	}
	for _, path := range []string{"/oidc/token", "/oidc/userinfo", "/oidc/logout"} {
		assertRemainingTimeout(t, path, remaining[path], tokenUserInfo)
	}
}

func assertRemainingTimeout(t *testing.T, path string, remaining, configured time.Duration) {
	t.Helper()
	const tolerance = 10 * time.Second
	if remaining < configured-tolerance || remaining > configured {
		t.Fatalf("%s remaining timeout = %v, want within %v of %v", path, remaining, tolerance, configured)
	}
}

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

func TestNewRejectsLoopbackHTTPEndpointForHTTPSIssuer(t *testing.T) {
	fake := newFakeOIDCServer(t)
	issuer := "https://issuer.example"
	fake.OverrideDiscoveryIssuer(issuer)
	fake.overrideDiscoveryEndpoint("authorization_endpoint", issuer+"/oidc/authorize")
	fake.overrideDiscoveryEndpoint("token_endpoint", fake.Server.URL+"/oidc/token")
	fake.overrideDiscoveryEndpoint("userinfo_endpoint", "https://userinfo.example/oidc/userinfo")
	fake.overrideDiscoveryEndpoint("jwks_uri", "https://keys.example/oidc/jwks")
	fake.overrideDiscoveryEndpoint("end_session_endpoint", "https://logout.example/oidc/logout")

	_, err := New(t.Context(), Config{
		IssuerURL:      issuer,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     routeIssuerToFakeServer(t, issuer, fake),
	})
	if err == nil {
		t.Fatal("expected HTTP loopback token endpoint rejection")
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindProtocol || typed.Cause != nil {
		t.Fatalf("error = %#v", err)
	}
	if fake.TokenCalls.Load() != 0 {
		t.Fatalf("token calls = %d", fake.TokenCalls.Load())
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

func TestRemoteKeySetOuterClientDoesNotFollowRedirect(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.setJWKSRedirect(fake.Server.URL + "/oidc/jwks-target")
	httpClient := fake.Server.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     httpClient,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, verifyErr := client.verifier.Verify(t.Context(), fake.signIDToken(t))
	if verifyErr == nil || fake.JWKSCalls.Load() != 1 || fake.JWKSTargetCalls.Load() != 0 {
		t.Fatalf(
			"verify error = %v, JWKS calls = %d, target calls = %d",
			verifyErr,
			fake.JWKSCalls.Load(),
			fake.JWKSTargetCalls.Load(),
		)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func routeIssuerToFakeServer(
	t *testing.T,
	issuer string,
	fake *fakeOIDCServer,
) *http.Client {
	t.Helper()
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		t.Fatalf("parse issuer URL: %v", err)
	}
	fakeURL, err := url.Parse(fake.Server.URL)
	if err != nil {
		t.Fatalf("parse fake server URL: %v", err)
	}
	baseTransport := fake.Server.Client().Transport
	return &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme != issuerURL.Scheme || request.URL.Host != issuerURL.Host {
			t.Fatalf("unexpected outbound URL: %s", request.URL.Redacted())
		}
		cloned := request.Clone(request.Context())
		rewrittenURL := *request.URL
		rewrittenURL.Scheme = fakeURL.Scheme
		rewrittenURL.Host = fakeURL.Host
		cloned.URL = &rewrittenURL
		return baseTransport.RoundTrip(cloned)
	})}
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
