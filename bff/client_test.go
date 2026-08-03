package bff

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestDefaultScopesAreExactAndDefensive(t *testing.T) {
	want := []string{"openid", "profile", "email", "groups"}
	first := DefaultScopes()
	if !slices.Equal(first, want) || slices.Contains(first, "roles") {
		t.Fatalf("DefaultScopes() = %v", first)
	}
	first[0] = "mutated"
	if got := DefaultScopes(); !slices.Equal(got, want) {
		t.Fatalf("DefaultScopes() after mutation = %v", got)
	}
}

type typedNilSecretProvider struct{}

func (*typedNilSecretProvider) Secret(context.Context) (string, error) { return "", nil }

func TestNewRejectsInvalidBFFConfiguration(t *testing.T) {
	tests := map[string]func(*Config){
		"missing core":                func(config *Config) { config.Core = nil },
		"missing client id":           func(config *Config) { config.ClientID = "" },
		"unaccepted client id":        func(config *Config) { config.ClientID = "different" },
		"missing secret provider":     func(config *Config) { config.ClientSecret = nil },
		"typed nil secret provider":   func(config *Config) { config.ClientSecret = (*typedNilSecretProvider)(nil) },
		"missing backend":             func(config *Config) { config.Backend = nil },
		"redirect whitespace":         func(config *Config) { config.RedirectURL = " " + config.RedirectURL },
		"redirect query":              func(config *Config) { config.RedirectURL += "?secret=value" },
		"redirect fragment":           func(config *Config) { config.RedirectURL += "#fragment" },
		"redirect user info":          func(config *Config) { config.RedirectURL = "https://user@example.test/callback" },
		"non-loopback http redirect":  func(config *Config) { config.RedirectURL = "http://example.test/callback" },
		"missing openid":              func(config *Config) { config.Scopes = []string{"profile"} },
		"roles scope":                 func(config *Config) { config.Scopes = []string{"openid", "roles"} },
		"duplicate scope":             func(config *Config) { config.Scopes = []string{"openid", "openid"} },
		"whitespace scope":            func(config *Config) { config.Scopes = []string{"openid", " profile"} },
		"missing session cookie name": func(config *Config) { config.SessionCookie.Name = "" },
		"same cookie names":           func(config *Config) { config.FlowCookie.Name = config.SessionCookie.Name },
		"cookie domain":               func(config *Config) { config.FlowCookie.Domain = "example.test" },
		"cookie path":                 func(config *Config) { config.FlowCookie.Path = "/auth" },
		"cookie not httponly":         func(config *Config) { config.FlowCookie.HttpOnly = false },
		"cookie wrong samesite":       func(config *Config) { config.FlowCookie.SameSite = http.SameSiteNoneMode },
		"cookie configured value":     func(config *Config) { config.FlowCookie.Value = "secret" },
		"cookie max age":              func(config *Config) { config.FlowCookie.MaxAge = 60 },
		"cookie expiry":               func(config *Config) { config.FlowCookie.Expires = time.Unix(1_900_000_000, 0) },
		"partitioned cookie":          func(config *Config) { config.FlowCookie.Partitioned = true },
		"negative flow ttl":           func(config *Config) { config.FlowTTL = -time.Second },
		"negative absolute ttl":       func(config *Config) { config.SessionAbsoluteTTL = -time.Second },
		"negative idle ttl":           func(config *Config) { config.SessionIdleTTL = -time.Second },
		"negative refresh window":     func(config *Config) { config.RefreshBeforeExpiry = -time.Second },
		"negative refresh lease":      func(config *Config) { config.RefreshLeaseTTL = -time.Second },
		"duplicate allowed return": func(config *Config) {
			config.AllowedReturnToURLs = []string{"https://app.example.test/done", "https://app.example.test/done"}
		},
		"unsafe allowed return": func(config *Config) { config.AllowedReturnToURLs = []string{"https://user@example.test/"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config, _, _ := newBFFTestConfig(t)
			mutate(&config)
			_, err := New(config)
			var typed *core.Error
			if !errors.As(err, &typed) || typed.Kind != core.KindInvalidConfig || typed.Operation != "bff.configure" {
				t.Fatalf("New() error = %#v", err)
			}
		})
	}
}

func TestNewValidatesRFC6749ScopeTokenSyntax(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		valid bool
	}{
		{name: "valid punctuation", scope: "api:read/write~!#$%&'()*+,-.;<=>?@[]^_`{|}", valid: true},
		{name: "space", scope: "api read"},
		{name: "tab", scope: "api\tread"},
		{name: "control", scope: "api\x1fread"},
		{name: "delete", scope: "api\x7fread"},
		{name: "quote", scope: `api"read`},
		{name: "backslash", scope: `api\read`},
		{name: "non ascii", scope: "api-é"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, _, _ := newBFFTestConfig(t)
			config.Scopes = []string{"openid", test.scope}
			_, err := New(config)
			if test.valid && err != nil {
				t.Fatalf("valid RFC 6749 scope token was rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid RFC 6749 scope token was accepted")
			}
		})
	}
}

func TestNewRequiresHostSecureProductionCookies(t *testing.T) {
	config, _, _ := newBFFTestConfig(t)
	config.RedirectURL = "https://app.example.test/callback"
	config.AllowInsecureLoopbackCookies = false
	if _, err := New(config); err == nil {
		t.Fatal("New() accepted insecure production cookies")
	}
	config.SessionCookie = productionCookie("__Host-app_session")
	config.FlowCookie = productionCookie("__Host-app_flow")
	if _, err := New(config); err != nil {
		t.Fatalf("New() rejected hardened production cookies: %v", err)
	}
	config.FlowCookie.Name = "app_flow"
	if _, err := New(config); err == nil {
		t.Fatal("New() accepted Secure production cookie without __Host- prefix")
	}
}

func productionCookie(name string) http.Cookie {
	return http.Cookie{Name: name, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func TestNewRejectsDiscoveryWithoutS256(t *testing.T) {
	// Core owns Discovery validation; the BFF can never be built around metadata
	// that did not advertise S256.
	plainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		base := "http://" + request.Host
		_, _ = w.Write([]byte(`{"issuer":"` + base + `","authorization_endpoint":"` + base + `/authorize","token_endpoint":"` + base + `/token","userinfo_endpoint":"` + base + `/userinfo","jwks_uri":"` + base + `/jwks","end_session_endpoint":"` + base + `/logout","code_challenge_methods_supported":["plain"],"id_token_signing_alg_values_supported":["RS256"]}`))
	}))
	defer plainServer.Close()
	_, err := core.New(t.Context(), core.Config{IssuerURL: plainServer.URL, Audiences: []string{testClientID}, HTTPClient: plainServer.Client()})
	var typed *core.Error
	if !errors.As(err, &typed) || typed.Kind != core.KindProtocol {
		t.Fatalf("core.New() error = %#v", err)
	}
}

func TestNewClonesInjectedHTTPClientAndConfiguredSlices(t *testing.T) {
	config, _, issuer := newBFFTestConfig(t)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	injected := issuer.Server.Client()
	injected.Jar = jar
	originalRedirect := func(*http.Request, []*http.Request) error { return nil }
	injected.CheckRedirect = originalRedirect
	scopes := []string{"openid", "groups"}
	allowed := []string{"https://app.example.test/done"}
	config.HTTPClient, config.Scopes, config.AllowedReturnToURLs = injected, scopes, allowed
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	scopes[0], allowed[0] = "mutated", "https://evil.example/"
	if !slices.Equal(client.scopes, []string{"openid", "groups"}) || client.validReturnTo("https://evil.example/") {
		t.Fatal("Client retained caller-owned configuration slices")
	}
	if injected.Jar != jar || injected.CheckRedirect == nil {
		t.Fatal("New mutated injected HTTP client")
	}
	if client.httpClient == injected || client.httpClient.Jar != nil {
		t.Fatal("Client did not isolate injected HTTP state")
	}
}

func TestSecretProviderFailureIsSanitized(t *testing.T) {
	config, _, issuer := newBFFTestConfig(t)
	secret := "provider-error-sensitive"
	config.ClientSecret = SecretProviderFunc(func(context.Context) (string, error) { return "", errors.New(secret) })
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	attempt := beginLogin(t, client, issuer, "/")
	response := serveCallback(t, client, attempt, "code="+testCode+"&state="+attempt.State)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), secret) || issuer.TokenCalls.Load() != 0 {
		t.Fatalf("secret-provider failure was not sanitized before response: status=%d calls=%d", response.Code, issuer.TokenCalls.Load())
	}
}
