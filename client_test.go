package iamcore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/authn"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/authz"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/middleware"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/memory"
)

type rootTestIAM struct {
	server *httptest.Server

	discoveryIssuer string
	userInfoStatus  int
	decisionStatus  int
	decisionAllowed bool

	discoveryCalls atomic.Int32
	userInfoCalls  atomic.Int32
	decisionCalls  atomic.Int32

	mu                    sync.Mutex
	lastUserInfoHeaders   http.Header
	lastDecisionHeaders   http.Header
	lastDecisionBody      map[string]string
	lastDecisionAuth      string
	requireInjectedClient bool
}

func newRootTestIAM(t *testing.T) *rootTestIAM {
	t.Helper()
	fake := &rootTestIAM{
		userInfoStatus:        http.StatusOK,
		decisionStatus:        http.StatusOK,
		decisionAllowed:       true,
		requireInjectedClient: true,
	}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	t.Cleanup(fake.server.Close)
	fake.discoveryIssuer = fake.server.URL
	return fake
}

func (f *rootTestIAM) serveHTTP(w http.ResponseWriter, request *http.Request) {
	if f.requireInjectedClient && request.Header.Get("X-Root-Test-Client") != "shared" {
		http.Error(w, "missing injected client", http.StatusBadGateway)
		return
	}
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		f.discoveryCalls.Add(1)
		issuer := f.discoveryIssuer
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/oidc/authorize",
			"token_endpoint":         issuer + "/oidc/token",
			"userinfo_endpoint":      issuer + "/oidc/userinfo",
			"jwks_uri":               issuer + "/oidc/jwks",
			"end_session_endpoint":   issuer + "/oidc/logout",
			"scopes_supported":       []string{"openid", "profile", "email", "roles"},
		})
	case "/oidc/userinfo":
		f.userInfoCalls.Add(1)
		f.mu.Lock()
		f.lastUserInfoHeaders = request.Header.Clone()
		status := f.userInfoStatus
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = io.WriteString(w, `{
				"sub":"op_usr_0123456789abcdefgjk",
				"username":"jane",
				"roles":["viewer"],
				"tenant":{"id":"tenant-1"}
			}`)
		} else {
			_, _ = io.WriteString(w, `{"message":"hostile-userinfo-secret"}`)
		}
	case "/authorization/v1/decisions":
		f.decisionCalls.Add(1)
		var body map[string]string
		_ = json.NewDecoder(request.Body).Decode(&body)
		f.mu.Lock()
		f.lastDecisionHeaders = request.Header.Clone()
		f.lastDecisionBody = body
		f.lastDecisionAuth = request.Header.Get("Authorization")
		status := f.decisionStatus
		allowed := f.decisionAllowed
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision_id": "dec-root-1",
				"allowed":     allowed,
				"reason_code": map[bool]string{true: "allowed", false: "denied"}[allowed],
				"request_id":  "req-root-1",
				"trace_id":    "trace-root-1",
			})
		} else {
			_, _ = io.WriteString(w, `{"message":"hostile-decision-secret"}`)
		}
	default:
		http.NotFound(w, request)
	}
}

func (f *rootTestIAM) httpClient() *http.Client {
	base := f.server.Client().Transport
	return &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		cloned := request.Clone(request.Context())
		cloned.Header = request.Header.Clone()
		cloned.Header.Set("X-Root-Test-Client", "shared")
		return base.RoundTrip(cloned)
	})}
}

func (f *rootTestIAM) decisionSnapshot() (http.Header, map[string]string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body := make(map[string]string, len(f.lastDecisionBody))
	for key, value := range f.lastDecisionBody {
		body[key] = value
	}
	return f.lastDecisionHeaders.Clone(), body, f.lastDecisionAuth
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func validRootConfig(fake *rootTestIAM) Config {
	return Config{
		IssuerURL:            fake.server.URL,
		ClientID:             "client-1",
		ClientSecretProvider: StaticSecret("client-secret"),
		RedirectURL:          fake.server.URL + "/callback",
		HTTPClient:           fake.httpClient(),
		Session: SessionConfig{
			Backend: memory.New(memory.Options{}),
		},
	}
}

type typedNilSecretProvider struct{}

func (*typedNilSecretProvider) Secret(context.Context) (string, error) {
	return "must-not-be-called", nil
}

func TestNewRejectsRequiredOmissionsTypedNilsAndInvalidTimeoutsBeforeDiscovery(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"nil context", func(*Config) {}},
		{"missing issuer", func(config *Config) { config.IssuerURL = "" }},
		{"missing client", func(config *Config) { config.ClientID = "" }},
		{"missing secret provider", func(config *Config) { config.ClientSecretProvider = nil }},
		{"typed nil secret provider", func(config *Config) {
			var provider *typedNilSecretProvider
			config.ClientSecretProvider = provider
		}},
		{"missing redirect", func(config *Config) { config.RedirectURL = "" }},
		{"missing backend", func(config *Config) { config.Session.Backend = nil }},
		{"typed nil backend", func(config *Config) {
			var backend *memory.Backend
			config.Session.Backend = backend
		}},
		{"scope without openid", func(config *Config) { config.Scopes = []string{"profile"} }},
		{"negative discovery timeout", func(config *Config) { config.Timeouts.DiscoveryJWKS = -1 }},
		{"negative token timeout", func(config *Config) { config.Timeouts.TokenUserInfo = -1 }},
		{"negative PDP timeout", func(config *Config) { config.Timeouts.PDP = -1 }},
		{"negative refresh timeout", func(config *Config) { config.Timeouts.RefreshLock = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newRootTestIAM(t)
			config := validRootConfig(fake)
			test.mutate(&config)
			ctx := t.Context()
			if test.name == "nil context" {
				ctx = nil
			}
			client, err := New(ctx, config)
			if err == nil || client != nil {
				t.Fatalf("New() = %#v, %v", client, err)
			}
			typed, ok := err.(*sdkerr.Error)
			if !ok || typed.Kind != sdkerr.KindInvalidConfig || typed.Cause != nil {
				t.Fatalf("error = %#v", err)
			}
			if fake.discoveryCalls.Load() != 0 {
				t.Fatalf("discovery calls = %d", fake.discoveryCalls.Load())
			}
		})
	}
}

func TestNewUsesDocumentedTimeoutAndScopeDefaults(t *testing.T) {
	fake := newRootTestIAM(t)
	client, err := New(t.Context(), validRootConfig(fake))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	wantTimeouts := TimeoutConfig{
		DiscoveryJWKS: 5 * time.Second,
		TokenUserInfo: 10 * time.Second,
		PDP:           3 * time.Second,
		RefreshLock:   15 * time.Second,
	}
	if client.timeouts != wantTimeouts {
		t.Fatalf("timeouts = %#v, want %#v", client.timeouts, wantTimeouts)
	}
	login := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2F", nil)
	client.LoginHandler().ServeHTTP(login, request)
	if login.Code != http.StatusFound {
		t.Fatalf("login status = %d body=%s", login.Code, login.Body.String())
	}
	location, err := url.Parse(login.Header().Get("Location"))
	if err != nil || location.Query().Get("scope") != "openid profile email roles" {
		t.Fatalf("login location = %q error=%v", login.Header().Get("Location"), err)
	}
}

func TestNewUsesExplicitTimeouts(t *testing.T) {
	fake := newRootTestIAM(t)
	config := validRootConfig(fake)
	config.Timeouts = TimeoutConfig{
		DiscoveryJWKS: 2 * time.Second,
		TokenUserInfo: 4 * time.Second,
		PDP:           6 * time.Second,
		RefreshLock:   8 * time.Second,
	}
	client, err := New(t.Context(), config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client.timeouts != config.Timeouts {
		t.Fatalf("timeouts = %#v, want %#v", client.timeouts, config.Timeouts)
	}
}

func TestNewRejectsDiscoveryIssuerMismatchWithoutLeakingIt(t *testing.T) {
	fake := newRootTestIAM(t)
	fake.discoveryIssuer = "https://different.example/path?client_secret=discovery-secret"
	client, err := New(t.Context(), validRootConfig(fake))
	if err == nil || client != nil {
		t.Fatalf("New() = %#v, %v", client, err)
	}
	if strings.Contains(err.Error(), "discovery-secret") ||
		strings.Contains(err.Error(), "different.example") {
		t.Fatalf("issuer mismatch leaked: %v", err)
	}
}

func TestNewRejectsInsecureNonLoopbackCookies(t *testing.T) {
	fake := newRootTestIAM(t)
	config := validRootConfig(fake)
	config.RedirectURL = "http://app.example/callback"
	config.Session.AllowInsecureLocalCookie = true
	config.Session.SessionCookie = insecureCookie("iam_session")
	config.Session.FlowCookie = insecureCookie("iam_flow")
	client, err := New(t.Context(), config)
	if err == nil || client != nil {
		t.Fatalf("New() = %#v, %v", client, err)
	}
}

func TestNewAcceptsExplicitInsecureLoopbackCookiesAndRetainsProductionDefaults(t *testing.T) {
	t.Run("explicit loopback development cookies", func(t *testing.T) {
		fake := newRootTestIAM(t)
		config := validRootConfig(fake)
		config.Session.AllowInsecureLocalCookie = true
		config.Session.SessionCookie = insecureCookie("iam_session")
		config.Session.FlowCookie = insecureCookie("iam_flow")
		client, err := New(t.Context(), config)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		response := httptest.NewRecorder()
		client.LoginHandler().ServeHTTP(
			response,
			httptest.NewRequest(http.MethodGet, fake.server.URL+"/auth/login?return_to=%2F", nil),
		)
		cookie := response.Header().Get("Set-Cookie")
		if response.Code != http.StatusFound || !strings.HasPrefix(cookie, "iam_flow=") ||
			strings.Contains(cookie, "Secure") {
			t.Fatalf("status=%d cookie=%q", response.Code, cookie)
		}
	})

	t.Run("production defaults", func(t *testing.T) {
		fake := newRootTestIAM(t)
		client, err := New(t.Context(), validRootConfig(fake))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		response := httptest.NewRecorder()
		client.LoginHandler().ServeHTTP(
			response,
			httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2F", nil),
		)
		cookie := response.Header().Get("Set-Cookie")
		for _, expected := range []string{"__Host-iam_core_flow=", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
			if !strings.Contains(cookie, expected) {
				t.Fatalf("cookie %q missing %q", cookie, expected)
			}
		}
	})
}

func insecureCookie(name string) http.Cookie {
	return http.Cookie{
		Name:     name,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func TestClientComposesAccessorsHandlersAndMiddlewareWithSharedHTTPClient(t *testing.T) {
	fake := newRootTestIAM(t)
	client, err := New(t.Context(), validRootConfig(fake))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client.OIDC() == nil || client.Authorization() == nil ||
		client.LoginHandler() == nil || client.CallbackHandler() == nil ||
		client.LogoutHandler() == nil {
		t.Fatal("root accessors or handlers returned nil")
	}

	authenticateRequest := httptest.NewRequest(http.MethodGet, "/profile", nil)
	authenticateRequest.Header.Set("Authorization", "Bearer bearer-root-secret")
	authenticateRequest.Header.Set("Traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
	authenticateRequest.Header.Set("Tracestate", "vendor=value")
	authenticateRequest.Header.Set("X-Request-ID", "req-incoming")
	authenticateRequest.Header.Set("Cookie", "untrusted-cookie=secret")
	authenticateResponse := httptest.NewRecorder()
	client.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		identity, identityOK := IdentityFromContext(request.Context())
		source, sourceOK := CredentialSourceFromContext(request.Context())
		if !identityOK || !sourceOK || identity.Subject != "op_usr_0123456789abcdefgjk" ||
			source != CredentialSource(authn.CredentialBearer) {
			t.Fatalf("identity=%#v source=%q identityOK=%v sourceOK=%v", identity, source, identityOK, sourceOK)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(authenticateResponse, authenticateRequest)
	if authenticateResponse.Code != http.StatusNoContent {
		t.Fatalf("authenticate status=%d body=%s", authenticateResponse.Code, authenticateResponse.Body.String())
	}

	requireRequest := httptest.NewRequest(http.MethodPatch, "/assets", nil)
	requireRequest.Header.Set("Authorization", "Bearer bearer-root-secret")
	requireRequest.Header.Set("Traceparent", authenticateRequest.Header.Get("Traceparent"))
	requireRequest.Header.Set("Tracestate", "vendor=value")
	requireRequest.Header.Set("X-Request-ID", "req-incoming")
	requireRequest.Header.Set("Cookie", "untrusted-cookie=secret")
	requireResponse := httptest.NewRecorder()
	client.RequirePermission(Permission{
		ResourceServer: "asset-api",
		Resource:       "assets",
		HTTPMethod:     http.MethodDelete,
	})(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		decision, ok := DecisionFromContext(request.Context())
		if !ok || decision.ID != "dec-root-1" || !decision.Allowed {
			t.Fatalf("decision = %#v ok=%v", decision, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(requireResponse, requireRequest)
	if requireResponse.Code != http.StatusNoContent ||
		requireResponse.Header().Get("X-IAM-Decision-ID") != "dec-root-1" {
		t.Fatalf("require status=%d headers=%#v body=%s", requireResponse.Code, requireResponse.Header(), requireResponse.Body.String())
	}

	decisionHeaders, body, authorization := fake.decisionSnapshot()
	if authorization != "Bearer bearer-root-secret" ||
		body["resource_server"] != "asset-api" || body["resource"] != "assets" ||
		body["http_method"] != http.MethodPatch {
		t.Fatalf("authorization=%q body=%#v", authorization, body)
	}
	for _, headers := range []http.Header{fake.lastUserInfoHeaders, decisionHeaders} {
		if headers.Get("X-Root-Test-Client") != "shared" ||
			headers.Get("Traceparent") == "" || headers.Get("Tracestate") != "vendor=value" ||
			headers.Get("X-Request-ID") != "req-incoming" {
			t.Fatalf("outgoing headers = %#v", headers)
		}
		if headers.Get("Cookie") != "" {
			t.Fatalf("outgoing Cookie = %q", headers.Get("Cookie"))
		}
	}
	if fake.discoveryCalls.Load() != 1 || fake.userInfoCalls.Load() != 2 ||
		fake.decisionCalls.Load() != 1 {
		t.Fatalf(
			"calls discovery=%d userinfo=%d decision=%d",
			fake.discoveryCalls.Load(),
			fake.userInfoCalls.Load(),
			fake.decisionCalls.Load(),
		)
	}
}

func TestClientAppliesCustomResponderToBothMiddleware(t *testing.T) {
	fake := newRootTestIAM(t)
	config := validRootConfig(fake)
	var calls atomic.Int32
	config.ErrorResponder = middleware.ErrorResponderFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
		_ error,
	) {
		calls.Add(1)
		w.WriteHeader(http.StatusTeapot)
	})
	client, err := New(t.Context(), config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, handler := range []http.Handler{
		client.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("Authenticate reached next")
		})),
		client.RequirePermission(Permission{ResourceServer: "assets", Resource: "assets"})(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("RequirePermission reached next")
			}),
		),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != http.StatusTeapot {
			t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("custom responder calls = %d", calls.Load())
	}
}

func TestClientDefaultLoggerIsSilentAndCustomLoggerDoesNotLeakSecrets(t *testing.T) {
	t.Run("default logger", func(t *testing.T) {
		fake := newRootTestIAM(t)
		client, err := New(t.Context(), validRootConfig(fake))
		if err != nil || client == nil {
			t.Fatalf("New() = %#v, %v", client, err)
		}
	})

	t.Run("custom logger redaction", func(t *testing.T) {
		const (
			token     = "submitted-access-token"
			secret    = "configured-client-secret"
			code      = "submitted-authorization-code"
			sessionID = "submitted-session-id"
		)
		fake := newRootTestIAM(t)
		fake.userInfoStatus = http.StatusUnauthorized
		config := validRootConfig(fake)
		config.ClientSecretProvider = StaticSecret(secret)
		var logs bytes.Buffer
		config.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
		client, err := New(t.Context(), config)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		authRequest := httptest.NewRequest(http.MethodGet, "/", nil)
		authRequest.Header.Set("Authorization", "Bearer "+token)
		client.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
			ServeHTTP(httptest.NewRecorder(), authRequest)

		callbackRequest := httptest.NewRequest(
			http.MethodGet,
			"/callback?state=state-secret&code="+code,
			nil,
		)
		client.CallbackHandler().ServeHTTP(httptest.NewRecorder(), callbackRequest)

		logoutRequest := httptest.NewRequest(http.MethodPost, "/logout", nil)
		logoutRequest.AddCookie(&http.Cookie{Name: "__Host-iam_core_session", Value: sessionID})
		client.LogoutHandler().ServeHTTP(httptest.NewRecorder(), logoutRequest)

		for _, value := range []string{token, secret, code, sessionID, "hostile-userinfo-secret"} {
			if strings.Contains(logs.String(), value) {
				t.Fatalf("logs leaked %q: %s", value, logs.String())
			}
		}
	})
}

func TestNewNormalizesTypedNilHooksAndResponder(t *testing.T) {
	fake := newRootTestIAM(t)
	config := validRootConfig(fake)
	var hooks *rootRecordingHooks
	var responder *rootNilResponder
	config.Hooks = hooks
	config.ErrorResponder = responder
	client, err := New(t.Context(), config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	response := httptest.NewRecorder()
	client.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

type rootRecordingHooks struct{}

func (*rootRecordingHooks) Observe(context.Context, observability.Event) {}

type rootNilResponder struct{}

func (*rootNilResponder) Respond(http.ResponseWriter, *http.Request, error) {}

func TestRootAliasesAndContextHelpersDelegate(t *testing.T) {
	var _ Identity = oidc.Identity{}
	var _ Permission = authz.Permission{}
	var _ Decision = authz.Decision{}
	var _ CredentialSource = authn.CredentialSource("")

	authenticator := &rootFakeAuthenticator{credential: authn.Credential{
		Source:      authn.CredentialBearer,
		AccessToken: "token",
		Identity: oidc.Identity{
			Subject: "subject",
			Roles:   []string{"viewer"},
		},
	}}
	authorizer := &rootFakeAuthorizer{decision: authz.Decision{
		ID: "decision", Allowed: true, ReasonCode: "allowed",
	}}
	handler := middleware.RequirePermission(
		authenticator,
		authorizer,
		authz.Permission{ResourceServer: "assets", Resource: "assets"},
	)(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		identity, identityOK := IdentityFromContext(request.Context())
		source, sourceOK := CredentialSourceFromContext(request.Context())
		decision, decisionOK := DecisionFromContext(request.Context())
		if !identityOK || !sourceOK || !decisionOK ||
			identity.Subject != "subject" || source != CredentialSource(authn.CredentialBearer) ||
			decision.ID != "decision" {
			t.Fatalf("identity=%#v source=%q decision=%#v", identity, source, decision)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

type rootFakeAuthenticator struct {
	credential authn.Credential
}

func (f *rootFakeAuthenticator) Authenticate(*http.Request) (authn.Credential, error) {
	return f.credential, nil
}

func (*rootFakeAuthenticator) ForceRefresh(context.Context, string) (*session.Session, error) {
	return nil, nil
}

type rootFakeAuthorizer struct {
	decision authz.Decision
}

func (f *rootFakeAuthorizer) Decide(context.Context, string, authz.Permission) (authz.Decision, error) {
	return f.decision, nil
}
