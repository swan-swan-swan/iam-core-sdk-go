package httpauthz_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz"
)

func TestRequirePermissionCallCounts(t *testing.T) {
	tests := []struct {
		name                             string
		decision                         httpauthz.Decision
		pdpErr                           error
		wantStatus, wantPDP, wantHandler int
	}{
		{name: "allow", decision: httpauthz.Decision{ID: "d1", Allowed: true, ReasonCode: "policy_allow"}, wantStatus: http.StatusOK, wantPDP: 1, wantHandler: 1},
		{name: "deny", decision: httpauthz.Decision{ID: "d2", Allowed: false, ReasonCode: "default_deny"}, wantStatus: http.StatusForbidden, wantPDP: 1},
		{name: "unauthorized", pdpErr: core.NewError(core.KindUnauthenticated, "httpauthz.decide", 401, false, nil), wantStatus: http.StatusUnauthorized, wantPDP: 1},
		{name: "unavailable", pdpErr: core.NewError(core.KindIAMUnavailable, "httpauthz.decide", 503, true, nil), wantStatus: http.StatusServiceUnavailable, wantPDP: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := &fakeVerifier{auth: validAuth()}
			pdp := &fakeAuthorizer{decision: test.decision, err: test.pdpErr}
			service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: pdp})
			if err != nil {
				t.Fatal(err)
			}
			var handlerCalls int
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlerCalls++
				w.WriteHeader(http.StatusOK)
			})
			request := httptest.NewRequest(http.MethodGet, "/orders", nil)
			request.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			handler, err := service.Require(boundRoute(t), next)
			if err != nil {
				t.Fatal(err)
			}
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || verifier.calls != 1 || pdp.calls != test.wantPDP || handlerCalls != test.wantHandler {
				t.Fatalf("status/verifier/pdp/handler=%d/%d/%d/%d", response.Code, verifier.calls, pdp.calls, handlerCalls)
			}
		})
	}
}

func TestCookieAndBearerAlwaysConflict(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/orders", nil)
	request.Header.Set("Authorization", "Bearer same-token")
	request.Header.Set("Cookie", "session=cookie-secret")
	resolver := &fakeSessionResolver{present: true, resolvePresent: true, credential: credentialWithToken("same-token")}
	verifier := &fakeVerifier{auth: validAuth()}
	pdp := &fakeAuthorizer{decision: httpauthz.Decision{ID: "d1", Allowed: true, ReasonCode: "policy_allow"}}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: pdp, Sessions: resolver})
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls int
	handler, err := service.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handlerCalls++ }))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || resolver.presentCalls != 1 || resolver.resolveCalls != 0 || verifier.calls != 0 || pdp.calls != 0 || handlerCalls != 0 {
		t.Fatalf("status/present/resolve/verifier/pdp/handler=%d/%d/%d/%d/%d/%d", response.Code, resolver.presentCalls, resolver.resolveCalls, verifier.calls, pdp.calls, handlerCalls)
	}
}

func TestAuthorizationPresenceConflictsBeforeMalformedHeaderParsing(t *testing.T) {
	resolver := &fakeSessionResolver{present: true}
	verifier := &fakeVerifier{auth: validAuth()}
	pdp := &fakeAuthorizer{}
	var gotKind core.Kind
	service, err := httpauthz.New(httpauthz.Config{
		Verifier: verifier, PDP: pdp, Sessions: resolver,
		Responder: httpauthz.ErrorResponderFunc(func(w http.ResponseWriter, _ *http.Request, err error) {
			var typed *core.Error
			if errors.As(err, &typed) && typed != nil {
				gotKind = typed.Kind
			}
			w.WriteHeader(http.StatusUnauthorized)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := service.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler called") }))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header["Authorization"] = []string{"not bearer", "Bearer second"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if gotKind != core.KindCredentialConflict || resolver.presentCalls != 1 || resolver.resolveCalls != 0 || verifier.calls != 0 {
		t.Fatalf("kind/present/resolve/verifier=%q/%d/%d/%d", gotKind, resolver.presentCalls, resolver.resolveCalls, verifier.calls)
	}
}

func TestAuthenticateBearerOnlyInjectsDefensiveAuthAndSource(t *testing.T) {
	verifier := &fakeVerifier{auth: validAuth()}
	resolver := &fakeSessionResolver{}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: &fakeAuthorizer{}, Sessions: resolver})
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls int
	handler, err := service.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		handlerCalls++
		auth, authOK := core.AuthContextFromContext(request.Context())
		source, sourceOK := httpauthz.CredentialSourceFromContext(request.Context())
		if !authOK || !sourceOK || source != core.CredentialBearer || auth.Subject != "op_usr_1" {
			t.Fatalf("context auth/source = redacted/%q/%v/%v", source, authOK, sourceOK)
		}
		if _, ok := httpauthz.DecisionFromContext(request.Context()); ok {
			t.Fatal("Authenticate injected a decision")
		}
		auth.Audience[0], auth.Scopes[0], auth.Groups[0] = "mutated", "mutated", "mutated"
		again, _ := core.AuthContextFromContext(request.Context())
		if again.Audience[0] != "portal" || again.Scopes[0] != "openid" || again.Groups[0] != "ops" {
			t.Fatal("context AuthContext was mutable")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer bearer-secret")
	request.Header.Set("Cookie", "session=cookie-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || handlerCalls != 1 || verifier.calls != 1 || verifier.rawToken != "bearer-secret" || resolver.presentCalls != 1 || resolver.resolveCalls != 0 {
		t.Fatalf("status/handler/verifier/present/resolve=%d/%d/%d/%d/%d", response.Code, handlerCalls, verifier.calls, resolver.presentCalls, resolver.resolveCalls)
	}
	if verifier.auth.Audience[0] != "portal" || verifier.auth.Scopes[0] != "openid" || verifier.auth.Groups[0] != "ops" {
		t.Fatal("middleware mutated verifier AuthContext")
	}
}

func TestAuthenticateSessionOnlyResolvesOnceWithoutVerifyingOrLoadingToken(t *testing.T) {
	var tokenCalls int
	credential := credentialWithToken("session-secret")
	credential.Tokens = core.TokenSourceFunc(func(context.Context) (string, error) { tokenCalls++; return "session-secret", nil })
	resolver := &fakeSessionResolver{present: true, resolvePresent: true, credential: credential}
	verifier := &fakeVerifier{auth: validAuth()}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: &fakeAuthorizer{}, Sessions: resolver})
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls int
	handler, err := service.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		handlerCalls++
		source, ok := httpauthz.CredentialSourceFromContext(request.Context())
		if !ok || source != core.CredentialSession {
			t.Fatalf("source = %q, %v", source, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNoContent || resolver.presentCalls != 1 || resolver.resolveCalls != 1 || verifier.calls != 0 || tokenCalls != 0 || handlerCalls != 1 {
		t.Fatalf("status/present/resolve/verifier/token/handler=%d/%d/%d/%d/%d/%d", response.Code, resolver.presentCalls, resolver.resolveCalls, verifier.calls, tokenCalls, handlerCalls)
	}
}

func TestAuthenticateRejectsMissingAndMalformedCredentialsBeforeVerification(t *testing.T) {
	tests := []struct {
		name   string
		header []string
	}{
		{name: "missing"},
		{name: "empty", header: []string{""}},
		{name: "multiple", header: []string{"Bearer one", "Bearer two"}},
		{name: "wrong scheme", header: []string{"Basic secret"}},
		{name: "wrong casing", header: []string{"bearer secret"}},
		{name: "comma", header: []string{"Bearer one,two"}},
		{name: "whitespace", header: []string{"Bearer two words"}},
		{name: "control", header: []string{"Bearer tok\nen"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeSessionResolver{}
			verifier := &fakeVerifier{auth: validAuth()}
			service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: &fakeAuthorizer{}, Sessions: resolver})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := service.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler called") }))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.header != nil {
				request.Header["Authorization"] = append([]string(nil), test.header...)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || resolver.presentCalls != 1 || resolver.resolveCalls != 0 || verifier.calls != 0 {
				t.Fatalf("status/present/resolve/verifier=%d/%d/%d/%d", response.Code, resolver.presentCalls, resolver.resolveCalls, verifier.calls)
			}
		})
	}
}

func TestSessionPresentErrorFailsClosedBeforeAllOtherWork(t *testing.T) {
	resolver := &fakeSessionResolver{presentErr: errors.New("cookie-secret-error")}
	verifier := &fakeVerifier{auth: validAuth()}
	pdp := &fakeAuthorizer{decision: httpauthz.Decision{ID: "d1", Allowed: true, ReasonCode: "policy_allow"}}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: pdp, Sessions: resolver})
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls int
	handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handlerCalls++ }))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer bearer-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || resolver.presentCalls != 1 || resolver.resolveCalls != 0 || verifier.calls != 0 || pdp.calls != 0 || handlerCalls != 0 {
		t.Fatalf("status/present/resolve/verifier/pdp/handler=%d/%d/%d/%d/%d/%d", response.Code, resolver.presentCalls, resolver.resolveCalls, verifier.calls, pdp.calls, handlerCalls)
	}
	if strings.Contains(response.Body.String(), "cookie-secret-error") || strings.Contains(response.Body.String(), "bearer-secret") || strings.Contains(response.Body.String(), "cookie-secret") {
		t.Fatal("error response disclosed credential material")
	}
}

func TestAuthenticateMapsVerifierFailureAndRejectsInvalidVerifiedAuth(t *testing.T) {
	tests := []struct {
		name       string
		auth       core.AuthContext
		err        error
		wantStatus int
	}{
		{name: "local JWT failure", err: core.NewError(core.KindUnauthenticated, "core.verify secret", 0, false, errors.New("jwt-secret")), wantStatus: http.StatusUnauthorized},
		{name: "JWKS unavailable", err: core.NewError(core.KindIAMUnavailable, "core.verify", 0, true, nil), wantStatus: http.StatusServiceUnavailable},
		{name: "blank subject", auth: core.AuthContext{Subject: "  "}, wantStatus: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := &fakeVerifier{auth: test.auth, err: test.err}
			service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: &fakeAuthorizer{}})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := service.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler called") }))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", "Bearer sensitive-token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || verifier.calls != 1 || strings.Contains(response.Body.String(), "sensitive-token") || strings.Contains(response.Body.String(), "jwt-secret") {
				t.Fatalf("status/verifier=%d/%d", response.Code, verifier.calls)
			}
		})
	}
}

func TestAuthenticateRejectsForgedSessionResolverResults(t *testing.T) {
	var typedNil *nilTokenSource
	tests := []struct {
		name           string
		credential     core.Credential
		resolvePresent bool
		resolveErr     error
		wantStatus     int
	}{
		{name: "vanished", credential: credentialWithToken("token"), resolvePresent: false, wantStatus: http.StatusUnauthorized},
		{name: "wrong source", credential: func() core.Credential { c := credentialWithToken("token"); c.Source = core.CredentialBearer; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "missing session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = ""; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "blank session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "  "; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "padded session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = " session-1 "; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "whitespace in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session 1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "control in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session\n1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "missing subject", credential: func() core.Credential { c := credentialWithToken("token"); c.Auth.Subject = ""; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "missing token source", credential: func() core.Credential { c := credentialWithToken("token"); c.Tokens = nil; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "typed nil token source", credential: func() core.Credential { c := credentialWithToken("token"); c.Tokens = typedNil; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "resolver error", resolvePresent: true, resolveErr: errors.New("resolver-secret"), wantStatus: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeSessionResolver{present: true, resolvePresent: test.resolvePresent, credential: test.credential, resolveErr: test.resolveErr}
			verifier := &fakeVerifier{auth: validAuth()}
			service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: &fakeAuthorizer{}, Sessions: resolver})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := service.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler called") }))
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != test.wantStatus || resolver.presentCalls != 1 || resolver.resolveCalls != 1 || verifier.calls != 0 || strings.Contains(response.Body.String(), "resolver-secret") {
				t.Fatalf("status/present/resolve/verifier=%d/%d/%d/%d", response.Code, resolver.presentCalls, resolver.resolveCalls, verifier.calls)
			}
		})
	}
}

func TestRequireRejectsMethodMismatchBeforeCredentialSelection(t *testing.T) {
	resolver := &fakeSessionResolver{present: true, credential: credentialWithToken("session-secret")}
	verifier := &fakeVerifier{auth: validAuth()}
	pdp := &fakeAuthorizer{}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: pdp, Sessions: resolver})
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls int
	handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handlerCalls++ }))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Authorization", "Bearer bearer-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || resolver.presentCalls != 0 || resolver.resolveCalls != 0 || verifier.calls != 0 || pdp.calls != 0 || handlerCalls != 0 {
		t.Fatalf("status/present/resolve/verifier/pdp/handler=%d/%d/%d/%d/%d/%d", response.Code, resolver.presentCalls, resolver.resolveCalls, verifier.calls, pdp.calls, handlerCalls)
	}
}

func TestRequirePassesRequestScopedBearerAndSessionTokenSources(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		resolver  *fakeSessionResolver
		wantToken string
		wantCalls int
	}{
		{name: "bearer", header: "Bearer bearer-secret", wantToken: "bearer-secret"},
		{name: "session", resolver: &fakeSessionResolver{present: true, resolvePresent: true, credential: credentialWithToken("session-secret")}, wantToken: "session-secret", wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := &fakeVerifier{auth: validAuth()}
			pdp := &fakeAuthorizer{decision: httpauthz.Decision{ID: "dec-1", Allowed: true, ReasonCode: "policy_allow"}, captureToken: true}
			cfg := httpauthz.Config{Verifier: verifier, PDP: pdp}
			if test.resolver != nil {
				cfg.Sessions = test.resolver
			}
			service, err := httpauthz.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent || pdp.calls != 1 || pdp.tokenErr != nil || pdp.token != test.wantToken || pdp.route.Method() != http.MethodGet {
				t.Fatalf("status/pdp/tokenErr/route=%d/%d/%v/%s", response.Code, pdp.calls, pdp.tokenErr, pdp.route.Method())
			}
			if test.resolver != nil && (test.resolver.presentCalls != 1 || test.resolver.resolveCalls != test.wantCalls || verifier.calls != 0) {
				t.Fatalf("present/resolve/verifier=%d/%d/%d", test.resolver.presentCalls, test.resolver.resolveCalls, verifier.calls)
			}
		})
	}
}

func TestRequireAllowInjectsDecisionAndAuthCopies(t *testing.T) {
	verifier := &fakeVerifier{auth: validAuth()}
	decision := httpauthz.Decision{ID: "opaque+id=with@valid/json:characters", Allowed: true, ReasonCode: "policy_allow", RequestID: "req-1", TraceID: "trace-1"}
	pdp := &fakeAuthorizer{decision: decision}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: pdp})
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls int
	handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		handlerCalls++
		got, ok := httpauthz.DecisionFromContext(request.Context())
		auth, authOK := core.AuthContextFromContext(request.Context())
		if !ok || !authOK || got != decision || auth.DecisionID != decision.ID || auth.ReasonCode != decision.ReasonCode {
			t.Fatalf("decision/auth context mismatch: %#v/%v/redacted/%v", got, ok, authOK)
		}
		got.ID = "mutated"
		auth.Audience[0] = "mutated"
		again, _ := httpauthz.DecisionFromContext(request.Context())
		authAgain, _ := core.AuthContextFromContext(request.Context())
		if again != decision || authAgain.Audience[0] != "portal" {
			t.Fatal("authorization context was mutable")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || handlerCalls != 1 || response.Header().Get("X-IAM-Decision-ID") != decision.ID {
		t.Fatalf("status/handler/header=%d/%d/%q", response.Code, handlerCalls, response.Header().Get("X-IAM-Decision-ID"))
	}
}

func TestRequireDenyProvidesDecisionContextButNeverCallsHandler(t *testing.T) {
	decision := httpauthz.Decision{ID: "dec-deny", Allowed: false, ReasonCode: "default_deny", RequestID: "req-1", TraceID: "trace-1"}
	var captured httpauthz.Decision
	var capturedAuth core.AuthContext
	var responderCalls int
	service, err := httpauthz.New(httpauthz.Config{
		Verifier: &fakeVerifier{auth: validAuth()}, PDP: &fakeAuthorizer{decision: decision},
		Responder: httpauthz.ErrorResponderFunc(func(w http.ResponseWriter, request *http.Request, err error) {
			responderCalls++
			captured, _ = httpauthz.DecisionFromContext(request.Context())
			capturedAuth, _ = core.AuthContextFromContext(request.Context())
			var typed *core.Error
			if !errors.As(err, &typed) || typed == nil || typed.Kind != core.KindForbidden {
				t.Fatalf("deny error = %T", err)
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler called") }))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || responderCalls != 1 || captured != decision || capturedAuth.DecisionID != decision.ID || capturedAuth.ReasonCode != decision.ReasonCode || response.Header().Get("X-IAM-Decision-ID") != decision.ID {
		t.Fatalf("status/responder/context/header=%d/%d/%#v/%q", response.Code, responderCalls, captured, response.Header().Get("X-IAM-Decision-ID"))
	}
}

func TestRequireNeverWritesUnsafeDecisionIDHeader(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{name: "empty", id: ""},
		{name: "newline", id: "opaque\ninjected"},
		{name: "carriage return", id: "opaque\rinjected"},
		{name: "nul", id: "opaque\x00injected"},
		{name: "unicode control", id: "opaque\u0085injected"},
		{name: "zero width format", id: "opaque\u200binjected"},
		{name: "bidi format", id: "opaque\u202einjected"},
		{name: "surrounding whitespace", id: " opaque-id "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := httpauthz.Decision{ID: test.id, Allowed: true, ReasonCode: "policy_allow"}
			service, err := httpauthz.New(httpauthz.Config{Verifier: &fakeVerifier{auth: validAuth()}, PDP: &fakeAuthorizer{decision: decision}})
			if err != nil {
				t.Fatal(err)
			}
			var captured httpauthz.Decision
			handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				captured, _ = httpauthz.DecisionFromContext(request.Context())
				w.WriteHeader(http.StatusNoContent)
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			response.Header().Set("X-IAM-Decision-ID", "stale-decision")
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent || response.Header().Get("X-IAM-Decision-ID") != "" || captured != decision {
				t.Fatalf("status/header/context=%d/%q/%#v", response.Code, response.Header().Get("X-IAM-Decision-ID"), captured)
			}
		})
	}
}
