package httpauthz_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz"
)

type serviceEventRecorder struct {
	mu     sync.Mutex
	events []core.Event
}

func (r *serviceEventRecorder) Observe(_ context.Context, event core.Event) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *serviceEventRecorder) snapshot() []core.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]core.Event(nil), r.events...)
}

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

func TestServiceObservesAndLogsSanitizedTerminalOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		decision    httpauthz.Decision
		verifierErr error
		pdpErr      error
		wantStatus  int
		wantOutcome string
		wantSource  string
	}{
		{name: "allow", decision: httpauthz.Decision{ID: "decision-id-sensitive", Allowed: true, ReasonCode: "policy_allow"}, wantStatus: http.StatusNoContent, wantOutcome: "allowed", wantSource: "bearer"},
		{name: "deny", decision: httpauthz.Decision{ID: "decision-id-sensitive", Allowed: false, ReasonCode: "default_deny"}, wantStatus: http.StatusForbidden, wantOutcome: "forbidden", wantSource: "bearer"},
		{name: "unauthenticated", verifierErr: core.NewError(core.KindUnauthenticated, "remote-error-sensitive", 0, false, errors.New("cause-sensitive")), wantStatus: http.StatusUnauthorized, wantOutcome: "unauthenticated"},
		{name: "unavailable", pdpErr: core.NewError(core.KindIAMUnavailable, "remote-error-sensitive", 503, true, errors.New("cause-sensitive")), wantStatus: http.StatusServiceUnavailable, wantOutcome: "unavailable", wantSource: "bearer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &serviceEventRecorder{}
			var logs bytes.Buffer
			verifier := &fakeVerifier{auth: validAuth(), err: test.verifierErr}
			pdp := &fakeAuthorizer{decision: test.decision, err: test.pdpErr}
			service, err := httpauthz.New(httpauthz.Config{
				Verifier: verifier, PDP: pdp, Observer: observer,
				Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/orders?query-secret-sensitive=1", nil)
			request.Header.Set("Authorization", "Bearer bearer-token-sensitive")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			events := observer.snapshot()
			if response.Code != test.wantStatus || len(events) != 1 || events[0].Operation != "httpauthz.service.require" ||
				events[0].Outcome != test.wantOutcome || events[0].CredentialSource != test.wantSource || events[0].Duration < 0 {
				t.Fatalf("status/events = %d/%#v", response.Code, events)
			}
			combined := logs.String() + fmt.Sprint(events)
			for _, secret := range []string{"bearer-token-sensitive", "query-secret-sensitive", "decision-id-sensitive", "remote-error-sensitive", "cause-sensitive"} {
				if strings.Contains(combined, secret) {
					t.Fatalf("service observability leaked %q", secret)
				}
			}
		})
	}
}

func TestAuthenticateObservesOneSanitizedSuccess(t *testing.T) {
	observer := &serviceEventRecorder{}
	service, err := httpauthz.New(httpauthz.Config{
		Verifier: &fakeVerifier{auth: validAuth()}, PDP: &fakeAuthorizer{}, Observer: observer,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := service.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer token-sensitive")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	events := observer.snapshot()
	if response.Code != http.StatusNoContent || len(events) != 1 || events[0].Operation != "httpauthz.service.authenticate" ||
		events[0].Outcome != "authenticated" || events[0].CredentialSource != "bearer" {
		t.Fatalf("status/events = %d/%#v", response.Code, events)
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

func TestMalformedPresentSessionConflictsBeforeCookieParsingError(t *testing.T) {
	resolver := &fakeSessionResolver{present: true, presentErr: errors.New("malformed-cookie-sensitive")}
	verifier := &fakeVerifier{auth: validAuth()}
	var gotKind core.Kind
	service, err := httpauthz.New(httpauthz.Config{
		Verifier: verifier, PDP: &fakeAuthorizer{}, Sessions: resolver,
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
	request.Header.Set("Authorization", "malformed-bearer-sensitive")
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

func TestAuthenticatePreservesInitializedEmptyGroups(t *testing.T) {
	auth := validAuth()
	auth.Groups = []string{}
	verifier := &fakeVerifier{auth: auth}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: &fakeAuthorizer{}})
	if err != nil {
		t.Fatal("construct middleware service")
	}
	handler, err := service.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		got, ok := core.AuthContextFromContext(request.Context())
		if !ok || got.Groups == nil || len(got.Groups) != 0 {
			t.Fatal("middleware did not preserve Groups as an initialized empty slice")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal("construct authentication middleware")
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer bearer-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if verifier.auth.Groups == nil {
		t.Fatal("middleware mutated verifier Groups presence")
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
		{name: "dot in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session.1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "plus in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session+1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "slash in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session/1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "equals in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session=1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "tilde in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session~1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "quote in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = `session"1`; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "backslash in session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = `session\1`; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "non ASCII session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "sessioné1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "zero width session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session\u200b1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "bidi session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session\u202e1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
		{name: "emoji session binding", credential: func() core.Credential { c := credentialWithToken("token"); c.SessionID = "session😀1"; return c }(), resolvePresent: true, wantStatus: http.StatusUnauthorized},
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

func TestAuthenticateAcceptsBFFSessionBindingGrammar(t *testing.T) {
	for _, sessionID := range []string{"a", "AZaz09_-", "session-1", "opaque_ID-123"} {
		credential := credentialWithToken("token")
		credential.SessionID = sessionID
		resolver := &fakeSessionResolver{present: true, resolvePresent: true, credential: credential}
		service, err := httpauthz.New(httpauthz.Config{Verifier: &fakeVerifier{auth: validAuth()}, PDP: &fakeAuthorizer{}, Sessions: resolver})
		if err != nil {
			t.Fatal(err)
		}
		handler, err := service.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != http.StatusNoContent || resolver.presentCalls != 1 || resolver.resolveCalls != 1 {
			t.Fatalf("status/present/resolve=%d/%d/%d", response.Code, resolver.presentCalls, resolver.resolveCalls)
		}
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

func TestRequireRejectsMalformedAuthorizerDecisionBeforeContextOrHandler(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*httpauthz.Decision)
	}{
		{name: "empty decision ID", mutate: func(d *httpauthz.Decision) { d.ID = "" }},
		{name: "padded decision ID", mutate: func(d *httpauthz.Decision) { d.ID = " decision-secret " }},
		{name: "control decision ID", mutate: func(d *httpauthz.Decision) { d.ID = "decision\nsecret" }},
		{name: "zero width decision ID", mutate: func(d *httpauthz.Decision) { d.ID = "decision\u200bsecret" }},
		{name: "bidi decision ID", mutate: func(d *httpauthz.Decision) { d.ID = "decision\u202esecret" }},
		{name: "invalid UTF8 decision ID", mutate: func(d *httpauthz.Decision) { d.ID = "decision\xffsecret" }},
		{name: "empty reason code", mutate: func(d *httpauthz.Decision) { d.ReasonCode = "" }},
		{name: "padded reason code", mutate: func(d *httpauthz.Decision) { d.ReasonCode = " reason-secret " }},
		{name: "control reason code", mutate: func(d *httpauthz.Decision) { d.ReasonCode = "reason\rsecret" }},
		{name: "zero width reason code", mutate: func(d *httpauthz.Decision) { d.ReasonCode = "reason\u200bsecret" }},
		{name: "bidi reason code", mutate: func(d *httpauthz.Decision) { d.ReasonCode = "reason\u202esecret" }},
		{name: "invalid UTF8 reason code", mutate: func(d *httpauthz.Decision) { d.ReasonCode = "reason\xffsecret" }},
		{name: "padded request ID", mutate: func(d *httpauthz.Decision) { d.RequestID = " request-secret " }},
		{name: "format request ID", mutate: func(d *httpauthz.Decision) { d.RequestID = "request\u200bsecret" }},
		{name: "control trace ID", mutate: func(d *httpauthz.Decision) { d.TraceID = "trace\nsecret" }},
		{name: "invalid UTF8 trace ID", mutate: func(d *httpauthz.Decision) { d.TraceID = "trace\xffsecret" }},
	}
	for _, allowed := range []bool{true, false} {
		outcome := "deny"
		if allowed {
			outcome = "allow"
		}
		for _, mutation := range mutations {
			t.Run(outcome+"/"+mutation.name, func(t *testing.T) {
				decision := httpauthz.Decision{
					ID: "decision-valid", Allowed: allowed, ReasonCode: "policy_valid",
					RequestID: "request-valid", TraceID: "trace-valid",
				}
				mutation.mutate(&decision)
				verifier := &fakeVerifier{auth: validAuth()}
				pdp := &fakeAuthorizer{decision: decision}
				var responderCalls, handlerCalls int
				service, err := httpauthz.New(httpauthz.Config{
					Verifier: verifier, PDP: pdp,
					Responder: httpauthz.ErrorResponderFunc(func(w http.ResponseWriter, request *http.Request, err error) {
						responderCalls++
						var typed *core.Error
						if !errors.As(err, &typed) || typed == nil || typed.Kind != core.KindProtocol {
							t.Fatalf("error = %T", err)
						}
						if _, ok := httpauthz.DecisionFromContext(request.Context()); ok {
							t.Fatal("malformed Decision reached request context")
						}
						auth, ok := core.AuthContextFromContext(request.Context())
						if !ok || auth.DecisionID != "" || auth.ReasonCode != "" {
							t.Fatal("malformed Decision reached AuthContext")
						}
						http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
					}),
				})
				if err != nil {
					t.Fatal(err)
				}
				handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					handlerCalls++
					w.WriteHeader(http.StatusNoContent)
				}))
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodGet, "/", nil)
				request.Header.Set("Authorization", "Bearer token")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusBadRequest || response.Header().Get("X-IAM-Decision-ID") != "" ||
					verifier.calls != 1 || pdp.calls != 1 || responderCalls != 1 || handlerCalls != 0 {
					t.Fatalf("status/header/verifier/PDP/responder/handler=%d/%t/%d/%d/%d/%d",
						response.Code, response.Header().Get("X-IAM-Decision-ID") != "", verifier.calls, pdp.calls, responderCalls, handlerCalls)
				}
				for _, secret := range []string{"decision-secret", "reason-secret", "request-secret", "trace-secret"} {
					if strings.Contains(response.Body.String(), secret) {
						t.Fatal("malformed Decision metadata reached response body")
					}
				}
			})
		}
	}
}

func TestRequireMalformedDecisionDefaultResponseIsSanitized(t *testing.T) {
	verifier := &fakeVerifier{auth: validAuth()}
	pdp := &fakeAuthorizer{decision: httpauthz.Decision{
		ID: " malformed-decision-secret ", Allowed: true, ReasonCode: "policy_allow",
	}}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: pdp})
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls int
	handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handlerCalls++ }))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Body.String() != "Bad Request\n" ||
		response.Header().Get("X-IAM-Decision-ID") != "" || verifier.calls != 1 || pdp.calls != 1 || handlerCalls != 0 {
		t.Fatalf("status/header/verifier/PDP/handler=%d/%t/%d/%d/%d",
			response.Code, response.Header().Get("X-IAM-Decision-ID") != "", verifier.calls, pdp.calls, handlerCalls)
	}
	if strings.Contains(response.Body.String(), "malformed-decision-secret") {
		t.Fatal("default response disclosed malformed Decision metadata")
	}
}

func TestRequireClearsStaleDecisionHeaderBeforeEveryBranch(t *testing.T) {
	tests := []struct {
		name                                 string
		method, header                       string
		sessions                             *fakeSessionResolver
		decision                             httpauthz.Decision
		pdpErr                               error
		wantStatus, wantPresent, wantResolve int
		wantVerify, wantPDP                  int
		wantHeader                           string
	}{
		{
			name: "method mismatch", method: http.MethodPost, header: "Bearer token",
			sessions:   &fakeSessionResolver{present: true},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "SessionPresent error", method: http.MethodGet, header: "Bearer token",
			sessions:   &fakeSessionResolver{presentErr: errors.New("session-present-secret")},
			wantStatus: http.StatusServiceUnavailable, wantPresent: 1,
		},
		{
			name: "credential error", method: http.MethodGet, header: "Basic credential-secret",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "ResolveSession error", method: http.MethodGet,
			sessions:   &fakeSessionResolver{present: true, resolvePresent: true, resolveErr: errors.New("resolve-session-secret")},
			wantStatus: http.StatusServiceUnavailable, wantPresent: 1, wantResolve: 1,
		},
		{
			name: "PDP error", method: http.MethodGet, header: "Bearer token",
			pdpErr:     core.NewError(core.KindIAMUnavailable, "pdp-secret", 0, true, nil),
			wantStatus: http.StatusServiceUnavailable, wantVerify: 1, wantPDP: 1,
		},
		{
			name: "malformed decision", method: http.MethodGet, header: "Bearer token",
			decision:   httpauthz.Decision{ID: "decision-valid", Allowed: true},
			wantStatus: http.StatusBadRequest, wantVerify: 1, wantPDP: 1,
		},
		{
			name: "deny unsafe decision", method: http.MethodGet, header: "Bearer token",
			decision:   httpauthz.Decision{ID: "deny\u202esecret", Allowed: false, ReasonCode: "default_deny"},
			wantStatus: http.StatusBadRequest, wantVerify: 1, wantPDP: 1,
		},
		{
			name: "allow safe replacement", method: http.MethodGet, header: "Bearer token",
			decision:   httpauthz.Decision{ID: "fresh-decision", Allowed: true, ReasonCode: "policy_allow"},
			wantStatus: http.StatusNoContent, wantVerify: 1, wantPDP: 1, wantHeader: "fresh-decision",
		},
		{
			name: "deny safe replacement", method: http.MethodGet, header: "Bearer token",
			decision:   httpauthz.Decision{ID: "fresh-deny", Allowed: false, ReasonCode: "default_deny"},
			wantStatus: http.StatusForbidden, wantVerify: 1, wantPDP: 1, wantHeader: "fresh-deny",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := &fakeVerifier{auth: validAuth()}
			pdp := &fakeAuthorizer{decision: test.decision, err: test.pdpErr}
			cfg := httpauthz.Config{Verifier: verifier, PDP: pdp}
			if test.sessions != nil {
				cfg.Sessions = test.sessions
			}
			service, err := httpauthz.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var handlerCalls int
			handler, err := service.Require(boundRoute(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlerCalls++
				w.WriteHeader(http.StatusNoContent)
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, "/", nil)
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}
			response := httptest.NewRecorder()
			response.Header().Set("X-IAM-Decision-ID", "stale-decision-secret")
			response.Header()["x-iam-decision-id"] = []string{"stale-lowercase-secret"}
			response.Header()["X-IAM-decision-ID"] = []string{"stale-mixed-case-secret"}
			handler.ServeHTTP(response, request)
			presentCalls := 0
			resolveCalls := 0
			if test.sessions != nil {
				presentCalls = test.sessions.presentCalls
				resolveCalls = test.sessions.resolveCalls
			}
			wantHandler := 0
			if test.wantStatus == http.StatusNoContent {
				wantHandler = 1
			}
			var decisionHeaderKeys, decisionHeaderValues int
			var decisionHeaderValue string
			for name, values := range response.Header() {
				if strings.EqualFold(name, "X-IAM-Decision-ID") {
					decisionHeaderKeys++
					decisionHeaderValues += len(values)
					if len(values) == 1 {
						decisionHeaderValue = values[0]
					}
				}
			}
			wantHeaderKeys := 0
			if test.wantHeader != "" {
				wantHeaderKeys = 1
			}
			if response.Code != test.wantStatus || decisionHeaderKeys != wantHeaderKeys || decisionHeaderValues != wantHeaderKeys ||
				decisionHeaderValue != test.wantHeader || presentCalls != test.wantPresent || resolveCalls != test.wantResolve ||
				verifier.calls != test.wantVerify || pdp.calls != test.wantPDP || handlerCalls != wantHandler {
				t.Fatalf("status/header-keys/header-values/present/resolve/verifier/PDP/handler=%d/%d/%d/%d/%d/%d/%d/%d",
					response.Code, decisionHeaderKeys, decisionHeaderValues, presentCalls, resolveCalls, verifier.calls, pdp.calls, handlerCalls)
			}
			if strings.Contains(response.Body.String(), "stale-decision-secret") || strings.Contains(response.Body.String(), "stale-lowercase-secret") ||
				strings.Contains(response.Body.String(), "stale-mixed-case-secret") || strings.Contains(response.Body.String(), "session-present-secret") ||
				strings.Contains(response.Body.String(), "resolve-session-secret") || strings.Contains(response.Body.String(), "credential-secret") ||
				strings.Contains(response.Body.String(), "pdp-secret") {
				t.Fatal("error response disclosed stale header or branch secret")
			}
		})
	}
}
