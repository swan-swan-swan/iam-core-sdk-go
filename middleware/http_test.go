package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/authn"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/authz"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

type fakeAuthenticator struct {
	mu sync.Mutex

	credential authn.Credential
	err        error
	refreshed  *session.Session
	refreshErr error

	authenticateCalls int
	refreshCalls      int
	propagated        http.Header
}

func (f *fakeAuthenticator) Authenticate(request *http.Request) (authn.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authenticateCalls++
	f.propagated = propagatedHeaders(request.Context())
	return f.credential, f.err
}

func (f *fakeAuthenticator) ForceRefresh(ctx context.Context, _ string) (*session.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshCalls++
	return f.refreshed, f.refreshErr
}

func (f *fakeAuthenticator) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authenticateCalls, f.refreshCalls
}

func (f *fakeAuthenticator) propagatedHeaders() http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.propagated.Clone()
}

type fakeAuthorizer struct {
	mu sync.Mutex

	decision  authz.Decision
	err       error
	decisions []authz.Decision
	errors    []error

	calls       int
	tokens      []string
	permissions []authz.Permission
	propagated  []http.Header
}

func (f *fakeAuthorizer) Decide(
	ctx context.Context,
	accessToken string,
	permission authz.Permission,
) (authz.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.calls
	f.calls++
	f.tokens = append(f.tokens, accessToken)
	f.permissions = append(f.permissions, permission)
	f.propagated = append(f.propagated, propagatedHeaders(ctx))
	decision, err := f.decision, f.err
	if index < len(f.decisions) {
		decision = f.decisions[index]
	}
	if index < len(f.errors) {
		err = f.errors[index]
	}
	return decision, err
}

func (f *fakeAuthorizer) snapshot() (int, []string, []authz.Permission, []http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tokens := append([]string(nil), f.tokens...)
	permissions := append([]authz.Permission(nil), f.permissions...)
	headers := make([]http.Header, len(f.propagated))
	for index := range f.propagated {
		headers[index] = f.propagated[index].Clone()
	}
	return f.calls, tokens, permissions, headers
}

func propagatedHeaders(ctx context.Context) http.Header {
	headers := make(http.Header)
	transport.ApplyHeaders(ctx, headers)
	return headers
}

func bearerCredential() authn.Credential {
	return authn.Credential{
		Source:      authn.CredentialBearer,
		AccessToken: "access-token",
		Identity: oidc.Identity{
			Subject:     "op_usr_0123456789abcdefgjk",
			Roles:       []string{"viewer"},
			Scopes:      []string{"openid"},
			ExtraClaims: map[string]json.RawMessage{"tenant": json.RawMessage(`"tenant-1"`)},
		},
	}
}

func sessionCredential() authn.Credential {
	credential := bearerCredential()
	credential.Source = authn.CredentialSession
	credential.SessionID = "session-1"
	return credential
}

func permission() authz.Permission {
	return authz.Permission{
		ResourceServer: "asset-api",
		Resource:       "assets",
		HTTPMethod:     http.MethodDelete,
	}
}

func TestRequirePermissionAllowsAndStoresDefensiveContext(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	authorizer := &fakeAuthorizer{decision: authz.Decision{
		ID: "opaque+id=with@valid/json:characters", Allowed: true, ReasonCode: "allowed",
	}}
	handler := RequirePermission(authenticator, authorizer, permission())(http.HandlerFunc(
		func(w http.ResponseWriter, request *http.Request) {
			identity, ok := IdentityFromContext(request.Context())
			if !ok || identity.Subject != "op_usr_0123456789abcdefgjk" {
				t.Fatalf("identity = %#v ok=%v", identity, ok)
			}
			source, ok := CredentialSourceFromContext(request.Context())
			if !ok || source != authn.CredentialBearer {
				t.Fatalf("source = %q ok=%v", source, ok)
			}
			decision, ok := DecisionFromContext(request.Context())
			if !ok || decision.ID != "opaque+id=with@valid/json:characters" {
				t.Fatalf("decision = %#v ok=%v", decision, ok)
			}

			identity.Roles[0] = "admin"
			identity.Scopes[0] = "root"
			identity.ExtraClaims["tenant"][1] = 'X'
			identity.ExtraClaims["new"] = json.RawMessage(`true`)
			again, _ := IdentityFromContext(request.Context())
			if again.Roles[0] != "viewer" || again.Scopes[0] != "openid" ||
				string(again.ExtraClaims["tenant"]) != `"tenant-1"` || again.ExtraClaims["new"] != nil {
				t.Fatalf("context identity was mutable: %#v", again)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/assets", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-IAM-Decision-ID") != "opaque+id=with@valid/json:characters" {
		t.Fatalf("decision header = %q", response.Header().Get("X-IAM-Decision-ID"))
	}
	if got := authenticator.credential.Identity.Roles[0]; got != "viewer" {
		t.Fatalf("source identity role = %q", got)
	}
}

func TestAuthenticateStoresIdentityAndSourceWithDefensiveCopies(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	handler := Authenticate(authenticator)(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		identity, identityOK := IdentityFromContext(request.Context())
		source, sourceOK := CredentialSourceFromContext(request.Context())
		if !identityOK || !sourceOK || source != authn.CredentialBearer {
			t.Fatalf("identity=%#v source=%q identityOK=%v sourceOK=%v", identity, source, identityOK, sourceOK)
		}
		identity.Roles[0] = "mutated"
		again, _ := IdentityFromContext(request.Context())
		if again.Roles[0] != "viewer" {
			t.Fatalf("identity role = %q", again.Roles[0])
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestMiddlewareAuthenticationErrorIsMinimal401(t *testing.T) {
	authenticator := &fakeAuthenticator{
		err: sdkerr.New(
			sdkerr.KindUnauthenticated,
			"authn.authenticate access-token cookie=session-secret",
			http.StatusUnauthorized,
			false,
			errors.New("cause-secret"),
		),
	}
	nextCalled := false
	handler := Authenticate(authenticator)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusUnauthorized || nextCalled {
		t.Fatalf("status=%d nextCalled=%v", response.Code, nextCalled)
	}
	const expected = "{\"error\":\"unauthenticated\"}\n"
	if response.Body.String() != expected {
		t.Fatalf("body = %q, want %q", response.Body.String(), expected)
	}
	for _, secret := range []string{"cause-secret", "access-token", "session-secret", "cookie", "Cause"} {
		if bytes.Contains(response.Body.Bytes(), []byte(secret)) {
			t.Fatalf("body leaked %q: %s", secret, response.Body.String())
		}
	}
}

func TestRequirePermissionDenyStoresDecisionForResponderAndWritesSafeHeader(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	authorizer := &fakeAuthorizer{decision: authz.Decision{
		ID:         "dec-deny",
		Allowed:    false,
		ReasonCode: "explicit_deny",
		RequestID:  "req-1",
		TraceID:    "trace-1",
	}}
	var captured authz.Decision
	responder := ErrorResponderFunc(func(w http.ResponseWriter, request *http.Request, err error) {
		captured, _ = DecisionFromContext(request.Context())
		defaultErrorResponder{}.Respond(w, request, err)
	})
	handler := RequirePermission(
		authenticator,
		authorizer,
		permission(),
		WithErrorResponder(responder),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("denied request reached next handler")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/assets", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if captured.ID != "dec-deny" || captured.ReasonCode != "explicit_deny" {
		t.Fatalf("captured decision = %#v", captured)
	}
	if got := response.Header().Get("X-IAM-Decision-ID"); got != "dec-deny" {
		t.Fatalf("decision header = %q", got)
	}
}

func TestRequirePermissionNeverWritesUnsafeOpaqueDecisionIDHeader(t *testing.T) {
	for _, test := range []struct {
		name    string
		id      string
		allowed bool
	}{
		{"newline allow", "opaque\ninjected", true},
		{"carriage return deny", "opaque\rinjected", false},
		{"nul allow", "opaque\x00injected", true},
		{"unicode control deny", "opaque\u0085injected", false},
		{"surrounding whitespace allow", " opaque-id ", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &fakeAuthenticator{credential: bearerCredential()}
			authorizer := &fakeAuthorizer{decision: authz.Decision{
				ID: test.id, Allowed: test.allowed, ReasonCode: "opaque",
			}}
			handler := RequirePermission(authenticator, authorizer, permission())(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}),
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if got := response.Header().Get("X-IAM-Decision-ID"); got != "" {
				t.Fatalf("unsafe decision header = %q", got)
			}
			decisionID := ""
			var payload map[string]string
			if response.Body.Len() > 0 && json.Unmarshal(response.Body.Bytes(), &payload) == nil {
				decisionID = payload["decision_id"]
			}
			if !test.allowed && decisionID != test.id {
				t.Fatalf("JSON decision ID = %q, want opaque %q", decisionID, test.id)
			}
		})
	}
}

func TestRequirePermissionPDPUnavailableIs503(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	authorizer := &fakeAuthorizer{err: sdkerr.New(
		sdkerr.KindIAMUnavailable,
		"authz.decide",
		http.StatusServiceUnavailable,
		true,
		errors.New("remote body secret"),
	)}
	response := httptest.NewRecorder()
	RequirePermission(authenticator, authorizer, permission())(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("unavailable request reached next")
		}),
	).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusServiceUnavailable ||
		stringsContainsAny(response.Body.String(), "remote body secret", "access-token") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRequirePermissionSession401RefreshesOnceAndUsesRefreshedTokenIdentity(t *testing.T) {
	authenticator := &fakeAuthenticator{
		credential: sessionCredential(),
		refreshed: &session.Session{
			ID:       "session-1",
			TokenSet: oidc.TokenSet{AccessToken: "refreshed-access-token"},
			Identity: oidc.Identity{
				Subject: "op_usr_0123456789abcdefgjk",
				Roles:   []string{"refreshed-role"},
				Scopes:  []string{"openid", "email"},
				ExtraClaims: map[string]json.RawMessage{
					"tenant": json.RawMessage(`"refreshed-tenant"`),
				},
			},
		},
	}
	authorizer := &fakeAuthorizer{
		decisions: []authz.Decision{
			{},
			{ID: "dec-refreshed", Allowed: true, ReasonCode: "allowed"},
		},
		errors: []error{
			sdkerr.New(sdkerr.KindUnauthenticated, "authz.decide", http.StatusUnauthorized, false, nil),
			nil,
		},
	}
	handler := RequirePermission(authenticator, authorizer, permission())(http.HandlerFunc(
		func(w http.ResponseWriter, request *http.Request) {
			identity, ok := IdentityFromContext(request.Context())
			if !ok || identity.Subject != "op_usr_0123456789abcdefgjk" || identity.Roles[0] != "refreshed-role" {
				t.Fatalf("refreshed identity = %#v ok=%v", identity, ok)
			}
			source, _ := CredentialSourceFromContext(request.Context())
			if source != authn.CredentialSession {
				t.Fatalf("source = %q", source)
			}
			w.WriteHeader(http.StatusNoContent)
		},
	))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	_, refreshCalls := authenticator.counts()
	calls, tokens, permissions, _ := authorizer.snapshot()
	if refreshCalls != 1 || calls != 2 {
		t.Fatalf("refresh calls=%d decision calls=%d", refreshCalls, calls)
	}
	if len(tokens) != 2 || tokens[0] != "access-token" || tokens[1] != "refreshed-access-token" {
		t.Fatalf("tokens = %#v", tokens)
	}
	if permissions[0].HTTPMethod != http.MethodPut || permissions[1].HTTPMethod != http.MethodPut {
		t.Fatalf("permissions = %#v", permissions)
	}
}

func TestRequirePermissionRejectsInvalidRefreshedSession(t *testing.T) {
	for _, test := range []struct {
		name      string
		refreshed *session.Session
	}{
		{"nil", nil},
		{"wrong ID", &session.Session{ID: "other", TokenSet: oidc.TokenSet{AccessToken: "new"}, Identity: oidc.Identity{Subject: "user"}}},
		{"empty token", &session.Session{ID: "session-1", Identity: oidc.Identity{Subject: "user"}}},
		{"empty subject", &session.Session{ID: "session-1", TokenSet: oidc.TokenSet{AccessToken: "new"}}},
		{"substituted subject", &session.Session{ID: "session-1", TokenSet: oidc.TokenSet{AccessToken: "new"}, Identity: oidc.Identity{Subject: "other-user"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &fakeAuthenticator{
				credential: sessionCredential(),
				refreshed:  test.refreshed,
			}
			authorizer := &fakeAuthorizer{err: sdkerr.New(
				sdkerr.KindUnauthenticated, "authz.decide", http.StatusUnauthorized, false, nil,
			)}
			response := httptest.NewRecorder()
			RequirePermission(authenticator, authorizer, permission())(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("invalid refresh reached next")
				}),
			).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			_, refreshCalls := authenticator.counts()
			calls, _, _, _ := authorizer.snapshot()
			if refreshCalls != 1 || calls != 1 {
				t.Fatalf("refresh calls=%d decision calls=%d", refreshCalls, calls)
			}
		})
	}
}

func TestRequirePermissionBearer401NeverRefreshes(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	authorizer := &fakeAuthorizer{err: sdkerr.New(
		sdkerr.KindUnauthenticated, "authz.decide", http.StatusUnauthorized, false, nil,
	)}
	response := httptest.NewRecorder()
	RequirePermission(authenticator, authorizer, permission())(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("unauthenticated request reached next")
		}),
	).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	_, refreshCalls := authenticator.counts()
	calls, _, _, _ := authorizer.snapshot()
	if refreshCalls != 0 || calls != 1 {
		t.Fatalf("refresh calls=%d decision calls=%d", refreshCalls, calls)
	}
}

func TestRequirePermissionSessionUnauthenticatedKindWithoutPDP401DoesNotRefresh(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation string
		status    int
	}{
		{name: "zero status", operation: "authz.decide"},
		{name: "non 401", operation: "authz.decide", status: http.StatusForbidden},
		{name: "other operation", operation: "authn.authenticate", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &fakeAuthenticator{
				credential: sessionCredential(),
				refreshed: &session.Session{
					ID: "session-1", TokenSet: oidc.TokenSet{AccessToken: "new"},
					Identity: bearerCredential().Identity,
				},
			}
			authorizer := &fakeAuthorizer{err: sdkerr.New(
				sdkerr.KindUnauthenticated,
				test.operation,
				test.status,
				false,
				nil,
			)}
			response := httptest.NewRecorder()
			RequirePermission(authenticator, authorizer, permission())(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("unauthenticated request reached next")
				}),
			).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			_, refreshCalls := authenticator.counts()
			calls, _, _, _ := authorizer.snapshot()
			if refreshCalls != 0 || calls != 1 {
				t.Fatalf("refresh calls=%d decision calls=%d", refreshCalls, calls)
			}
		})
	}
}

func TestRequirePermissionDoesNotRecoverOtherFirstResults(t *testing.T) {
	for _, test := range []struct {
		name     string
		decision authz.Decision
		err      error
		status   int
	}{
		{
			name:     "deny",
			decision: authz.Decision{ID: "deny", Allowed: false, ReasonCode: "denied"},
			status:   http.StatusForbidden,
		},
		{
			name:   "bad request",
			err:    sdkerr.New(sdkerr.KindProtocol, "authz.decide", http.StatusBadRequest, false, nil),
			status: http.StatusBadRequest,
		},
		{
			name:   "timeout",
			err:    sdkerr.New(sdkerr.KindIAMUnavailable, "authz.decide", http.StatusServiceUnavailable, true, nil),
			status: http.StatusServiceUnavailable,
		},
		{
			name:   "malformed success",
			err:    sdkerr.New(sdkerr.KindProtocol, "authz.decide", http.StatusOK, false, nil),
			status: http.StatusServiceUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &fakeAuthenticator{
				credential: sessionCredential(),
				refreshed: &session.Session{
					ID: "session-1", TokenSet: oidc.TokenSet{AccessToken: "new"},
					Identity: oidc.Identity{Subject: "op_usr_0123456789abcdefgjk"},
				},
			}
			authorizer := &fakeAuthorizer{decision: test.decision, err: test.err}
			response := httptest.NewRecorder()
			RequirePermission(authenticator, authorizer, permission())(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("failed request reached next")
				}),
			).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != test.status {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			_, refreshCalls := authenticator.counts()
			calls, _, _, _ := authorizer.snapshot()
			if refreshCalls != 0 || calls != 1 {
				t.Fatalf("refresh calls=%d decision calls=%d", refreshCalls, calls)
			}
		})
	}
}

func TestRequirePermissionNeverRecoversAfterSecondDecision(t *testing.T) {
	for _, test := range []struct {
		name     string
		decision authz.Decision
		err      error
		status   int
	}{
		{
			name:   "second 401",
			err:    sdkerr.New(sdkerr.KindUnauthenticated, "authz.decide", http.StatusUnauthorized, false, nil),
			status: http.StatusUnauthorized,
		},
		{
			name:     "second deny",
			decision: authz.Decision{ID: "deny-2", Allowed: false, ReasonCode: "denied"},
			status:   http.StatusForbidden,
		},
		{
			name:   "second 503",
			err:    sdkerr.New(sdkerr.KindIAMUnavailable, "authz.decide", http.StatusServiceUnavailable, true, nil),
			status: http.StatusServiceUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &fakeAuthenticator{
				credential: sessionCredential(),
				refreshed: &session.Session{
					ID: "session-1", TokenSet: oidc.TokenSet{AccessToken: "new"},
					Identity: oidc.Identity{Subject: "op_usr_0123456789abcdefgjk"},
				},
			}
			authorizer := &fakeAuthorizer{
				decisions: []authz.Decision{{}, test.decision},
				errors: []error{
					sdkerr.New(sdkerr.KindUnauthenticated, "authz.decide", http.StatusUnauthorized, false, nil),
					test.err,
				},
			}
			response := httptest.NewRecorder()
			RequirePermission(authenticator, authorizer, permission())(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("failed request reached next")
				}),
			).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != test.status {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			_, refreshCalls := authenticator.counts()
			calls, _, _, _ := authorizer.snapshot()
			if refreshCalls != 1 || calls != 2 {
				t.Fatalf("refresh calls=%d decision calls=%d", refreshCalls, calls)
			}
		})
	}
}

func TestRequirePermissionOverridesPrefilledMethod(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	authorizer := &fakeAuthorizer{decision: authz.Decision{ID: "allow", Allowed: true, ReasonCode: "allowed"}}
	response := httptest.NewRecorder()
	RequirePermission(authenticator, authorizer, permission())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	).ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/", nil))
	_, _, permissions, _ := authorizer.snapshot()
	if len(permissions) != 1 || permissions[0].HTTPMethod != http.MethodPatch {
		t.Fatalf("permissions = %#v", permissions)
	}
}

func TestMiddlewarePropagatesOnlyAllowlistedIncomingHeaders(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	authorizer := &fakeAuthorizer{decision: authz.Decision{ID: "allow", Allowed: true, ReasonCode: "allowed"}}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
	request.Header.Set("Tracestate", "vendor=value")
	request.Header.Set("X-Request-ID", "req-1")
	request.Header.Set("Authorization", "Bearer incoming-secret")
	request.Header.Set("Cookie", "session=incoming-secret")
	request.Header.Set("X-Other", "do-not-forward")

	response := httptest.NewRecorder()
	RequirePermission(authenticator, authorizer, permission())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	).ServeHTTP(response, request)
	authHeaders := authenticator.propagatedHeaders()
	_, _, _, decisionHeaders := authorizer.snapshot()
	for _, headers := range append([]http.Header{authHeaders}, decisionHeaders...) {
		if headers.Get("Traceparent") == "" || headers.Get("Tracestate") != "vendor=value" ||
			headers.Get("X-Request-ID") != "req-1" {
			t.Fatalf("missing propagated headers: %#v", headers)
		}
		for _, forbidden := range []string{"Authorization", "Cookie", "X-Other"} {
			if headers.Get(forbidden) != "" {
				t.Fatalf("propagated %s: %#v", forbidden, headers)
			}
		}
	}
}

func TestMiddlewareNilDependenciesAndOptionsFailWithoutPanic(t *testing.T) {
	var typedNilAuthenticator *fakeAuthenticator
	var typedNilAuthorizer *fakeAuthorizer
	tests := map[string]http.Handler{
		"authenticate nil authenticator":       Authenticate(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})),
		"authenticate typed nil authenticator": Authenticate(typedNilAuthenticator)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})),
		"authenticate nil next":                Authenticate(&fakeAuthenticator{credential: bearerCredential()})(nil),
		"require nil authenticator":            RequirePermission(nil, &fakeAuthorizer{}, permission())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})),
		"require nil authorizer":               RequirePermission(&fakeAuthenticator{}, nil, permission())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})),
		"require typed nil authorizer":         RequirePermission(&fakeAuthenticator{}, typedNilAuthorizer, permission())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})),
		"require nil next and options": RequirePermission(
			&fakeAuthenticator{},
			&fakeAuthorizer{},
			permission(),
			nil,
			WithErrorResponder(nil),
			WithHooks(nil),
			WithLogger(nil),
		)(nil),
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestRequirePermissionCallsDependenciesOncePerConcurrentRequest(t *testing.T) {
	const requestCount = 32
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	authorizer := &fakeAuthorizer{decision: authz.Decision{ID: "allow", Allowed: true, ReasonCode: "allowed"}}
	handler := RequirePermission(authenticator, authorizer, permission())(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	var wait sync.WaitGroup
	wait.Add(requestCount)
	for range requestCount {
		go func() {
			defer wait.Done()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != http.StatusNoContent {
				t.Errorf("status = %d body=%s", response.Code, response.Body.String())
			}
		}()
	}
	wait.Wait()
	authenticateCalls, refreshCalls := authenticator.counts()
	decisionCalls, _, _, _ := authorizer.snapshot()
	if authenticateCalls != requestCount || refreshCalls != 0 || decisionCalls != requestCount {
		t.Fatalf("authenticate=%d refresh=%d decide=%d", authenticateCalls, refreshCalls, decisionCalls)
	}
}

func TestMiddlewareObservabilityContainsOnlyFixedSafeFields(t *testing.T) {
	const (
		token   = "submitted-token-secret"
		subject = "op_usr_secret_subject"
		reason  = "sensitive-decision-reason"
	)
	credential := bearerCredential()
	credential.AccessToken = token
	credential.Identity.Subject = subject
	authenticator := &fakeAuthenticator{credential: credential}
	authorizer := &fakeAuthorizer{decision: authz.Decision{
		ID: "sensitive-decision-id", Allowed: false, ReasonCode: reason,
	}}
	hooks := &recordingHooks{}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	response := httptest.NewRecorder()
	RequirePermission(
		authenticator,
		authorizer,
		permission(),
		WithHooks(hooks),
		WithLogger(logger),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	if len(hooks.events) != 1 {
		t.Fatalf("events = %#v", hooks.events)
	}
	event := hooks.events[0]
	if event.Operation != "middleware.require_permission" || event.Outcome != "deny" ||
		event.CredentialSource != string(authn.CredentialBearer) {
		t.Fatalf("event = %#v", event)
	}
	for _, secret := range []string{token, subject, reason, "sensitive-decision-id"} {
		if stringsContainsAny(logs.String(), secret) {
			t.Fatalf("logs leaked %q: %s", secret, logs.String())
		}
	}
}

func TestAuthenticateObservesFinalOutcomeAndCredentialSource(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: bearerCredential()}
	hooks := &recordingHooks{}
	response := httptest.NewRecorder()
	Authenticate(authenticator, WithHooks(hooks))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if len(hooks.events) != 1 {
		t.Fatalf("events = %#v", hooks.events)
	}
	event := hooks.events[0]
	if event.Operation != "middleware.authenticate" || event.Outcome != "success" ||
		event.CredentialSource != string(authn.CredentialBearer) {
		t.Fatalf("event = %#v", event)
	}
}

type recordingHooks struct {
	mu     sync.Mutex
	events []observability.Event
}

func (h *recordingHooks) Observe(_ context.Context, event observability.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
}

func stringsContainsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && bytes.Contains([]byte(value), []byte(candidate)) {
			return true
		}
	}
	return false
}
