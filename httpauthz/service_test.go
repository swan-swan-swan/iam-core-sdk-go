package httpauthz_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz"
)

type fakeVerifier struct {
	auth     core.AuthContext
	err      error
	calls    int
	rawToken string
}

func (f *fakeVerifier) VerifyAccessToken(_ context.Context, raw string) (core.AuthContext, error) {
	f.calls++
	f.rawToken = raw
	return f.auth, f.err
}

type fakeAuthorizer struct {
	decision     httpauthz.Decision
	err          error
	calls        int
	route        httpauthz.Route
	captureToken bool
	token        string
	tokenErr     error
}

func (f *fakeAuthorizer) Decide(ctx context.Context, tokens core.TokenSource, route httpauthz.Route) (httpauthz.Decision, error) {
	f.calls++
	f.route = route
	if f.captureToken {
		f.token, f.tokenErr = tokens.AccessToken(ctx)
	}
	return f.decision, f.err
}

type fakeSessionResolver struct {
	credential     core.Credential
	present        bool
	presentErr     error
	resolvePresent bool
	resolveErr     error
	presentCalls   int
	resolveCalls   int
}

func (f *fakeSessionResolver) SessionPresent(*http.Request) (bool, error) {
	f.presentCalls++
	return f.present, f.presentErr
}

func (f *fakeSessionResolver) ResolveSession(*http.Request) (core.Credential, bool, error) {
	f.resolveCalls++
	return f.credential, f.resolvePresent, f.resolveErr
}

type nilTokenSource struct{}

func (*nilTokenSource) AccessToken(context.Context) (string, error) { return "", nil }

func validAuth() core.AuthContext {
	return core.AuthContext{
		Subject: "op_usr_1", Issuer: "https://iam.example", Audience: []string{"portal"},
		TokenID: "jti-1", ExpiresAt: time.Now().Add(time.Minute), Scopes: []string{"openid"}, Groups: []string{"ops"},
	}
}

func credentialWithToken(token string) core.Credential {
	return core.Credential{
		Source: core.CredentialSession, SessionID: "session-1", Auth: validAuth(),
		Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return token, nil }),
	}
}

func boundRoute(t *testing.T) httpauthz.Route {
	t.Helper()
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{
		Name: "list_orders", Method: http.MethodGet, ResourceServer: "orders_api", Resource: "orders",
	}})
	if err != nil {
		t.Fatal(err)
	}
	binder := manifest.NewBinder()
	route, err := binder.Bind("list_orders")
	if err != nil {
		t.Fatal(err)
	}
	if err := binder.Validate(); err != nil {
		t.Fatal(err)
	}
	return route
}

func TestNewRejectsNilAndTypedNilDependencies(t *testing.T) {
	validVerifier := &fakeVerifier{auth: validAuth()}
	validPDP := &fakeAuthorizer{}
	var nilVerifier *fakeVerifier
	var nilPDP *fakeAuthorizer
	var nilSessions *fakeSessionResolver
	var nilResponder httpauthz.ErrorResponderFunc
	var nilObserver *countingObserver

	tests := []struct {
		name string
		cfg  httpauthz.Config
	}{
		{name: "missing verifier", cfg: httpauthz.Config{PDP: validPDP}},
		{name: "typed nil verifier", cfg: httpauthz.Config{Verifier: nilVerifier, PDP: validPDP}},
		{name: "missing PDP", cfg: httpauthz.Config{Verifier: validVerifier}},
		{name: "typed nil PDP", cfg: httpauthz.Config{Verifier: validVerifier, PDP: nilPDP}},
		{name: "typed nil sessions", cfg: httpauthz.Config{Verifier: validVerifier, PDP: validPDP, Sessions: nilSessions}},
		{name: "typed nil responder", cfg: httpauthz.Config{Verifier: validVerifier, PDP: validPDP, Responder: nilResponder}},
		{name: "typed nil observer", cfg: httpauthz.Config{Verifier: validVerifier, PDP: validPDP, Observer: nilObserver}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := httpauthz.New(test.cfg)
			if service != nil || err == nil {
				t.Fatalf("New() = %v, %v", service, err)
			}
			var typed *core.Error
			if !errors.As(err, &typed) || typed == nil || typed.Kind != core.KindInvalidConfig {
				t.Fatalf("New() error = %T", err)
			}
		})
	}
}

type countingObserver struct{}

func (*countingObserver) Observe(context.Context, core.Event) {}

func TestNewAllowsOptionalDependenciesToBeAbsent(t *testing.T) {
	service, err := httpauthz.New(httpauthz.Config{Verifier: &fakeVerifier{auth: validAuth()}, PDP: &fakeAuthorizer{}})
	if err != nil || service == nil {
		t.Fatalf("New() = %v, %v", service, err)
	}
}

func TestMiddlewareConstructorsFailFastForHandlerAndRoute(t *testing.T) {
	verifier := &fakeVerifier{auth: validAuth()}
	pdp := &fakeAuthorizer{}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: pdp})
	if err != nil {
		t.Fatal(err)
	}
	var typedNil http.HandlerFunc
	for name, handler := range map[string]http.Handler{"nil": nil, "typed nil": typedNil} {
		t.Run("authenticate "+name, func(t *testing.T) {
			if got, err := service.Authenticate(handler); got != nil || err == nil {
				t.Fatalf("Authenticate() = %v, %v", got, err)
			}
		})
		t.Run("require "+name, func(t *testing.T) {
			if got, err := service.Require(boundRoute(t), handler); got != nil || err == nil {
				t.Fatalf("Require() = %v, %v", got, err)
			}
		})
	}
	if got, err := service.Require(httpauthz.Route{}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); got != nil || err == nil {
		t.Fatalf("Require(invalid route) = %v, %v", got, err)
	}
	if verifier.calls != 0 || pdp.calls != 0 {
		t.Fatalf("construction performed request work: verifier/PDP=%d/%d", verifier.calls, pdp.calls)
	}
}

func TestNilServiceRejectsMiddlewareConstruction(t *testing.T) {
	var service *httpauthz.Service
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if got, err := service.Authenticate(next); got != nil || err == nil {
		t.Fatalf("Authenticate() = %v, %v", got, err)
	}
	if got, err := service.Require(boundRoute(t), next); got != nil || err == nil {
		t.Fatalf("Require() = %v, %v", got, err)
	}
}
