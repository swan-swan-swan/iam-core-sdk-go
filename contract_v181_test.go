package iamcore_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz"
)

func TestV181FrozenContract(t *testing.T) {
	if core.ContractVersion != "v1.8.1" {
		t.Fatalf("contract version=%q", core.ContractVersion)
	}
	wantScopes := []string{"openid", "profile", "email", "groups"}
	gotScopes := bff.DefaultScopes()
	if !slices.Equal(gotScopes, wantScopes) || slices.Contains(gotScopes, "roles") {
		t.Fatalf("default scopes=%v", gotScopes)
	}
	gotScopes[0] = "mutated"
	if second := bff.DefaultScopes(); !slices.Equal(second, wantScopes) {
		t.Fatalf("default scopes after caller mutation=%v", second)
	}
}

type contractVerifier struct{ calls int }

func (v *contractVerifier) VerifyAccessToken(context.Context, string) (core.AuthContext, error) {
	v.calls++
	return core.AuthContext{Subject: "contract-subject"}, nil
}

type contractAuthorizer struct {
	calls    int
	decision httpauthz.Decision
}

func (a *contractAuthorizer) Decide(context.Context, core.TokenSource, httpauthz.Route) (httpauthz.Decision, error) {
	a.calls++
	return a.decision, nil
}

func TestV181RequireMakesOnePDPDecisionOnlyAfterValidBearer(t *testing.T) {
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{
		Name: "list_orders", Method: http.MethodGet, ResourceServer: "orders_api", Resource: "orders",
	}})
	if err != nil {
		t.Fatal("compile manifest")
	}
	binder := manifest.NewBinder()
	route, err := binder.Bind("list_orders")
	if err != nil {
		t.Fatal("bind route")
	}
	if err := binder.Validate(); err != nil {
		t.Fatal("validate manifest")
	}

	verifier := &contractVerifier{}
	authorizer := &contractAuthorizer{decision: httpauthz.Decision{ID: "decision-1", Allowed: true, ReasonCode: "allow"}}
	service, err := httpauthz.New(httpauthz.Config{Verifier: verifier, PDP: authorizer})
	if err != nil {
		t.Fatal("create authorization service")
	}
	handlerCalls := 0
	handler, err := service.Require(route, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal("require route")
	}

	allowed := httptest.NewRequest(http.MethodGet, "/orders", nil)
	allowed.Header.Set("Authorization", "Bearer opaque-contract-token")
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusNoContent || verifier.calls != 1 || authorizer.calls != 1 || handlerCalls != 1 {
		t.Fatalf("allow status/verifier/authorizer/handler=%d/%d/%d/%d", allowedResponse.Code, verifier.calls, authorizer.calls, handlerCalls)
	}

	verifier.calls = 0
	authorizer.calls = 0
	handlerCalls = 0
	invalid := httptest.NewRequest(http.MethodGet, "/orders", nil)
	invalid.Header.Set("Authorization", "Bearer !")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusUnauthorized || verifier.calls != 0 || authorizer.calls != 0 || handlerCalls != 0 {
		t.Fatalf("invalid status/verifier/authorizer/handler=%d/%d/%d/%d", invalidResponse.Code, verifier.calls, authorizer.calls, handlerCalls)
	}
}
