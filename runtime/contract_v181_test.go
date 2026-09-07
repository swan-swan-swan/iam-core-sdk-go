package iamcore_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/authzcontract"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpcatalog"
)

func TestContractManifestV2JSON(t *testing.T) {
	spec, err := httpauthz.NewRouteSpec("GET", "/api/v1/oidc-clients", "iam.oidcclient.list", "iam:oidc_client:select")
	if err != nil {
		t.Fatal(err)
	}
	manifest := httpcatalog.Manifest{SchemaVersion: httpcatalog.ManifestSchemaVersion, Application: "iam", Service: "iam-core", Release: "dev", Routes: []httpcatalog.Route{{Name: spec.Name, Method: spec.Method, RouteTemplate: spec.RouteTemplate, ResourceServer: spec.ResourceServer, Resource: spec.Resource, Action: spec.Action}}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":"2","application":"iam","service":"iam-core","release":"dev","routes":[{"name":"iam.oidcclient.list","method":"GET","route_template":"/api/v1/oidc-clients","resource_server":"iam","resource":"iam_oidcclient_list","action":"iam:oidc_client:select"}]}`
	if string(raw) != want {
		t.Fatalf("wire manifest = %s", raw)
	}
	parsed, err := authzcontract.ParseAction("iam:oidc_client:select")
	if err != nil || parsed.String() != "iam:oidc_client:select" {
		t.Fatalf("canonical action = %#v, %v", parsed, err)
	}
	if _, err := authzcontract.ParseAction("iam:user:list"); err == nil {
		t.Fatal("accepted unknown verb")
	}
}

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
		Name: "orders.item.list", Method: http.MethodGet, RouteTemplate: "/orders", ResourceServer: "orders_api", Resource: "orders_item_list", Action: "orders_api:orders:select",
	}})
	if err != nil {
		t.Fatal("compile manifest")
	}
	binder := manifest.NewBinder()
	route, err := binder.Bind("orders.item.list")
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
