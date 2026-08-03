package ginadapter_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	ginadapter "github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/gin"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz"
)

type verifier struct {
	auth  core.AuthContext
	err   error
	calls atomic.Int64
}

func (v *verifier) VerifyAccessToken(context.Context, string) (core.AuthContext, error) {
	v.calls.Add(1)
	return v.auth, v.err
}

type authorizer struct {
	decision httpauthz.Decision
	err      error
	calls    atomic.Int64
}

func (a *authorizer) Decide(context.Context, core.TokenSource, httpauthz.Route) (httpauthz.Decision, error) {
	a.calls.Add(1)
	return a.decision, a.err
}

func TestRequireAllowsOnceAndExposesRootContexts(t *testing.T) {
	service, route, pdp := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow", RequestID: "request-1", TraceID: "trace-1",
	}, nil, nil)
	middleware, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}

	router := newRouter()
	var downstream atomic.Int64
	router.GET("/orders", middleware, func(c *gin.Context) {
		downstream.Add(1)
		auth, ok := ginadapter.AuthContext(c)
		if !ok || auth.Subject != "op_usr_1" || auth.DecisionID != "decision-allow" || auth.ReasonCode != "policy_allow" {
			t.Fatalf("AuthContext() = redacted, %v", ok)
		}
		decision, ok := ginadapter.Decision(c)
		if !ok || decision != (httpauthz.Decision{ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow", RequestID: "request-1", TraceID: "trace-1"}) {
			t.Fatalf("Decision() = %#v, %v", decision, ok)
		}
		c.Header("X-Application", "orders")
		c.String(http.StatusCreated, "created")
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest(http.MethodGet, "/orders"))
	if response.Code != http.StatusCreated || response.Body.String() != "created" || response.Header().Get("X-Application") != "orders" ||
		response.Header().Get("X-IAM-Decision-ID") != "decision-allow" || downstream.Load() != 1 || pdp.calls.Load() != 1 {
		t.Fatalf("status/body/app-header/decision-header/downstream/pdp = %d/%q/%q/%q/%d/%d",
			response.Code, response.Body.String(), response.Header().Get("X-Application"),
			response.Header().Get("X-IAM-Decision-ID"), downstream.Load(), pdp.calls.Load())
	}
}

func TestRequireDeniesWithoutChangingRootResponse(t *testing.T) {
	const rootBody = "root-denied\n"
	responder := httpauthz.ErrorResponderFunc(func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.Header().Add("X-Root-Response", "first")
		w.Header().Add("X-Root-Response", "second")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(rootBody))
	})
	service, route, pdp := newService(t, httpauthz.Decision{ID: "decision-deny", Allowed: false, ReasonCode: "default_deny"}, nil, responder)
	middleware, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}
	router := newRouter()
	var downstream atomic.Int64
	router.GET("/orders", middleware, func(*gin.Context) { downstream.Add(1) })

	response := httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest(http.MethodGet, "/orders"))
	if response.Code != http.StatusForbidden || response.Body.String() != rootBody ||
		strings.Join(response.Header().Values("X-Root-Response"), ",") != "first,second" ||
		response.Header().Get("X-IAM-Decision-ID") != "decision-deny" || downstream.Load() != 0 || pdp.calls.Load() != 1 {
		t.Fatalf("status/body/root-header/decision-header/downstream/pdp = %d/%q/%q/%q/%d/%d",
			response.Code, response.Body.String(), strings.Join(response.Header().Values("X-Root-Response"), ","),
			response.Header().Get("X-IAM-Decision-ID"), downstream.Load(), pdp.calls.Load())
	}
}

func TestRequireFailsClosedExactlyLikeRootMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		decision   httpauthz.Decision
		pdpErr     error
		wantStatus int
	}{
		{name: "deny", decision: httpauthz.Decision{ID: "decision-deny", Allowed: false, ReasonCode: "default_deny"}, wantStatus: http.StatusForbidden},
		{name: "PDP unauthenticated", pdpErr: core.NewError(core.KindUnauthenticated, "httpauthz.decide", http.StatusUnauthorized, false, nil), wantStatus: http.StatusUnauthorized},
		{name: "PDP unavailable", pdpErr: core.NewError(core.KindIAMUnavailable, "httpauthz.decide", http.StatusServiceUnavailable, true, nil), wantStatus: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, route, pdp := newService(t, test.decision, test.pdpErr, nil)
			middleware, err := ginadapter.Require(service, route)
			if err != nil {
				t.Fatal(err)
			}
			router := newRouter()
			var downstream atomic.Int64
			router.GET("/orders", middleware, func(*gin.Context) { downstream.Add(1) })
			response := httptest.NewRecorder()
			router.ServeHTTP(response, signedRequest(http.MethodGet, "/orders"))
			if response.Code != test.wantStatus || downstream.Load() != 0 || pdp.calls.Load() != 1 {
				t.Fatalf("status/downstream/pdp = %d/%d/%d", response.Code, downstream.Load(), pdp.calls.Load())
			}
		})
	}
}

func TestRequireRejectsMissingCredentialBeforePDPAndDownstream(t *testing.T) {
	service, route, pdp := newService(t, httpauthz.Decision{ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow"}, nil, nil)
	middleware, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}
	router := newRouter()
	var downstream atomic.Int64
	router.GET("/orders", middleware, func(*gin.Context) { downstream.Add(1) })
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if response.Code != http.StatusUnauthorized || downstream.Load() != 0 || pdp.calls.Load() != 0 {
		t.Fatalf("status/downstream/pdp = %d/%d/%d", response.Code, downstream.Load(), pdp.calls.Load())
	}
}

func TestAuthenticateAddsAuthWithoutDecisionOrPDP(t *testing.T) {
	service, _, pdp := newService(t, httpauthz.Decision{ID: "must-not-run", Allowed: true, ReasonCode: "policy_allow"}, nil, nil)
	middleware, err := ginadapter.Authenticate(service)
	if err != nil {
		t.Fatal(err)
	}
	router := newRouter()
	var downstream atomic.Int64
	router.GET("/profile", middleware, func(c *gin.Context) {
		downstream.Add(1)
		auth, ok := ginadapter.AuthContext(c)
		if !ok || auth.Subject != "op_usr_1" || auth.DecisionID != "" || auth.ReasonCode != "" {
			t.Fatalf("AuthContext() = redacted, %v", ok)
		}
		if decision, ok := ginadapter.Decision(c); ok || decision != (httpauthz.Decision{}) {
			t.Fatalf("Decision() = %#v, %v", decision, ok)
		}
		c.Status(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest(http.MethodGet, "/profile"))
	if response.Code != http.StatusNoContent || downstream.Load() != 1 || pdp.calls.Load() != 0 {
		t.Fatalf("status/downstream/pdp = %d/%d/%d", response.Code, downstream.Load(), pdp.calls.Load())
	}
}

func TestContextHelpersUseRequestContextAndPreserveDefensiveCopies(t *testing.T) {
	service, route, _ := newService(t, httpauthz.Decision{ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow"}, nil, nil)
	middleware, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}
	router := newRouter()
	router.GET("/orders", middleware, func(c *gin.Context) {
		c.Set("AuthContext", core.AuthContext{Subject: "untrusted-gin-value"})
		auth, ok := ginadapter.AuthContext(c)
		if !ok || auth.Subject != "op_usr_1" {
			t.Fatalf("AuthContext() = redacted, %v", ok)
		}
		auth.Audience[0] = "mutated"
		auth.Scopes[0] = "mutated"
		auth.Groups[0] = "mutated"
		again, ok := ginadapter.AuthContext(c)
		if !ok || again.Audience[0] != "orders-api" || again.Scopes[0] != "orders.read" || again.Groups[0] != "operators" {
			t.Fatal("AuthContext() did not retain root defensive-copy semantics")
		}
		decision, ok := ginadapter.Decision(c)
		if !ok {
			t.Fatal("Decision() was absent")
		}
		decision.ID = "mutated"
		againDecision, ok := ginadapter.Decision(c)
		if !ok || againDecision.ID != "decision-allow" {
			t.Fatal("Decision() did not retain root value semantics")
		}
		c.Status(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest(http.MethodGet, "/orders"))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestContextHelpersRejectNilContextAndRequest(t *testing.T) {
	var nilContext *gin.Context
	if auth, ok := ginadapter.AuthContext(nilContext); ok || !reflect.DeepEqual(auth, core.AuthContext{}) {
		t.Fatalf("AuthContext(nil) = %#v, %v", auth, ok)
	}
	if decision, ok := ginadapter.Decision(nilContext); ok || decision != (httpauthz.Decision{}) {
		t.Fatalf("Decision(nil) = %#v, %v", decision, ok)
	}
	emptyContext := &gin.Context{}
	if auth, ok := ginadapter.AuthContext(emptyContext); ok || !reflect.DeepEqual(auth, core.AuthContext{}) {
		t.Fatalf("AuthContext(empty) = %#v, %v", auth, ok)
	}
	if decision, ok := ginadapter.Decision(emptyContext); ok || decision != (httpauthz.Decision{}) {
		t.Fatalf("Decision(empty) = %#v, %v", decision, ok)
	}
}

func TestEscapedRequestContextMatchesRootMiddlewareShape(t *testing.T) {
	directService, directRoute, _ := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow",
	}, nil, nil)
	var directContext context.Context
	directHandler, err := directService.Require(directRoute, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		directContext = request.Context()
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	directHandler.ServeHTTP(httptest.NewRecorder(), signedRequest(http.MethodGet, "/orders"))

	service, route, _ := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow",
	}, nil, nil)
	middleware, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}
	var escapedRequest *http.Request
	router := newRouter()
	router.GET("/orders", middleware, func(c *gin.Context) {
		escapedRequest = c.Request
		c.Status(http.StatusNoContent)
	})
	router.ServeHTTP(httptest.NewRecorder(), signedRequest(http.MethodGet, "/orders"))

	if escapedRequest == nil || directContext == nil {
		t.Fatal("middleware did not reach terminal handler")
	}
	if got, want := contextShape(escapedRequest.Context()), contextShape(directContext); !reflect.DeepEqual(got, want) {
		t.Fatalf("adapter added lifecycle state to escaped Request.Context(): shape=%v, root=%v", got, want)
	}
}

func TestNestedAdaptersDoNotLayerLifecycleStateInRequestContext(t *testing.T) {
	directService, directRoute, directPDP := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow",
	}, nil, nil)
	var directContext context.Context
	required, err := directService.Require(directRoute, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		directContext = request.Context()
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := directService.Authenticate(required)
	if err != nil {
		t.Fatal(err)
	}
	authenticated.ServeHTTP(httptest.NewRecorder(), signedRequest(http.MethodGet, "/orders"))
	if directPDP.calls.Load() != 1 {
		t.Fatalf("direct PDP calls = %d", directPDP.calls.Load())
	}

	service, route, pdp := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow",
	}, nil, nil)
	authenticate, err := ginadapter.Authenticate(service)
	if err != nil {
		t.Fatal(err)
	}
	require, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}
	var escapedContext context.Context
	var downstream atomic.Int64
	router := newRouter()
	router.GET("/orders", authenticate, require, func(c *gin.Context) {
		downstream.Add(1)
		escapedContext = c.Request.Context()
		c.Status(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest(http.MethodGet, "/orders"))

	if response.Code != http.StatusNoContent || downstream.Load() != 1 || pdp.calls.Load() != 1 || escapedContext == nil {
		t.Fatalf("status/downstream/pdp/context = %d/%d/%d/%v", response.Code, downstream.Load(), pdp.calls.Load(), escapedContext != nil)
	}
	if got, want := contextShape(escapedContext), contextShape(directContext); !reflect.DeepEqual(got, want) {
		t.Fatalf("nested adapters layered lifecycle state: shape=%v, root=%v", got, want)
	}
}

func TestAdapterDoesNotRetainLifecycleStateAcrossRequests(t *testing.T) {
	directService, directRoute, _ := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow",
	}, nil, nil)
	var directContext context.Context
	directHandler, err := directService.Require(directRoute, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		directContext = request.Context()
	}))
	if err != nil {
		t.Fatal(err)
	}
	directHandler.ServeHTTP(httptest.NewRecorder(), signedRequest(http.MethodGet, "/orders"))
	directShape := contextShape(directContext)

	service, route, pdp := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow",
	}, nil, nil)
	middleware, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}
	const requests = 64
	escaped := make([]*http.Request, 0, requests)
	router := newRouter()
	router.GET("/orders", middleware, func(c *gin.Context) {
		escaped = append(escaped, c.Request)
		c.Status(http.StatusNoContent)
	})
	for range requests {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, signedRequest(http.MethodGet, "/orders"))
		if response.Code != http.StatusNoContent {
			t.Fatalf("status = %d", response.Code)
		}
	}
	if len(escaped) != requests || pdp.calls.Load() != requests {
		t.Fatalf("escaped/PDP = %d/%d", len(escaped), pdp.calls.Load())
	}
	for index, request := range escaped {
		auth, authOK := core.AuthContextFromContext(request.Context())
		decision, decisionOK := httpauthz.DecisionFromContext(request.Context())
		if !authOK || auth.Subject != "op_usr_1" || !decisionOK || decision.ID != "decision-allow" {
			t.Fatalf("request %d lost root contexts", index)
		}
		if shape := contextShape(request.Context()); !reflect.DeepEqual(shape, directShape) {
			t.Fatalf("request %d retained adapter lifecycle state: shape=%v, root=%v", index, shape, directShape)
		}
	}
}

func TestAdmissionWriterDoesNotReplaceGinWriter(t *testing.T) {
	service, route, _ := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow",
	}, nil, nil)
	middleware, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}
	var original gin.ResponseWriter
	router := newRouter()
	router.GET("/orders",
		func(c *gin.Context) {
			original = c.Writer
			c.Next()
			if c.Writer != original {
				t.Error("adapter retained its writer after the synchronous call")
			}
		},
		middleware,
		func(c *gin.Context) {
			if c.Writer != original {
				t.Error("adapter exposed its writer to downstream Gin handlers")
			}
			c.String(http.StatusOK, "unchanged")
		},
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest(http.MethodGet, "/orders"))
	if response.Code != http.StatusOK || response.Body.String() != "unchanged" {
		t.Fatalf("status/body = %d/%q", response.Code, response.Body.String())
	}
}

func TestMiddlewareHandlerRejectsNilContextAndRequest(t *testing.T) {
	service, route, _ := newService(t, httpauthz.Decision{
		ID: "decision-allow", Allowed: true, ReasonCode: "policy_allow",
	}, nil, nil)
	middleware, err := ginadapter.Require(service, route)
	if err != nil {
		t.Fatal(err)
	}
	middleware(nil)
	empty := &gin.Context{}
	middleware(empty)
	if !empty.IsAborted() {
		t.Fatal("middleware did not abort a nil request")
	}
}

func TestConstructorsPropagateTypedSanitizedRootErrors(t *testing.T) {
	service, _, _ := newService(t, httpauthz.Decision{}, nil, nil)
	var nilService *httpauthz.Service
	tests := []struct {
		name string
		call func() (gin.HandlerFunc, error)
	}{
		{name: "nil authenticate service", call: func() (gin.HandlerFunc, error) { return ginadapter.Authenticate(nil) }},
		{name: "typed nil authenticate service", call: func() (gin.HandlerFunc, error) { return ginadapter.Authenticate(nilService) }},
		{name: "nil require service", call: func() (gin.HandlerFunc, error) { return ginadapter.Require(nil, httpauthz.Route{}) }},
		{name: "typed nil require service", call: func() (gin.HandlerFunc, error) { return ginadapter.Require(nilService, httpauthz.Route{}) }},
		{name: "invalid route", call: func() (gin.HandlerFunc, error) { return ginadapter.Require(service, httpauthz.Route{}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := test.call()
			if handler != nil || err == nil {
				t.Fatalf("constructor = %v, %v", handler, err)
			}
			var typed *core.Error
			if !errors.As(err, &typed) || typed == nil || typed.Kind != core.KindInvalidConfig ||
				typed.Operation != "httpauthz.configure" || err.Error() != "httpauthz.configure: invalid_config" {
				t.Fatalf("error = %T %q", err, err)
			}
		})
	}
}

func newRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func newService(t *testing.T, decision httpauthz.Decision, pdpErr error, responder httpauthz.ErrorResponder) (*httpauthz.Service, httpauthz.Route, *authorizer) {
	t.Helper()
	pdp := &authorizer{decision: decision, err: pdpErr}
	service, err := httpauthz.New(httpauthz.Config{
		Verifier: &verifier{auth: core.AuthContext{
			Subject: "op_usr_1", Issuer: "https://iam.example", Audience: []string{"orders-api"},
			TokenID: "jti-1", IssuedAt: time.Unix(100, 0), ExpiresAt: time.Unix(200, 0),
			Scopes: []string{"orders.read"}, Groups: []string{"operators"},
		}},
		PDP: pdp, Responder: responder,
	})
	if err != nil {
		t.Fatal(err)
	}
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
	return service, route, pdp
}

func signedRequest(method, path string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Authorization", "Bearer access-token")
	return request
}

func contextShape(ctx context.Context) []string {
	var shape []string
	for ctx != nil {
		value := reflect.ValueOf(ctx)
		shape = append(shape, value.Type().String())
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				break
			}
			value = value.Elem()
		}
		parent := value.FieldByName("Context")
		if !parent.IsValid() || !parent.CanInterface() {
			break
		}
		var ok bool
		ctx, ok = parent.Interface().(context.Context)
		if !ok {
			break
		}
	}
	return shape
}
