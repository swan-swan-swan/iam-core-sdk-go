package gin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	ginframework "github.com/gin-gonic/gin"
	iamcore "github.com/swan-swan-swan/iam-core-client-sdk-go"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/memory"
)

const bearerToken = "gin-access-token"

type contextMarker struct{}

type testIAM struct {
	server *httptest.Server

	mu              sync.Mutex
	decisionStatus  int
	decisionAllowed bool
}

func newTestIAM(t *testing.T) *testIAM {
	t.Helper()
	fake := &testIAM{
		decisionStatus:  http.StatusOK,
		decisionAllowed: true,
	}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *testIAM) serveHTTP(w http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 f.server.URL,
			"authorization_endpoint": f.server.URL + "/oidc/authorize",
			"token_endpoint":         f.server.URL + "/oidc/token",
			"userinfo_endpoint":      f.server.URL + "/oidc/userinfo",
			"jwks_uri":               f.server.URL + "/oidc/jwks",
			"end_session_endpoint":   f.server.URL + "/oidc/logout",
			"scopes_supported":       []string{"openid", "profile", "email", "roles"},
		})
	case "/oidc/userinfo":
		if request.Header.Get("Authorization") != "Bearer "+bearerToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sub":"gin-user","username":"jane","roles":["viewer"]}`)
	case "/authorization/v1/decisions":
		f.mu.Lock()
		status := f.decisionStatus
		allowed := f.decisionAllowed
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision_id": "dec-gin",
				"allowed":     allowed,
				"reason_code": map[bool]string{true: "allowed", false: "explicit_deny"}[allowed],
				"request_id":  "req-gin",
				"trace_id":    "trace-gin",
			})
			return
		}
		_, _ = io.WriteString(w, `{"message":"unavailable"}`)
	default:
		http.NotFound(w, request)
	}
}

func (f *testIAM) setDecision(status int, allowed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decisionStatus = status
	f.decisionAllowed = allowed
}

func newClient(t *testing.T, fake *testIAM) *iamcore.Client {
	t.Helper()
	client, err := iamcore.New(t.Context(), iamcore.Config{
		IssuerURL:            fake.server.URL,
		ClientID:             "gin-client",
		ClientSecretProvider: iamcore.StaticSecret("gin-client-secret"),
		RedirectURL:          fake.server.URL + "/callback",
		HTTPClient:           fake.server.Client(),
		Session: iamcore.SessionConfig{
			Backend: memory.New(memory.Options{}),
		},
	})
	if err != nil {
		t.Fatalf("iamcore.New() error = %v", err)
	}
	return client
}

func permission() iamcore.Permission {
	return iamcore.Permission{
		ResourceServer: "asset-api",
		Resource:       "assets",
	}
}

func newRequest(authenticated bool) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/assets", nil)
	request = request.WithContext(context.WithValue(request.Context(), contextMarker{}, "preserved"))
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	return request
}

func serveHTTPPermission(
	t *testing.T,
	client *iamcore.Client,
	authenticated bool,
	nextCalls *int,
) *httptest.ResponseRecorder {
	t.Helper()
	handler := client.RequirePermission(permission())(http.HandlerFunc(
		func(w http.ResponseWriter, request *http.Request) {
			*nextCalls = *nextCalls + 1
			if request.Context().Value(contextMarker{}) != "preserved" {
				t.Fatal("net/http handler lost the incoming request Context")
			}
			identity, ok := iamcore.IdentityFromContext(request.Context())
			if !ok {
				http.Error(w, "missing identity", http.StatusInternalServerError)
				return
			}
			_, _ = io.WriteString(w, `{"sub":"`+identity.Subject+`"}`)
		},
	))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newRequest(authenticated))
	return response
}

func serveGinPermission(
	t *testing.T,
	client *iamcore.Client,
	authenticated bool,
	nextCalls *int,
) *httptest.ResponseRecorder {
	t.Helper()
	ginframework.SetMode(ginframework.TestMode)
	router := ginframework.New()
	router.GET(
		"/assets",
		RequirePermission(client, "asset-api", "assets"),
		func(c *ginframework.Context) {
			*nextCalls = *nextCalls + 1
			if c.Request.Context().Value(contextMarker{}) != "preserved" {
				t.Fatal("Gin handler lost the wrapped request Context")
			}
			identity, ok := Identity(c)
			if !ok {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			decision, ok := Decision(c)
			if !ok || decision.ID != "dec-gin" {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			c.JSON(http.StatusOK, ginframework.H{"sub": identity.Subject})
		},
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, newRequest(authenticated))
	return response
}

func TestRequirePermissionMatchesNetHTTPAndAbortsRejectedRequests(t *testing.T) {
	tests := []struct {
		name            string
		authenticated   bool
		decisionStatus  int
		decisionAllowed bool
	}{
		{
			name:            "unauthenticated",
			authenticated:   false,
			decisionStatus:  http.StatusOK,
			decisionAllowed: true,
		},
		{
			name:            "deny",
			authenticated:   true,
			decisionStatus:  http.StatusOK,
			decisionAllowed: false,
		},
		{
			name:            "unavailable",
			authenticated:   true,
			decisionStatus:  http.StatusServiceUnavailable,
			decisionAllowed: false,
		},
		{
			name:            "allow",
			authenticated:   true,
			decisionStatus:  http.StatusOK,
			decisionAllowed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newTestIAM(t)
			fake.setDecision(test.decisionStatus, test.decisionAllowed)
			client := newClient(t, fake)
			httpCalls, ginCalls := 0, 0

			httpResponse := serveHTTPPermission(t, client, test.authenticated, &httpCalls)
			ginResponse := serveGinPermission(t, client, test.authenticated, &ginCalls)

			if ginResponse.Code != httpResponse.Code {
				t.Fatalf("Gin status = %d, net/http status = %d", ginResponse.Code, httpResponse.Code)
			}
			if ginResponse.Body.String() != httpResponse.Body.String() {
				t.Fatalf("Gin body = %q, net/http body = %q", ginResponse.Body.String(), httpResponse.Body.String())
			}
			wantCalls := 0
			if test.decisionAllowed && test.decisionStatus == http.StatusOK && test.authenticated {
				wantCalls = 1
			}
			if httpCalls != wantCalls || ginCalls != wantCalls {
				t.Fatalf("handler calls: Gin=%d net/http=%d, want %d", ginCalls, httpCalls, wantCalls)
			}
		})
	}
}

func TestAuthenticatePreservesContextAndExposesIdentity(t *testing.T) {
	fake := newTestIAM(t)
	client := newClient(t, fake)
	ginframework.SetMode(ginframework.TestMode)
	router := ginframework.New()
	calls := 0
	router.GET("/profile", Authenticate(client), func(c *ginframework.Context) {
		calls++
		if c.Request.Context().Value(contextMarker{}) != "preserved" {
			t.Fatal("Gin handler lost the wrapped request Context")
		}
		identity, ok := Identity(c)
		if !ok || identity.Subject != "gin-user" {
			t.Fatalf("identity = %#v ok=%v", identity, ok)
		}
		if _, ok := Decision(c); ok {
			t.Fatal("Authenticate unexpectedly stored a decision")
		}
		c.Status(http.StatusNoContent)
	})

	response := httptest.NewRecorder()
	request := newRequest(true)
	request.URL.Path = "/profile"
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
}

func TestConstructorsPanicWithStaticMessageForNilClient(t *testing.T) {
	var client *iamcore.Client
	for _, test := range []struct {
		name      string
		construct func()
	}{
		{"Authenticate", func() { _ = Authenticate(client) }},
		{"RequirePermission", func() { _ = RequirePermission(client, "asset-api", "assets") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != "iamcore/gin: nil Client" {
					t.Fatalf("panic = %#v", recovered)
				}
			}()
			test.construct()
		})
	}
}

func TestContextHelpersRejectNilContext(t *testing.T) {
	if identity, ok := Identity(nil); ok || identity.Subject != "" {
		t.Fatalf("Identity(nil) = %#v, %v", identity, ok)
	}
	if decision, ok := Decision(nil); ok || decision != (iamcore.Decision{}) {
		t.Fatalf("Decision(nil) = %#v, %v", decision, ok)
	}
}

func TestContextHelpersRejectContextWithoutRequest(t *testing.T) {
	c := &ginframework.Context{}
	if identity, ok := Identity(c); ok || identity.Subject != "" {
		t.Fatalf("Identity(empty Context) = %#v, %v", identity, ok)
	}
	if decision, ok := Decision(c); ok || decision != (iamcore.Decision{}) {
		t.Fatalf("Decision(empty Context) = %#v, %v", decision, ok)
	}
}
