package authz

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
)

func TestDecideSendsOnlyThreeAllowedFields(t *testing.T) {
	server, captured := newDecisionServer(t, http.StatusOK, `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"allowed"},"request_id":"req-1","trace_id":"trace-1"}`)
	client := newDecisionClient(t, server)
	decision, err := client.Decide(context.Background(), "access-token", Permission{ResourceServer: "asset-api", Resource: "assets", HTTPMethod: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := captured.Load().(string), `{"resource_server":"asset-api","resource":"assets","http_method":"GET"}`; got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	if !decision.Allowed || decision.ID != "dec-1" || decision.RequestID != "req-1" || decision.TraceID != "trace-1" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestDecideSetsPostBearerAndJSONHeaders(t *testing.T) {
	var method, authorization, contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, authorization, contentType = r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision_id":"dec-1","allowed":true,"reason_code":"allowed"}`)
	}))
	defer server.Close()
	client := newDecisionClient(t, server)
	if _, err := client.Decide(context.Background(), "access-token", validPermission()); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || authorization != "Bearer access-token" || contentType != "application/json" {
		t.Fatalf("request = method %q authorization %q content type %q", method, authorization, contentType)
	}
}

func TestDecideSupportsDirectResponseAndUnknownReasonCode(t *testing.T) {
	server, _ := newDecisionServer(t, http.StatusOK, `{"decision_id":"dec-1","allowed":true,"reason_code":"future_reason"}`)
	defer server.Close()
	decision, err := newDecisionClient(t, server).Decide(context.Background(), "access-token", validPermission())
	if err != nil || !decision.Allowed || decision.ReasonCode != "future_reason" {
		t.Fatalf("decision %#v, err %v", decision, err)
	}
}

func TestDecideDenyIsSuccessful(t *testing.T) {
	server, _ := newDecisionServer(t, http.StatusOK, `{"code":0,"data":{"decision_id":"dec-1","allowed":false,"reason_code":"policy_denied"}}`)
	defer server.Close()
	decision, err := newDecisionClient(t, server).Decide(context.Background(), "access-token", validPermission())
	if err != nil || decision.Allowed || decision.ReasonCode != "policy_denied" {
		t.Fatalf("decision %#v, err %v", decision, err)
	}
}

func TestDecideFailsClosedForStatus(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		kind   sdkerr.Kind
		retry  bool
	}{
		{"bad request", http.StatusBadRequest, sdkerr.KindProtocol, false},
		{"unauthenticated", http.StatusUnauthorized, sdkerr.KindUnauthenticated, false},
		{"unavailable", http.StatusServiceUnavailable, sdkerr.KindIAMUnavailable, true},
		{"invalid six hundred", 600, sdkerr.KindProtocol, false},
		{"invalid six ninety-nine", 699, sdkerr.KindProtocol, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := newDecisionServer(t, test.status, `{"message":"hostile-secret"}`)
			defer server.Close()
			decision, err := newDecisionClient(t, server).Decide(context.Background(), "access-token", validPermission())
			if decision.Allowed || err == nil {
				t.Fatalf("decision %#v, err %v", decision, err)
			}
			assertDecisionError(t, err, test.kind, test.status, test.retry, "hostile-secret", "access-token")
		})
	}
}

func TestDecideFailsClosedForInvalidSuccessResponses(t *testing.T) {
	for _, body := range []string{
		``, `not-json`, `{`, `{"decision_id":"dec-1","allowed":true,"reason_code":"ok"} trailing`,
		`{"decision_id":"dec-1","decision_id":"dec-2","allowed":true,"reason_code":"ok"}`,
		`{"decision_id":"dec-1","reason_code":"ok"}`,
		`{"decision_id":"dec-1","allowed":"true","reason_code":"ok"}`,
		`{"allowed":false,"reason_code":"denied"}`,
		`{"decision_id":"dec-1","allowed":false}`,
		`{"code":99,"data":{"decision_id":"dec-1","allowed":true,"reason_code":"ok"}}`,
	} {
		t.Run(body, func(t *testing.T) {
			server, _ := newDecisionServer(t, http.StatusOK, body)
			defer server.Close()
			decision, err := newDecisionClient(t, server).Decide(context.Background(), "access-token", validPermission())
			if err == nil || decision.Allowed {
				t.Fatalf("decision %#v, err %v", decision, err)
			}
			assertDecisionError(t, err, sdkerr.KindProtocol, http.StatusOK, false, body, "access-token")
		})
	}
}

func TestDecideFailsClosedForNonJSONAndNoContent(t *testing.T) {
	for _, test := range []struct {
		name, contentType, body string
		status                  int
	}{
		{"non-json success", "text/plain", `hostile-secret`, http.StatusOK},
		{"no content", "application/json", ``, http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			decision, err := newDecisionClient(t, server).Decide(context.Background(), "access-token", validPermission())
			if err == nil || decision.Allowed {
				t.Fatalf("decision %#v, err %v", decision, err)
			}
			assertDecisionError(t, err, sdkerr.KindProtocol, test.status, false, "hostile-secret", "access-token")
		})
	}
}

func TestDecideOnlyMakesOneFreshRequestPerCall(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if calls.Load() == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"decision_id":"dec-2","allowed":true,"reason_code":"allowed"}`)
	}))
	defer server.Close()
	client := newDecisionClient(t, server)
	if _, err := client.Decide(context.Background(), "access-token", validPermission()); err == nil {
		t.Fatal("first decision unexpectedly succeeded")
	}
	if decision, err := client.Decide(context.Background(), "access-token", validPermission()); err != nil || !decision.Allowed {
		t.Fatalf("second decision %#v, err %v", decision, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
}

func TestNewValidatesIssuerAndEndpoint(t *testing.T) {
	for _, config := range []Config{
		{}, {IssuerURL: "http://example.com"}, {IssuerURL: "https://example.com/?secret=value"},
		{IssuerURL: "https://issuer.example?"}, {IssuerURL: "https://issuer.example#fragment"}, {IssuerURL: "https://user@issuer.example"},
		{IssuerURL: "https://example.com", Endpoint: "http://example.com/authorization/v1/decisions"},
		{IssuerURL: "https://example.com", Endpoint: "https://example.com/authorization/v1/decisions#fragment"},
	} {
		if client, err := New(config); err == nil || client != nil {
			t.Fatalf("New(%#v) = %v, %v", config, client, err)
		}
	}
	client, err := New(Config{IssuerURL: "https://issuer.example/", Endpoint: "https://pdp.example/authorization/v1/decisions?tenant=safe"})
	if err != nil || client == nil {
		t.Fatalf("New valid endpoint: %v", err)
	}
}

func TestNewDerivesExactDecisionPathFromIssuer(t *testing.T) {
	client, err := New(Config{IssuerURL: "https://issuer.example/base/"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := client.endpoint, "https://issuer.example/base/authorization/v1/decisions"; got != want {
		t.Fatalf("endpoint = %q, want %q", got, want)
	}
}

func TestDecidePreservesConfiguredEndpointQuery(t *testing.T) {
	var gotPath, gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision_id":"dec-1","allowed":true,"reason_code":"allowed"}`)
	}))
	defer server.Close()
	client, err := New(Config{IssuerURL: server.URL, Endpoint: server.URL + "/custom?tenant=one%2Ftwo", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Decide(context.Background(), "access-token", validPermission()); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/custom" || gotQuery != "tenant=one%2Ftwo" {
		t.Fatalf("endpoint = %s?%s", gotPath, gotQuery)
	}
}

func TestDecideAllowsFutureEnvelopeStatusExtension(t *testing.T) {
	server, _ := newDecisionServer(t, http.StatusOK, `{"code":0,"status":400,"data":{"decision_id":"dec-1","allowed":true,"reason_code":"allowed"}}`)
	defer server.Close()
	decision, err := newDecisionClient(t, server).Decide(context.Background(), "access-token", validPermission())
	if err != nil || !decision.Allowed {
		t.Fatalf("decision %#v, err %v", decision, err)
	}
}

func TestDecideRejectsWrongTypedKnownCorrelation(t *testing.T) {
	for _, body := range []string{
		`{"decision_id":"dec-1","allowed":true,"reason_code":"allowed","request_id":null}`,
		`{"decision_id":"dec-1","allowed":true,"reason_code":"allowed","trace_id":1}`,
		`{"code":0,"data":{"decision_id":"dec-1","allowed":true,"reason_code":"allowed"},"request_id":false}`,
		`{"code":0,"data":{"decision_id":"dec-1","allowed":true,"reason_code":"allowed"},"trace_id":null}`,
	} {
		t.Run(body, func(t *testing.T) {
			server, _ := newDecisionServer(t, http.StatusOK, body)
			defer server.Close()
			_, err := newDecisionClient(t, server).Decide(context.Background(), "access-token", validPermission())
			assertDecisionError(t, err, sdkerr.KindProtocol, http.StatusOK, false)
		})
	}
}

func TestDecideAcceptsOpaqueDecisionIDsWithoutLoggingThem(t *testing.T) {
	const opaqueID = "opaque+id=with@valid/json:characters"
	for _, test := range []struct {
		name     string
		response string
		allowed  bool
	}{
		{"direct allow", `{"decision_id":"opaque+id=with@valid/json:characters","allowed":true,"reason_code":"allowed"}`, true},
		{"envelope deny", `{"code":0,"data":{"decision_id":"opaque+id=with@valid/json:characters","allowed":false,"reason_code":"denied"}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := newDecisionServer(t, http.StatusOK, test.response)
			defer server.Close()
			var logs bytes.Buffer
			hook := &recordingHook{}
			client, err := New(Config{
				IssuerURL:  server.URL,
				HTTPClient: server.Client(),
				Hooks:      hook,
				Logger:     slog.New(slog.NewTextHandler(&logs, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			decision, err := client.Decide(context.Background(), "access-token", validPermission())
			if err != nil || decision.ID != opaqueID || decision.Allowed != test.allowed {
				t.Fatalf("decision %#v, err %v", decision, err)
			}
			if strings.Contains(logs.String(), opaqueID) || hook.event.Operation != operation || hook.event.Outcome == "" {
				t.Fatalf("logs or hook reflected decision ID: logs=%q event=%#v", logs.String(), hook.event)
			}
		})
	}
}

func TestDecideRejectsInvalidInputsWithoutLeakingThem(t *testing.T) {
	server, _ := newDecisionServer(t, http.StatusOK, `{"decision_id":"dec-1","allowed":true,"reason_code":"allowed"}`)
	defer server.Close()
	client := newDecisionClient(t, server)
	for _, test := range []struct {
		token      string
		permission Permission
		secret     string
	}{
		{"", validPermission(), ""}, {" access-token", validPermission(), "access-token"}, {"access-token", Permission{ResourceServer: "asset-api", Resource: " assets", HTTPMethod: http.MethodGet}, "assets"},
		{"access-token", Permission{ResourceServer: "asset-api", Resource: "assets", HTTPMethod: "get"}, ""}, {"access-token", Permission{ResourceServer: "asset-api", Resource: "assets\nsecret", HTTPMethod: http.MethodGet}, "secret"},
		{"access-token", Permission{ResourceServer: "asset-api", Resource: "assets\u009fsecret", HTTPMethod: http.MethodGet}, "secret"},
	} {
		_, err := client.Decide(context.Background(), test.token, test.permission)
		if err == nil {
			t.Fatal("Decide unexpectedly succeeded")
		}
		assertDecisionError(t, err, sdkerr.KindInvalidConfig, 0, false, test.secret, test.token)
	}
}

func TestDecideContextCancellationIsUnavailableAndRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newDecisionClient(t, server).Decide(ctx, "access-token", validPermission())
	assertDecisionError(t, err, sdkerr.KindIAMUnavailable, http.StatusServiceUnavailable, true, "access-token")
}

func newDecisionServer(t *testing.T, status int, responseBody string) (*httptest.Server, *atomic.Value) {
	t.Helper()
	captured := &atomic.Value{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		captured.Store(string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, responseBody)
	}))
	return server, captured
}

func newDecisionClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := New(Config{IssuerURL: server.URL, HTTPClient: server.Client(), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func validPermission() Permission {
	return Permission{ResourceServer: "asset-api", Resource: "assets", HTTPMethod: http.MethodGet}
}

func assertDecisionError(t *testing.T, err error, kind sdkerr.Kind, status int, retryable bool, forbidden ...string) {
	t.Helper()
	var typed *sdkerr.Error
	if !errors.As(err, &typed) || typed.Kind != kind || typed.HTTPStatus != status || typed.Retryable != retryable || typed.Cause != nil {
		t.Fatalf("error = %#v, want kind=%q status=%d retryable=%v", err, kind, status, retryable)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("error leaked %q: %v", value, err)
		}
	}
}

type recordingHook struct{ event observability.Event }

func (h *recordingHook) Observe(_ context.Context, event observability.Event) { h.event = event }
