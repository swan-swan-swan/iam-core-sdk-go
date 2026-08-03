package httpauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

const validDecisionResponse = `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"request_id":"req-1","trace_id":"trace-1"}`

func TestRouteExposesOnlyCompiledDecisionCoordinates(t *testing.T) {
	route := compiledRoute()
	if route.Method() != "GET" || route.ResourceServer() != "orders_api" || route.Resource() != "orders" {
		t.Fatalf("route coordinates = %q/%q/%q", route.Method(), route.ResourceServer(), route.Resource())
	}
}

func TestDecideSendsOnlyFrozenThreeFields(t *testing.T) {
	var body map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issuer/authorization/v1/decisions" || r.Method != http.MethodPost {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("accept = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, validDecisionResponse)
	}))
	defer server.Close()

	client, err := NewPDPClient(PDPConfig{IssuerURL: server.URL + "/issuer///", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	var tokenCalls atomic.Int32
	decision, err := client.Decide(t.Context(), core.TokenSourceFunc(func(context.Context) (string, error) {
		tokenCalls.Add(1)
		return "access-token", nil
	}), compiledRoute())
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision != (Decision{ID: "dec-1", Allowed: true, ReasonCode: "policy_allow", RequestID: "req-1", TraceID: "trace-1"}) {
		t.Fatalf("Decide() decision = %#v", decision)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d", tokenCalls.Load())
	}
	if got := slices.Sorted(maps.Keys(body)); !slices.Equal(got, []string{"http_method", "resource", "resource_server"}) {
		t.Fatalf("request keys = %v", got)
	}
	want := map[string]string{"http_method": "GET", "resource": "orders", "resource_server": "orders_api"}
	for key, value := range want {
		var got string
		if err := json.Unmarshal(body[key], &got); err != nil || got != value {
			t.Fatalf("request[%q] = %q, %v", key, got, err)
		}
	}
}

func TestDecideReturnsAllowAndDeny(t *testing.T) {
	tests := []struct {
		name    string
		allowed bool
		reason  string
	}{
		{name: "allow", allowed: true, reason: "policy_allow"},
		{name: "deny", allowed: false, reason: "default_deny"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":%t,"reason_code":%q},"request_id":"req-1","trace_id":"trace-1"}`, test.allowed, test.reason)
			client := newDecisionTestClient(t, http.StatusOK, "application/json", body)
			decision, err := client.Decide(t.Context(), staticToken("token"), compiledRoute())
			if err != nil {
				t.Fatalf("Decide() error = %v", err)
			}
			if decision.Allowed != test.allowed || decision.ReasonCode != test.reason {
				t.Fatalf("Decide() decision = %#v", decision)
			}
		})
	}
}

func TestDecideMapsHTTPAndTransportFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantKind  core.Kind
		retryable bool
	}{
		{name: "bad request", status: http.StatusBadRequest, wantKind: core.KindProtocol},
		{name: "unauthenticated", status: http.StatusUnauthorized, wantKind: core.KindUnauthenticated},
		{name: "unavailable", status: http.StatusServiceUnavailable, wantKind: core.KindIAMUnavailable, retryable: true},
		{name: "unexpected forbidden", status: http.StatusForbidden, wantKind: core.KindProtocol},
		{name: "unexpected too many requests", status: http.StatusTooManyRequests, wantKind: core.KindProtocol},
		{name: "unexpected internal failure", status: http.StatusInternalServerError, wantKind: core.KindProtocol},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newDecisionTestClient(t, test.status, "text/plain", "sensitive response body")
			decision, err := client.Decide(t.Context(), staticToken("sensitive-token"), compiledRoute())
			if decision != (Decision{}) {
				t.Fatalf("Decide() decision = %#v", decision)
			}
			assertCoreError(t, err, test.wantKind, test.status, test.retryable)
			assertNoLeak(t, err, "sensitive response body", "sensitive-token")
		})
	}

	t.Run("network error", func(t *testing.T) {
		secret := "network-secret"
		var calls atomic.Int32
		client, err := NewPDPClient(PDPConfig{
			IssuerURL: "https://iam.example",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New(secret)
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Decide(t.Context(), staticToken("sensitive-token"), compiledRoute())
		assertCoreError(t, err, core.KindIAMUnavailable, 0, true)
		assertNoLeak(t, err, secret, "sensitive-token")
		if calls.Load() != 1 {
			t.Fatalf("round trips = %d", calls.Load())
		}
	})

	t.Run("timeout", func(t *testing.T) {
		var deadlineSeen atomic.Bool
		client, err := NewPDPClient(PDPConfig{
			IssuerURL: "https://iam.example",
			HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				_, hasDeadline := request.Context().Deadline()
				deadlineSeen.Store(hasDeadline)
				<-request.Context().Done()
				return nil, request.Context().Err()
			})},
			Timeout: 10 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Decide(t.Context(), staticToken("token"), compiledRoute())
		assertCoreError(t, err, core.KindIAMUnavailable, 0, true)
		if !deadlineSeen.Load() {
			t.Fatal("transport request context did not have a deadline")
		}
	})
}

func TestDecideRejectsInvalidResponseBodies(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "non JSON body", contentType: "application/json", body: "not-json-sensitive"},
		{name: "wrong content type", contentType: "text/plain", body: validDecisionResponse},
		{name: "missing content type", body: validDecisionResponse},
		{name: "empty body", contentType: "application/json", body: ""},
		{name: "nonzero envelope code", contentType: "application/json", body: `{"code":1,"message":"failure","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "bare response", contentType: "application/json", body: `{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}`},
		{name: "duplicate key", contentType: "application/json", body: `{"code":0,"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"}}`},
		{name: "trailing JSON", contentType: "application/json", body: validDecisionResponse + `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newDecisionTestClient(t, http.StatusOK, test.contentType, test.body)
			decision, err := client.Decide(t.Context(), staticToken("body-test-token"), compiledRoute())
			if decision != (Decision{}) {
				t.Fatalf("Decide() decision = %#v", decision)
			}
			assertCoreError(t, err, core.KindProtocol, http.StatusOK, false)
			assertNoLeak(t, err, test.body, "body-test-token", "not-json-sensitive")
		})
	}

	t.Run("oversized body", func(t *testing.T) {
		body := strings.Repeat("x", (1<<20)+1)
		client := newDecisionTestClient(t, http.StatusOK, "application/json", body)
		_, err := client.Decide(t.Context(), staticToken("oversize-token"), compiledRoute())
		assertCoreError(t, err, core.KindProtocol, http.StatusOK, false)
		assertNoLeak(t, err, body, "oversize-token")
	})
}

func TestDecideNeverRetries(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := NewPDPClient(PDPConfig{IssuerURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.Decide(t.Context(), staticToken("token"), compiledRoute())
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestNewPDPClientValidatesAndNormalizesEndpoint(t *testing.T) {
	invalid := []struct {
		name   string
		issuer string
	}{
		{name: "empty"},
		{name: "padded", issuer: " https://iam.example"},
		{name: "relative", issuer: "/issuer"},
		{name: "missing host", issuer: "https:///issuer"},
		{name: "userinfo", issuer: "https://user:password@iam.example"},
		{name: "query", issuer: "https://iam.example?secret=value"},
		{name: "empty query", issuer: "https://iam.example?"},
		{name: "fragment", issuer: "https://iam.example#secret"},
		{name: "empty fragment", issuer: "https://iam.example#"},
		{name: "insecure remote", issuer: "http://iam.example"},
		{name: "unsupported scheme", issuer: "ftp://iam.example"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewPDPClient(PDPConfig{IssuerURL: test.issuer})
			if client != nil {
				t.Fatalf("NewPDPClient() client = %#v", client)
			}
			assertConfigureError(t, err)
			assertNoLeak(t, err, "password", "secret=value", "secret")
		})
	}

	for _, issuer := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "https://iam.example/base///"} {
		t.Run(issuer, func(t *testing.T) {
			client, err := NewPDPClient(PDPConfig{IssuerURL: issuer})
			if err != nil {
				t.Fatalf("NewPDPClient() error = %v", err)
			}
			want := strings.TrimRight(issuer, "/") + "/authorization/v1/decisions"
			if client.endpoint != want {
				t.Fatalf("endpoint = %q, want %q", client.endpoint, want)
			}
		})
	}

	client, err := NewPDPClient(PDPConfig{IssuerURL: "https://iam.example", Timeout: -time.Nanosecond})
	if client != nil {
		t.Fatalf("NewPDPClient() client = %#v", client)
	}
	assertConfigureError(t, err)
}

func TestNewPDPClientClonesCallerHTTPClientWithoutCookiesOrRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer target.Close()

	var cookieSeen string
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieSeen = r.Header.Get("Cookie")
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(mustParseURL(t, redirector.URL), []*http.Cookie{{Name: "session", Value: "cookie-secret"}})
	callerRedirect := func(*http.Request, []*http.Request) error { return nil }
	caller := redirector.Client()
	caller.Jar = jar
	caller.CheckRedirect = callerRedirect
	client, err := NewPDPClient(PDPConfig{IssuerURL: redirector.URL, HTTPClient: caller})
	if err != nil {
		t.Fatal(err)
	}
	if caller.Jar != jar || caller.CheckRedirect == nil {
		t.Fatal("NewPDPClient() mutated caller HTTP client")
	}
	if client.httpClient == caller || client.httpClient.Jar != nil || client.httpClient.CheckRedirect == nil {
		t.Fatal("NewPDPClient() did not isolate HTTP client state")
	}
	_, decideErr := client.Decide(t.Context(), staticToken("token"), compiledRoute())
	assertCoreError(t, decideErr, core.KindProtocol, http.StatusFound, false)
	if redirected.Load() != 0 {
		t.Fatalf("redirect target calls = %d", redirected.Load())
	}
	if cookieSeen != "" {
		t.Fatalf("request cookie = %q", cookieSeen)
	}
}

func TestDecideRejectsInvalidInputsBeforeTokenOrNetwork(t *testing.T) {
	tests := []struct {
		name  string
		route Route
	}{
		{name: "zero route"},
		{name: "not compiled", route: Route{method: "GET", resourceServer: "orders_api", resource: "orders"}},
		{name: "blank method", route: Route{resourceServer: "orders_api", resource: "orders", compiled: true}},
		{name: "lowercase method", route: Route{method: "get", resourceServer: "orders_api", resource: "orders", compiled: true}},
		{name: "unknown method", route: Route{method: "CUSTOM", resourceServer: "orders_api", resource: "orders", compiled: true}},
		{name: "blank resource server", route: Route{method: "GET", resource: "orders", compiled: true}},
		{name: "padded resource server", route: Route{method: "GET", resourceServer: " orders_api", resource: "orders", compiled: true}},
		{name: "blank resource", route: Route{method: "GET", resourceServer: "orders_api", compiled: true}},
		{name: "padded resource", route: Route{method: "GET", resourceServer: "orders_api", resource: "orders ", compiled: true}},
		{name: "control in resource", route: Route{method: "GET", resourceServer: "orders_api", resource: "ord\x00ers", compiled: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var tokenCalls, networkCalls atomic.Int32
			client := newCountingPDPClient(t, &networkCalls)
			_, err := client.Decide(t.Context(), core.TokenSourceFunc(func(context.Context) (string, error) {
				tokenCalls.Add(1)
				return "token", nil
			}), test.route)
			assertCoreError(t, err, core.KindInvalidConfig, 0, false)
			if tokenCalls.Load() != 0 || networkCalls.Load() != 0 {
				t.Fatalf("token/network calls = %d/%d", tokenCalls.Load(), networkCalls.Load())
			}
		})
	}

	t.Run("nil token source", func(t *testing.T) {
		var networkCalls atomic.Int32
		client := newCountingPDPClient(t, &networkCalls)
		_, err := client.Decide(t.Context(), nil, compiledRoute())
		assertCoreError(t, err, core.KindInvalidConfig, 0, false)
		if networkCalls.Load() != 0 {
			t.Fatalf("network calls = %d", networkCalls.Load())
		}
	})

	t.Run("typed nil token source", func(t *testing.T) {
		var networkCalls atomic.Int32
		client := newCountingPDPClient(t, &networkCalls)
		var tokens *nilTokenSource
		_, err := client.Decide(t.Context(), tokens, compiledRoute())
		assertCoreError(t, err, core.KindInvalidConfig, 0, false)
		if networkCalls.Load() != 0 {
			t.Fatalf("network calls = %d", networkCalls.Load())
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		var tokenCalls, networkCalls atomic.Int32
		client := newCountingPDPClient(t, &networkCalls)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := client.Decide(ctx, core.TokenSourceFunc(func(context.Context) (string, error) {
			tokenCalls.Add(1)
			return "token", nil
		}), compiledRoute())
		assertCoreError(t, err, core.KindIAMUnavailable, 0, true)
		if tokenCalls.Load() != 0 || networkCalls.Load() != 0 {
			t.Fatalf("token/network calls = %d/%d", tokenCalls.Load(), networkCalls.Load())
		}
	})
}

func TestDecideHandlesTokenSourceFailuresWithoutLeaksOrNetwork(t *testing.T) {
	tests := []struct {
		name  string
		token string
		err   error
		kind  core.Kind
	}{
		{name: "arbitrary error", err: errors.New("token-source-secret"), kind: core.KindUnauthenticated},
		{name: "typed unavailable", err: core.NewError(core.KindIAMUnavailable, "secret-operation", 503, true, errors.New("typed-secret")), kind: core.KindIAMUnavailable},
		{name: "empty token", token: "", kind: core.KindUnauthenticated},
		{name: "padded token", token: " token-secret", kind: core.KindUnauthenticated},
		{name: "control token", token: "token\r\nsecret", kind: core.KindUnauthenticated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var tokenCalls, networkCalls atomic.Int32
			client := newCountingPDPClient(t, &networkCalls)
			_, err := client.Decide(t.Context(), core.TokenSourceFunc(func(context.Context) (string, error) {
				tokenCalls.Add(1)
				return test.token, test.err
			}), compiledRoute())
			assertCoreErrorKind(t, err, test.kind)
			assertNoLeak(t, err, test.token, "token-source-secret", "secret-operation", "typed-secret")
			if tokenCalls.Load() != 1 || networkCalls.Load() != 0 {
				t.Fatalf("token/network calls = %d/%d", tokenCalls.Load(), networkCalls.Load())
			}
		})
	}
}

func TestDecideTelemetryIsLowCardinalityAndLeakFree(t *testing.T) {
	const token = "telemetry-token-secret"
	const body = "telemetry-body-secret"
	var logs bytes.Buffer
	var mu sync.Mutex
	var events []core.Event
	client := newDecisionTestClientWithConfig(t, http.StatusOK, "application/json", body, func(cfg *PDPConfig) {
		cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
		cfg.Observer = core.ObserverFunc(func(_ context.Context, event core.Event) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, event)
		})
	})
	_, err := client.Decide(t.Context(), staticToken(token), compiledRoute())
	if err == nil {
		t.Fatal("Decide() error = nil")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].Operation != "httpauthz.decide" || events[0].Outcome != "error" || events[0].CredentialSource != "" || events[0].Duration < 0 {
		t.Fatalf("event = %#v", events[0])
	}
	combined := logs.String() + fmt.Sprint(events) + err.Error()
	for _, secret := range []string{token, body, "orders_api", "orders", "req-1", "trace-1"} {
		if secret != "" && strings.Contains(combined, secret) {
			t.Fatalf("telemetry leaked %q in %q", secret, combined)
		}
	}
	if !strings.Contains(logs.String(), "operation=httpauthz.decide") || !strings.Contains(logs.String(), "outcome=error") {
		t.Fatalf("logs = %q", logs.String())
	}
}

func TestNewPDPClientTreatsTypedNilObserverAsAbsent(t *testing.T) {
	var observer *nilObserver
	client := newDecisionTestClientWithConfig(t, http.StatusOK, "application/json", validDecisionResponse, func(cfg *PDPConfig) {
		cfg.Observer = observer
	})
	if _, err := client.Decide(t.Context(), staticToken("token"), compiledRoute()); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
}

func compiledRoute() Route {
	return Route{method: "GET", resourceServer: "orders_api", resource: "orders", compiled: true}
}

func staticToken(token string) core.TokenSource {
	return core.TokenSourceFunc(func(context.Context) (string, error) { return token, nil })
}

func newDecisionTestClient(t *testing.T, status int, contentType, body string) *PDPClient {
	t.Helper()
	return newDecisionTestClientWithConfig(t, status, contentType, body, nil)
}

func newDecisionTestClientWithConfig(t *testing.T, status int, contentType, body string, configure func(*PDPConfig)) *PDPClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	cfg := PDPConfig{IssuerURL: server.URL, HTTPClient: server.Client()}
	if configure != nil {
		configure(&cfg)
	}
	client, err := NewPDPClient(cfg)
	if err != nil {
		t.Fatalf("NewPDPClient() error = %v", err)
	}
	return client
}

func newCountingPDPClient(t *testing.T, calls *atomic.Int32) *PDPClient {
	t.Helper()
	client, err := NewPDPClient(PDPConfig{
		IssuerURL: "https://iam.example",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(validDecisionResponse)),
			}, nil
		})},
	})
	if err != nil {
		t.Fatalf("NewPDPClient() error = %v", err)
	}
	return client
}

func assertCoreError(t *testing.T, err error, kind core.Kind, status int, retryable bool) {
	t.Helper()
	var typed *core.Error
	if !errors.As(err, &typed) {
		t.Fatalf("error = %#v, want *core.Error", err)
	}
	if typed.Kind != kind || typed.Operation != "httpauthz.decide" || typed.HTTPStatus != status || typed.Retryable != retryable {
		t.Fatalf("error = %#v", typed)
	}
}

func assertCoreErrorKind(t *testing.T, err error, kind core.Kind) {
	t.Helper()
	var typed *core.Error
	if !errors.As(err, &typed) || typed.Kind != kind || typed.Operation != "httpauthz.decide" {
		t.Fatalf("error = %#v, want kind %q", err, kind)
	}
}

func assertConfigureError(t *testing.T, err error) {
	t.Helper()
	var typed *core.Error
	if !errors.As(err, &typed) || typed.Kind != core.KindInvalidConfig || typed.Operation != "httpauthz.configure" || typed.HTTPStatus != 0 || typed.Retryable {
		t.Fatalf("error = %#v, want invalid configuration error", err)
	}
}

func assertNoLeak(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	formatted := fmt.Sprintf("%v %#v", err, err)
	for _, secret := range secrets {
		if secret != "" && strings.Contains(formatted, secret) {
			t.Fatalf("error leaked %q in %q", secret, formatted)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type nilTokenSource struct{}

func (*nilTokenSource) AccessToken(context.Context) (string, error) {
	panic("typed nil token source invoked")
}

type nilObserver struct{}

func (*nilObserver) Observe(context.Context, core.Event) { panic("typed nil observer invoked") }

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
