package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoSuccessUsesOneTokenAndOneHTTPRequest(t *testing.T) {
	t.Parallel()

	const token = "one-attempt-token"
	tokens := &countingTokenSource{token: token}
	observer := &recordingObserver{}
	var serverCalls atomic.Int32
	var bodyCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		serverCalls.Add(1)
		if request.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", request.Method)
		}
		if request.URL.Path != "/base/api/v1/applications/app-1" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if request.URL.RawQuery != "page=2&search=client_secret%3Dquery-marker" {
			t.Errorf("raw query = %q", request.URL.RawQuery)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := request.Header.Get("Idempotency-Key"); got != "idem-123" {
			t.Errorf("Idempotency-Key = %q", got)
		}
		if got := request.Header.Get("Cookie"); got != "" {
			t.Errorf("Cookie = %q, want empty", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if string(body) != `{"name":"application"}` {
			t.Errorf("request body = %s", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"code":0,"message":"ok","data":{"id":"app-1"},"request_id":"req-1","trace_id":"trace-1"}`)
	}))
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New(): %v", err)
	}
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(): %v", err)
	}
	jar.SetCookies(serverURL, []*http.Cookie{{Name: "session", Value: "must-not-be-sent"}})

	client, err := New(Config{
		BaseURL:     server.URL + "/base",
		TokenSource: tokens,
		HTTPClient:  &http.Client{Jar: jar},
		Observer:    observer,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	var out struct {
		ID string `json:"id"`
	}
	metadata, err := client.Do(context.Background(), Request{
		Operation: "management.applications.create",
		Method:    http.MethodPost,
		Path:      "/api/v1/applications/app-1",
		Query: url.Values{
			"search": {"client_secret=query-marker"},
			"page":   {"2"},
		},
		Body:           countedJSONBody{calls: &bodyCalls},
		IdempotencyKey: "idem-123",
	}, &out)
	if err != nil {
		t.Fatalf("Do(): %v", err)
	}
	if metadata != (Metadata{RequestID: "req-1", TraceID: "trace-1"}) || out.ID != "app-1" {
		t.Fatalf("metadata/out = %#v/%#v", metadata, out)
	}
	if tokens.calls.Load() != 1 || serverCalls.Load() != 1 || bodyCalls.Load() != 1 {
		t.Fatalf("calls token/server/body = %d/%d/%d, want 1/1/1", tokens.calls.Load(), serverCalls.Load(), bodyCalls.Load())
	}
	events := observer.snapshot()
	if len(events) != 1 || events[0].Operation != "management.applications.create" || events[0].Outcome != "success" || events[0].StatusCode != 200 || events[0].Duration < 0 {
		t.Fatalf("events = %#v", events)
	}
}

func TestDoUsesOneTokenAndOneHTTPRequestForEveryTerminalResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		status      int
		body        string
		wantKind    Kind
		wantOutcome string
	}{
		{name: "success", status: 200, body: `{"code":0,"message":"ok","data":null}`, wantOutcome: "success"},
		{name: "unauthenticated", status: 401, body: `{"code":1,"message":"no","data":null}`, wantKind: KindUnauthenticated, wantOutcome: string(KindUnauthenticated)},
		{name: "conflict", status: 409, body: `{"code":2,"message":"conflict","data":{"revision":2}}`, wantKind: KindConflict, wantOutcome: string(KindConflict)},
		{name: "rate limited", status: 429, body: `{"code":3,"message":"slow down","data":null}`, wantKind: KindRateLimited, wantOutcome: string(KindRateLimited)},
		{name: "unavailable", status: 503, body: `{"code":4,"message":"unavailable","data":null}`, wantKind: KindIAMUnavailable, wantOutcome: string(KindIAMUnavailable)},
		{name: "malformed JSON", status: 200, body: `{"code":`, wantKind: KindProtocol, wantOutcome: string(KindProtocol)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var serverCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				serverCalls.Add(1)
				writer.WriteHeader(tt.status)
				_, _ = io.WriteString(writer, tt.body)
			}))
			defer server.Close()

			tokens := &countingTokenSource{token: "token"}
			observer := &recordingObserver{}
			client, err := New(Config{BaseURL: server.URL, TokenSource: tokens, Observer: observer})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			_, err = client.Do(context.Background(), Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test"}, nil)
			if tt.wantKind == "" {
				if err != nil {
					t.Fatalf("Do(): %v", err)
				}
			} else if !errorHasKind(err, tt.wantKind) {
				t.Fatalf("Do() error = %v, want kind %s", err, tt.wantKind)
			}
			if tokens.calls.Load() != 1 || serverCalls.Load() != 1 {
				t.Fatalf("calls token/server = %d/%d, want 1/1", tokens.calls.Load(), serverCalls.Load())
			}
			events := observer.snapshot()
			if len(events) != 1 || events[0].Outcome != tt.wantOutcome || events[0].StatusCode != tt.status {
				t.Fatalf("events = %#v", events)
			}
		})
	}
}

func TestDoRejectsInvalidRequestBeforeTokenOrHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request Request
	}{
		{name: "blank operation", request: Request{Method: http.MethodGet, Path: "/api/v1/test"}},
		{name: "unsafe operation", request: Request{Operation: "management.test\nsecret", Method: http.MethodGet, Path: "/api/v1/test"}},
		{name: "unscoped operation", request: Request{Operation: "attacker-marker", Method: http.MethodGet, Path: "/api/v1/test"}},
		{name: "empty operation segment", request: Request{Operation: "management.", Method: http.MethodGet, Path: "/api/v1/test"}},
		{name: "double operation separator", request: Request{Operation: "management..test", Method: http.MethodGet, Path: "/api/v1/test"}},
		{name: "noncanonical operation case", request: Request{Operation: "Management.test", Method: http.MethodGet, Path: "/api/v1/test"}},
		{name: "lowercase method", request: Request{Operation: "management.test", Method: "get", Path: "/api/v1/test"}},
		{name: "non API path", request: Request{Operation: "management.test", Method: http.MethodGet, Path: "/test"}},
		{name: "unclean path", request: Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/../secret"}},
		{name: "path query", request: Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test?secret=value"}},
		{name: "query control", request: Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test", Query: url.Values{"filter": {"safe\nsecret"}}}},
		{name: "query blank key", request: Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test", Query: url.Values{"": {"value"}}}},
		{name: "query missing values", request: Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test", Query: url.Values{"filter": nil}}},
		{name: "idempotency control", request: Request{Operation: "management.test", Method: http.MethodPost, Path: "/api/v1/test", IdempotencyKey: "key\r\nsecret"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var serverCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { serverCalls.Add(1) }))
			defer server.Close()
			tokens := &countingTokenSource{token: "token"}
			observer := &recordingObserver{}
			client, err := New(Config{BaseURL: server.URL, TokenSource: tokens, Observer: observer})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			_, err = client.Do(context.Background(), tt.request, nil)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("Do() error = %v, want ErrInvalidArgument", err)
			}
			if tokens.calls.Load() != 0 || serverCalls.Load() != 0 {
				t.Fatalf("calls token/server = %d/%d, want 0/0", tokens.calls.Load(), serverCalls.Load())
			}
			events := observer.snapshot()
			if len(events) != 1 || events[0].Outcome != string(KindInvalidArgument) || events[0].StatusCode != 0 {
				t.Fatalf("events = %#v", events)
			}
		})
	}
}

func TestDoRejectsInvalidTokenWithoutSendingHTTPRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		err   error
	}{
		{name: "blank", token: ""},
		{name: "whitespace", token: "   "},
		{name: "trim changing", token: " token"},
		{name: "source error", err: errTestTokenSource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var serverCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { serverCalls.Add(1) }))
			defer server.Close()
			tokens := &countingTokenSource{token: tt.token, err: tt.err}
			client, err := New(Config{BaseURL: server.URL, TokenSource: tokens})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			_, err = client.Do(context.Background(), Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test"}, nil)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Do() error = %v, want ErrUnauthenticated", err)
			}
			if tokens.calls.Load() != 1 || serverCalls.Load() != 0 {
				t.Fatalf("calls token/server = %d/%d, want 1/0", tokens.calls.Load(), serverCalls.Load())
			}
		})
	}
}

func TestDoEncodesBodyOnceAndDoesNotSendOnEncodingFailure(t *testing.T) {
	t.Parallel()

	var bodyCalls atomic.Int32
	var serverCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { serverCalls.Add(1) }))
	defer server.Close()
	tokens := &countingTokenSource{token: "token"}
	client, err := New(Config{BaseURL: server.URL, TokenSource: tokens})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	_, err = client.Do(context.Background(), Request{
		Operation: "management.test",
		Method:    http.MethodPost,
		Path:      "/api/v1/test",
		Body:      failingJSONBody{calls: &bodyCalls},
	}, nil)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Do() error = %v, want ErrInvalidArgument", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", err), "body-marker-must-not-leak") {
		t.Fatalf("Do() error leaked JSON encoding failure: %v", err)
	}
	if tokens.calls.Load() != 1 || bodyCalls.Load() != 1 || serverCalls.Load() != 0 {
		t.Fatalf("calls token/body/server = %d/%d/%d, want 1/1/0", tokens.calls.Load(), bodyCalls.Load(), serverCalls.Load())
	}
}

func TestDoDoesNotFollowRedirectAndRejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "redirect", handler: func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "/api/v1/second-attempt", http.StatusFound)
		}},
		{name: "oversized", handler: func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, strings.Repeat("x", maxResponseBytes+1))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var serverCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				serverCalls.Add(1)
				tt.handler(writer, request)
			}))
			defer server.Close()
			tokens := &countingTokenSource{token: "token"}
			client, err := New(Config{BaseURL: server.URL, TokenSource: tokens})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			_, err = client.Do(context.Background(), Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test"}, nil)
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("Do() error = %v, want ErrProtocol", err)
			}
			if tokens.calls.Load() != 1 || serverCalls.Load() != 1 {
				t.Fatalf("calls token/server = %d/%d, want 1/1", tokens.calls.Load(), serverCalls.Load())
			}
		})
	}
}

func TestDoHonorsShorterCallerDeadlineAndClientTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		clientTimeout time.Duration
		callerTimeout time.Duration
	}{
		{name: "caller deadline", clientTimeout: time.Second, callerTimeout: 80 * time.Millisecond},
		{name: "client timeout", clientTimeout: 80 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var serverCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				serverCalls.Add(1)
				<-request.Context().Done()
			}))
			defer server.Close()
			tokens := &countingTokenSource{token: "token"}
			observer := &recordingObserver{}
			client, err := New(Config{BaseURL: server.URL, TokenSource: tokens, Timeout: tt.clientTimeout, Observer: observer})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			ctx := context.Background()
			var cancel context.CancelFunc = func() {}
			if tt.callerTimeout != 0 {
				ctx, cancel = context.WithTimeout(ctx, tt.callerTimeout)
			}
			defer cancel()
			started := time.Now()
			_, err = client.Do(ctx, Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test"}, nil)
			if !errors.Is(err, ErrIAMUnavailable) {
				t.Fatalf("Do() error = %v, want ErrIAMUnavailable", err)
			}
			if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
				t.Fatalf("Do() elapsed = %v, timeout did not win", elapsed)
			}
			if tokens.calls.Load() != 1 || serverCalls.Load() != 1 {
				t.Fatalf("calls token/server = %d/%d, want 1/1", tokens.calls.Load(), serverCalls.Load())
			}
			events := observer.snapshot()
			if len(events) != 1 || events[0].Outcome != string(KindIAMUnavailable) {
				t.Fatalf("events = %#v", events)
			}
		})
	}
}

func TestDoObserverPanicDoesNotChangeResult(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		status   int
		body     string
		wantKind Kind
	}{
		{name: "success", status: 200, body: `{"code":0,"message":"ok","data":null}`},
		{name: "error", status: 409, body: `{"code":9,"message":"conflict","data":null}`, wantKind: KindConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var serverCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				serverCalls.Add(1)
				writer.WriteHeader(tt.status)
				_, _ = io.WriteString(writer, tt.body)
			}))
			defer server.Close()
			tokens := &countingTokenSource{token: "token"}
			client, err := New(Config{BaseURL: server.URL, TokenSource: tokens, Observer: &recordingObserver{panic: true}})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			_, err = client.Do(context.Background(), Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test"}, nil)
			if tt.wantKind == "" && err != nil {
				t.Fatalf("Do(): %v", err)
			}
			if tt.wantKind != "" && !errorHasKind(err, tt.wantKind) {
				t.Fatalf("Do() error = %v, want kind %s", err, tt.wantKind)
			}
			if tokens.calls.Load() != 1 || serverCalls.Load() != 1 {
				t.Fatalf("calls token/server = %d/%d, want 1/1", tokens.calls.Load(), serverCalls.Load())
			}
		})
	}
}

func TestDoProtocolFailureDoesNotLeakRawResponse(t *testing.T) {
	t.Parallel()

	const rawResponseMarker = "raw-response-marker-must-not-leak"
	observer := &recordingObserver{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"code":0,"message":"`+rawResponseMarker+`","data":`)
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, TokenSource: staticTokenSource("token"), Observer: observer})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	_, err = client.Do(context.Background(), Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test"}, nil)
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("Do() error = %v, want ErrProtocol", err)
	}
	for _, rendered := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(rendered, rawResponseMarker) {
			t.Fatalf("formatted error leaked raw response: %q", rendered)
		}
	}
	events := observer.snapshot()
	if len(events) != 1 || events[0].Operation != "management.test" || events[0].Outcome != string(KindProtocol) || events[0].StatusCode != 200 {
		t.Fatalf("events = %#v", events)
	}
}

func TestDoDoesNotLeakTransportFailureOrRequestSecrets(t *testing.T) {
	t.Parallel()

	const (
		tokenMarker = "token-marker"
		queryMarker = "query-marker"
		bodyMarker  = "body-marker"
	)
	var attempts atomic.Int32
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return nil, fmt.Errorf("transport failed: %s %s %s", tokenMarker, queryMarker, bodyMarker)
	})
	tokens := &countingTokenSource{token: tokenMarker}
	observer := &recordingObserver{}
	client, err := New(Config{
		BaseURL:     "https://example.com",
		TokenSource: tokens,
		HTTPClient:  &http.Client{Transport: transport},
		Observer:    observer,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	_, err = client.Do(context.Background(), Request{
		Operation: "management.test",
		Method:    http.MethodPost,
		Path:      "/api/v1/test",
		Query:     url.Values{"filter": {queryMarker}},
		Body:      map[string]string{"value": bodyMarker},
	}, nil)
	if !errors.Is(err, ErrIAMUnavailable) {
		t.Fatalf("Do() error = %v, want ErrIAMUnavailable", err)
	}
	formatted := fmt.Sprintf("%+v", err)
	for _, marker := range []string{tokenMarker, queryMarker, bodyMarker, "Authorization"} {
		if strings.Contains(formatted, marker) {
			t.Fatalf("formatted error leaked %q: %q", marker, formatted)
		}
	}
	if tokens.calls.Load() != 1 || attempts.Load() != 1 {
		t.Fatalf("calls token/http = %d/%d, want 1/1", tokens.calls.Load(), attempts.Load())
	}
	events := observer.snapshot()
	if len(events) != 1 || events[0].Outcome != string(KindIAMUnavailable) || events[0].Operation != "management.test" {
		t.Fatalf("events = %#v", events)
	}
}

func TestDoOmitsContentTypeAndIdempotencyHeadersWhenAbsent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Content-Type"); got != "" {
			t.Errorf("Content-Type = %q, want empty", got)
		}
		if got := request.Header.Get("Idempotency-Key"); got != "" {
			t.Errorf("Idempotency-Key = %q, want empty", got)
		}
		_, _ = io.WriteString(writer, `{"code":0,"message":"ok","data":null}`)
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, TokenSource: staticTokenSource("token")})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if _, err := client.Do(context.Background(), Request{Operation: "management.test", Method: http.MethodGet, Path: "/api/v1/test"}, nil); err != nil {
		t.Fatalf("Do(): %v", err)
	}
}

type countedJSONBody struct{ calls *atomic.Int32 }

func (body countedJSONBody) MarshalJSON() ([]byte, error) {
	body.calls.Add(1)
	return []byte(`{"name":"application"}`), nil
}

type failingJSONBody struct{ calls *atomic.Int32 }

func (body failingJSONBody) MarshalJSON() ([]byte, error) {
	body.calls.Add(1)
	return nil, errors.New("body-marker-must-not-leak")
}

func errorHasKind(err error, kind Kind) bool {
	var managementError *Error
	return errors.As(err, &managementError) && managementError.Kind == kind
}

var _ json.Marshaler = countedJSONBody{}
var _ json.Marshaler = failingJSONBody{}
