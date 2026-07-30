package transport

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type failingBody struct {
	secret string
}

func (body failingBody) Read([]byte) (int, error) {
	return 0, errors.New(body.secret)
}

func (failingBody) Close() error {
	return nil
}

type partialFailingBody struct {
	body   string
	secret string
	read   bool
}

func (body *partialFailingBody) Read(buffer []byte) (int, error) {
	if body.read {
		return 0, io.EOF
	}
	body.read = true
	return copy(buffer, body.body), errors.New(body.secret)
}

func (*partialFailingBody) Close() error {
	return nil
}

func TestClientRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"value":"` + strings.Repeat("x", 128) + `"}`))
	}))
	defer server.Close()

	client := Client{HTTP: server.Client(), MaxBodyBytes: 32}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	_, err := client.Do(req)
	assertSDKError(t, err, sdkerr.KindProtocol, "transport.response", http.StatusBadGateway, false)
}

func TestClientReturnsBoundedMetadataWithOversizedBodyError(t *testing.T) {
	rawHeader := http.Header{
		"Content-Type": {"application/json"},
		"X-Request-Id": {"request-safe"},
	}
	client := Client{
		HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     rawHeader,
				Body:       io.NopCloser(strings.NewReader(`{"hostile":"response-secret"}`)),
			}, nil
		})},
		MaxBodyBytes: 8,
	}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

	response, err := client.Do(request)

	assertSDKError(t, err, sdkerr.KindProtocol, "transport.response", http.StatusUnauthorized, false)
	if response.StatusCode != http.StatusUnauthorized || len(response.Body) != 8 ||
		response.Header.Get("X-Request-ID") != "request-safe" ||
		response.Correlation.RequestID != "request-safe" {
		t.Fatalf("response = %#v", response)
	}
	response.Header.Set("X-Request-ID", "mutated")
	if rawHeader.Get("X-Request-ID") != "request-safe" {
		t.Fatalf("raw header was mutated: %#v", rawHeader)
	}
}

func TestClientReturnsMetadataWithContentTypeError(t *testing.T) {
	client := Client{HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header: http.Header{
				"Content-Type": {"text/plain; hostile=response-secret"},
				"X-Request-Id": {"request-safe"},
			},
			Body: io.NopCloser(strings.NewReader("hostile-response-secret")),
		}, nil
	})}}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

	response, err := client.Do(request)

	assertSDKError(t, err, sdkerr.KindProtocol, "transport.response", http.StatusServiceUnavailable, false)
	if response.StatusCode != http.StatusServiceUnavailable ||
		response.Header.Get("X-Request-ID") != "request-safe" ||
		response.Correlation.RequestID != "request-safe" ||
		string(response.Body) != "hostile-response-secret" {
		t.Fatalf("response = %#v", response)
	}
	if strings.Contains(err.Error(), "hostile") || strings.Contains(err.Error(), "response-secret") {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestClientReturnsMetadataWithBodyReadError(t *testing.T) {
	client := Client{HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"Content-Type": {"application/json"},
				"X-Request-Id": {"request-safe"},
			},
			Body: &partialFailingBody{
				body:   "partial-response-secret",
				secret: "hostile-read-secret",
			},
		}, nil
	})}}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

	response, err := client.Do(request)

	assertSDKError(t, err, sdkerr.KindIAMUnavailable, "transport.response", http.StatusServiceUnavailable, true)
	if response.StatusCode != http.StatusUnauthorized ||
		response.Header.Get("X-Request-ID") != "request-safe" ||
		response.Correlation.RequestID != "request-safe" ||
		string(response.Body) != "partial-response-secret" {
		t.Fatalf("response = %#v", response)
	}
	if strings.Contains(err.Error(), "hostile") || strings.Contains(err.Error(), "read-secret") {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestClientAcceptsEmptyBodyWithoutContentType(t *testing.T) {
	client := Client{HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     http.Header{"X-Request-Id": {"request-safe"}},
			Body:       http.NoBody,
		}, nil
	})}}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

	response, err := client.Do(request)

	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if response.StatusCode != http.StatusNoContent || len(response.Body) != 0 ||
		response.Correlation.RequestID != "request-safe" {
		t.Fatalf("response = %#v", response)
	}
}

func TestClientAcceptsBodyAtExactLimit(t *testing.T) {
	body := []byte(`{"ok":true}`)
	client := Client{
		HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(string(body))),
			}, nil
		})},
		MaxBodyBytes: int64(len(body)),
	}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != string(body) {
		t.Fatalf("body = %q", response.Body)
	}
}

func TestClientRejectsUnrepresentableBodyLimit(t *testing.T) {
	for _, limit := range []int64{-1, math.MaxInt64} {
		t.Run("limit "+strconv.FormatInt(limit, 10), func(t *testing.T) {
			calls := 0
			client := Client{
				HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
					calls++
					return nil, errors.New("must not execute")
				})},
				MaxBodyBytes: limit,
			}
			request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

			_, err := client.Do(request)

			assertSDKError(t, err, sdkerr.KindInvalidConfig, "transport.configure", 0, false)
			if calls != 0 {
				t.Fatalf("transport calls = %d, want 0", calls)
			}
		})
	}
}

func TestClientContentTypeHandling(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		wantError   bool
	}{
		{name: "missing", wantError: true},
		{name: "malformed", contentType: `application/json; hostile="token-secret`, wantError: true},
		{name: "non JSON", contentType: "text/plain; hostile=token-secret", wantError: true},
		{name: "JSON suffix", contentType: "application/problem+json; charset=utf-8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := Client{HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Header:     http.Header{"Content-Type": {test.contentType}},
					Body:       io.NopCloser(strings.NewReader(`{}`)),
				}, nil
			})}}
			request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

			_, err := client.Do(request)
			if !test.wantError {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertSDKError(t, err, sdkerr.KindProtocol, "transport.response", http.StatusBadGateway, false)
			if strings.Contains(err.Error(), "token-secret") ||
				(test.contentType != "" && strings.Contains(err.Error(), test.contentType)) {
				t.Fatalf("error reflects Content-Type: %q", err)
			}
		})
	}
}

func TestClientSanitizesNetworkAndBodyReadErrors(t *testing.T) {
	tests := []struct {
		name      string
		transport roundTripperFunc
		operation string
	}{
		{
			name: "network",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("GET https://example.test?token=network-secret Authorization: Bearer credential")
			},
			operation: "transport.request",
		},
		{
			name: "body read",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       failingBody{secret: "body-secret session_id=session-value"},
				}, nil
			},
			operation: "transport.response",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := Client{HTTP: &http.Client{Transport: test.transport}}
			request, _ := http.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"https://example.test?authorization_code=request-secret",
				nil,
			)

			_, err := client.Do(request)

			assertSDKError(t, err, sdkerr.KindIAMUnavailable, test.operation, http.StatusServiceUnavailable, true)
			for _, secret := range []string{"network-secret", "credential", "body-secret", "session-value", "request-secret", "example.test"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked %q: %q", secret, err)
				}
			}
		})
	}
}

func TestClientInvokesInjectedTransportOnce(t *testing.T) {
	calls := 0
	client := Client{HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("injected transport failure")
	})}}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

	_, _ = client.Do(request)

	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}

func TestClientClonesResponseHeaders(t *testing.T) {
	rawHeader := make(http.Header)
	rawHeader.Set("Content-Type", "application/json")
	rawHeader.Set("X-Request-ID", "request-original")
	client := Client{HTTP: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     rawHeader,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
		}, nil
	})}}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Header.Set("X-Request-ID", "request-mutated")
	if got := rawHeader.Get("X-Request-ID"); got != "request-original" {
		t.Fatalf("raw header mutated to %q", got)
	}
}

func TestDefaultHTTPClientDisablesConnectionReuseAndHTTP2(t *testing.T) {
	client := newDefaultHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	if !transport.DisableKeepAlives {
		t.Fatal("default transport permits connection reuse")
	}
	if transport.TLSNextProto == nil || len(transport.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto = %#v, want explicit HTTP/2 disablement", transport.TLSNextProto)
	}
}

func TestDefaultHTTPClientDoesNotFollowRedirects(t *testing.T) {
	targetCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/target" {
			targetCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"target":true}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		http.Redirect(w, request, "/target?authorization_code=redirect-secret", http.StatusFound)
	}))
	defer server.Close()

	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/start", nil)
	response, err := (Client{}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusFound)
	}
	if targetCalls != 0 {
		t.Fatalf("redirect target calls = %d, want 0", targetCalls)
	}
}

func TestDefaultClientReturns503WithoutReplay(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporarily unavailable"}`))
	}))
	defer server.Close()

	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	response, err := (Client{}).Do(request)

	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
	if requests != 1 {
		t.Fatalf("server requests = %d, want 1", requests)
	}
}

func TestDecodeJSONRejectsMalformedAndTrailingValues(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "malformed", body: `{"value":`},
		{name: "trailing value", body: `{"value":"ok"} {"secret":"trailing-secret"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var target struct {
				Value string `json:"value"`
			}
			err := DecodeJSON([]byte(test.body), &target)
			assertSDKError(t, err, sdkerr.KindProtocol, "transport.decode_json", 0, false)
			if strings.Contains(err.Error(), "trailing-secret") {
				t.Fatalf("error leaked response content: %q", err)
			}
		})
	}
}

func TestDecodeJSONAllowsUnknownFields(t *testing.T) {
	var target struct {
		Value string `json:"value"`
	}
	err := DecodeJSON([]byte(`{"value":"known","future_field":{"nested":true}}`), &target)
	if err != nil {
		t.Fatal(err)
	}
	if target.Value != "known" {
		t.Fatalf("value = %q", target.Value)
	}
}

func TestClientCapturesCorrelation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "req-header")
		_, _ = w.Write([]byte(`{"request_id":"req-body","trace_id":"trace-body"}`))
	}))
	defer server.Close()

	client := Client{HTTP: server.Client(), MaxBodyBytes: 1024}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Correlation.RequestID != "req-header" || response.Correlation.TraceID != "trace-body" {
		t.Fatalf("correlation = %#v", response.Correlation)
	}
}

func assertSDKError(
	t *testing.T,
	err error,
	kind sdkerr.Kind,
	operation string,
	status int,
	retryable bool,
) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	var typed *sdkerr.Error
	if !errors.As(err, &typed) {
		t.Fatalf("error type = %T, want *sdkerr.Error", err)
	}
	if typed.Kind != kind || typed.Operation != operation {
		t.Fatalf("error metadata = (%q, %q), want (%q, %q)", typed.Kind, typed.Operation, kind, operation)
	}
	if typed.Cause != nil || errors.Unwrap(typed) != nil {
		t.Fatalf("error retained unsafe cause: %#v", typed.Cause)
	}
	if typed.HTTPStatus != status || typed.Retryable != retryable {
		t.Fatalf(
			"error availability metadata = (%d, %t), want (%d, %t)",
			typed.HTTPStatus,
			typed.Retryable,
			status,
			retryable,
		)
	}
	if typed.RequestID != "" || typed.TraceID != "" || typed.DecisionID != "" {
		t.Fatalf("error retained unexpected metadata: %#v", typed)
	}
	if got, want := err.Error(), operation+": "+string(kind); got != want {
		t.Fatalf("error text = %q, want %q", got, want)
	}
}
