package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"` + strings.Repeat("x", 128) + `"}`))
	}))
	defer server.Close()

	client := Client{HTTP: server.Client(), MaxBodyBytes: 32}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected oversized response error")
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
