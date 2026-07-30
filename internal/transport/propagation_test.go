package transport

import (
	"context"
	"net/http"
	"testing"
)

func TestApplyHeadersForwardsOnlyAllowlistedHeaders(t *testing.T) {
	source := http.Header{
		"Traceparent":   {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		"Tracestate":    {"vendor=value"},
		"X-Request-Id":  {"req-1"},
		"Authorization": {"Bearer must-not-forward"},
		"Cookie":        {"must-not-forward"},
	}
	ctx := WithHeaders(context.Background(), source)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test", nil)
	ApplyHeaders(ctx, req.Header)

	if req.Header.Get("Traceparent") == "" || req.Header.Get("X-Request-ID") != "req-1" {
		t.Fatalf("missing propagation headers: %#v", req.Header)
	}
	if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
		t.Fatalf("sensitive headers propagated: %#v", req.Header)
	}
}

func TestWithHeadersClonesAllowlistedSourceValues(t *testing.T) {
	source := http.Header{
		"Traceparent":  {"trace-original"},
		"Tracestate":   {"state-original"},
		"X-Request-Id": {"request-original"},
	}
	ctx := WithHeaders(context.Background(), source)
	source.Set("Traceparent", "trace-mutated")
	source.Set("Tracestate", "state-mutated")
	source.Set("X-Request-ID", "request-mutated")

	destination := make(http.Header)
	ApplyHeaders(ctx, destination)

	if got := destination.Get("Traceparent"); got != "trace-original" {
		t.Fatalf("Traceparent = %q", got)
	}
	if got := destination.Get("Tracestate"); got != "state-original" {
		t.Fatalf("Tracestate = %q", got)
	}
	if got := destination.Get("X-Request-ID"); got != "request-original" {
		t.Fatalf("X-Request-ID = %q", got)
	}
}
