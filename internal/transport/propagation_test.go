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
