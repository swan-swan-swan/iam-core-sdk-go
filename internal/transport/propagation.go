package transport

import (
	"context"
	"net/http"
	"strings"
)

type propagationKey struct{}

var forwardedHeaders = [...]string{"Traceparent", "Tracestate", "X-Request-ID"}

func WithHeaders(ctx context.Context, source http.Header) context.Context {
	values := make(http.Header, len(forwardedHeaders))
	for _, name := range forwardedHeaders {
		if value := strings.TrimSpace(source.Get(name)); value != "" {
			values.Set(name, value)
		}
	}
	return context.WithValue(ctx, propagationKey{}, values)
}

func ApplyHeaders(ctx context.Context, destination http.Header) {
	values, _ := ctx.Value(propagationKey{}).(http.Header)
	for _, name := range forwardedHeaders {
		if value := strings.TrimSpace(values.Get(name)); value != "" {
			destination.Set(name, value)
		}
	}
}
