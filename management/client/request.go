package client

import (
	"context"
	"net/url"
)

// Metadata identifies a completed management API request.
type Metadata struct {
	RequestID string
	TraceID   string
}

// Request is a validated management API request. Path is a canonical
// /api/v1/... path without a query or fragment.
type Request struct {
	Operation      string
	Method         string
	Path           string
	Query          url.Values
	Body           any
	IdempotencyKey string
}

// Transport executes a management API request.
type Transport interface {
	Do(ctx context.Context, request Request, out any) (Metadata, error)
}

// Page contains a page of management API results.
type Page[T any] struct {
	Items    []T
	Page     int
	PageSize int
	Total    int64
}
