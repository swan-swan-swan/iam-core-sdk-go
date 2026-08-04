package client

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDecodeEnvelopeDecodesSuccessfulDataAndAllowsUnknownFields(t *testing.T) {
	t.Parallel()

	type result struct {
		Name string `json:"name"`
	}
	var out result
	metadata, err := decodeEnvelope([]byte(`{
		"code":0,
		"message":"ok",
		"data":{"name":"application"},
		"request_id":"request-123",
		"trace_id":"trace:456",
		"future":{"nested":true}
	}`), 200, "management.applications.get", &out)
	if err != nil {
		t.Fatalf("decodeEnvelope(): %v", err)
	}
	if out.Name != "application" {
		t.Fatalf("decoded name = %q, want application", out.Name)
	}
	if metadata != (Metadata{RequestID: "request-123", TraceID: "trace:456"}) {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestDecodeEnvelopeRejectsDuplicateKeysAtEveryObjectDepth(t *testing.T) {
	t.Parallel()

	tests := []string{
		`{"code":0,"code":0,"message":"ok","data":null}`,
		`{"code":0,"message":"ok","data":{"name":"one","name":"two"}}`,
		`{"code":0,"message":"ok","data":{"items":[{"id":1,"id":2}]}}`,
		`{"code":0,"message":"ok","data":null,"future":{"value":1,"value":2}}`,
	}
	for _, raw := range tests {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeEnvelope([]byte(raw), 200, "management.test", nil); !errors.Is(err, ErrProtocol) {
				t.Fatalf("decodeEnvelope() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestDecodeEnvelopeRejectsMalformedOrIncompleteEnvelope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ``},
		{name: "not object", raw: `[]`},
		{name: "trailing JSON", raw: `{"code":0,"message":"ok","data":null}{}`},
		{name: "missing code", raw: `{"message":"ok","data":null}`},
		{name: "missing message", raw: `{"code":0,"data":null}`},
		{name: "missing data", raw: `{"code":0,"message":"ok"}`},
		{name: "blank message", raw: `{"code":0,"message":" \n\t","data":null}`},
		{name: "nonzero success code", raw: `{"code":7,"message":"ok","data":null}`},
		{name: "unsafe request ID", raw: `{"code":0,"message":"ok","data":null,"request_id":"request\nsecret"}`},
		{name: "unsafe trace ID", raw: `{"code":0,"message":"ok","data":null,"trace_id":"trace with spaces"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeEnvelope([]byte(tt.raw), 200, "management.test", nil); !errors.Is(err, ErrProtocol) {
				t.Fatalf("decodeEnvelope() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestDecodeEnvelopeRejectsWrongEnvelopeFieldTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		raw    string
	}{
		{name: "null code", status: 200, raw: `{"code":null,"message":"ok","data":null}`},
		{name: "string code", status: 200, raw: `{"code":"0","message":"ok","data":null}`},
		{name: "null message", status: 200, raw: `{"code":0,"message":null,"data":null}`},
		{name: "number message", status: 200, raw: `{"code":0,"message":1,"data":null}`},
		{name: "string data", status: 200, raw: `{"code":0,"message":"ok","data":"value"}`},
		{name: "number error data", status: 409, raw: `{"code":1,"message":"conflict","data":2}`},
		{name: "null request ID", status: 200, raw: `{"code":0,"message":"ok","data":null,"request_id":null}`},
		{name: "number request ID", status: 200, raw: `{"code":0,"message":"ok","data":null,"request_id":1}`},
		{name: "null trace ID", status: 200, raw: `{"code":0,"message":"ok","data":null,"trace_id":null}`},
		{name: "object trace ID", status: 200, raw: `{"code":0,"message":"ok","data":null,"trace_id":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeEnvelope([]byte(tt.raw), tt.status, "management.test", nil); !errors.Is(err, ErrProtocol) {
				t.Fatalf("decodeEnvelope() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestDecodeEnvelopePermitsNullSuccessDataOnlyWithoutOutput(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"code":0,"message":"ok","data":null}`)
	if _, err := decodeEnvelope(raw, 204, "management.test", nil); err != nil {
		t.Fatalf("decodeEnvelope(nil output): %v", err)
	}
	var out any
	if _, err := decodeEnvelope(raw, 200, "management.test", &out); !errors.Is(err, ErrProtocol) {
		t.Fatalf("decodeEnvelope(non-nil output) error = %v, want ErrProtocol", err)
	}
}

func TestDecodeEnvelopeStrictlyDecodesSuccessOutput(t *testing.T) {
	t.Parallel()

	type result struct {
		Name string `json:"name"`
	}
	var out result
	raw := []byte(`{"code":0,"message":"ok","data":{"name":"application","future":true}}`)
	if _, err := decodeEnvelope(raw, 200, "management.test", &out); !errors.Is(err, ErrProtocol) {
		t.Fatalf("decodeEnvelope() error = %v, want ErrProtocol for unknown output field", err)
	}
}

func TestDecodeEnvelopeMapsHTTPErrorAndCopiesStructuredData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status    int
		kind      Kind
		retryable bool
	}{
		{status: 400, kind: KindProtocol},
		{status: 401, kind: KindUnauthenticated},
		{status: 403, kind: KindForbidden},
		{status: 404, kind: KindNotFound},
		{status: 409, kind: KindConflict},
		{status: 429, kind: KindRateLimited, retryable: true},
		{status: 500, kind: KindIAMUnavailable, retryable: true},
		{status: 599, kind: KindIAMUnavailable, retryable: true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%d", tt.kind, tt.status), func(t *testing.T) {
			t.Parallel()
			raw := []byte(`{"code":0,"message":"request failed","data":{"reason":"bounded"},"request_id":"request-1","trace_id":"trace-1"}`)
			var out struct{ MustRemainEmpty string }
			metadata, err := decodeEnvelope(raw, tt.status, "management.applications.get", &out)
			if err == nil {
				t.Fatal("decodeEnvelope() error = nil")
			}
			var managementError *Error
			if !errors.As(err, &managementError) {
				t.Fatalf("decodeEnvelope() error type = %T, want *Error", err)
			}
			if managementError.Kind != tt.kind || managementError.StatusCode != tt.status || managementError.IAMCode != 0 || managementError.Retryable != tt.retryable {
				t.Fatalf("management error = %#v", managementError)
			}
			if managementError.Operation != "management.applications.get" || managementError.RequestID != "request-1" || managementError.TraceID != "trace-1" {
				t.Fatalf("management error metadata = %#v", managementError)
			}
			if metadata != (Metadata{RequestID: "request-1", TraceID: "trace-1"}) {
				t.Fatalf("metadata = %#v", metadata)
			}
			if string(managementError.Data) != `{"reason":"bounded"}` {
				t.Fatalf("error data = %s", managementError.Data)
			}
			raw[strings.Index(string(raw), "bounded")] = 'X'
			if string(managementError.Data) != `{"reason":"bounded"}` {
				t.Fatal("error data aliases response body")
			}
			if out.MustRemainEmpty != "" {
				t.Fatal("non-2xx response decoded into success output")
			}
		})
	}
}

func TestDecodeEnvelopePermitsNullErrorData(t *testing.T) {
	t.Parallel()

	_, err := decodeEnvelope([]byte(`{"code":0,"message":"unauthenticated","data":null}`), 401, "management.test", new(any))
	var managementError *Error
	if !errors.As(err, &managementError) {
		t.Fatalf("decodeEnvelope() error = %v, want *Error", err)
	}
	if len(managementError.Data) != 0 {
		t.Fatalf("error data = %s, want empty", managementError.Data)
	}
}

func TestDecodeEnvelopeRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()

	raw := append([]byte(`{"code":0,"message":"`), 0xff)
	raw = append(raw, []byte(`","data":null}`)...)
	if _, err := decodeEnvelope(raw, 200, "management.test", nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("decodeEnvelope() error = %v, want ErrProtocol", err)
	}
}
