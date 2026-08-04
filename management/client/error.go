package client

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Kind categorizes a management API error.
type Kind string

const (
	KindInvalidConfig   Kind = "invalid_config"
	KindInvalidArgument Kind = "invalid_argument"
	KindUnauthenticated Kind = "unauthenticated"
	KindForbidden       Kind = "forbidden"
	KindNotFound        Kind = "not_found"
	KindConflict        Kind = "conflict"
	KindRateLimited     Kind = "rate_limited"
	KindIAMUnavailable  Kind = "iam_unavailable"
	KindProtocol        Kind = "protocol"
)

// Error describes a management API failure. Data is structured diagnostic
// data only; Error deliberately never includes it in formatted output.
type Error struct {
	Kind       Kind
	Operation  string
	StatusCode int
	IAMCode    int
	Retryable  bool
	RequestID  string
	TraceID    string
	Data       json.RawMessage
}

var (
	ErrInvalidConfig   = &Error{Kind: KindInvalidConfig}
	ErrInvalidArgument = &Error{Kind: KindInvalidArgument}
	ErrUnauthenticated = &Error{Kind: KindUnauthenticated}
	ErrForbidden       = &Error{Kind: KindForbidden}
	ErrNotFound        = &Error{Kind: KindNotFound}
	ErrConflict        = &Error{Kind: KindConflict}
	ErrRateLimited     = &Error{Kind: KindRateLimited}
	ErrIAMUnavailable  = &Error{Kind: KindIAMUnavailable}
	ErrProtocol        = &Error{Kind: KindProtocol}
)

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("management API error: operation=%s kind=%s status=%d", e.Operation, e.Kind, e.StatusCode)
}

// Is reports whether target has the same error kind. It makes the package
// sentinel errors usable with errors.Is.
func (e *Error) Is(target error) bool {
	if e == nil {
		return false
	}
	other, ok := target.(*Error)
	return ok && other != nil && e.Kind != "" && e.Kind == other.Kind
}

// ErrorData decodes structured diagnostic data from a management Error.
// It copies the raw bytes before decoding so callers never receive the
// error's backing slice.
func ErrorData(err error, out any) bool {
	var managementError *Error
	if !errors.As(err, &managementError) || managementError == nil || len(managementError.Data) == 0 {
		return false
	}
	return json.Unmarshal(cloneErrorData(managementError.Data), out) == nil
}

// maxErrorDataBytes bounds structured diagnostics to the management response
// body limit. HTTP response handling uses this same cap before constructing an
// Error.
const maxErrorDataBytes = 1 << 20

func cloneErrorData(data json.RawMessage) json.RawMessage {
	if len(data) > maxErrorDataBytes {
		data = data[:maxErrorDataBytes]
	}
	return append(json.RawMessage(nil), data...)
}
