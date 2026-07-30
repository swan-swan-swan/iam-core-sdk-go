package sdkerr

import (
	"errors"
	"fmt"
)

type Kind string

const (
	KindInvalidConfig      Kind = "invalid_config"
	KindUnauthenticated    Kind = "unauthenticated"
	KindCredentialConflict Kind = "credential_conflict"
	KindForbidden          Kind = "forbidden"
	KindProtocol           Kind = "protocol_error"
	KindSessionUnavailable Kind = "session_unavailable"
	KindIAMUnavailable     Kind = "iam_unavailable"
)

var (
	ErrUnauthenticated = errors.New("iamcore: unauthenticated")
	ErrForbidden       = errors.New("iamcore: forbidden")
	ErrUnavailable     = errors.New("iamcore: unavailable")
)

type Error struct {
	Kind       Kind
	Operation  string
	HTTPStatus int
	RequestID  string
	TraceID    string
	DecisionID string
	Retryable  bool
	Cause      error
}

func New(kind Kind, operation string, status int, retryable bool, cause error) *Error {
	return &Error{Kind: kind, Operation: operation, HTTPStatus: status, Retryable: retryable, Cause: cause}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Operation == "" {
		return string(e.Kind)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Kind)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *Error) Is(target error) bool {
	switch target {
	case ErrUnauthenticated:
		return e != nil && e.Kind == KindUnauthenticated
	case ErrForbidden:
		return e != nil && e.Kind == KindForbidden
	case ErrUnavailable:
		return e != nil && (e.Kind == KindIAMUnavailable || e.Kind == KindSessionUnavailable)
	default:
		return false
	}
}
