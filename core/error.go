package core

import (
	"errors"
	"fmt"
)

type Kind string
type Reason string

const ContractVersion = "v1.8.1"

const (
	KindInvalidConfig            Kind   = "invalid_config"
	KindProtocol                 Kind   = "protocol_error"
	KindUnauthenticated          Kind   = "unauthenticated"
	KindForbidden                Kind   = "forbidden"
	KindIAMUnavailable           Kind   = "iam_unavailable"
	KindSessionUnavailable       Kind   = "session_unavailable"
	KindCredentialConflict       Kind   = "credential_conflict"
	ReasonInvalidGrant           Reason = "invalid_grant"
	ReasonAccessDenied           Reason = "access_denied"
	ReasonTemporarilyUnavailable Reason = "temporarily_unavailable"
)

var (
	ErrUnauthenticated = errors.New("iamcore: unauthenticated")
	ErrForbidden       = errors.New("iamcore: forbidden")
	ErrUnavailable     = errors.New("iamcore: unavailable")
	ErrInvalidGrant    = errors.New("iamcore: invalid grant")
)

type Error struct {
	Kind       Kind
	Reason     Reason
	Operation  string
	HTTPStatus int
	RequestID  string
	TraceID    string
	DecisionID string
	Retryable  bool
	cause      error
}

func NewError(kind Kind, operation string, status int, retryable bool, cause error) *Error {
	return &Error{Kind: kind, Operation: operation, HTTPStatus: status, Retryable: retryable, cause: cause}
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

func (e *Error) Is(target error) bool {
	switch target {
	case ErrUnauthenticated:
		return e != nil && e.Kind == KindUnauthenticated
	case ErrForbidden:
		return e != nil && e.Kind == KindForbidden
	case ErrUnavailable:
		return e != nil && (e.Kind == KindIAMUnavailable || e.Kind == KindSessionUnavailable)
	case ErrInvalidGrant:
		return e != nil && e.Reason == ReasonInvalidGrant
	default:
		return false
	}
}
