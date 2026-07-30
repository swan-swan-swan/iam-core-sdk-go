package iamcore

import "github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"

type Error = sdkerr.Error
type ErrorKind = sdkerr.Kind
type ErrorReason = sdkerr.Reason

const (
	ErrorInvalidConfig      = sdkerr.KindInvalidConfig
	ErrorUnauthenticated    = sdkerr.KindUnauthenticated
	ErrorCredentialConflict = sdkerr.KindCredentialConflict
	ErrorForbidden          = sdkerr.KindForbidden
	ErrorProtocol           = sdkerr.KindProtocol
	ErrorSessionUnavailable = sdkerr.KindSessionUnavailable
	ErrorIAMUnavailable     = sdkerr.KindIAMUnavailable

	ErrorReasonInvalidGrant = sdkerr.ReasonInvalidGrant
)

var (
	ErrUnauthenticated = sdkerr.ErrUnauthenticated
	ErrForbidden       = sdkerr.ErrForbidden
	ErrUnavailable     = sdkerr.ErrUnavailable
	ErrInvalidGrant    = sdkerr.ErrInvalidGrant
)
