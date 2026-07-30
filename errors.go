package iamcore

import "github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"

type Error = sdkerr.Error
type ErrorKind = sdkerr.Kind

const (
	ErrorInvalidConfig      = sdkerr.KindInvalidConfig
	ErrorUnauthenticated    = sdkerr.KindUnauthenticated
	ErrorCredentialConflict = sdkerr.KindCredentialConflict
	ErrorForbidden          = sdkerr.KindForbidden
	ErrorProtocol           = sdkerr.KindProtocol
	ErrorSessionUnavailable = sdkerr.KindSessionUnavailable
	ErrorIAMUnavailable     = sdkerr.KindIAMUnavailable
)

var (
	ErrUnauthenticated = sdkerr.ErrUnauthenticated
	ErrForbidden       = sdkerr.ErrForbidden
	ErrUnavailable     = sdkerr.ErrUnavailable
)
