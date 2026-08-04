package httpauthz

import (
	"errors"
	"net/http"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

// ErrorResponder writes a caller-visible middleware error response.
type ErrorResponder interface {
	Respond(http.ResponseWriter, *http.Request, error)
}

// ErrorResponderFunc adapts a function to ErrorResponder.
type ErrorResponderFunc func(http.ResponseWriter, *http.Request, error)

func (f ErrorResponderFunc) Respond(w http.ResponseWriter, request *http.Request, err error) {
	f(w, request, err)
}

type defaultErrorResponder struct{}

func (defaultErrorResponder) Respond(w http.ResponseWriter, _ *http.Request, err error) {
	status := http.StatusServiceUnavailable
	var typed *core.Error
	if errors.As(err, &typed) && typed != nil {
		switch typed.Kind {
		case core.KindUnauthenticated, core.KindCredentialConflict:
			status = http.StatusUnauthorized
		case core.KindForbidden:
			status = http.StatusForbidden
		case core.KindInvalidConfig, core.KindProtocol:
			status = http.StatusBadRequest
		case core.KindIAMUnavailable, core.KindSessionUnavailable:
			status = http.StatusServiceUnavailable
		default:
			status = http.StatusServiceUnavailable
		}
	}
	http.Error(w, http.StatusText(status), status)
}
