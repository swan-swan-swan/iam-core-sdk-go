package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
)

// ErrorResponder writes a caller-visible middleware error.
type ErrorResponder interface {
	Respond(http.ResponseWriter, *http.Request, error)
}

// ErrorResponderFunc adapts a function to ErrorResponder.
type ErrorResponderFunc func(http.ResponseWriter, *http.Request, error)

func (f ErrorResponderFunc) Respond(w http.ResponseWriter, request *http.Request, err error) {
	f(w, request, err)
}

type defaultErrorResponder struct{}

type errorResponse struct {
	Error      string `json:"error"`
	DecisionID string `json:"decision_id,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	TraceID    string `json:"trace_id,omitempty"`
}

func (defaultErrorResponder) Respond(w http.ResponseWriter, request *http.Request, err error) {
	status, kind, typed := responseError(err)
	payload := errorResponse{Error: string(kind)}
	if typed != nil {
		payload.DecisionID = typed.DecisionID
		payload.RequestID = typed.RequestID
		payload.TraceID = typed.TraceID
	}
	if request != nil {
		if decision, ok := DecisionFromContext(request.Context()); ok {
			payload.DecisionID = decision.ID
			payload.ReasonCode = decision.ReasonCode
			payload.RequestID = decision.RequestID
			payload.TraceID = decision.TraceID
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func responseError(err error) (int, sdkerr.Kind, *sdkerr.Error) {
	var typed *sdkerr.Error
	if !errors.As(err, &typed) || typed == nil {
		return http.StatusServiceUnavailable, sdkerr.KindIAMUnavailable, nil
	}
	switch typed.Kind {
	case sdkerr.KindInvalidConfig:
		return http.StatusBadRequest, typed.Kind, typed
	case sdkerr.KindProtocol:
		if strings.HasPrefix(typed.Operation, "authz.") &&
			typed.HTTPStatus != http.StatusBadRequest {
			return http.StatusServiceUnavailable, typed.Kind, typed
		}
		return http.StatusBadRequest, typed.Kind, typed
	case sdkerr.KindUnauthenticated, sdkerr.KindCredentialConflict:
		return http.StatusUnauthorized, typed.Kind, typed
	case sdkerr.KindForbidden:
		return http.StatusForbidden, typed.Kind, typed
	case sdkerr.KindSessionUnavailable, sdkerr.KindIAMUnavailable:
		return http.StatusServiceUnavailable, typed.Kind, typed
	default:
		return http.StatusServiceUnavailable, sdkerr.KindIAMUnavailable, typed
	}
}
