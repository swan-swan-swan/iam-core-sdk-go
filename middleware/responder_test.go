package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/authz"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
)

func TestDefaultErrorResponderStatusAndExactFixedJSON(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		kind   string
	}{
		{
			name:   "invalid config",
			err:    sdkerr.New(sdkerr.KindInvalidConfig, "configure", 0, false, errors.New("secret")),
			status: http.StatusBadRequest,
			kind:   "invalid_config",
		},
		{
			name:   "protocol bad request",
			err:    sdkerr.New(sdkerr.KindProtocol, "authz.decide", http.StatusBadRequest, false, nil),
			status: http.StatusBadRequest,
			kind:   "protocol_error",
		},
		{
			name:   "unauthenticated",
			err:    sdkerr.New(sdkerr.KindUnauthenticated, "authenticate", http.StatusUnauthorized, false, nil),
			status: http.StatusUnauthorized,
			kind:   "unauthenticated",
		},
		{
			name:   "credential conflict",
			err:    sdkerr.New(sdkerr.KindCredentialConflict, "authenticate", http.StatusUnauthorized, false, nil),
			status: http.StatusUnauthorized,
			kind:   "credential_conflict",
		},
		{
			name:   "forbidden",
			err:    sdkerr.New(sdkerr.KindForbidden, "authorize", http.StatusForbidden, false, nil),
			status: http.StatusForbidden,
			kind:   "forbidden",
		},
		{
			name:   "session unavailable",
			err:    sdkerr.New(sdkerr.KindSessionUnavailable, "authenticate", 0, true, nil),
			status: http.StatusServiceUnavailable,
			kind:   "session_unavailable",
		},
		{
			name:   "IAM unavailable",
			err:    sdkerr.New(sdkerr.KindIAMUnavailable, "authorize", 0, true, nil),
			status: http.StatusServiceUnavailable,
			kind:   "iam_unavailable",
		},
		{
			name:   "malformed PDP success",
			err:    sdkerr.New(sdkerr.KindProtocol, "authz.decide", http.StatusOK, false, nil),
			status: http.StatusServiceUnavailable,
			kind:   "protocol_error",
		},
		{
			name:   "unknown",
			err:    errors.New("raw-secret"),
			status: http.StatusServiceUnavailable,
			kind:   "iam_unavailable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			defaultErrorResponder{}.Respond(response, request, test.err)
			if response.Code != test.status {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type = %q", got)
			}
			want := "{\"error\":\"" + test.kind + "\"}\n"
			if response.Body.String() != want {
				t.Fatalf("body = %q, want %q", response.Body.String(), want)
			}
			if stringsContainsAny(response.Body.String(), "secret", "raw-secret", "configure", "authorize") {
				t.Fatalf("body leaked error details: %s", response.Body.String())
			}
		})
	}
}

func TestDefaultErrorResponderUsesDecisionContextAndOpaqueID(t *testing.T) {
	decision := authz.Decision{
		ID:         "opaque\njson-id",
		ReasonCode: "future_reason",
		RequestID:  "req-1",
		TraceID:    "trace-1",
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(contextWithDecision(request.Context(), decision))
	err := &sdkerr.Error{
		Kind:       sdkerr.KindForbidden,
		Operation:  "middleware.require_permission",
		HTTPStatus: http.StatusForbidden,
		DecisionID: "must-not-override-context",
		RequestID:  "error-request",
		TraceID:    "error-trace",
		Cause:      errors.New("cause-secret"),
	}
	response := httptest.NewRecorder()
	defaultErrorResponder{}.Respond(response, request, err)
	const want = "{\"error\":\"forbidden\",\"decision_id\":\"opaque\\njson-id\",\"reason_code\":\"future_reason\",\"request_id\":\"req-1\",\"trace_id\":\"trace-1\"}\n"
	if response.Code != http.StatusForbidden || response.Body.String() != want {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestErrorResponderFuncDelegates(t *testing.T) {
	called := false
	responder := ErrorResponderFunc(func(w http.ResponseWriter, request *http.Request, err error) {
		called = request.Method == http.MethodPost && err != nil
		w.WriteHeader(http.StatusTeapot)
	})
	response := httptest.NewRecorder()
	responder.Respond(response, httptest.NewRequest(http.MethodPost, "/", nil), errors.New("error"))
	if !called || response.Code != http.StatusTeapot {
		t.Fatalf("called=%v status=%d", called, response.Code)
	}
}
