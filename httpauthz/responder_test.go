package httpauthz

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestResponderMapsErrorsToMinimalStatuses(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "unauthenticated", err: core.NewError(core.KindUnauthenticated, "secret-operation", 418, false, errors.New("cause-secret")), status: http.StatusUnauthorized},
		{name: "credential conflict", err: core.NewError(core.KindCredentialConflict, "secret-operation", 418, false, nil), status: http.StatusUnauthorized},
		{name: "forbidden", err: core.NewError(core.KindForbidden, "secret-operation", 418, false, nil), status: http.StatusForbidden},
		{name: "invalid config", err: core.NewError(core.KindInvalidConfig, "secret-operation", 418, false, nil), status: http.StatusBadRequest},
		{name: "protocol", err: core.NewError(core.KindProtocol, "secret-operation", 418, false, nil), status: http.StatusBadRequest},
		{name: "iam unavailable", err: core.NewError(core.KindIAMUnavailable, "secret-operation", 418, true, nil), status: http.StatusServiceUnavailable},
		{name: "session unavailable", err: core.NewError(core.KindSessionUnavailable, "secret-operation", 418, true, nil), status: http.StatusServiceUnavailable},
		{name: "unknown kind", err: core.NewError(core.Kind("future-secret-kind"), "secret-operation", 418, false, nil), status: http.StatusServiceUnavailable},
		{name: "untyped", err: errors.New("raw-error-secret"), status: http.StatusServiceUnavailable},
		{name: "wrapped", err: errors.Join(errors.New("wrapper-secret"), core.NewError(core.KindForbidden, "secret-operation", 0, false, nil)), status: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/?access_token=query-secret", nil)
			request.Header.Set("Authorization", "Bearer header-secret")
			request.Header.Set("Cookie", "session=cookie-secret")
			defaultErrorResponder{}.Respond(response, request, test.err)
			if response.Code != test.status || response.Body.String() != http.StatusText(test.status)+"\n" {
				t.Fatalf("response = %d %q", response.Code, response.Body.String())
			}
			for _, secret := range []string{"secret-operation", "cause-secret", "future-secret-kind", "raw-error-secret", "wrapper-secret", "query-secret", "header-secret", "cookie-secret", "access_token", "session="} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatalf("response body disclosed %q", secret)
				}
			}
		})
	}
}

func TestResponderFuncAdaptsFunction(t *testing.T) {
	var calls int
	responder := ErrorResponderFunc(func(w http.ResponseWriter, _ *http.Request, _ error) {
		calls++
		w.WriteHeader(http.StatusTeapot)
	})
	response := httptest.NewRecorder()
	responder.Respond(response, httptest.NewRequest(http.MethodGet, "/", nil), errors.New("ignored"))
	if calls != 1 || response.Code != http.StatusTeapot {
		t.Fatalf("calls/status = %d/%d", calls, response.Code)
	}
}
