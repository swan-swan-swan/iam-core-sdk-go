package iamcore

import (
	"errors"
	"net/http"
	"testing"
)

func TestInvalidGrantRootAliasesClassifyTypedError(t *testing.T) {
	err := &Error{
		Kind:       ErrorUnauthenticated,
		Operation:  "oidc.refresh",
		HTTPStatus: http.StatusBadRequest,
		Reason:     ErrorReasonInvalidGrant,
	}

	var reason ErrorReason = err.Reason
	if reason != ErrorReasonInvalidGrant || !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("reason = %q, error = %#v", reason, err)
	}
}
