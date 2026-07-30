package sdkerr

import (
	"errors"
	"net/http"
	"testing"
)

func TestErrorSupportsKindAndSentinelMatching(t *testing.T) {
	cause := errors.New("dial tcp 10.0.0.1:443")
	err := New(KindIAMUnavailable, "oidc.userinfo", http.StatusServiceUnavailable, true, cause)
	err.RequestID = "req-1"

	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("error must match ErrUnavailable")
	}
	if got := err.Error(); got != "oidc.userinfo: iam_unavailable" {
		t.Fatalf("Error() = %q", got)
	}
	if err.Unwrap() != cause {
		t.Fatal("Unwrap() must return cause")
	}
}

func TestErrorStringNeverIncludesSensitiveCause(t *testing.T) {
	err := New(KindUnauthenticated, "authn.callback", http.StatusUnauthorized, false, errors.New("token=secret-value"))
	if got := err.Error(); got != "authn.callback: unauthenticated" {
		t.Fatalf("Error() leaked cause: %q", got)
	}
}
