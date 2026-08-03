package core_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestErrorStringNeverIncludesCause(t *testing.T) {
	secret := "secret-access-token"
	err := core.NewError(core.KindProtocol, "core.verify", 0, false, errors.New(secret))
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked cause: %q", err)
	}
}
