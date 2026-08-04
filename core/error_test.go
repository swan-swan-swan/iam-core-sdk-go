package core_test

import (
	"errors"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/testkit"
)

func TestErrorStringNeverIncludesCause(t *testing.T) {
	secret := "secret-access-token"
	err := core.NewError(core.KindProtocol, "core.verify", 0, false, errors.New(secret))
	testkit.AssertNoLeak(t, err.Error(), secret)
}
