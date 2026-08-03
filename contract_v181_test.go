package iamcore_test

import (
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestV181FrozenContract(t *testing.T) {
	if core.ContractVersion != "v1.8.1" {
		t.Fatalf("contract version=%q", core.ContractVersion)
	}
}
