package iamcore_test

import (
	"slices"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestV181FrozenContract(t *testing.T) {
	if core.ContractVersion != "v1.8.1" {
		t.Fatalf("contract version=%q", core.ContractVersion)
	}
	wantScopes := []string{"openid", "profile", "email", "groups"}
	gotScopes := bff.DefaultScopes()
	if !slices.Equal(gotScopes, wantScopes) || slices.Contains(gotScopes, "roles") {
		t.Fatalf("default scopes=%v", gotScopes)
	}
	gotScopes[0] = "mutated"
	if second := bff.DefaultScopes(); !slices.Equal(second, wantScopes) {
		t.Fatalf("default scopes after caller mutation=%v", second)
	}
}
