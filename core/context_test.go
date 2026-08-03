package core_test

import (
	"context"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestAuthContextFromContextReturnsDefensiveCopy(t *testing.T) {
	original := core.AuthContext{
		Subject:  "op_usr_1",
		Audience: []string{"portal"},
		Scopes:   []string{"openid", "groups"},
		Groups:   []string{"ops"},
	}
	ctx := core.ContextWithAuthContext(context.Background(), original)

	got, ok := core.AuthContextFromContext(ctx)
	if !ok {
		t.Fatal("AuthContextFromContext() ok = false")
	}
	got.Audience[0], got.Scopes[0], got.Groups[0] = "changed", "changed", "changed"

	again, _ := core.AuthContextFromContext(ctx)
	if again.Audience[0] != "portal" || again.Scopes[0] != "openid" || again.Groups[0] != "ops" {
		t.Fatalf("stored context was aliased: %#v", again)
	}
}

func TestAuthContextFromContextPreservesInitializedEmptyGroups(t *testing.T) {
	original := core.AuthContext{Subject: "op_usr_1", Groups: []string{}}
	ctx := core.ContextWithAuthContext(context.Background(), original)

	got, ok := core.AuthContextFromContext(ctx)
	if !ok {
		t.Fatal("AuthContextFromContext() ok = false")
	}
	if got.Groups == nil || len(got.Groups) != 0 {
		t.Fatal("Groups was not preserved as an initialized empty slice")
	}

	again, ok := core.AuthContextFromContext(ctx)
	if !ok || again.Groups == nil || len(again.Groups) != 0 {
		t.Fatal("second Groups copy was not preserved as an initialized empty slice")
	}
}
