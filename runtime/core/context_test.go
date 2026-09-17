package core_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
)

func TestAuthContextAuthenticationMethodsAreDefensivelyCopied(t *testing.T) {
	authTime := time.Unix(1_800_000_000, 0).UTC()
	original := core.AuthContext{
		Subject:               "op_usr_1",
		AuthTime:              authTime,
		AuthenticationMethods: []string{"pwd", "otp"},
	}
	ctx := core.ContextWithAuthContext(context.Background(), original)
	original.AuthenticationMethods[0] = "mutated-source"

	got, ok := core.AuthContextFromContext(ctx)
	if !ok {
		t.Fatal("AuthContextFromContext() ok = false")
	}
	if !got.AuthTime.Equal(authTime) || !slices.Equal(got.AuthenticationMethods, []string{"pwd", "otp"}) {
		t.Fatalf("authentication context = %#v", got)
	}
	got.AuthenticationMethods[1] = "mutated-result"

	again, _ := core.AuthContextFromContext(ctx)
	if !slices.Equal(again.AuthenticationMethods, []string{"pwd", "otp"}) {
		t.Fatalf("stored authentication methods were aliased: %#v", again.AuthenticationMethods)
	}
}

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
