package bff

import (
	"errors"
	"slices"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

func TestReconcileScopesUsesOnlyAvailableSourcesAsSortedSets(t *testing.T) {
	tests := []struct {
		name, token string
		access, id  []string
		want        []string
		wantError   bool
	}{
		{name: "all equal after normalization", token: "openid groups groups", access: []string{"groups", "openid"}, id: []string{" openid ", "groups"}, want: []string{"groups", "openid"}},
		{name: "token only", token: "profile openid", want: []string{"openid", "profile"}},
		{name: "access only", access: []string{"openid"}, want: []string{"openid"}},
		{name: "id present empty", id: []string{}, want: []string{}},
		{name: "no source", wantError: true},
		{name: "token access mismatch", token: "openid groups", access: []string{"openid"}, wantError: true},
		{name: "access id mismatch", access: []string{"openid"}, id: []string{"openid", "groups"}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := reconcileScopes(test.token, test.access, test.id)
			if test.wantError {
				var typed *core.Error
				if !errors.As(err, &typed) || typed.Kind != core.KindProtocol || typed.Operation != "bff.scope" {
					t.Fatalf("reconcileScopes() error = %#v", err)
				}
				return
			}
			if err != nil || !slices.Equal(got, test.want) {
				t.Fatalf("reconcileScopes() = %v, %v; want %v", got, err, test.want)
			}
		})
	}
}

func TestNormalizeGroupsTrimsSortsDeduplicatesAndPreservesPresentEmpty(t *testing.T) {
	got := normalizeGroups([]string{" ops ", "", "dev", "ops", "  "})
	if !slices.Equal(got, []string{"dev", "ops"}) {
		t.Fatalf("normalizeGroups() = %v", got)
	}
	empty := normalizeGroups([]string{})
	if empty == nil || len(empty) != 0 {
		t.Fatalf("normalizeGroups(empty) = %#v", empty)
	}
	if normalizeGroups(nil) != nil {
		t.Fatal("normalizeGroups(nil) should preserve absence")
	}
}

func TestReconcileScopesReturnsDefensiveCopy(t *testing.T) {
	access := []string{"openid", "groups"}
	got, err := reconcileScopes("", access, nil)
	if err != nil {
		t.Fatal(err)
	}
	got[0] = "mutated"
	if !slices.Equal(access, []string{"openid", "groups"}) {
		t.Fatalf("input mutated: %v", access)
	}
}
