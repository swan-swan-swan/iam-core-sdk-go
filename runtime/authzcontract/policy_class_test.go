package authzcontract_test

import (
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/authzcontract"
	"testing"
)

// TestPolicyClassValidation 防止显式分类丢失或把写入能力伪装为只读。
func TestPolicyClassValidation(t *testing.T) {
	for _, tc := range []struct {
		method, action, class string
		valid                 bool
	}{
		{"GET", "opsgw:jenkins:access", "CardAccess", true},
		{"POST", "opsgw:application:select", "ReadOnlyAccess", true},
		{"GET", "opsgw:portal:discover", "ReadOnlyAccess", true},
		{"POST", "opsgw:application:preview", "ReadOnlyAccess", true},
		{"GET", "opsgw:application:export", "ReadOnlyAccess", true},
		{"POST", "opsgw:application:execute", "FullAccess", true},
		{"GET", "opsgw:admin:access", "FullAccess", true},
		{"GET", "opsgw:jenkins:access", "", false},
		{"GET", "opsgw:jenkins:access", "cardaccess", false},
		{"GET", "opsgw:jenkins:access", "Unknown", false},
		{"DELETE", "opsgw:application:delete", "ReadOnlyAccess", false},
		{"GET", "opsgw:application:reveal", "ReadOnlyAccess", false},
		{"GET", "opsgw:jenkins:access", "ReadOnlyAccess", false},
		{"POST", "opsgw:jenkins:access", "CardAccess", false},
		{"GET", "opsgw:application:select", "CardAccess", false},
		{"get", "opsgw:jenkins:access", "CardAccess", false},
		{"", "opsgw:application:select", "FullAccess", false},
		{"INVALID", "opsgw:application:select", "FullAccess", false},
		{"GET", "opsgw:application:read", "FullAccess", false},
		{"GET", " opsgw:application:select", "ReadOnlyAccess", false},
	} {
		t.Run(tc.method+"/"+tc.action+"/"+tc.class, func(t *testing.T) {
			err := authzcontract.ValidatePolicyClass(tc.method, tc.action, authzcontract.PolicyClass(tc.class))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
