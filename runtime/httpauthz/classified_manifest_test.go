package httpauthz_test

import (
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/authzcontract"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpauthz"
	"strings"
	"testing"
)

// TestClassifiedSpecPreservesPDPFacts 防止分类改变请求授权坐标。
func TestClassifiedSpecPreservesPDPFacts(t *testing.T) {
	got, err := httpauthz.NewClassifiedRouteSpec("GET", "/api/v1/apps/:id/open", "portal.app.jenkins.open", "opsgw:jenkins:access", authzcontract.PolicyClassCardAccess)
	if err != nil {
		t.Fatal(err)
	}
	want, err := httpauthz.NewRouteSpec("GET", "/api/v1/apps/:id/open", "portal.app.jenkins.open", "opsgw:jenkins:access")
	if err != nil || got.Spec != want {
		t.Fatal("classification changed PDP route facts")
	}
	for _, tc := range []struct {
		method, template, name, action string
		class                          authzcontract.PolicyClass
	}{
		{"GET", "/apps?secret=x", "portal.app.open", "opsgw:jenkins:access", authzcontract.PolicyClassCardAccess},
		{"GET", "/apps", "Bad.Name", "opsgw:jenkins:access", authzcontract.PolicyClassCardAccess},
		{"DELETE", "/apps", "portal.app.delete", "opsgw:jenkins:delete", authzcontract.PolicyClassReadOnlyAccess},
	} {
		if _, err := httpauthz.NewClassifiedRouteSpec(tc.method, tc.template, tc.name, tc.action, tc.class); err == nil {
			t.Fatal("accepted invalid classified declaration")
		}
	}
}

// TestClassifiedPolicyClassErrorIdentifiesField 保证调用方能定位分类错误且不泄露输入。
func TestClassifiedPolicyClassErrorIdentifiesField(t *testing.T) {
	_, err := httpauthz.NewClassifiedRouteSpec("GET", "/apps", "portal.app.open", "opsgw:jenkins:access", authzcontract.PolicyClass("sensitive-value"))
	if err == nil || !strings.Contains(err.Error(), "policy_class") || strings.Contains(err.Error(), "sensitive-value") {
		t.Fatalf("classification error is not field-safe: %v", err)
	}
}
