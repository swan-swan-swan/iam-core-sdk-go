package authzcontract_test

import (
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/authzcontract"
)

func TestParseActionContract(t *testing.T) {
	valid := []string{"iam:oidc_client:select", "opsgw:portal:discover", "iam:plugin_credential:rotate", "opsgw:iam-core:access", "app:goose-case:select", strings.Repeat("a", 53) + ":b:select"}
	for _, verb := range []string{"access", "discover", "select", "create", "update", "delete", "execute", "preview", "publish", "approve", "bind", "revoke", "rotate", "reveal", "export", "import"} {
		valid = append(valid, "iam:user:"+verb)
	}
	for _, raw := range valid {
		action, err := authzcontract.ParseAction(raw)
		if err != nil || action.String() != raw || action.Server+":"+action.Domain+":"+action.Verb != raw {
			t.Errorf("valid action %q did not round-trip: %v", raw, err)
		}
	}
	invalid := []string{"", "iam:user", "iam:user:select:all", "IAM:user:select", "iam:user:list", "iam:user:get", "iam:user:*", "ops-ws:user:select", "ops_ws:user:select", " iam:user:select", "iam:user:select ", "iam:user__name:select", "iam:_user:select", "iam:user_:select", "iam:oidc-client:select", "opsgw:iam_core:access", "opsgw:iam01core:access", "1iam:user:select", "iam:用戶:select", "iam:user:select\n", strings.Repeat("a", 56) + ":b:select"}
	for _, raw := range invalid {
		if _, err := authzcontract.ParseAction(raw); err == nil {
			t.Errorf("accepted invalid action %q", raw)
		} else if raw != "" && strings.Contains(err.Error(), raw) {
			t.Error("error includes raw action")
		}
	}
}

func TestRouteNameCanonicalResource(t *testing.T) {
	for _, tc := range []struct {
		raw, server, resource string
	}{
		{"portal.app.iam-core.open", "opsgw", "http:opsgw:portal.app.iam-core.open"},
		{"iam.oidcclient.list", "iam", "http:iam:iam_oidcclient_list"},
		{strings.Repeat("a", 60) + ".b.c", "opsgw", "http:opsgw:" + strings.Repeat("a", 60) + ".b.c"},
	} {
		route, err := authzcontract.ParseRouteName(tc.raw)
		if err != nil || route.String() != tc.raw || route.CanonicalResource(tc.server) != tc.resource {
			t.Errorf("route %q: canonical resource %q, error %v", tc.raw, route.CanonicalResource(tc.server), err)
		}
	}
	for _, raw := range []string{"", "a.b", "A.b.c", "a.b_c.d", ".a.b.c", "a..b.c", "a.b.c.", "a.b.-c", "a.b.c-", "a.b.*", "a.b.123", " a.b.c", "a.b.c\n", "a.b.名", strings.Repeat("a", 61) + ".b.c"} {
		if _, err := authzcontract.ParseRouteName(raw); err == nil {
			t.Errorf("accepted invalid route %q", raw)
		}
	}
}

func TestValidateRouteTemplate(t *testing.T) {
	for _, raw := range []string{"/", "/api/v1/apps", "/api/v1/apps/:application_open_id", "/apps/{id}", "/files/*path"} {
		if err := authzcontract.ValidateRouteTemplate(raw); err != nil {
			t.Errorf("rejected path %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"", "apps", "https://example.com/apps", "//example.com/apps", "/apps?token=secret", "/apps#fragment", " /apps", "/apps ", "/apps\n", "/apps\\evil", "/apps\x00", "/%zz"} {
		if err := authzcontract.ValidateRouteTemplate(raw); err == nil {
			t.Errorf("accepted invalid path %q", raw)
		} else if raw != "" && strings.Contains(err.Error(), raw) {
			t.Error("error includes raw template")
		}
	}
}
