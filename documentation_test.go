package iamcoresdk_test

import (
	"os"
	"strings"
	"testing"
)

func TestDocumentationContract(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(raw)
	}
	requireAll := func(name, content string, required ...string) {
		t.Helper()
		for _, claim := range required {
			if !strings.Contains(content, claim) {
				t.Errorf("%s missing %q", name, claim)
			}
		}
	}
	forbidAll := func(name, content string, forbidden ...string) {
		t.Helper()
		for _, claim := range forbidden {
			if strings.Contains(content, claim) {
				t.Errorf("%s contains forbidden claim %q", name, claim)
			}
		}
	}

	readme := read("README.md")
	requireAll("README", readme,
		"IAM Core Go SDK",
		"v0.9.0",
		"单一 Go Module",
		"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core",
		"github.com/swan-swan-swan/iam-core-sdk-go/management/client",
		"github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin",
		"github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis",
		"management 不参与普通业务请求链路",
		"RPC 暂不支持",
		"runtime/httpcatalog",
		"runtime/applicationhandoff",
		"不创建 Application、OIDC Client、Policy",
		"auth.mode=none",
		"不初始化 Runtime SDK",
		"PKCE S256",
		"一次 PDP",
		"TokenSource",
		"不自动重试",
		"42",
		"可选的 BFF Session 存储",
		"Client、FailoverClient 或 ClusterClient",
		"Redis 6.2+",
		"不执行 Lua",
	)
	forbidAll("README", readme,
		"IAM Core Go Client SDK",
		"IAM 管理 API 不受支持",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/core",
	)

	migration := read("docs/migration-v0.2-to-v0.3.md")
	for _, mapping := range []string{
		"github.com/swan-swan-swan/iam-core-client-sdk-go/core -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/core",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/bff -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/testkit -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/testkit",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/gin -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis",
	} {
		requireAll("v0.3 migration", migration, mapping)
	}
	requireAll("v0.3 migration", migration,
		"不存在 deprecated wrapper",
		"先移除旧 Module",
		"RPC 暂不支持",
		"management 不参与普通业务请求链路",
	)

	compatibility := read("COMPATIBILITY.md")
	requireAll("COMPATIBILITY", compatibility,
		"v0.2.x",
		"github.com/swan-swan-swan/iam-core-client-sdk-go",
		"Runtime only",
		"v0.3.x",
		"v0.4.x",
		"v0.5.x",
		"v0.6.x",
		"v0.7.x",
		"v0.8.x",
		"v0.9.x",
		"github.com/swan-swan-swan/iam-core-sdk-go",
		"Runtime + approved platform-integration Management",
		"IAM Core v1.8.1",
	)

	changelog := read("CHANGELOG.md")
	requireAll("CHANGELOG", changelog,
		"operationally breaking",
		"Lua evaluation",
		"v0.8.0",
		"v0.6.0",
		"v0.4.0",
		"single root Module",
		"v0.3.0",
		"Breaking",
		"applications",
		"oidcclients",
		"admission",
		"groupmappings",
		"catalog",
		"policies",
		"TokenSource",
		"不自动重试",
		"SensitiveString",
		"42",
		"Cloud Provider",
		"audits",
	)

	contract := read("docs/iam-core-v1.8.1-contract.md")
	requireAll("v1.8.1 contract", contract,
		"Runtime 契约",
		"Management 契约",
		"42 个",
		"TokenSource",
		"一次 HTTP 请求",
		"不自动重试",
		"SensitiveString",
		"RPC 暂不支持",
		"users",
		"organizations",
		"global roles",
		"Cloud Provider",
		"audits",
	)
	forbidAll("v1.8.1 contract", contract,
		"IAM Application、OIDC Client、Resource Catalog、Policy、用户、组织、角色与审计查询/管理\n接口都不属于本 SDK",
	)

	handoffContract := read("docs/iam-core-v1.9.0-contract.md")
	requireAll("v1.9.0 contract", handoffContract,
		"Application Handoff",
		"runtime/applicationhandoff",
		"POST /api/v1/application-handoffs",
		"TokenSource",
		"协议不接受 Subject",
		"application-handoff:create",
		"不管理目标系统权限",
		"60 秒",
		"不跟随",
	)

	integration := read("integration/redis/redis_test.go")
	requireAll("Redis integration", integration, "redis:6.2-alpine", "redis:7.4-alpine")
}
