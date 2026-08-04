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
	section := func(name, content, start, end string) string {
		t.Helper()
		startIndex := strings.Index(content, start)
		if startIndex < 0 {
			t.Fatalf("%s missing section start %q", name, start)
		}
		remainder := content[startIndex:]
		endIndex := strings.Index(remainder, end)
		if endIndex < 0 {
			t.Fatalf("%s missing section end %q", name, end)
		}
		return remainder[:endIndex]
	}
	forbidAll := func(name, content string, forbidden ...string) {
		t.Helper()
		for _, claim := range forbidden {
			if strings.Contains(content, claim) {
				t.Errorf("%s contains forbidden legacy claim %q", name, claim)
			}
		}
	}

	readme := read("README.md")
	requireAll("README", readme,
		"PKCE S256",
		"openid profile email groups",
		"一次 PDP",
		"RPC 暂不支持",
		"/adapters/gin",
		"/adapters/redis",
		"v0.2 是一次干净的破坏性重写",
		"不与 v0.1 源码兼容",
		"IAM 管理 API 不受支持",
		"roles 不被接受",
		"__Host-example_session",
		"__Host-example_flow",
		"PDP 401",
		"不会刷新凭证或重试 PDP",
		"本地登出",
		"集中登出",
		"generation-bound",
		"server-time",
		"Sessions: client",
		"未配置 SessionResolver 的 Bearer-only",
		"忽略无关 Cookie",
	)
	forbidAll("README", readme,
		"openid profile email roles",
		"iamcore.New(",
		"PDP 401 时刷新并重试",
		"仅当 Bearer 与当前 Session Access Token 完全一致才接受",
		"SDK 不提供 Public Client 或 PKCE",
		"Bearer 与 BFF Session Cookie 同时存在会直接返回 credential conflict",
	)
	redisReadme := section("README", readme, "Redis adapter 实现", "## 安全与错误边界")
	requireAll("README Redis example", redisReadme,
		`"crypto/rand"`,
		`"github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis"`,
		`"github.com/swan-swan-swan/iam-core-client-sdk-go/core"`,
		"Clock:  core.RealClock{}",
		"Random: rand.Reader",
	)
	if got := strings.Count(redisReadme, "if err != nil {"); got < 2 {
		t.Errorf("README Redis example error checks = %d, want at least 2", got)
	}

	compatibility := read("COMPATIBILITY.md")
	requireAll("COMPATIBILITY", compatibility,
		"v0.1.x = IAM Core v1.7.1 only",
		"v0.2.x = IAM Core v1.8.1",
		"不与 v0.1 源码兼容",
	)

	migration := read("docs/migration-v0.1-to-v0.2.md")
	requireAll("migration guide", migration,
		"替换而不是包装",
		"不提供兼容开关",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/core",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/bff",
		"github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz",
		"配置 SessionResolver 后",
		"Bearer-only",
		"忽略无关 Cookie",
	)
	forbidAll("migration guide", migration,
		"fallback flag",
		"compatibility flag",
		"iamcore.New(",
		"两种 credential 同时存在现在总是冲突",
	)

	contract := read("docs/iam-core-v1.8.1-contract.md")
	requireAll("v1.8.1 contract", contract,
		"GET /.well-known/openid-configuration",
		"GET /oidc/authorize",
		"POST /oidc/token",
		"GET /oidc/userinfo",
		"GET /oidc/jwks",
		"GET /oidc/logout",
		"POST /authorization/v1/decisions",
		"code_challenge_method=S256",
		"resource_server",
		"http_method",
		"decision_id",
		"reason_code",
		"RPC 不在本 SDK v0.2 的支持范围内",
		"配置 SessionResolver 后",
		"Bearer-only",
		"忽略无关 Cookie",
	)
	forbidAll("v1.8.1 contract", contract,
		"Cookie 与 Bearer 同时出现直接视为 credential conflict",
	)

	example := read("examples/runtime/bff/main.go")
	requireAll("BFF example", example,
		"core.New(",
		"bff.New(",
		"memory.New(",
		"__Host-example_session",
		"__Host-example_flow",
		"IAMCORE_ISSUER_URL",
		"IAMCORE_CLIENT_ID",
		"IAMCORE_CLIENT_SECRET",
		"IAMCORE_REDIRECT_URL",
		"HTTP_ADDR",
		"/auth/login",
		"/auth/callback",
		"/me",
		"/auth/logout/local",
		"/auth/logout/central",
		"mux.Handle(\"GET /auth/login\"",
		"mux.Handle(\"GET /auth/callback\"",
		"mux.Handle(\"GET /me\"",
		"mux.Handle(\"POST /auth/logout/local\"",
		"mux.Handle(\"POST /auth/logout/central\"",
		"iamHTTPClient := &http.Client{Timeout: 15 * time.Second}",
	)
	normalizedExample := strings.Join(strings.Fields(example), " ")
	if got := strings.Count(normalizedExample, "HTTPClient: iamHTTPClient"); got != 2 {
		t.Errorf("BFF example outbound HTTP client injections = %d, want 2", got)
	}
	if got := strings.Count(example, "mux.Handle("); got != 5 {
		t.Errorf("BFF example route registrations = %d, want 5", got)
	}
	for _, field := range []string{
		`Value:       ""`,
		`Domain:      ""`,
		`MaxAge:      0`,
		`Expires:     time.Time{}`,
		`Partitioned: false`,
	} {
		if got := strings.Count(example, field); got != 2 {
			t.Errorf("BFF example explicit cookie field %q count = %d, want 2", field, got)
		}
	}

	workflow := read(".github/workflows/ci.yml")
	requireAll("CI workflow", workflow,
		"go-version: \"1.24.x\"",
		"go test ./... -count=1",
		"go test -race ./... -count=1",
		"go vet ./...",
		"go build ./examples/runtime/...",
		"GOWORK=off go test ./... -count=1",
		"GOWORK=off go test -race ./... -count=1",
		"GOWORK=off go vet ./...",
		"cache-dependency-path: runtime/adapters/gin/go.sum",
		"working-directory: runtime/adapters/gin",
		"cache-dependency-path: runtime/adapters/redis/go.sum",
		"working-directory: runtime/adapters/redis",
		"go build -o /tmp/iamcore-gin-example ./example",
		"go build -o /tmp/iamcore-redis-example ./example",
		"working-directory: integration",
		"GOTOOLCHAIN=local go test ./redis -count=1",
		"GOTOOLCHAIN=local go test -race ./redis -count=1",
		"GOTOOLCHAIN=local go vet ./...",
		"Redis 6.2/7.4",
		"dubbo|triple|google\\.golang\\.org/grpc",
	)
	forbidAll("CI workflow", workflow,
		"go build ./examples/...",
		"cache-dependency-path: adapters/gin/go.sum",
		"working-directory: adapters/gin",
		"cache-dependency-path: adapters/redis/go.sum",
		"working-directory: adapters/redis",
		"continue-on-error",
		"|| true",
		"-short",
		"SKIP",
		"skip",
	)

	integration := read("integration/redis/redis_test.go")
	requireAll("Redis integration", integration, "redis:6.2-alpine", "redis:7.4-alpine")
}
