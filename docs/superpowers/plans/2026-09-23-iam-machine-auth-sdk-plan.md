# IAM Core SDK 机器主体与 Catalog Bearer 接入计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `iam-core-sdk-go` 暴露经过验证的机器主体声明，并让 HTTP Catalog 使用调用方注入的 `core.TokenSource` 发送 Bearer Token。

**Architecture:** 保持 SDK 现有凭据边界：Runtime 只验证令牌，管理和运行时 Client 只消费调用方注入的 `core.TokenSource`。SDK 不新增 Client Credentials 获取、缓存、刷新或 Secret 持久化实现；这些职责由各业务服务自己的 IAM 适配层承担。

**Tech Stack:** Go 1.24、标准库 HTTP、IAM Core SDK v3 现有 `runtime/core`、`runtime/httpcatalog`。

**Spec:** `docs/superpowers/specs/2026-09-23-iam-service-account-prerequisite-spec.md`


## 冻结执行身份

```yaml
kind: standalone-goal
goal_id: GOAL-20260927-001
target_repos:
  - client-sdk
repository_dependencies:
  client-sdk: []
verification:
  client-sdk:
    - go test ./... -count=1
    - go test -race ./... -count=1
    - go vet ./...
    - go build ./examples/...
    - git diff --check
```

本文件与同仓规格提交后构成 Goal 的冻结来源。只有生成 source handle、完成需求审查并取得绑定该 handle 的用户明确批准后，才创建 Goal 运行态并实施。

## Global Constraints

- 本计划只修改当前 `client-sdk` 仓库。
- IAM Core 服务端机器身份合同已由提交 `0d981363f21d7117cc2ae0e708899a27db8b822a` 交付并完成本地 Kubernetes 验收；本 Goal 不修改服务端。
- SDK 不接收 Client Secret，不调用 Token Endpoint，不持久化或刷新 Access Token。
- `subject_type` 只接受服务端合同声明的稳定值；升级前仍在 TTL 内且缺少该声明的既有用户 Access Token 按原用户合同兼容，非空未知值失败关闭，机器 Token 不允许缺失或回退为用户。
- `azp`/Client ID 必须来自已验签 Token；不得从请求头、业务参数或 Catalog Manifest 推断。
- HTTP Catalog 的 `service` 必填；SDK 只提交调用服务自己的完整清单。
- Bearer 获取失败返回脱敏错误，日志和 Observer 不包含 Token、Secret 或响应正文。

---

### Task 1: 在 AuthContext 暴露机器主体声明

**Files:**
- Modify: `runtime/core/context.go`
- Modify: `runtime/core/context_test.go`
- Modify: `runtime/core/verify.go`
- Modify: `runtime/core/verify_test.go`
- Modify: `runtime/bff/callback.go`
- Modify: `runtime/bff/refresh.go`
- Modify: `runtime/httpauthz/credential.go`
- Test: `runtime/bff/callback_test.go`
- Test: `runtime/bff/refresh_test.go`
- Test: `runtime/httpauthz/credential_test.go`

**Interfaces:**
- Produces: `core.AuthContext.SubjectType`、`core.AuthContext.AuthorizedParty`。
- Consumes: JWT `subject_type` 与 `azp`。

- [x] **Step 1: 写机器声明解析、未知类型和防御性复制测试**

```go
func TestVerifyAccessTokenExposesMachinePrincipal(t *testing.T) {
    auth := verifyAccessToken(t, map[string]any{
        "sub": "op_sa_beacon", "subject_type": "service_account",
        "azp": "beacon-server-machine", "aud": "beacon-api",
    })
    require.Equal(t, "service_account", auth.SubjectType)
    require.Equal(t, "beacon-server-machine", auth.AuthorizedParty)
}
```

- [x] **Step 2: 运行 RED**

Run: `go test ./runtime/core ./runtime/bff ./runtime/httpauthz -run 'SubjectType|AuthorizedParty|AuthContext' -count=1`

Expected: FAIL，`tokenClaims` 与 `AuthContext` 尚未暴露两个字段。

- [x] **Step 3: 实现严格声明解析和上下文传播**

访问令牌允许现有用户主体与 `service_account`；机器主体必须同时具有非空 `sub`、`subject_type=service_account` 和 `azp`。ID Token/BFF 会话继续使用用户合同，不将机器主体引入交互式登录。

- [x] **Step 4: 验证 Runtime 与 BFF 回归**

Run: `go test ./runtime/core ./runtime/bff ./runtime/httpauthz -count=1`

Expected: PASS；现有用户 Token 行为不变。

- [x] **Step 5: 提交任务**

```bash
git add runtime/core runtime/bff runtime/httpauthz
git commit -m "feat(runtime): expose machine principal claims"
```

### Task 2: HTTP Catalog 改用注入的 TokenSource

**Files:**
- Modify: `runtime/httpcatalog/registry.go`
- Modify: `runtime/httpcatalog/client.go`
- Modify: `runtime/httpcatalog/registry_test.go`
- Create: `runtime/httpcatalog/bearer_auth_test.go`
- Create: `runtime/httpcatalog/service_scope_test.go`

**Interfaces:**
- Consumes: `core.TokenSource`。
- Produces: `Authorization: Bearer <access-token>` 的 Catalog registration；Manifest 继续包含稳定 `application`、`service`、`release`。

- [x] **Step 1: 写 Bearer、service 和敏感信息测试**

```go
func TestRegistryUsesInjectedBearerToken(t *testing.T) {
    registry := newRegistry(t, Config{
        Application: "beacon", Service: "notify-server", Release: "test",
        Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil }),
    })
    registry.Register(route("notify.task.list"))
    registry.Sync(context.Background())
    require.Equal(t, "Bearer machine-token", capturedHeader(t, "Authorization"))
}
```

测试同时断言：空或 typed-nil TokenSource 被拒绝；TokenSource 错误和非 2xx 响应不泄露敏感值；调用方 Request 不被修改；Observer 使用 `bearer` 凭据来源。

- [x] **Step 2: 运行 RED**

Run: `go test ./runtime/httpcatalog -run 'Bearer|TokenSource|Service' -count=1`

Expected: FAIL，当前 Config 仍要求 `ClientID`/`ClientSecret` 并发送 Basic Auth。

- [x] **Step 3: 替换 Catalog 认证配置**

```go
type Config struct {
    BaseURL string
    Application string
    Service string
    Release string
    Tokens core.TokenSource
    HTTPClient *http.Client
    Observer core.Observer
}
```

删除 Catalog 专用的 `ClientID` 后缀规则和 `ClientSecret` 字段。`Sync` 每次通过 `Tokens.AccessToken(ctx)` 取得当前令牌，在克隆请求上设置 Bearer Header；Registry 本身不缓存令牌。

- [x] **Step 4: 增加迁移说明**

**Files:**
- Modify: `README.md`
- Create: `runtime/httpcatalog/doc.go`
- Modify: `SPEC.md`

说明业务服务必须自行实现并注入 `core.TokenSource`，SDK 不提供 Client Credentials 生命周期；Catalog 的重试仍由业务启动生命周期负责。

- [x] **Step 5: SDK 全量验证并提交**

Run: `go test ./... -race -count=1 && go vet ./... && git diff --check`

Expected: PASS。

```bash
git add runtime/httpcatalog runtime/core runtime/bff runtime/httpauthz README.md SPEC.md
git commit -m "feat(catalog): use injected bearer token source"
```

## 交付边界

- 本计划不创建 `runtime/clientcredentials` 包。
- 本计划不接受 Client Secret 配置，也不替业务服务选择缓存、重试或 Secret 加载方式。
- 塔哨各后端在自身计划内实现 Client Credentials TokenSource，并注入本计划产出的 SDK 接口。
