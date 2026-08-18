# OIDC PKCE 与 roles 管理契约收缩 SDK Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 从 Go 管理 SDK 的 OIDC Client 公共模型和请求体删除 PKCE policy 与 legacy roles 字段，同时保持 Runtime/BFF 的 S256 强制行为。

**Architecture:** `management/oidcclients` 的输入、输出和 wire model 与新 Server API 对齐；JSON decoder 继续忽略旧服务端额外字段。Runtime/BFF 不改配置面，继续生成 S256 code challenge。

**Tech Stack:** Go 1.24、net/http、encoding/json、Go testing

**Spec:** `../../../../iam-core-design/docs/superpowers/specs/2026-08-18-oidc-pkce-roles-contract-contraction-design.md`

## Global Constraints

- 管理 SDK 公共结构体不得再暴露 `PKCEPolicy`、`LegacyRolesClaim`。
- Create/UpdateSecurity 请求体不得包含 `pkcePolicy`、`legacyRolesClaim`。
- 旧服务端返回多余字段时解码必须成功。
- Runtime/BFF 必须继续强制 `code_challenge_method=S256`。

---

### Task 1: 先用契约测试锁定新请求体

**Files:**
- Modify: `management/oidcclients/client_test.go`

**Interfaces:**
- Consumes: `Client.Create`、`Client.UpdateSecurity`
- Produces: 不包含已删除字段的精确 JSON 测试。

- [ ] **Step 1: 修改 create/update security 期望请求体并加入旧响应兼容输入**

```go
body: `{"clientId":"ops-portal","displayName":"Ops","description":"portal","allowedScopes":["openid","groups"],"redirectUris":["https://ops.example/callback"]}`
```

```go
body: `{"clientType":"confidential","allowedScopes":["openid"],"accessTokenTtlSeconds":300,"idTokenTtlSeconds":300,"groupsTokenTtlSeconds":120,"revision":7}`
```

保留测试响应中的 `pkcePolicy`、`legacyRolesClaim`，证明 decoder 会忽略旧字段。

- [ ] **Step 2: 运行测试验证 RED**

Run: `go test ./management/oidcclients -run 'TestClientUsesExactOIDCContracts|TestOIDCConversions' -count=1`

Expected: FAIL，因为 SDK 仍序列化两个旧字段。

### Task 2: 删除公共模型与序列化字段

**Files:**
- Modify: `management/oidcclients/model.go`
- Modify: `management/oidcclients/client.go`
- Modify: `management/oidcclients/client_test.go`

**Interfaces:**
- Consumes: Task 1 新契约测试
- Produces: 收缩后的 `CreateInput`、`OIDCClient`、`Security`、`UpdateSecurityInput`。

- [ ] **Step 1: 删除模型字段和 wire copy**

```go
type UpdateSecurityInput struct {
    ClientType            string
    AllowedScopes         []string
    AccessTokenTTLSeconds uint32
    IDTokenTTLSeconds     uint32
    GroupsTokenTTLSeconds uint32
    Revision              uint64
}
```

`CreateInput`、`OIDCClient`、`Security` 及 wire structs 同步删除 PKCE/legacy roles 字段。

- [ ] **Step 2: 删除 request body 字段与 recommended 校验**

```go
func validSecurityInput(input UpdateSecurityInput) bool {
    if input.ClientType != "public" && input.ClientType != "confidential" {
        return false
    }
    return validStringList(input.AllowedScopes) &&
        input.AccessTokenTTLSeconds > 0 && input.IDTokenTTLSeconds > 0 &&
        input.GroupsTokenTTLSeconds > 0 && input.GroupsTokenTTLSeconds <= 300
}
```

- [ ] **Step 3: 运行 management package tests 验证 GREEN**

Run: `gofmt -w management/oidcclients/model.go management/oidcclients/client.go management/oidcclients/client_test.go && go test ./management/oidcclients -count=1`

Expected: PASS。

### Task 3: 验证 Runtime S256 与 SDK 全仓

**Files:**
- Verify: `runtime/bff`
- Verify: `management/oidcclients`

**Interfaces:**
- Consumes: 最终管理 SDK 模型
- Produces: 无 recommended 管理入口且 Runtime 仍强制 S256 的 SDK。

- [ ] **Step 1: 运行 S256 focused tests**

Run: `go test ./runtime/bff/... -run 'PKCE|S256|Authorize' -count=1`

Expected: PASS。

- [ ] **Step 2: 扫描生产代码残留**

Run: `rg -n 'recommended|PKCEPolicy|LegacyRolesClaim' management/oidcclients runtime/bff -g '*.go'`

Expected: management 生产代码无匹配；runtime 只允许与强制 S256 相关的固定实现，不允许 recommended 配置分支。

- [ ] **Step 3: 执行 SDK 完整验证**

Run: `go test ./... -count=1 && go vet ./... && git diff --check`

Expected: 全部通过。
