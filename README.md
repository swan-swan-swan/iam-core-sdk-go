# IAM Core Go SDK

本仓库提供面向 IAM Core v1.9.0（兼容既有 v1.8.1 Runtime/Management 契约）的 Go SDK。`v0.10.0` 使用单一 Go Module
`github.com/swan-swan-swan/iam-core-sdk-go`，并在同一版本中明确划分两类能力：

- `runtime/*`：业务请求链路中的 OIDC/BFF、HTTP Resource Server、Gin 与 Redis adapter。
- `management/*`：受控管理服务、专用 CLI 或 CI/CD 使用的平台接入控制面 Client。

`v0.10.0` 保持 Gin 和 Redis Adapter 合并进根 Module，公开 import 路径不变，并在 Application
Handoff Runtime Client 之上新增浏览器全局退出与绝对/空闲 Session 策略。升级前请阅读
[v0.3 → v0.4 迁移指南](docs/migration-v0.3-to-v0.4.md)并删除旧的 Adapter Module 依赖。
从旧仓库名迁移时，另请参考
[v0.2 → v0.3 迁移指南](docs/migration-v0.2-to-v0.3.md)。
RPC 暂不支持，也没有 RPC package、adapter 或兼容承诺。

最低 Go 版本为 1.24。协议边界见
[IAM Core v1.9.0 契约](docs/iam-core-v1.9.0-contract.md)，版本矩阵见
[COMPATIBILITY.md](COMPATIBILITY.md)。

## 安装

根 Module 同时包含 Runtime、Management、Gin Adapter 与 Redis Adapter，只需安装一个版本：

```bash
go get github.com/swan-swan-swan/iam-core-sdk-go@v0.10.0
```

根 Module 的依赖图包含 Gin 和 go-redis，但未 import 对应 Adapter 的程序不会编译或链接这些
package。Docker、Moby 和 Testcontainers 仍只属于仓库内 integration 测试 Module。SDK 每个版本
只创建一个根标签，例如 `v0.10.0`。

## 能力边界

| 使用方 | 使用能力 | 约束 |
| --- | --- | --- |
| 普通 Go 业务进程、Ops Gateway | `runtime/*` | 登录、Session、JWT、HTTP PDP；不做管理面写入 |
| 受控管理服务、专用 CLI、CI/CD | `management/*` | 调用方注入高权限 Token；显式执行单个管理操作 |
| Go 脚手架无鉴权模式 | 不初始化 SDK | `auth.mode=none` 时不初始化 Runtime SDK，也不建立本地账号体系或伪造 IAM 身份 |

management 不参与普通业务请求链路。`runtime/httpcatalog` 只允许业务应用启动时同步代码拥有的
HTTP Catalog；它不创建 Application、OIDC Client、Policy、角色绑定或用户授权。无鉴权模式是
调用方运行策略，不是 SDK 内的降级开关。

## Runtime

Runtime 的公开入口位于：

- `github.com/swan-swan-swan/iam-core-sdk-go/runtime/core`
- `github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff`
- `github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz`
- `github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpcatalog`
- `github.com/swan-swan-swan/iam-core-sdk-go/runtime/applicationhandoff`
- `github.com/swan-swan-swan/iam-core-sdk-go/runtime/testkit`

浏览器 BFF 示例位于 [`examples/runtime/bff`](examples/runtime/bff)，Bearer-only HTTP Resource
Server 示例位于 [`examples/runtime/nethttp`](examples/runtime/nethttp)。BFF 强制 PKCE S256，
默认 scope 为 `openid profile email groups`；不接受 `roles` 回退。Session 保存在服务端，
浏览器 Cookie 只承载不透明 ID。

HTTP Resource Server 使用显式 Route Manifest。每个已通过本地认证的受保护请求执行恰好
一次 PDP；deny、401、5xx、超时、网络错误和畸形 envelope 都失败关闭。授权结果不缓存，
也不会使用 groups 或本地规则降级。PDP 401 不刷新凭证、不重试 PDP。

迁移后的路由应提供三级 `Action`（例如 `orders:orders:list`）。SDK 将它发送为可选的
`expected_action`，并在允许结果中核对 IAM Core 返回的实际 `action`；缺失或不匹配会按协议
错误失败关闭。未迁移路由可暂时省略 `Action`，保持旧请求与响应兼容行为。

`runtime/applicationhandoff` 使用调用方逐请求注入的 `core.TokenSource`，为当前用户创建 60 秒一次性
Application 登录交接。输入不包含 Subject、目标系统角色或资产权限；Client 不缓存 Token 或 Launch URL，
也不跟随重定向。`decisionId` 必须原样使用 PDP 返回的 `dec_` 审计标识，`correlationId` 使用独立的
`op_cor_` 标识。典型消费方收到 `CreateOutput` 后立即把浏览器 302 到 `LaunchURL`。

Gin adapter 是 `net/http` 授权服务的薄适配层：

```go
import ginadapter "github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin"
```

`runtime/httpcatalog` 收集代码拥有的 `RouteSpec`，要求 `ResourceServer` 等于三级 Action 第一段、
`Resource` 等于后两段以下划线连接，并使用独立的 `*-catalog-registrar` OIDC Client Basic 凭据
执行单次启动同步。Registry 在同步成功前保持 health down；重试调度由业务进程 lifecycle 负责。

Redis adapter 是可选的 BFF Session 存储，实现加密的 Backend，并使用 generation-bound、fenced、
server-time lease 保护 refresh 原子提交。应用必须提供自己的 go-redis
Client、FailoverClient 或 ClusterClient；服务端要求 Redis 6.2+。adapter 只使用 Redis 原生命令和
事务，不执行 Lua evaluation：

```go
import redisadapter "github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis"
```

## Management

Management 由共享 Transport 和六个互不依赖的领域 Client 组成：

- `management/applications`
- `management/oidcclients`
- `management/admission`
- `management/groupmappings`
- `management/catalog`
- `management/policies`

当前冻结 IAM Core v1.8.1 的 42 个管理端点。共享 Client 位于
`github.com/swan-swan-swan/iam-core-sdk-go/management/client`，只接受调用方注入的
`TokenSource`：

```go
type TokenSource interface {
    AccessToken(context.Context) (string, error)
}
```

Management Client 不取得、刷新或持久化 Token，不接收用户名密码。每次调用只取一次 Token，
最多发送一次 HTTP 请求，不自动重试；调用方必须根据 revision、hash、幂等键和最新资源状态
显式决定是否再次提交。

可运行示例位于 [`examples/management`](examples/management)。它先读取 Application 列表，
只有 `IAMCORE_EXAMPLE_APPLY_ADMISSION_UPDATE=true` 时才执行带
`login_policy_revision` 的准入更新：

```bash
IAMCORE_MANAGEMENT_BASE_URL=https://iam.example.com \
IAMCORE_MANAGEMENT_ACCESS_TOKEN='injected-by-a-controlled-process' \
go run ./examples/management
```

显式更新需要同时提供完整目标与期望 revision；以下 ID 仅展示格式：

```bash
IAMCORE_MANAGEMENT_BASE_URL=https://iam.example.com \
IAMCORE_MANAGEMENT_ACCESS_TOKEN='injected-by-a-controlled-process' \
IAMCORE_EXAMPLE_APPLY_ADMISSION_UPDATE=true \
IAMCORE_APPLICATION_OPEN_ID=op_app_0123456789abcdefghj \
IAMCORE_ADMISSION_RULE_OPEN_ID=op_lpr_0123456789abcdefghj \
IAMCORE_ADMISSION_SUBJECT_TYPE=user \
IAMCORE_ADMISSION_SUBJECT_OPEN_ID=op_usr_0123456789abcdefghj \
IAMCORE_ADMISSION_EFFECT=allow \
IAMCORE_ADMISSION_LOGIN_POLICY_REVISION=7 \
go run ./examples/management
```

示例不读取用户名或密码，不打印 Token/Secret，也不在启动时自动配置 IAM。OIDC Client 凭据
创建响应中的 Secret 使用 `SensitiveString`；默认字符串、Go 格式化与 JSON 均只输出
`[REDACTED]`，必须显式调用 `Reveal()` 读取。

## 安全与错误边界

- Runtime 只接受 RS256 JWT/JWKS，并验证 `kid/iss/aud/sub/jti/iat/exp` 与可选 `nbf`。
- Authorization Code、Refresh Token、PDP 和所有 Management 请求都不做 SDK 级自动重试。
- Management Base URL 生产环境必须为 HTTPS；仅 loopback 测试允许 HTTP。Client 禁止重定向、
  清除 Cookie Jar，并施加有限总超时。
- Token、Authorization Header、Client Secret、OIDC Credential Secret、Cookie、Session/Flow
  ID、完整响应正文与完整 URL query 不进入错误或观测。
- Management Observer 每次调用最多收到一个终态事件；Observer panic 被隔离，不影响返回值，
  也不会触发第二次请求。
- 不支持 users、organizations、global roles、Cloud Provider、登录准入审计或授权决策 audits。

## 开发验证

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./examples/...
```

Runtime、Management、Gin 和 Redis Adapter 都由根 Module 的普通测试、race 和 vet 覆盖。
integration 是不发布的测试 Module；其 Redis 6.2/7.4 conformance 依赖 Docker-enabled runner。
发布 workflow 在根 Module 和 integration 全部通过后，只为 release merge commit 创建并推送
一个根标签；开发工作站不创建或推送发布标签。真实发布前 GitHub repository metadata 必须已是
`swan-swan-swan/iam-core-sdk-go`。

## 浏览器全局退出与 Session 策略

`bff.Client.GlobalLogoutHandler` 清理当前应用的本地 BFF Session，并以顶层 `303 See Other`
跳转到 discovery 提供的可信 IAM end-session endpoint。应用应通过同源 POST form 提交该端点，
不得使用 `fetch` 或 iframe 发起全局退出，以便浏览器继续执行 IAM 前端通道退出流程。

`bff.Client.FrontchannelLogoutHandler` 验证 IAM 签发的短时、受 audience 约束的退出 token，
幂等清理当前主机 Session，并仅向配置的 IAM Origin 回传交易结果。`PlatformID` 必须与 IAM 注册契约
一致：以小写字母开头、只含小写字母和数字、长度 3-64。

BFF Session 默认绝对有效期为七天、空闲有效期为十二小时。调用方可通过
`SessionAbsoluteTTL` 和 `SessionIdleTTL` 配置正数时长；空闲有效期不得超过绝对有效期，
活跃续期也不会突破绝对截止时间。
