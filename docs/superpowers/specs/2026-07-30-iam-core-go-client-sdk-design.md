# IAM Core Go 客户端 SDK 设计

## 1. 文档信息

- 日期：2026-07-30
- SDK 模块：`github.com/swan-swan-swan/iam-core-client-sdk-go`
- IAM Core Issuer：`https://iam.wuhl-goose.top`
- 首版目标版本：`v0.1.0`
- 最低 Go 版本：Go 1.24
- 状态：已完成方案评审，等待实现计划

## 2. 背景与目标

IAM Core 通过 OIDC/OAuth 2.0 提供统一登录和用户身份，通过独立 PDP
接口提供 Application 绑定的 HTTP 权限决策，并为每次 allow/deny 决策记录审计。

当前各 Go 业务平台如果直接对接协议，需要重复实现：

- OIDC Discovery、授权跳转、回调和 Token 交换；
- ID Token/JWKS 校验、UserInfo 获取和 Token 刷新；
- Session Cookie、后端会话存储和 Refresh Token 并发轮换；
- Bearer Token 认证和 Cookie/Bearer 冲突处理；
- PDP 请求、失败关闭、错误映射和决策审计关联；
- Gin 或 `net/http` 中间件、日志脱敏和链路标识传播。

本 SDK 的目标是让一个新的 Go 平台只需配置 Issuer、Client ID、Client
Secret、Callback URL 和 Session Backend，即可完成登录、身份获取、Token
自动刷新、登出和细粒度 HTTP 权限校验。

## 3. 已确认范围

### 3.1 首版包含

- 面向服务端 Go Web/BFF 和 Go HTTP API 的业务接入能力；
- Authorization Code + Confidential Client 登录；
- OIDC Discovery、授权 URL、Token 交换、刷新、UserInfo 和登出；
- ID Token 的 RS256/JWKS 校验；
- 可插拔 Session Backend；
- 开发测试用 Memory Backend；
- 生产多实例用 Redis Backend；
- Session 数据 AES-GCM 加密 Codec；
- Session Cookie 和 `Authorization: Bearer` 两种凭证；
- `net/http` 核心认证、授权中间件；
- Gin 薄适配器；
- `/authorization/v1/decisions` PDP 客户端；
- 稳定错误模型、请求关联标识和可观测性 Hooks；
- net/http、Gin、Redis 三类接入示例。

### 3.2 首版不包含

- IAM Core 用户、角色、Application、策略和审计管理面 SDK；
- Echo、Fiber 等额外框架适配器；
- 移动端、桌面端、CLI 或纯 SPA Public Client；
- PKCE。当前 IAM Core 未声明或执行 PKCE 契约；
- 本地角色授权或 `RequireRole`；
- 组织/部门强类型 Claim。当前 UserInfo 没有稳定组织 Claim；
- 自动注册 IAM Core Application、OIDC Client 或资源目录；
- 对 IAM Core Token、Refresh 或 PDP 请求的隐式自动重试；
- 掩盖 TLS 错误或提供 `InsecureSkipVerify` 快捷配置。

## 4. 服务端契约基线

设计基于当前线上 Discovery/JWKS、当前服务端实现和 v1.7.1 产品契约。
SDK 以线上运行时和服务端实现为兼容基线，同时容忍响应中增加未知字段。

当前协议端点：

| 能力 | 端点 |
| --- | --- |
| Discovery | `GET /.well-known/openid-configuration` |
| Authorization | `GET/POST /oidc/authorize` |
| Token | `POST /oidc/token` |
| UserInfo | `GET /oidc/userinfo` |
| JWKS | `GET /oidc/jwks` |
| Logout | `GET /oidc/logout` |
| PDP | `POST /authorization/v1/decisions` |

当前稳定约束：

- Issuer 为 `https://iam.wuhl-goose.top`；
- 授权类型为 Authorization Code；
- Token Endpoint 使用 Client ID/Client Secret；
- Token 使用 RS256，JWKS 包含 `kid`；
- Scope 支持 `openid profile email roles`；
- Access Token 不携带 `roles`；
- ID Token 和 UserInfo 仅在实际授予 `roles` Scope 时返回全局角色；
- UserInfo `sub` 是用户公开 `open_id`；
- `roles` 只是全局身份画像，不能替代 PDP；
- PDP 从 Access Token audience 派生 OIDC Client 和 Application；
- PDP 请求只接受 Resource Server、Resource 和 HTTP Method；
- PDP 对 allow/deny 都先成功写入决策审计，再返回结果；
- PDP 依赖不可用、协议异常或审计失败时必须失败关闭。

服务端可能返回三类 JSON：

1. OIDC 原始成功响应，如 Token、UserInfo、JWKS；
2. OAuth 错误：`error/error_description`；
3. IAM 信封：`code/message/data/request_id/trace_id`。

SDK 传输层应兼容 PDP 数据位于 IAM 信封 `data` 中和直接返回决策对象两种形式，
避免文档与运行时响应包装差异传导到业务调用方。

## 5. 方案选择

### 5.1 采用：分层模块化 SDK

根 `iamcore.Client` 提供便捷入口，协议、会话、认证、授权和框架适配保持独立。
`net/http` 是核心，Gin 适配器只转换 Context 和 Handler 调用。

优点：

- 协议逻辑、Session 状态和框架中间件可独立测试；
- 业务方可以只使用低层 OIDC 或 PDP Client；
- 后续增加 Session Backend 或 Web 框架不会破坏核心；
- 公共 API 可以稳定，服务端响应 DTO 的变化留在传输层内部。

### 5.2 未采用：单体 Client

单体入口初期方法少，但会让配置、协议、存储、刷新锁和框架类型相互耦合，
难以独立验证或扩展。

### 5.3 未采用：OpenAPI 生成 Client 为主体

OpenAPI 生成适合普通 CRUD，却无法消除 OIDC 浏览器跳转、Session、Cookie、
Refresh Token 并发轮换和中间件的手写工作。生成模型也会把服务端文档细节暴露为
公共 SDK API。

## 6. 包结构

```text
/
├── client.go
├── config.go
├── identity.go
├── errors.go
├── oidc/
├── session/
├── session/memory/
├── session/redis/
├── authn/
├── authz/
├── middleware/
├── middleware/gin/
├── internal/transport/
└── examples/
```

职责：

- 根包：统一 Client、配置、错误、身份和 Context Helper；
- `oidc`：Discovery、授权 URL、Token、UserInfo、JWT/JWKS；
- `session`：Session、登录事务、Backend、锁和 Codec 接口；
- `session/memory`：测试与单实例开发实现；
- `session/redis`：生产多实例 Backend；
- `authn`：登录、回调、刷新、登出和凭证解析；
- `authz`：PDP 请求与 Decision；
- `middleware`：`net/http` 认证和授权中间件；
- `middleware/gin`：Gin Context 薄适配；
- `internal/transport`：HTTP、响应大小限制、响应解析和脱敏。

## 7. 配置模型

推荐构造：

```go
client, err := iamcore.New(ctx, iamcore.Config{
    IssuerURL:   "https://iam.wuhl-goose.top",
    ClientID:    cfg.IAMClientID,
    ClientSecretProvider: iamcore.StaticSecret(cfg.IAMClientSecret),
    RedirectURL: "https://asset.example.com/auth/callback",
    Scopes:      []string{"openid", "profile", "email", "roles"},
    Session: iamcore.SessionConfig{
        Backend: redisBackend,
    },
})
```

核心配置：

```go
type Config struct {
    IssuerURL           string
    ClientID            string
    ClientSecretProvider ClientSecretProvider
    RedirectURL         string
    Scopes              []string
    HTTPClient          *http.Client
    Session             SessionConfig
    Timeouts            TimeoutConfig
    Logger              *slog.Logger
    Hooks               Hooks
}
```

`New` 执行配置校验和 OIDC Discovery：

- Issuer、Client ID、Secret Provider、Redirect URL 和 Backend 必填；
- Scope 默认 `openid profile email roles`，且必须包含 `openid`；
- Discovery 返回的 `issuer` 必须与配置精确匹配；
- 生产 URL 使用 HTTPS；
- 自定义根证书通过注入 `http.Client` 提供；
- Cookie 名称、Path、Domain 和 Secure 组合必须合法；
- 登录回跳 Allowlist 必须在处理请求前完成配置。

默认超时：

| 操作 | 超时 |
| --- | --- |
| Discovery/JWKS | 5 秒 |
| Token/UserInfo | 10 秒 |
| PDP | 3 秒 |
| Refresh Lock | 15 秒 |
| 登录事务 | 10 分钟 |
| 身份在线重验间隔 | 30 秒 |
| Session 空闲有效期 | 8 小时 |
| Session 绝对有效期 | 7 天 |

调用方 Context 的截止时间早于默认值时，以调用方截止时间为准。

## 8. OIDC 登录与回调

### 8.1 登录

`LoginHandler`：

1. 校验回跳地址，只允许相对路径或显式 Allowlist；
2. 生成密码学安全的 `state`、`nonce` 和 Flow ID；
3. 将 Flow 记录写入 Session Backend；
4. 写入短期、HttpOnly 的 Flow Cookie；
5. 使用 Discovery 中的 Authorization Endpoint 构造 URL；
6. 请求 `response_type=code` 和配置 Scope，携带 `state/nonce`；
7. 302 跳转到 IAM Core。

### 8.2 回调

`CallbackHandler`：

1. 读取并一次性消费 Flow Cookie 和 Flow 记录；
2. 常量时间校验回调 `state`；
3. 处理 OIDC `error/error_description`；
4. 使用授权码、Redirect URL 和 Client Secret 交换 Token；
5. 使用 Discovery/JWKS 校验 ID Token 签名、`kid/alg/iss/aud/exp/nbf`；
6. 校验 ID Token `nonce`；
7. 调用 UserInfo；
8. 校验 `userinfo.sub == id_token.sub`；
9. 创建后端 Session；
10. 写正式 Session Cookie，清除 Flow Cookie；
11. 跳转至已校验的回跳地址。

任一步失败都不得建立 Session。授权码、Token、Client Secret、Flow ID 和 Cookie
原文不得进入响应或日志。

### 8.3 PKCE 边界

首版只支持有能力安全保存 Client Secret 的服务端应用。SDK 不发送未被服务端验证的
PKCE 参数，避免给调用方造成虚假安全保证。服务端正式增加并声明
`code_challenge_methods_supported` 后，再设计 Public Client 支持。

## 9. Session 设计

### 9.1 Cookie

正式 Cookie 默认：

```text
Name=__Host-iam_core_session
HttpOnly=true
Secure=true
SameSite=Lax
Path=/
Domain=<unset>
```

Cookie 只保存高熵、不可预测的 Session ID，不保存任何 Token 或身份 Claim。
`Secure=false` 只允许在显式开发配置且 Redirect URL 为 localhost 或回环地址时使用；
其他情况构造 Client 直接报错。

### 9.2 Session 数据

```go
type Session struct {
    ID                  string
    Version             uint64
    TokenSet            TokenSet
    Identity            Identity
    GrantedScopes       []string
    CreatedAt           time.Time
    UpdatedAt           time.Time
    LastSeenAt          time.Time
    ExpiresAt           time.Time
    IdentityValidatedAt time.Time
}
```

Session 由绝对有效期、空闲有效期和 Refresh Token 可用性共同约束。Access Token
过期只触发刷新，不直接终止 Session；Refresh Token 失效、Session 超过空闲有效期或
超过绝对有效期时，要求重新登录。

### 9.3 Backend 能力

```go
type Backend interface {
    SessionStore
    FlowStore
    RefreshLocker
}
```

能力边界：

- `SessionStore`：创建、读取、基于 `Version` 的原子比较更新和删除 Session；
- `FlowStore`：创建并一次性消费登录事务；
- `RefreshLocker`：按 Session ID 获取带 TTL 的刷新互斥锁；
- 所有读取都区分“不存在”“已过期”和“后端不可用”；
- Backend 必须通过 SDK 提供的一致性测试套件。

Memory Backend 用于测试和开发，并提供过期清理。Redis Backend 使用原子操作和
带所有权 Token 的分布式锁，解锁时只能删除自己持有的锁。

### 9.4 加密

Redis Session 和 Flow 数据通过 Codec 编解码。默认生产 Codec 使用 32 字节密钥的
AES-256-GCM：

- 每条密文使用独立随机 Nonce；
- 密文携带非敏感 Key ID；
- Keyring 包含一个当前加密密钥和零到多个历史解密密钥；
- 读取旧密钥数据后，可在正常更新时使用当前密钥重写；
- 密钥不由 SDK 持久化，也不进入日志。

### 9.5 Refresh Token 并发轮换

Access Token 临近过期时：

1. 获取 Session 级刷新锁；
2. 获取锁后重新读取 Session；
3. 如果其他请求已经刷新，直接使用最新 Token；
4. 否则调用 Token Endpoint 执行 Refresh；
5. 再次确认锁所有权仍有效；
6. 校验新 ID Token，并按 Session Version 原子更新；
7. 释放锁。

本地单实例不能只依赖 `singleflight`，因为生产部署可能有多个实例。仅使用更新时 CAS
也不充分，因为两个实例可能已同时使用同一个轮换型 Refresh Token。

`invalid_grant` 表示会话不可继续，删除本地 Session 并要求重新登录。网络错误或 IAM
暂时不可用不删除仍可能有效的 Refresh Token，返回可重试的不可用错误。
如果刷新过程中锁已过期或失去所有权，当前执行者不得提交 Token，必须重新读取
Session；无法确认安全状态时返回不可用错误。

## 10. 身份模型

```go
type Identity struct {
    Subject     string
    Username    string
    Email       string
    DisplayName string
    Roles       []string
    Scopes      []string
    ExtraClaims map[string]json.RawMessage
}
```

规则：

- `Subject` 是 UserInfo `sub`，即用户公开 `open_id`；
- `profile/email/roles` 分别控制对应字段；
- `Roles` 只能用于身份展示和非安全 UX；
- SDK 不提供角色授权中间件；
- `ExtraClaims` 保存未知 UserInfo 字段，作为组织等未来 Claim 的兼容扩展点；
- 当前不调用用户管理接口聚合 `team_display_name`，避免普通业务 Client 获得管理权限。

Context Helper：

```go
identity, ok := iamcore.IdentityFromContext(ctx)
source, ok := iamcore.CredentialSourceFromContext(ctx)
decision, ok := iamcore.DecisionFromContext(ctx)
```

## 11. 凭证解析与认证

支持：

- Session Cookie；
- `Authorization: Bearer <access_token>`；
- 两者同时存在且 Bearer Token 与 Session 当前 Access Token 完全相同。

两者同时存在但 Token 不同，即使解析到同一用户，也返回
`401 credential_conflict`。SDK 不静默选择其中一个，避免身份混淆。

默认认证策略：

- Session：读取后端 Session，按需刷新 Token，并按配置周期在线重验 UserInfo；
- Bearer：调用 UserInfo 在线验证，确保撤销、禁用、Scope 和 audience 生效；
- ID Token、Refresh Token、BFF Cookie 或未知 audience 不能作为 Bearer 凭证；
- 可以提供显式低层 JWT 验证方法，但不能把“本地签名有效”等同于“未撤销且有权限”。

## 12. 授权决策

### 12.1 模型

```go
type Permission struct {
    ResourceServer string
    Resource       string
    HTTPMethod     string
}

type Decision struct {
    ID         string
    Allowed    bool
    ReasonCode string
    RequestID  string
    TraceID    string
}
```

中间件创建时只声明 Resource Server 和 Resource，HTTP Method 从当前请求派生：

```go
protected := client.RequirePermission(iamcore.Permission{
    ResourceServer: "asset-api",
    Resource:       "assets",
})(handler)
```

禁止调用方在 PDP 请求中传入 Application、Client ID、Subject、角色、Action 或路由模板。
SDK 不根据 URL 自动猜测 Resource，目录编码必须显式声明。

低层调用：

```go
decision, err := client.Authorization().Decide(ctx, accessToken, iamcore.Permission{
    ResourceServer: "asset-api",
    Resource:       "assets",
    HTTPMethod:     http.MethodGet,
})
```

### 12.2 结果处理

- `allowed=true`：继续 Handler，把 Decision 写入 Context；
- `allowed=false`：返回 403，保留 `decision_id/reason_code` 供排障；
- PDP 401：Session 可刷新凭证后重新发起一次决策；Bearer 直接返回 401；
- PDP 400：视为资源映射或调用协议错误；
- PDP 503、超时、响应解析失败：返回 503；
- 所有异常均失败关闭；
- 不缓存 Decision，因为缓存会延迟权限变化，并绕过逐次决策审计。

Reason Code 使用字符串承载。未知值原样保留，不能因为服务端新增 Reason Code
导致反序列化失败。

## 13. 中间件 API

### 13.1 net/http

```go
mux.Handle("/auth/login", client.LoginHandler())
mux.Handle("/auth/callback", client.CallbackHandler())
mux.Handle("/auth/logout", client.LogoutHandler())

mux.Handle("/profile", client.Authenticate(profileHandler))
mux.Handle("/assets", client.RequirePermission(iamcore.Permission{
    ResourceServer: "asset-api",
    Resource:       "assets",
})(assetsHandler))
```

`RequirePermission` 包含认证步骤，不要求业务方先手工叠加 `Authenticate`。

### 13.2 Gin

```go
router.GET(
    "/assets",
    ginmw.RequirePermission(client, "asset-api", "assets"),
    listAssets,
)
```

Gin 适配器复用 `net/http` 核心能力，不自行实现 Token、Session 或 PDP 逻辑。

### 13.3 错误响应

提供可替换 `ErrorResponder`。默认返回最小 JSON：

```json
{
  "error": "forbidden",
  "decision_id": "dec_xxx",
  "reason_code": "explicit_deny",
  "request_id": "req_xxx",
  "trace_id": "trace_xxx"
}
```

默认响应不包含服务端内部错误、Token、Secret、Session ID 或调用栈。

## 14. 错误模型

```go
type Error struct {
    Kind       ErrorKind
    Operation  string
    HTTPStatus int
    RequestID  string
    TraceID    string
    DecisionID string
    Retryable  bool
    Cause      error
}
```

稳定 Error Kind：

- `invalid_config`
- `unauthenticated`
- `credential_conflict`
- `forbidden`
- `protocol_error`
- `session_unavailable`
- `iam_unavailable`

支持：

```go
errors.Is(err, iamcore.ErrUnauthenticated)
errors.Is(err, iamcore.ErrForbidden)
errors.Is(err, iamcore.ErrUnavailable)
```

Token、Refresh 和 PDP 不做 SDK 级自动重试：

- Authorization Code 和 Refresh Token 具有一次性或轮换语义；
- PDP 每次调用都生成 Decision 并写入审计；
- 盲目重试可能造成状态冲突或重复审计。

Session 凭证收到 PDP 401 后执行的“刷新凭证并重新决策一次”属于有上限的协议恢复，
不是对超时、5xx 或网络错误的传输重试。首次无效 Token 不会形成 allow/deny
Decision；恢复后只接受第二次决策的结果。

SDK 通过 `Retryable` 表达瞬时错误，由业务在明确语义后决定是否发起新的业务请求。

## 15. 登出

登出顺序：

1. 读取当前 Session；
2. 删除本地 Session，使当前应用立即退出；
3. 携带 ID Token Hint 和可用 Access Token 调用 IAM Core Logout；
4. 清除浏览器 Session Cookie；
5. 返回结果。

IAM Core 不可用时，本地 Session 仍保持删除，不恢复已退出会话；SDK 返回带关联标识的
可重试远端登出错误。Handler 可以通过配置决定向最终用户显示成功还是不可用提示，
但不得重新建立本地 Session。

## 16. 安全设计

- 使用密码学安全随机源生成 state、nonce、Flow ID 和 Session ID；
- state 和 Flow 记录一次性消费，阻止重放；
- ID Token 校验 `alg/kid/iss/aud/exp/nbf/nonce`；
- UserInfo `sub` 必须与 ID Token `sub` 一致；
- 回跳地址只允许相对路径或显式 Allowlist；
- Cookie 默认使用 `__Host-` 前缀、Secure、HttpOnly 和 SameSite=Lax；
- Session 数据在 Redis 中加密；
- Refresh Token 使用分布式互斥；
- 限制远端响应体大小并校验 JSON Content-Type；
- 不提供 TLS 跳过验证配置；
- 不把敏感值写入日志、错误、指标或 Trace；
- 不基于角色或本地 Decision 缓存做安全放行；
- IAM/PDP/Session Backend 异常时失败关闭。

## 17. 可观测性

- 日志使用标准库 `log/slog`，默认静默；
- 自动传播 `traceparent`、`tracestate` 和 `X-Request-ID`；
- 捕获 IAM Core 返回的 `request_id/trace_id/decision_id`；
- 为 Discovery、Token、UserInfo、Refresh、PDP 和 Session 操作记录耗时；
- 指标 Label 只使用 `operation/outcome/credential_source` 等低基数值；
- Hooks 允许接入 Prometheus/OpenTelemetry，不把具体指标实现绑定到核心包；
- 日志字段只记录操作、结果、耗时、错误分类和脱敏关联标识。

## 18. 测试设计

### 18.1 单元与协议测试

- 使用 `httptest.Server` 模拟 Discovery、JWKS、Token、UserInfo 和 PDP；
- 注入 Clock、随机源和 HTTP Client；
- 覆盖 OIDC 原始响应、OAuth 错误和 IAM 信封；
- 覆盖未知字段和未知 Reason Code；
- 覆盖 ID Token 签名、issuer、audience、nonce 和时间边界。

### 18.2 Session 一致性测试

为所有 Backend 提供共享 Conformance Suite：

- 创建、读取、更新、删除；
- Session 和 Flow TTL；
- Flow 一次性消费；
- 并发刷新互斥；
- 锁所有权和锁过期；
- Backend 不可用；
- 加密密钥轮换。

Redis Backend 使用真实 Redis 运行集成测试，避免仅用内存替身掩盖原子性差异。

### 18.3 中间件与安全测试

- Cookie、Bearer 和冲突凭证；
- Refresh Token 并发轮换；
- state 重放和 nonce 不匹配；
- 开放重定向；
- Session 固定攻击；
- PDP allow、deny、401、400、503 和超时；
- 敏感数据不出现在日志或错误中；
- `net/http` 与 Gin 行为一致。

### 18.4 Fuzz 与基础门禁

- Fuzz 远端响应解码、JWT Claim、Cookie 和回跳地址；
- 执行：

```bash
go test ./... -count=1
go test -race ./...
go vet ./...
git diff --check
```

## 19. 版本与兼容策略

- 初始版本为 `v0.1.0`；
- 完成至少一个真实业务平台接入并稳定公共 API 后发布 `v1.0.0`；
- 遵循 SemVer；
- 未知 JSON 字段默认容忍；
- 未知 Reason Code 原样保留；
- 当前模块路径固定为
  `github.com/swan-swan-swan/iam-core-client-sdk-go`；
- 破坏性 v2 变更使用 Go Module `/v2` 路径；
- 每个版本维护 IAM Core 兼容矩阵和升级说明；
- 服务端增加 Scope、Claim 或响应字段不应自动构成 SDK 破坏性变更。

## 20. 验收标准

首版完成需要同时满足：

1. 新项目能在 10 分钟内根据 Quickstart 完成 IAM Core 登录；
2. net/http 和 Gin 示例均可运行；
3. Memory 和 Redis Backend 通过同一 Conformance Suite；
4. 多实例并发刷新不会重复消费 Refresh Token；
5. Session Cookie 和 Bearer Token 均可认证；
6. 冲突凭证被明确拒绝；
7. UserInfo 身份按 Scope 映射且保留扩展 Claim；
8. 权限中间件显式调用 PDP 并失败关闭；
9. allow/deny Decision ID 可从 Context 获取；
10. 所有错误可通过稳定 Kind 或 `errors.Is` 判断；
11. 日志、错误、指标和 Trace 不泄露敏感值；
12. 单元、Race、Redis 集成、安全和 Fuzz 测试通过；
13. README 包含配置、登录、回调、身份、授权、刷新和登出示例；
14. 发布说明包含 IAM Core 兼容版本和已知限制。

## 21. 后续演进

以下能力在独立设计评审后再加入：

- IAM Core 服务端 PKCE 契约和 Public Client；
- 标准化组织/部门 Scope 与强类型 Claim；
- Echo/Fiber 等框架适配；
- 管理面独立 SDK 或子模块；
- Secret Manager、KMS 或 Vault 的官方适配；
- 基于正式能力发现的服务端兼容协商；
- 面向跨服务调用的 Token Exchange 或服务身份。
