# IAM Core Go Client SDK v0.2.0 重写设计

## 1. 背景与结论

IAM Core Go Client SDK 当前版本以一个根 `Client` 同时组合 OIDC/BFF、服务端 Session、Bearer 认证、HTTP PDP 和框架中间件。该结构实现了 IAM Core v1.7.1 的既有能力，但与 IAM Core v1.8.1 的 PKCE、Client groups、真实 granted scope、单次 PDP 和场景隔离边界不兼容。

本次工作将 SDK 作为尚未投入生产的新项目处理，采用破坏性重写，不保留 v0.1 API、兼容 facade、legacy decision decoder 或 legacy roles profile。发布目标为 `v0.2.0`，它只面向 IAM Core v1.8.1 契约。

RPC 不属于本次范围。本版本不创建 `rpc` 包，不引入 Dubbo/Triple 依赖，也不预留未经真实消费场景验证的 RPC 接口。

## 2. 契约来源与优先级

设计依据按以下优先级解释：

1. 用户在本次设计评审中确认的范围：破坏性纯净重写、无兼容层、暂不实现 RPC。
2. 《IAM Core Client SDK 职责与边界（v1.8.1）》修订版 24。
3. 《IAM Core Go Client SDK v1.8.1 边界审查与重构计划》修订版 4。
4. IAM Core Server 当前 `dev` 实现，核对基线为 `05770eef8b506a44a2b422a656a550dee1cb58da`。

当旧 SDK 行为与上述契约冲突时，删除旧行为。当 SDK 文档与 Server 当前 v1.8.1 HTTP 契约冲突时，以 Server 的冻结 OpenAPI 和实现为准，但不得扩大 SDK 到管理面能力。

## 3. 目标与非目标

### 3.1 目标

- 实现强制 PKCE S256 的服务端 OIDC/BFF 登录链路。
- 只公开当前 Client 的 `groups`，并准确建模实际 granted scope。
- 在 refresh 后原子替换 Token、Identity、Groups 和 Granted Scopes。
- 为 HTTP Resource Server 提供本地 JWT 验证、显式 Route Manifest、单次 PDP 和失败关闭中间件。
- 将核心、Gin、Redis 和 Docker 集成测试依赖隔离到合理的 Go module。
- 提供默认拒绝、安全可控且无生产依赖污染的 `testkit`。
- 通过类型、构造期校验和测试，防止敏感信息进入日志、错误、Hook、Trace 和指标。

### 3.2 非目标

- 不兼容 v0.1 的根 `Client`、`Config`、`authn`、`authz`、`middleware` 或 Session API。
- 不实现 RPC Consumer/Provider、Dubbo/Triple adapter、RPC 撤销或 RPC AuthContext。
- 不实现 IAM Core Application、OIDC Client、Resource Catalog、Policy 或审计管理 API。
- 不实现本地 Casbin、本地 PDP、PDP allow/deny 缓存或 PDP 自动重试。
- 不支持 no-PKCE、plain PKCE、默认 `roles` 或 legacy roles profile。
- 不提供通用 `ExtraClaims` 作为公开稳定模型。
- 不实现 SPA、移动端或浏览器 Token 存储。
- 不自动创建、修改或注册 IAM Core 管理面对象。

## 4. 仓库与 Module 结构

仓库采用一个根 module、两个可发布 adapter module 和一个仅用于集成测试的 module：

```text
iam-core-client-sdk-go/
├── go.mod
├── go.work
├── core/
├── bff/
│   └── session/
│       └── memory/
├── httpauthz/
├── testkit/
├── examples/
│   ├── bff/
│   └── nethttp/
├── adapters/
│   ├── gin/
│   │   ├── go.mod
│   │   └── example/
│   └── redis/
│       ├── go.mod
│       └── example/
└── integration/
    └── go.mod
```

根目录不再提供组合式 `iamcore` 公共 facade。调用方显式导入自己需要的 `/core`、`/bff`、`/httpauthz` 或 `/testkit`。

依赖边界如下：

- 根 module 只包含标准库以及 OIDC、OAuth 2.0、JOSE/JWT 所需依赖。
- `adapters/gin` 独立依赖 Gin，并依赖根 module 的 `httpauthz`。
- `adapters/redis` 独立依赖 go-redis，并实现 `bff/session` 契约。
- `integration` 独立依赖 Testcontainers，并测试 Redis 6.2/7.4 等真实依赖。
- `testkit` 位于根 module，但不得依赖 Gin、Redis、Docker 或 Testcontainers。
- `go.work` 只服务仓库内联合开发和 CI；发布时根 module、`adapters/gin` 和 `adapters/redis` 分别使用对应 module tag。

## 5. 组件边界

### 5.1 `core`

`core` 提供共享安全原语：

- OIDC Discovery 获取、验证和不可变快照。
- JWKS 获取、缓存、未知 `kid` 的一次受控刷新和刷新频率限制。
- RS256 Access Token 与 ID Token 验证。
- issuer、audience、`exp`、`iat`、可选 `nbf`、`jti`、nonce 和算法约束。
- 强类型 `AuthContext`、Identity、Granted Scopes 和 Groups。
- 统一安全错误模型、HTTP transport、超时和观测接口。
- 受控 `TokenSource`，供授权链路使用原始 access token，而不把 token 放进普通业务 DTO。

`core` 不依赖 Session、Cookie、Redis、Gin、PDP 路由或业务 Handler。

稳定身份模型至少包含：

- `Subject`
- `Issuer`
- `Audience`
- `TokenID`
- `IssuedAt`、`NotBefore`、`ExpiresAt`
- `Scopes`
- `Groups`
- `Username`、`DisplayName`、`Email`
- `DecisionID`、`ReasonCode`；尚未执行 HTTP PDP 时为空
- `TraceID`

`Groups` 和 `Scopes` 经过 trim、去重、排序并返回防御性副本。没有 group mapping 时 `Groups` 为已初始化的空切片，不从 roles 或其他 Client 回退。`Username`、`DisplayName`、`Email` 只有在相应 granted scope 和已验证 Claim 同时允许时才暴露。

### 5.2 `bff`

`bff` 负责浏览器 OIDC/BFF 生命周期：

- 服务端 Login Flow。
- state、nonce、PKCE verifier 和 S256 challenge。
- authorize URL、Callback、code exchange 和 ID Token 验证。
- UserInfo 资料加载与 subject 交叉校验。
- 服务端应用 Session、主动 refresh 和原子 refresh rotation。
- 本地应用 Logout 与 IAM Core 集中 Logout 的不同语义。
- Host-only、HttpOnly、Secure、SameSite 和 Path 安全 Cookie 默认值。

生产构造必须显式提供 Client Secret Provider、精确 Redirect URL、Session Backend 和平台独立 Cookie 名称。生产 Cookie 名称必须满足 `__Host-` 约束；只有显式的本地开发选项允许非 Secure Cookie。

`bff/session` 定义 Flow、Session、存储、一次性消费、refresh lease、fencing 和带 lease 的原子提交契约。Memory 实现只用于测试、开发和单进程。Redis 实现位于独立 adapter module。

### 5.3 `httpauthz`

`httpauthz` 提供 HTTP Resource Server 能力：

- Bearer credential 提取和本地业务 JWT 验证。
- 可注入的 BFF Session credential resolver，接口只依赖 `core` 类型，不反向依赖 `bff` 包。
- 严格的 IAM Core PDP Client。
- 本地 Route Manifest、编译后 Route 和绑定校验。
- `net/http` 认证与授权中间件。
- `DecisionContext` 与失败关闭错误映射。

`httpauthz` 不读取 UserInfo，不直接依赖 Session Backend，不实现 refresh，不缓存授权结果，也不接受业务代码覆盖可信的 subject、Client、Application、Action 或 audience。

### 5.4 `testkit`

`testkit` 提供：

- Fake Discovery、JWKS、Authorize、Token、UserInfo 和 PDP Server。
- 固定 Clock、确定性 Random 和测试密钥。
- PKCE challenge/verifier 记录器。
- Token、refresh rotation、scope shrink 和 groups fixture。
- PDP allow、deny、401、503、超时和畸形 envelope fixture。
- 调用计数和敏感信息泄漏断言。

Fake PDP 默认返回 deny。测试必须显式配置 allow，避免测试替身把遗漏配置误变成授权通过。

## 6. BFF 数据流

### 6.1 构造与 Discovery

`bff.New` 在返回可用对象前完成配置校验和 Discovery。Discovery 必须满足：

- 返回的 issuer 与配置 issuer 规范化后一致。
- authorize、token、userinfo、JWKS 和 end-session 端点合法且遵循 TLS 约束。
- `code_challenge_methods_supported` 精确包含 `S256`；缺少 S256 时构造失败。
- 当前实现只接受 RS256 签名算法。

所有构造错误在启动期返回，禁止生成延迟到首个请求才失败的错误 Handler。

### 6.2 Begin Login

Begin Login 执行以下步骤：

1. 校验 return-to，只接受站内相对路径或显式 allowlist 中的绝对 URL。
2. 使用密码学安全随机源生成 Flow ID、state、nonce 和 RFC 7636 合法 verifier。
3. 计算 `base64url-no-padding(SHA256(verifier))` challenge。
4. 把 verifier 与 state、nonce、Client、Redirect URL、return-to、创建和过期时间写入短时服务端 Flow。
5. 浏览器 Flow Cookie 只保存随机 Flow ID。
6. authorize URL 只包含 challenge 和 `code_challenge_method=S256`，不包含 verifier。

Flow 必须有界 TTL，并通过 Backend 的一次性 `ConsumeFlow` 读取。Redis adapter 必须加密 Flow payload；verifier 不进入长期 Session。

### 6.3 Callback

Callback 按以下顺序失败关闭：

1. 读取 Flow ID 并一次性消费 Flow。无论后续成功或失败，该 Flow 均不得再次使用。
2. 校验 OAuth error、state、Client、精确 Redirect URL 和 Flow 时效。
3. 使用 code 和 verifier 执行一次 code exchange；结果不确定时不自动重试。
4. 验证 ID Token 的签名、issuer、audience、nonce、时间和算法。
5. 规范化并交叉检查所有可用 granted scope 来源。
6. 调用 UserInfo 补充资料，并要求 UserInfo subject 与 ID Token subject 相同。
7. 创建平台独立的服务端 Session，并设置 Session Cookie。

Granted scope 规则为：

- Token Response 的 `scope` 存在时作为首选来源。
- 已验证 Access Token 或 ID Token 中存在 scope 时必须与首选来源规范化后相容。
- Token Response 缺少 scope 时，可从已验证 Access Token 或 ID Token 的 scope 建立结果；多个已验证来源必须一致。
- 所有来源都无法确定时返回协议错误。
- 永远不得回退到配置中的 requested scopes。

### 6.4 Refresh

Session access token 进入 refresh window 后，在任何受保护远端调用前主动 refresh：

1. 获取带 fencing token 的 refresh lease。
2. 重新读取当前 Session 和版本，避免使用过时快照。
3. 调用 token endpoint 一次，不自动重试。
4. 验证新 ID Token/Access Token，获取必要 UserInfo，并重新构建 Identity、Groups 和 Granted Scopes。
5. 通过带 lease 的 CAS 一次性提交新 TokenSet、Identity、Groups、Granted Scopes、版本和时效。
6. 释放 lease；过期或失效的 lease 不得提交。

任一新 Token 或 Claim 验证失败时，不提交任何新状态。`invalid_grant` 使用同一 fencing 语义删除本地 Session；`temporarily_unavailable` 或网络错误保留当前可重试 Session，但当前需要新 token 的请求失败关闭。

### 6.5 Logout

提供两个语义不同的入口：

- 本地 Logout：删除当前应用 Session 和 Cookie，不声称退出其他消费平台。
- 集中 Logout：先完成本地清理，再发起 IAM Core end-session 流程。

远端 Logout 失败不得恢复已经删除的本地 Session。

## 7. HTTP 授权数据流

### 7.1 Route Manifest

应用在启动期声明稳定 Route：标准大写 HTTP Method、Resource Server code 和 Resource code。Manifest 编译时拒绝：

- 空值或包含前后空白的稳定编码。
- 非标准或非大写 Method。
- 重复声明或重复绑定。
- 未编译 Route 被交给授权中间件。

Manifest 与 adapter 可以在本地保留路由名称或模板用于绑定完整性检查，但这些本地信息不得进入 PDP 请求。PDP 请求永远只包含：

```json
{
  "resource_server": "orders_api",
  "resource": "orders",
  "http_method": "GET"
}
```

### 7.2 Credential 解析

- API Bearer 模式从单个 `Authorization: Bearer` Header 获取 token，并通过 `core` 本地验证。
- BFF Session 模式通过注入的 Session credential resolver 获得受控 TokenSource 和已验证 AuthContext。
- Cookie 与 Bearer 同时存在时直接返回 credential conflict，不比较 token 密文是否相同。
- 原始 token 只存在于请求生命周期内的 TokenSource，不进入公开 AuthContext 或业务 DTO。

Session credential resolver 可以在 PDP 前根据本地 token 时效主动 refresh。PDP 返回 401 后不得反应式 refresh 或重试 PDP。

### 7.3 PDP

每个受保护请求执行以下步骤：

1. 解析且验证唯一 credential。
2. 取得 Manifest 已编译 Route，并使用真实请求的大写 Method 做一致性检查。
3. 从 TokenSource 取得当前 access token。
4. 向 `POST /authorization/v1/decisions` 发出恰好一次请求。
5. 解析 IAM Core v1.8.1 统一 envelope。
6. 仅在 HTTP 200、`code=0`、decision 字段合法且 `allowed=true` 时注入 DecisionContext 并执行 Handler。

PDP Client 必须拒绝重复 JSON key、尾随 JSON、错误字段类型、非零 `code`、缺少合法 `message`、缺少 `decision_id`、缺少 `reason_code`、错误 envelope 或裸 decision 响应。为了允许同一 v1.8.x 契约内的附加元数据，合法 envelope 中未知的非冲突字段可以忽略，但不得改变必需字段的解释。

PDP 结果映射：

| 结果 | SDK 语义 | Handler |
| --- | --- | --- |
| 200、allowed=true | allow | 执行一次 |
| 200、allowed=false | forbidden | 不执行 |
| 400 | SDK 配置或协议错误 | 不执行 |
| 401 | unauthenticated | 不执行，不 refresh，不重试 |
| 503、超时、网络错误 | IAM unavailable | 不执行 |
| 畸形或不一致 envelope | protocol error | 不执行 |

SDK 不缓存 allow/deny，不自动重试 PDP，不使用陈旧 allow、本地 groups 或本地规则降级放行。

## 8. 错误、安全与可观测性

统一错误至少包含：

- Kind：invalid configuration、protocol、unauthenticated、forbidden、IAM unavailable、credential conflict。
- Operation：稳定低基数操作名。
- HTTP status、retryable、reason code。
- 经过安全校验的 request ID、trace ID、decision ID。

错误不暴露远端响应 body、原始 URL query 或敏感 cause 文本。OAuth `invalid_grant`、`access_denied`、`temporarily_unavailable` 需要保留不同的安全类型和 Session 状态动作。

以下内容不得进入日志、错误、Hook、APM body capture、Trace baggage、metrics label 或测试快照：

- Access Token、ID Token、Refresh Token。
- Authorization Header。
- Client Secret。
- Authorization Code。
- PKCE verifier。
- Cookie、Session ID、Flow ID。
- 带完整 query 的 redirect/callback URL。

可观测性只使用稳定低基数字段：operation、outcome、credential source、HTTP result class 和 duration。request ID、trace ID、decision ID 只用于日志与 Trace 关联，不作为 metrics label。

网络访问统一使用 TLS 校验、有限连接池和分操作超时。授权链路默认失败关闭。Discovery/JWKS 可缓存；未知 `kid` 只允许一次受控刷新，并限制刷新频率。仍在有效期内的可信 JWKS 可用于本地密码学验证，但不能代替新的 PDP allow。

## 9. 测试策略

所有实现使用测试驱动开发：每个行为先加入失败测试，再实现最小代码并运行相关 package 和全量验证。

### 9.1 契约测试

冻结 IAM Core Server 当前 v1.8.1 的以下行为为仓库内自包含 fixture：

- Discovery 的 issuer、端点、RS256 和 `code_challenge_methods_supported=["S256"]`。
- Token Response 与 granted scope。
- UserInfo、groups 和空 mapping。
- PDP 三字段请求与统一成功 envelope。
- OAuth、PDP 401/503 和稳定错误分类。

测试不依赖开发者本机的 IAM Core Server 路径或运行实例。

### 9.2 安全负向矩阵

至少覆盖：

- PKCE 缺失、plain、challenge/verifier mismatch、非法 verifier、code replay。
- state、nonce、issuer、audience、kid、alg、签名、`exp`、`iat`、`nbf` 和 `jti` 错误。
- requested scope 高于 granted scope、scope shrink、不同来源 scope 不一致。
- groups 空 mapping、重复值、跨 Client 泄漏和 roles 回退。
- Cookie/Bearer 双凭据。
- PDP deny、401、503、超时、网络错误、重复 key、尾随 JSON、裸响应和字段类型错误。
- Refresh 并发、过期 lease、fencing、CAS 冲突、rotation、`invalid_grant` 和部分状态提交。
- return-to 开放重定向和 Cookie 安全属性。

### 9.3 调用次数与副作用

HTTP 授权测试明确断言每个请求：

- PDP 调用最多一次。
- UserInfo 调用零次。
- Handler 调用最多一次。
- deny、401、503、超时和协议错误时 Handler 调用零次。

Refresh 测试断言新 TokenSet、Identity、Groups 和 Granted Scopes 要么一起提交，要么全部不提交。

### 9.4 泄漏与别名测试

- 捕获并扫描错误、结构化日志、Hook、Trace 和测试输出中的敏感值。
- 对所有公开切片、map 和 byte 数据验证防御性复制，调用方修改返回值不得改变内部状态。
- Fuzz return-to、Cookie/Header 解析和 PDP JSON decoder。

### 9.5 Module 与集成验证

发布门槛包括：

- 根 module、Gin adapter、Redis adapter 和 integration module 的普通测试。
- 所有可发布 module 的 `go vet`。
- 根 module 与 adapters 的 race 测试。
- Redis 6.2/7.4 conformance。
- BFF、net/http、Gin 和 Redis 示例编译。
- `go mod graph` 检查，证明根 module 不包含 Gin、Redis、Docker 或 Testcontainers。
- README、Compatibility、Changelog 与公开 Go 文档一致。

## 10. 实施与删除顺序

重写按以下依赖顺序交付：

1. 冻结 v1.8.1 契约 fixture，并建立多 module/go.work 骨架。
2. 实现 `core` Discovery、JWKS/JWT、AuthContext、错误和安全观测。
3. 实现 BFF PKCE、Callback、真实 granted scope 和服务端 Session。
4. 实现 refresh fencing/CAS、原子 Claims 更新和 Logout。
5. 实现 `httpauthz` 严格 PDP、Route Manifest 和 net/http middleware。
6. 实现 Gin、Redis adapters 和 `testkit`。
7. 迁移示例、文档和集成测试。
8. 在新契约测试覆盖相应行为后，删除全部旧根 facade、旧 package 和旧测试。
9. 执行所有 module 的发布门槛，发布 `v0.2.0`。

删除旧代码是本次交付的一部分，不保留双轨实现。实现期间可以短暂按测试依赖顺序并存，但最终提交必须只有新 API 和新文档。

## 11. 完成标准

本次重写完成必须同时满足：

- BFF 可完成 Login、Callback、me、Refresh、本地 Logout 和集中 Logout。
- 浏览器运行态不接触 Token、Client Secret 或 PKCE verifier。
- 默认 scopes 为 `openid profile email groups`，不请求或公开 roles。
- Identity 和 Session 只报告真实 granted scope；refresh 后立即反映新的 groups 和 scope。
- HTTP Route 必须使用编译 Manifest；PDP 请求只有三个冻结字段。
- 每个完成认证的受保护 HTTP 请求 PDP 恰好一次、UserInfo 零次；认证失败的请求 PDP 为零次；只有明确 allow 执行 Handler。
- deny、401、503、超时、协议错误、审计不可用和配置错误全部失败关闭。
- 根 module 依赖图不包含 Gin、Redis、Docker 或 Testcontainers。
- 所有普通测试、vet、race、Redis conformance、示例和泄漏扫描通过。
- 仓库不包含 RPC、旧 facade、legacy PDP decoder、legacy roles profile 或 v0.1 兼容分支。
