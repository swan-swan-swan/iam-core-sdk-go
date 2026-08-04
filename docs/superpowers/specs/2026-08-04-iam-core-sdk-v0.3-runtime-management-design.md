# IAM Core Go SDK v0.3.0 Runtime 与 Management 设计

## 1. 背景与结论

当前仓库以 `github.com/swan-swan-swan/iam-core-client-sdk-go` 发布 `v0.2.0`，已经完成 IAM Core v1.8.1 的 OIDC/BFF、HTTP Resource Server、Gin adapter 和 Redis adapter。现有 Runtime 安全行为已经通过普通测试，且不应在下一阶段中顺带重写。

`v0.3.0` 将仓库和根 Module 统一命名为 `iam-core-sdk-go`，在同一仓库中建立 `runtime/` 与 `management/` 两个能力域。现有 Runtime 迁入新路径；Management 新增平台接入控制面的强类型 HTTP Client。

本版本不支持 RPC：不创建 RPC package、接口、adapter 或示例，不定义 RPC 兼容承诺，也不引入 IAM RPC 的直接生产依赖。隔离的 integration Module 可能因 Testcontainers 间接包含 gRPC 依赖，该传递依赖不构成 SDK RPC 能力。

## 2. 目标与非目标

### 2.1 目标

- 将根 Module 改为 `github.com/swan-swan-swan/iam-core-sdk-go`。
- 将现有 Core、BFF、HTTP Authz、TestKit、Gin 和 Redis 迁入 `runtime/`，保持 `v0.2.0` 已冻结的安全行为。
- 提供共享 Management Transport、注入式 TokenSource、统一错误、严格 envelope 解码、请求关联和安全观测。
- 提供 Application、OIDC Client、登录准入、Client Group Mapping、HTTP Resource Catalog 和 Policy Document 的分域强类型 Client。
- 为所有 Management 方法冻结 HTTP Method、Path、Query、请求字段、响应 envelope 和错误映射契约。
- 发布 Runtime、Management 最小示例、迁移指南、兼容矩阵和 `v0.3.0` 发布门禁。

### 2.2 非目标

- 不保留 `iam-core-client-sdk-go` 的 deprecated wrapper、转发 package 或旧 import 兼容层。
- 不改变 Runtime 的 PKCE、JWT、Session、单次 PDP、fail-closed、无授权缓存和无自动重试语义。
- 不实现 RPC Consumer/Provider、Dubbo/Triple adapter、RPC AuthContext 或 RPC 撤销。
- 不实现 IAM 用户、组织、全局角色、Cloud Provider、登录准入审计查询或授权决策审计查询 Client。
- 不实现用户名密码登录、`client_credentials` 或其他 IAM Core 当前不支持的凭据流程。
- 不提供 Application 自动注册、`EnsureApplication`、跨领域一键接入或业务启动时自动 Provisioning。
- 不生成并公开整套 OpenAPI Client。

## 3. 仓库与 Module 结构

目标结构如下：

```text
iam-core-sdk-go/
├── go.mod
├── runtime/
│   ├── core/
│   ├── bff/
│   │   └── session/
│   ├── httpauthz/
│   ├── testkit/
│   └── adapters/
│       ├── gin/
│       │   └── go.mod
│       └── redis/
│           └── go.mod
├── management/
│   ├── client/
│   ├── applications/
│   ├── oidcclients/
│   ├── admission/
│   ├── groupmappings/
│   ├── catalog/
│   └── policies/
├── examples/
│   ├── runtime/
│   │   ├── bff/
│   │   └── nethttp/
│   └── management/
├── integration/
│   └── go.mod
└── docs/
```

根 Module 同时发布 `runtime/*` 和 `management/*`。Gin 与 Redis 保持独立 Module，目标路径分别为：

```text
github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin
github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis
```

`integration` 只用于仓库联合测试，不作为已发布 SDK 依赖。仓库内 `go.work` 只服务本地开发与 CI。

旧根 facade 不恢复。调用方显式导入所需 Runtime 或 Management package。Management 领域 package 只能依赖 `management/client`，不得相互依赖；Management 不依赖 Runtime，Runtime 也不依赖 Management。

## 4. Runtime 迁移边界

Runtime 迁移是路径和发布边界变更，不是功能重写：

- `core` 迁入 `runtime/core`。
- `bff` 及 `bff/session` 迁入 `runtime/bff`。
- `httpauthz` 迁入 `runtime/httpauthz`。
- `testkit` 迁入 `runtime/testkit`。
- `adapters/gin` 与 `adapters/redis` 迁入 `runtime/adapters` 下的独立 Module。
- 原 `examples/bff` 和 `examples/nethttp` 迁入 `examples/runtime`。

迁移后继续保持以下已冻结契约：PKCE S256、Client groups、真实 granted scopes、RS256 JWT/JWKS、服务端 BFF Session、refresh fencing、显式 Route Manifest、每个受保护请求恰好一次 PDP、PDP 不重试、不缓存授权结论、Bearer/Session 冲突失败关闭，以及敏感信息不进入错误和观测。

所有旧 import 在同一变更中删除。`v0.2.x` 使用旧 Module，`v0.3.x` 使用新 Module；不在运行时同时加载两代 SDK。

## 5. Management 共享 Client

### 5.1 认证

IAM Core 当前只支持 `authorization_code` 与 `refresh_token`，不支持 `client_credentials`。Management Client 不负责取得、刷新或持久化管理 Token，只接受调用方注入的最小接口：

```go
type TokenSource interface {
	AccessToken(ctx context.Context) (string, error)
}
```

Admin BFF 可以用结构化接口传入当前管理员 Session 的 TokenSource。CLI、CI/CD 或专用管理服务必须通过受控外部流程取得管理 Token。SDK 不接收用户名或密码，不尝试模拟机器凭据。

### 5.2 配置与 Transport

共享 Client 的公开配置为：

```go
type Config struct {
	BaseURL     string
	TokenSource TokenSource
	HTTPClient  *http.Client
	Timeout     time.Duration
	Observer    Observer
}
```

生产 Base URL 必须使用 HTTPS；仅 loopback 测试允许 HTTP。构造期拒绝 URL userinfo、query、fragment、缺失 TokenSource 和负超时。Client 复制调用方的 `http.Client`，清除 Cookie Jar，禁止重定向，并对每个管理请求施加有限总超时。更短的 caller context deadline 优先。

每次调用只从 TokenSource 读取一次 Access Token，并最多发出一个 HTTP 请求。SDK 不自动刷新、不自动重试，也不根据 HTTP Method 推断重试安全性。Token、Authorization Header、Secret、完整响应正文和完整 URL query 不进入错误、日志、Hook、Trace baggage 或 metrics label。

### 5.3 Envelope 与元数据

Management Client 严格解析 IAM Core 统一 envelope。成功响应必须具有合法 `code`、`message` 和与方法相符的 `data`；可选 `request_id`、`trace_id` 以安全元数据返回。解码拒绝重复 JSON key、尾随 JSON、错误字段类型、非零成功 code、超限 body 和缺失必需数据。允许同一 IAM Core v1.8.x 内新增不冲突字段。

领域 Client 依赖共享 `Transport` 接口，以便测试注入，但普通调用方通过 `client.New(Config)` 构造真实实现。Transport 只负责一次请求、认证、envelope 和元数据，不包含领域路径或自动编排。

### 5.4 错误

共享错误 Kind 固定为：

- `invalid_config`
- `invalid_argument`
- `unauthenticated`
- `forbidden`
- `not_found`
- `conflict`
- `rate_limited`
- `iam_unavailable`
- `protocol`

错误公开稳定 operation、HTTP status、IAM code、retryable、request ID 和 trace ID，不公开远端原始 body 或敏感 cause。网络错误、超时与 5xx 映射为 `iam_unavailable`，但 SDK 不因此自动重试。401、403、404、409 和 429 保留不同 Kind。

存在并发版本语义的接口在 409 时返回强类型 Conflict 信息，包括服务端明确提供的最新 revision/hash 和脱敏影响摘要。调用方必须重新读取资源并显式决定是否再次提交。

### 5.5 敏感值

OIDC Client 凭据创建响应中的 Secret 只返回一次。SDK 使用专用的单字段值类型 `SensitiveString` 保存该值；`String()`、`GoString()` 和默认格式化只输出 `[REDACTED]`，调用方必须显式调用 `Reveal()`。`Reveal()` 可以重复调用；“只返回一次”描述服务端创建凭据响应，不表示 SDK 在值副本间维护一次性共享状态。SDK 不缓存、不持久化、不克隆到观测事件，也不在后续查询响应中建模 Secret。

## 6. Management 领域能力

### 6.1 `applications`

提供 Application 列表、详情、创建、展示信息更新、状态切换和受约束硬删除。公开方法使用 `HardDelete` 表达服务端语义，不提供级联删除或自动清理下级引用。

### 6.2 `oidcclients`

提供 Application 下的 OIDC Client 列表与创建、非敏感配置查询、安全配置查询与带版本更新、一次性 confidential Client 凭据创建和指定凭据撤销。创建凭据使用显式幂等选项时只透传调用方提供的幂等键，SDK 不自动生成或重试。

### 6.3 `admission`

分别建模 Application 层与 OIDC Client 层登录准入规则。提供分页查询、创建、带 `login_policy_revision` 的更新和软删除。两层 API 共享值对象，但保持不同的路径构造器，避免 Client 层规则误写入 Application 层。

### 6.4 `groupmappings`

提供单个 OIDC Client 下 Role Open ID 到 Client 专属 group 的查询、创建、更新和删除。SDK 校验公开 ID 与 group 基本格式，但不复制 IAM Core 的角色存在性和业务冲突规则。

### 6.5 `catalog`

提供 HTTP Resource Catalog 查询，Resource Server、Resource、Action 的创建与更新，Method 到 Action Mapping 更新，未引用实体停用，以及 managed Catalog 显式发布。当前发布契约是无请求体的单次 `POST`，不虚构服务端尚未提供的 revision/hash 参数；SDK 也不根据 Runtime Route Manifest 自动写入 Catalog。

### 6.6 `policies`

提供 Policy Document 列表、详情、创建、更新、预览、角色绑定和编译结果查询。SDK 传递强类型 Policy 文档与绑定请求，但不在本地实现 Policy 编译器、Casbin、语义降级或自动发布。

### 6.7 明确排除

Management 不覆盖用户、组织、全局角色、Cloud Provider、登录准入审计查询和授权决策审计查询。后续扩展必须通过新的设计评审，不把这些接口塞入现有领域 Client。

## 7. 写操作与一致性

- `Create`、`Update`、`Delete`、`Deactivate`、`Revoke` 和 `Publish` 每次最多发送一个请求。
- SDK 不自动生成幂等键。服务端支持时，由调用方通过请求选项显式提供；SDK 只校验并透传。
- SDK 不因超时、网络错误、429 或 5xx 自动重试。调用方必须根据操作语义、幂等键和最新资源状态显式决定重试。
- revision/hash 并发字段在对应写方法签名中是必填参数，不隐藏在全局 Client 状态中。
- 删除、软删除、停用、撤销和受约束硬删除使用不同方法名，不能统一成模糊的 `Delete`。
- 列表接口显式接受 page/page_size 或 cursor。SDK 不提供无限自动翻页或把全部结果一次性读入内存的 helper。
- 所有公开 ID、Client ID、Role Open ID 和稳定编码在请求前校验空值、前后空白和契约允许的基本格式；最终业务校验仍由 IAM Core 执行。

## 8. 契约来源与测试策略

Management 契约来源按以下优先级解释：

1. 本设计中经用户确认的能力、安全和兼容边界。
2. IAM Core Server 当前冻结 OpenAPI。
3. IAM Core Server 对应 Handler、DTO 与契约测试。

SDK 仓库保存最小化、自包含的 Management 契约 fixture，不在测试时依赖开发者本机 IAM Core 路径或运行实例，也不把自动生成的完整 OpenAPI Client 作为公共 API。

所有实现遵循 TDD：先写失败测试，再写最小实现。测试至少覆盖：

- 每个领域方法的 HTTP Method、Path、Query、请求字段和响应类型。
- TokenSource 每请求调用一次，HTTP 请求最多一次，所有错误路径不自动重试。
- Base URL、超时、重定向、Cookie Jar 和 caller cancellation 边界。
- 成功 envelope、401、403、404、409、429、5xx、网络错误、超时、畸形 JSON、重复 key、尾随 JSON和超限 body。
- revision/hash 冲突、幂等键透传、一次性 Secret 只在创建响应出现。
- 错误、Observer、日志和格式化输出不泄漏 Token、Authorization Header、Secret 或响应正文。
- Runtime 迁移前后的行为测试保持一致。
- 根 Module 不出现 RPC 公共 package 或 IAM RPC 直接生产依赖。

发布验证至少包含：

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
git diff --check
```

Gin、Redis 和 integration Module 分别执行测试、race 与 vet。Redis 6.2/7.4 conformance 继续在 Docker 可用的 CI runner 上执行。文档示例必须编译，公开 API 必须通过契约和敏感信息泄漏测试。

## 9. 示例与接入边界

Runtime 示例继续覆盖 BFF 和 `net/http` HTTP Resource Server。Management 示例只展示：构造注入式 TokenSource、创建单个领域 Client、执行一次读操作，以及带 revision 的一次写操作。示例不读取用户密码、不打印 Secret、不启动自动 Provisioning。

Ops Gateway 与 Go 脚手架的普通业务进程只使用 `runtime/*`。受控 IAM 管理服务、专用 CLI 或 CI/CD 才能使用 `management/*`，并持有独立高权限 Token。业务应用启动和普通请求链路不得创建、修改或删除 IAM 对象。

Go 脚手架的无鉴权模式属于调用方运行策略：`auth.mode=none` 时不初始化 Runtime SDK，也不建立本地账号体系或伪造 IAM 身份。该模式不由本 SDK 提供开关。

## 10. 迁移与发布

`v0.3.0` 是破坏性版本。发布前 GitHub 仓库必须重命名为 `iam-core-sdk-go`。迁移指南提供旧路径到新路径的精确映射，并要求消费项目移除旧 Module 后再加入新 Module。

`COMPATIBILITY.md` 同时记录：

- `v0.2.x`：旧 Module `iam-core-client-sdk-go`，仅 Runtime，IAM Core v1.8.1。
- `v0.3.x`：新 Module `iam-core-sdk-go`，Runtime 与平台接入 Management，IAM Core v1.8.1。

根 Module、Gin adapter 和 Redis adapter 使用对应 `v0.3.x` tag。Release CI 检查 VERSION、module path、嵌套 Module 依赖、tag、示例、文档关键语义和仓库中不存在旧 import。历史 `v0.2.x` tag 保持不变。

## 11. 实施阶段

本设计在同一个 `v0.3.0` 开发周期内分四个可独立验证的阶段：

1. Runtime Module、目录、adapter 和示例的干净迁移。
2. Management 共享 Client、错误、envelope、TokenSource 与安全测试。
3. 按 `applications`、`oidcclients`、`admission`、`groupmappings`、`catalog`、`policies` 顺序交付分域 Client。
4. 契约覆盖、示例、迁移文档、兼容矩阵和 Release CI 收口。

每个阶段必须保持仓库可测试。Management 的完成标准是已确认范围内的当前 IAM Core 管理端点全部具有强类型方法和契约测试，而不是只创建目录或空接口。
