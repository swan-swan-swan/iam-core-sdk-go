# 从 v0.1 迁移到 v0.2

v0.2 面向 IAM Core v1.8.1，是对 v0.1/v1.7.1 SDK 的整体替换而不是包装。迁移应删除旧根
Client 与旧 package 调用，再按使用场景接入新模块；不提供兼容开关、fallback facade 或
双轨运行模式。

## 1. 先升级服务端契约

确认目标 IAM Core 是 v1.8.1，并为业务 Client 配置：

- Confidential Client 与精确 redirect URL；
- S256 PKCE；
- `openid profile email groups`（或其包含 `openid` 的最小子集）；
- Application 下稳定的 Resource Server、Resource 与 HTTP Method；
- 对应 Policy 与强制决策审计。

v0.2 不会自动迁移或创建这些管理对象。仍停留 v1.7.1 的调用方必须继续使用 v0.1.x，
不能把两代运行时混用。

## 2. 替换 module 与 imports

删除旧根 facade、`authn`、`authz`、`middleware`、`oidc`、旧 Session/Redis 和旧 Gin
imports，改为显式导入：

```text
github.com/swan-swan-swan/iam-core-client-sdk-go/core
github.com/swan-swan-swan/iam-core-client-sdk-go/bff
github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session
github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz
```

可选 adapter 是独立模块：

```text
github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/gin
github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis
```

根模块和每个使用的 adapter 都固定到同一 `v0.2.x` 版本线。不要复制仓库 `go.work` 到
消费项目；它只服务本仓库联合开发。

## 3. 拆分旧根 Client

- OIDC Discovery/JWKS/JWT 验证：构造 `core.Runtime`。
- 浏览器登录、Callback、Session refresh、Me 和 Logout：构造 `bff.Client`。
- HTTP Bearer/Session 认证和 PDP：构造 `httpauthz.Service`。
- 多副本 Session：单独构造 Redis adapter，并作为 `bff.Config.Backend` 注入。

旧的组合式 Client、Config、Handler helper 和 Context helper 没有兼容别名。新构造器都在
启动期校验安全边界，启动失败应终止服务，不能延迟到首个请求后忽略。

## 4. 重建浏览器入口

为 `bff.Config` 显式提供 Runtime、Client ID、Secret Provider、精确 Redirect URL、Backend
以及两个平台独立 Cookie 模板。生产 Cookie 必须 host-only、`Path=/`、`HttpOnly`、
`Secure`、`SameSite=Lax` 且使用不同的 `__Host-` 名称。

把旧登录/Callback/身份/登出路由替换为 `LoginHandler`、`CallbackHandler`、`MeHandler`、
`LocalLogoutHandler` 和 `CentralLogoutHandler`。注意后两个都只接受 POST，且语义不同：
本地登出不退出 IAM Core；集中登出在本地删除后调用 end-session。

删除所有无 PKCE、plain PKCE 或 verifier 由浏览器保存的流程。v0.2 只允许 PKCE S256，
state、nonce、verifier 和 return target 都绑定到一次性服务端 Flow。

## 5. 迁移身份与 scopes

把默认 scope 从旧 roles 画像改为 `openid profile email groups`。删除 `Roles` 与
`ExtraClaims` 依赖；使用 `core.AuthContext.Groups` 和强类型字段。`roles` 不是 groups 的
别名，也不会被接受。

业务必须按实际 granted scopes 处理字段缺失。Refresh 后使用新 Session/AuthContext，
不能保留旧 groups、旧 scopes 或旧 Token 的局部状态。

## 6. 重建 HTTP 授权

为每个受保护路由声明 `httpauthz.RouteSpec`，编译 Manifest，通过 Binder 唯一绑定，并在
启动服务前调用 `Validate`。把旧 Permission/裸 Decision decoder 或按 URL 猜资源的代码
替换为 `Service.Require(compiledRoute, handler)`。

新的 `Require` 每请求最多进行一次 PDP 调用。删除 PDP 401 后 refresh-and-retry、缓存 allow/
deny、使用本地 roles/groups 放行以及 Cookie/Bearer 内容相同就接受的逻辑。两种 credential
同时存在现在总是冲突。

## 7. 验证与删除旧示例

以仓库的 `examples/bff`、`examples/nethttp`、`adapters/gin/example` 和
`adapters/redis/example` 为新基线，删除旧 v0.1 示例，执行普通测试、race、vet、独立 module
构建与 Redis 6.2/7.4 conformance。

迁移完成后，代码库中不应再出现旧根 facade/包路径、no-PKCE、legacy roles、bare decision、
dual-credential 或 PDP 401 重试分支。RPC 与 IAM 管理 API 需要独立产品和安全设计，不能通过
本次迁移顺带加入。
