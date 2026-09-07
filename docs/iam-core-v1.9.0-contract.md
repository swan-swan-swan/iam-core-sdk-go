# IAM Core v1.9.0 SDK Contract

本文冻结 IAM Core Go SDK v0.9 的 Application Handoff Runtime 扩展。除本文明确新增的能力外，
OIDC/BFF、HTTP PDP、HTTP Catalog Registration 与 Management API 继续遵循
`iam-core-v1.8.1-contract.md` 的既有兼容和失败关闭语义。

## Application Handoff

公开 package：

```text
github.com/swan-swan-swan/iam-core-sdk-go/runtime/applicationhandoff
```

Client 只调用：

```text
POST /api/v1/application-handoffs
```

请求 JSON 固定为 `applicationOpenId`、`decisionId`、`correlationId`。协议不接受 Subject；IAM Core
必须从已验证 Access Token 的 `sub` 取得用户身份，并同时验证 Token 的 `aud`、`client_id`、`azp`
以及精确的 `application-handoff:create` scope。

调用方必须为每次 `Create` 注入 `core.TokenSource`。SDK 每次只读取一次 Token，不获取、刷新、缓存、
持久化或记录 Token。Client 禁止重定向、清除 Cookie Jar、限制总超时与响应体大小，不自动重试。

成功响应中的 `expiresIn` 是整数秒，SDK 转换为 `time.Duration`。`launchUrl` 是由 IAM Core 根据已注册
插件实例固定构造的短时 URL；SDK 只把它返回给当前调用方，不保存在 Client。调用方应立即以 302
返回给浏览器，不记录 URL 或其中的一次性 code。

## 身份与权限边界

Application Handoff 只证明一个不可变 `(issuer, subject)` 身份并携带 IAM Access Profile 意图。
插件负责把该身份映射到目标系统本地用户。目标系统继续拥有用户组、资产、系统角色和会话审计；
SDK 不管理目标系统权限，也不允许调用方在 Handoff 请求中提交目标系统角色或资产权限。

IAM Core 只在目标插件身份 revision 已完成对账时签发 Handoff。一次性 code 的有效期为 60 秒，
兑换后原子失效；SDK 不提供 code 兑换 API，该能力只属于目标插件的 Runtime Credential。

## 错误与敏感信息

无效配置/输入、TokenSource 失败、401/403、非成功状态、超时、超限响应和畸形 envelope 都失败关闭。
错误和 Observer 事件不得包含 Token、Launch URL、Cookie、完整响应正文或完整查询串。SDK 不跟随
IAM Core 返回的重定向。
