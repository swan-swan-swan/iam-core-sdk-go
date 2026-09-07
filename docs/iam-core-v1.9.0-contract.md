# IAM Core v1.9.0 SDK Contract

本文冻结 IAM Core Go SDK v0.9 的 Application Handoff Runtime 扩展。除本文明确新增的能力外，
OIDC/BFF、HTTP PDP、HTTP Catalog Registration 与 Management API 继续遵循
`iam-core-v1.8.1-contract.md` 的既有兼容和失败关闭语义。

SDK v2.0.0 的统一授权扩展以下文 Manifest v2 为准；HTTP 路由字段及命名约束覆盖旧版本的可选声明。

## 统一授权与 Manifest v2（SDK v2.0.0）

本扩展使用 `github.com/swan-swan-swan/iam-core-sdk-go/v2` 根 module；全部当前集成 import 添加 `/v2`。
旧 v1.x/v0.x module 路径属于历史契约，消费方应协调替换依赖，不用 replace 或同时引入两个 SDK module。

`httpauthz.NewRouteSpec(method, routeTemplate, routeName, action)` 是完整声明的构造入口。
`runtime/authzcontract` 严格校验三段 Action：每段 token 匹配
`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`，总长最多 64；verb 仅允许 access、discover、select、create、
update、delete、execute、preview、publish、approve、bind、revoke、rotate、reveal、export、import。
示例 `iam:oidc_client:select` 合法，旧 `iam:user:list` 非法，不做大小写或空白修正。

Route Name 匹配 `^[a-z0-9]+(?:\.[a-z0-9]+){2,}$`，总长最多 64；Resource 为点替换下划线的确定性
结果，ResourceServer 为 Action 第一段。RouteTemplate 为无 scheme、host、query、fragment 的绝对路径。
CompileManifest 和 Registry 均重新验证这些关系。多个逻辑路由可以共享 Action，动态逻辑路由可以共享
Method + RouteTemplate；名称与派生 Resource 必须唯一，不允许 YAML 路由绑定。

Catalog 的 PUT 注册请求包含 `schema_version`（固定字符串 `"2"`）、`application`、`service`、
`release`、`routes`。每条 Route 固定包含 `name`、`method`、`route_template`、`resource_server`、
`resource`、`action`，按 Name 排序发送。PDP 请求继续使用稳定资源和方法，同时必须发送
`expected_action`；模板只用于 HTTP 注册和 Catalog 对账，不作为 PDP Resource。允许响应中缺失或
不匹配的 Action 失败关闭，PDP 调用仍不重试、不缓存。

本扩展指定发布版本 v2.0.0；v0.10.0 是已存在的退出能力版本，不复用。完整声明与 Manifest v2 对
旧调用方存在不兼容影响，必须先部署支持 v2 的服务端，再协调升级消费方、Catalog 与精确资源策略。
不提供永久 Manifest v1 回退；本地不创建或推送标签。

## Application Handoff

公开 package：

```text
github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/applicationhandoff
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
