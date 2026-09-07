# IAM Core Go SDK v2.0.0 Contract

本文定义 IAM Core Go SDK v2.0.0 的统一授权与 Manifest v2 契约。SDK 版本不等于 IAM Core Server
版本；消费方必须连接已经支持 Manifest v2 的服务端。

本次收紧必填路由声明、Action 词表及 Resource 派生规则，属于破坏性公共契约变更，使用新的 major
版本 v2.0.0。历史 [IAM Core v1.8.1 契约](iam-core-v1.8.1-contract.md) 和
[IAM Core v1.9.0 Handoff 契约](iam-core-v1.9.0-contract.md) 保持冻结，记录原版本语义和旧 module
路径；当前集成的命名、路由、Manifest 和 module 路径以本文为准。

## 单一 v2 module

根 module 固定为 `github.com/swan-swan-swan/iam-core-sdk-go/v2`，最低 Go 版本为 1.24。
所有当前 production/test/example import 必须包含 `/v2`；不使用 replace 或同时引入旧根 module
维持旧路径。Gin/Redis Adapter 仍属于同一个可发布根 module。

正式发布后安装：

```sh
go get github.com/swan-swan-swan/iam-core-sdk-go/v2@v2.0.0
```

当前 VERSION 为 2.0.0，v2 标签只由正式发布流程创建；本地不创建或推送标签。
既有 integration 是非发布测试 module，通过 go.work use 消费本地 v2，仅在该 workspace 中运行。

## 严格命名

Action 严格为 `<server>:<domain>:<verb>`，总长不超过 64；每段 token 匹配
`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`。不 trim、不转小写，不接受二段、四段、大写、连字符、通配符、
连续下划线或首尾下划线。

动词仅允许 `access`、`discover`、`select`、`create`、`update`、`delete`、`execute`、`preview`、
`publish`、`approve`、`bind`、`revoke`、`rotate`、`reveal`、`export`、`import`。
读取统一使用 `select`；`iam:oidc_client:select` 合法，`iam:user:list` 非法。

Route Name 匹配 `^[a-z0-9]+(?:\.[a-z0-9]+){2,}$`，至少三段、总长不超过 64；段内没有下划线。
Resource Code 唯一派生为 Route Name 中的点替换为下划线，例如 `portal.application.list` 派生
`portal_application_list`。ResourceServer 是 Action 第一段。调用方不能手写或覆盖派生坐标。

Route Template 是以 `/` 开头的绝对框架路径，不含 scheme、host、query、fragment。例如
`/api/v1/apps/:application_open_id`。模板用于 HTTP 注册、目录展示和对账，不作为 PDP Resource。

一个 Action 可以映射多条表达相同授权语义的逻辑路由。动态逻辑路由可以共享 Method + RouteTemplate，
但 Route Name 和派生 Resource 必须唯一。读取和修改必须使用符合各自语义的 Action。
YAML 只承载连接与部署配置，禁止 route/action/resource 路由绑定。

## 完整声明与校验

当前公开 package：

```text
github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/authzcontract
github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/httpauthz
github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/httpcatalog
```

`httpauthz.NewRouteSpec(method, routeTemplate, routeName, action)` 返回完整 RouteSpec，包含 Name、Method、
RouteTemplate、ResourceServer、Resource、Action。命名校验统一由 `runtime/authzcontract` 提供。

应用的统一路由包装器消费同一个声明值，完成框架路由注册、PDP middleware 绑定及 Registry 登记。
CompileManifest 与 Registry 均重新校验全部字段，拒绝调用方构造的不一致结构体和冲突声明。
编译后的 Route 保留 Name 和 RouteTemplate，Binder 保证每个清单条目恰好绑定一次。
Registry 对完全相同的重复声明保留幂等登记；同名不同声明失败。

## Manifest v2 注册协议

启动时向 `PUT /api/v1/http-resource-catalog/registration` 发送当前应用的完整清单。顶层
`schema_version` 固定为字符串 `"2"`；每次快照按 Route Name 排序，单条路由字段固定如下：

```json
{
  "schema_version": "2",
  "application": "opsgw",
  "service": "ops-gateway",
  "release": "dev",
  "routes": [{
    "name": "portal.application.list",
    "method": "GET",
    "route_template": "/api/v1/apps",
    "resource_server": "opsws",
    "resource": "portal_application_list",
    "action": "opsws:portal:discover"
  }]
}
```

Registry 使用独立 `*-catalog-registrar` OIDC Client Basic 凭据执行单次启动同步；重试由应用的
启动生命周期调度。同步成功前健康状态保持失败；不把 Action 或 Method + RouteTemplate 当作唯一键。
Catalog 能力不创建 Application、OIDC Client、Policy、角色绑定或用户授权。

## PDP 与安全边界

PDP 请求携带 `resource_server`、从 Route Name 派生的 `resource`、`http_method` 和必填
`expected_action`。允许响应的实际 `action` 必须存在并精确匹配声明，否则按协议错误失败关闭。
每个通过本地认证的受保护请求恰好调用一次 PDP；拒绝、401、5xx、超时、网络错误和畸形响应都失败关闭。
PDP 401 不刷新凭据、不重试；不缓存决定，不使用本地角色或 groups 降级。

Runtime Token 由调用方按请求通过 `core.TokenSource` 注入，不获取、持久化或记录 Token。HTTP Client
禁止重定向、清除 Cookie Jar、限制超时与响应体。错误、日志及 Observer 不包含 Token、Secret、Cookie、
Session ID、完整查询串或响应正文。Runtime 与受控 Management 调用边界保持独立。

OIDC/BFF、浏览器全局退出、绝对/空闲 Session 策略与 Application Handoff 的既有安全行为保持不变。
Handoff 当前 package 为 `github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/applicationhandoff`；
仍只为当前用户请求一次性登录交接，不管理目标系统权限。历史文档中的 import 路径不能用于当前 v2 集成。

## 协调迁移

1. 先部署已经支持 Manifest v2 的 IAM Core Server。
2. 消费方替换旧 module 依赖和全部 import 为 `/v2`，使用 NewRouteSpec 构造完整声明。
3. 迁移旧 verb、Route Name 和 Resource；从 Action 派生的旧 Resource 不能直接沿用。
4. 协调更新 Catalog 与精确资源 Policy，随后启用业务路由并验证授权结果。

不完整 RouteSpec、Manifest v1、缺失 Action/RouteTemplate 或不一致坐标不会自动回退。新 SDK 不提供
永久 v1 兼容模式；历史文档保留原字节，新的契约变更必须写入当前版本文档。
