# Catalog Manifest v4 分类契约（待发布的兼容 3.x 能力）

此实现引用 IAM Server 中唯一正式规格与计划：source commit
`9f05a79f23435a2b79f9106d1ddac40484cc1b0a`，
`docs/superpowers/specs/2026-11-16-sdk-catalog-policy-classification-design.md`
（SHA-256 `bcb211b8f09f1210a9463752a00492ee86f5f03f93b1d9012f769c87744d3c67`），
`docs/superpowers/plans/2026-11-16-sdk-catalog-policy-classification.md`
（SHA-256 `f1c962cad8cc33cfec2b9f30d12b327df7823c2bf6563949954417e97c2155d3`）。
本页说明 SDK 接口及兼容性，不构成独立产品规格或发布批准。

Go module 保持 `github.com/swan-swan-swan/iam-core-sdk-go/v3`。Manifest v4 与 Go module 主版本独立；
下一兼容 3.x 发布提供这些新增 API，本次代码交付不分配版本、不创建 tag。

## 单一分类声明

使用 `authzcontract.PolicyClassFullAccess`、`PolicyClassReadOnlyAccess`、`PolicyClassCardAccess`。
三种值区分大小写，缺失、未知、空白或不合法的组合均拒绝，不推断默认类别：

| 分类 | 本地验证 | IAM 域策略集合 |
| --- | --- | --- |
| FullAccess | 公共合同允许的 HTTP Method 与 Action | 域 FullAccess |
| ReadOnlyAccess | 仅 select/discover/preview/export，允许读取类 POST | 域 FullAccess 与 ReadOnlyAccess |
| CardAccess | 仅 GET/access，调用方显式保证入口语义 | 域 CardAccess；混合域另加入 FullAccess |

纯 Card 域只生成 CardAccess，不生成相同正文的 FullAccess/ReadOnlyAccess。FullAccess 包含全部已声明域能力，
不以通配符扩大范围；三种访问级别不替代 policy_type=system/custom 或 source_kind=sdk_auto。
同 Action 的多路由必须分类一致；SDK 检查当前服务，IAM 负责跨服务 Application 聚合检查。
分类不更改 Action、Resource、Method、用户角色或目标平台原生权限。

`httpauthz.NewClassifiedRouteSpec(method, template, name, action, class)` 返回包含原四字段 `Spec`
的 wrapper。应用从同一个值取 `Spec` 交给框架及 PDP，整个 wrapper 交给
`Registry.RegisterClassified`。禁止在配置中另建分类映射。

`httpcatalog.NewClassifiedRegistry(Config)` 创建 v4 Registry，复用现有凭据、超时、同步与心跳配置。
`ExportClassifiedManifest()` 返回排序且独立的 `ClassifiedManifest` 副本；导出不发网络请求、不持久化，
不改变健康状态。必须有至少一条经过验证的路由。调用方自行管理导出的清单文件。

## 报文与摘要

v4 单条路由固定五字段：`name/method/route_template/action/policy_class`，不发送派生资源字段。
摘要使用 schema_version/application/service/routes，routes 按 name、method 排序，字段按上述顺序，
UTF-8 紧凑 JSON 后 SHA-256，前缀 `sha256:`。release 和 deployment_generation 不进入摘要。
分类单独变化也改变摘要，已同步 Registry 必须以新部署代次重新创建后发布。

共享 fixture：[`runtime/httpcatalog/testdata/classified-manifest-v4.json`](../runtime/httpcatalog/testdata/classified-manifest-v4.json)。
其 routes 故意乱序，规范摘要为：

```text
sha256:dcbe88742790dfa490d74f88444874892dfb17b1d1aff5888f169c2b58ada700
```

摘要先用独立 Python JSON/SHA-256 计算，再由 SDK 公开摘要函数及真实 PUT 报文核验；Server 应独立重算，
不能只信任 SDK 提交的摘要。fixture 的原文件 SHA-256 与规范 Manifest 摘要是不同概念。

## 兼容与失败行为

`RouteSpec`、`Route`、`Manifest` 保持原字段和构造器签名，`NewRegistry`/`Register` 仍只使用
Manifest v3 原四字段 JSON 及原摘要。v3 Registry 调用 RegisterClassified/ExportClassifiedManifest、
v4 Registry 调用 Register 均拒绝，不进行协议转换。

Registrar HTTPS Basic 与已弃用的显式 Tokens 兼容入口保持互斥；凭据每次从宿主读取，不缓存、不记录。
同步核对响应 Application、代次、Catalog hash 及本地重算的 Manifest hash。心跳沿用当前成功同步版本。
错误响应不泄露远端正文；409 会隔离实例并停止续约，不自动注册。其他失败遵循既有有界心跳重试，
从不把 v4 变为 v3；不支持 v4 的旧 Server 返回错误。

先升级 Server，再按维护 runbook 准备完整 Application bundle、预检和单独批准的原子切换，最后启用调用方 v4。
活动 schema=4 后旧 SDK v3 注册或旧心跳不能用于恢复；恢复需服务端受控迁移和更高代次。
真实 SDK 发布、生产 DDL、部署、plan/apply 和账号验收均留给独立批准流程。

参阅离线可运行示例 [`examples/runtime/catalog`](../examples/runtime/catalog/main.go)。
