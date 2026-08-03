# Compatibility

- `v0.1.x = IAM Core v1.7.1 only`
- `v0.2.x = IAM Core v1.8.1`

| SDK | IAM Core contract | Go | Notes |
| --- | --- | --- | --- |
| v0.1.x | v1.7.1 only | 1.24+ | 历史 API；无 PKCE，使用旧根 facade 和旧包布局 |
| v0.2.x | v1.8.1 | 1.24+ | 强制 PKCE S256、Client groups、真实 granted scopes、Manifest 与单次 PDP |

v0.2 是破坏性重写，不与 v0.1 源码兼容，也不提供运行时兼容模式。根模块、Gin adapter
和 Redis adapter 分别发布并使用各自的 `v0.2.x` tag；仓库内 `go.work` 只用于联合开发，
不构成已发布模块的依赖。

兼容范围仅覆盖本仓库文档冻结的 IAM Core v1.8.1 OIDC/BFF 与 HTTP PDP 契约。RPC、IAM
管理 API、SPA/移动端 Token 存储、其他框架 adapter 和服务端对象自动注册均不在兼容承诺内。
同一 v1.8.x 契约可增加不冲突的 JSON 元数据，但必需字段、字段类型、签名算法和失败关闭
语义不能变化。
