# Compatibility

| SDK | Module | IAM Core contract | Go | 能力 |
| --- | --- | --- | --- | --- |
| v0.1.x | `github.com/swan-swan-swan/iam-core-client-sdk-go` | v1.7.1 only | 1.24+ | 历史根 facade |
| v0.2.x | `github.com/swan-swan-swan/iam-core-client-sdk-go` | IAM Core v1.8.1 | 1.24+ | Runtime only |
| v0.3.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.8.1 | 1.24+ | Runtime + approved platform-integration Management |

`v0.3.x` 不与 `v0.2.x` 源码兼容，也没有 deprecated wrapper；消费项目必须按迁移指南更换
Module 和 import。Runtime 延续 PKCE S256、Client groups、真实 granted scopes、Manifest、
单次 PDP 与 fail-closed 语义。Management 兼容范围是当前冻结的 42 个 IAM Core v1.8.1
管理端点。

根、Gin 和 Redis 分别使用 `v0.3.x`、`runtime/adapters/gin/v0.3.x` 和
`runtime/adapters/redis/v0.3.x` 标签。仓库内 `go.work` 只用于联合开发，不构成已发布 Module
的依赖。

RPC、users、organizations、global roles、Cloud Provider、audits、SPA/移动端 Token 存储、
其他框架 adapter 和自动 Provision 不在兼容承诺内。同一 IAM Core v1.8.x 可以增加不冲突的
JSON 元数据，但不能改变必需字段、类型、签名算法、revision/hash 或失败关闭语义。
