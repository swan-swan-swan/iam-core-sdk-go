# Compatibility

| SDK | Module | IAM Core contract | Go | 能力 |
| --- | --- | --- | --- | --- |
| v0.1.x | `github.com/swan-swan-swan/iam-core-client-sdk-go` | v1.7.1 only | 1.24+ | 历史根 facade |
| v0.2.x | `github.com/swan-swan-swan/iam-core-client-sdk-go` | IAM Core v1.8.1 | 1.24+ | Runtime only |
| v0.3.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.8.1 | 1.24+ | Runtime + approved platform-integration Management |
| v0.4.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.8.1 | 1.24+ | Single-Module Runtime + Management + Gin/Redis Adapter |
| v0.5.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.8.1 | 1.24+ | Redis 6.2+ native Session operations |
| v0.6.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.8.1 + expected Action extension | 1.24+ | Canonical three-level expected Action drift validation |
| v0.7.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.8.1 OIDC security contraction | 1.24+ | PKCE、Client security 与 expected Action |
| v0.8.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core HTTP Catalog registration extension | 1.24+ | Action-aligned startup Catalog registration |
| v0.9.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.9.0 Application Handoff extension | 1.24+ | Request-scoped Application Handoff Runtime Client |

`v0.3.x` 不与 `v0.2.x` 源码兼容，也没有 deprecated wrapper；消费项目必须按迁移指南更换
Module 和 import。Runtime 延续 PKCE S256、Client groups、真实 granted scopes、Manifest、
单次 PDP 与 fail-closed 语义。Management 兼容范围是当前冻结的 42 个 IAM Core v1.8.1
管理端点。

`v0.3.x` 的 Gin 和 Redis Adapter 是嵌套 Module，需要目录前缀标签。`v0.4.x` 及后续版本将全部公开 SDK
package 合并进根 Module，每个版本只使用一个根标签。integration 仍是仅用于仓库内
Docker conformance 的测试 Module，不发布也不创建标签。

RPC、users、organizations、global roles、Cloud Provider、audits、SPA/移动端 Token 存储、
其他框架 adapter 和 Application/OIDC Client/Policy 自动 Provision 不在兼容承诺内。v0.8.x 仅承诺
通过 `runtime/httpcatalog` 自动同步代码拥有的 HTTP Catalog。v0.9.x 新增的
`runtime/applicationhandoff` 只签发当前用户的一次性登录交接，不管理目标系统权限。同一 IAM Core
兼容版本可以增加不冲突的 JSON 元数据，但不能改变必需字段、类型、签名算法、revision/hash 或失败关闭语义。
Handoff 的 `decisionId` 原样使用 PDP 返回的 `dec_` 标识，`correlationId` 使用独立的 `op_cor_` 标识；
消费方不得改写决策审计 ID。
