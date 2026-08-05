# Compatibility

| SDK | Module | IAM Core contract | Go | 能力 |
| --- | --- | --- | --- | --- |
| v0.1.x | `github.com/swan-swan-swan/iam-core-client-sdk-go` | v1.7.1 only | 1.24+ | 历史根 facade |
| v0.2.x | `github.com/swan-swan-swan/iam-core-client-sdk-go` | IAM Core v1.8.1 | 1.24+ | Runtime only |
| v0.3.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.8.1 | 1.24+ | Runtime + approved platform-integration Management |
| v0.4.x | `github.com/swan-swan-swan/iam-core-sdk-go` | IAM Core v1.8.1 | 1.24+ | Single-Module Runtime + Management + Gin/Redis Adapter |

`v0.3.x` 不与 `v0.2.x` 源码兼容，也没有 deprecated wrapper；消费项目必须按迁移指南更换
Module 和 import。Runtime 延续 PKCE S256、Client groups、真实 granted scopes、Manifest、
单次 PDP 与 fail-closed 语义。Management 兼容范围是当前冻结的 42 个 IAM Core v1.8.1
管理端点。

`v0.3.x` 的 Gin 和 Redis Adapter 是嵌套 Module，需要目录前缀标签。`v0.4.x` 将全部公开 SDK
package 合并进根 Module，每个版本只使用一个 `v0.4.x` 根标签。integration 仍是仅用于仓库内
Docker conformance 的测试 Module，不发布也不创建标签。

RPC、users、organizations、global roles、Cloud Provider、audits、SPA/移动端 Token 存储、
其他框架 adapter 和自动 Provision 不在兼容承诺内。同一 IAM Core v1.8.x 可以增加不冲突的
JSON 元数据，但不能改变必需字段、类型、签名算法、revision/hash 或失败关闭语义。
