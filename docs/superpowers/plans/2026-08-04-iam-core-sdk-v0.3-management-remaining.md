# IAM Core Go SDK v0.3 Management Remaining Plan

**目标：** 在已完成 Runtime 迁移、42 端点 fixture 和 Management 共享安全类型的基础上，完成 Management Client、跨域安全收口与 v0.3 发布准备。

**执行约束：** 本计划只有以下 6 个顶层宏观任务。TDD、诊断、验证、修复、代码评审和提交都是所属任务的内部动作，不拆成额外任务；新发现工作必须并入现有任务。原细计划 `2026-08-04-iam-core-sdk-v0.3-management.md` 仅作为接口与端点技术参考，设计约束以 `docs/superpowers/specs/2026-08-04-iam-core-sdk-v0.3-runtime-management-design.md` 为准。

**已完成基线：** Runtime 迁移与最终审查已完成；`management/testdata/contract-v1.8.1.json` 已冻结 42 个端点；`management/client` 的 TokenSource、请求接口、错误、安全观测类型和单字段 `SensitiveString` 已完成。当前未提交的 `config.go`、`decode.go` 及其测试属于任务 1，保留并继续使用。

| 任务 | 宏观范围 | 完成标准 |
| --- | --- | --- |
| 1. 完成共享 Management Transport | 完成 Config、一次请求 Bearer Transport、严格 envelope 解码、元数据、Observer 隔离和所有安全边界；吸收当前已开始的 config/decode 工作。 | 每次调用只取一次 token、最多一次 HTTP 请求且不重试；URL、超时、redirect、Cookie、body 上限、重复 JSON key、错误映射和泄漏边界符合设计；`management/client` 的普通、race、fuzz、vet 与根回归通过。 |
| 2. 完成 Application 与 OIDC Client 管理 | 在 `management/applications` 和 `management/oidcclients` 实现 fixture 中的 13 个端点，覆盖 Application 生命周期、OIDC Client、安全配置和凭据管理。 | 方法、路径、query、JSON、revision 和 idempotency 与技术参考一致；Secret 仅在创建响应建模为显式可 Reveal 且默认脱敏的 `SensitiveString`；两个 domain 不互相依赖，测试与泄漏检查通过。 |
| 3. 完成 Admission 与 Group Mapping 管理 | 在 `management/admission` 和 `management/groupmappings` 实现 fixture 中的 12 个端点，区分 Application 层与 Client 层准入路径。 | revision、冲突数据、软删除、公开 ID 与 group 格式验证符合设计；不复制服务端角色存在性规则，不做自动编排；两个 domain 的普通、race 与 vet 通过。 |
| 4. 完成 Catalog 与 Policy 管理 | 在 `management/catalog` 和 `management/policies` 实现 fixture 中的 17 个端点。 | Catalog 发布保持无请求体单次 POST，不从 Runtime Manifest 自动写入；Policy JSON 作为不透明完整对象处理，不实现本地编译器、Casbin evaluator 或 RPC；revision/hash、冲突与防御性复制测试通过。 |
| 5. 收口 42 端点契约与跨域安全 | 将六个 domain 的公开操作与 fixture 做精确集合校验，并统一验证依赖、禁止范围和敏感信息泄漏。 | 42 个 method/path/operation 一一对应且无缺失、重复或额外项；不存在 users、organizations、global roles、Cloud Provider、audits、RPC 或 Runtime/adapter 重依赖；共享错误、Observer、fmt、JSON 和日志 marker 测试以及 Management 全量普通、race、vet 通过。 |
| 6. 完成交付与 v0.3 发布准备 | 补 Management 示例、迁移指南、README、兼容矩阵、Changelog、CI 和最终 release contract。 | `VERSION=0.3.0`；临时 prerelease guard 被最终三标签原子发布门禁替换；root/Gin/Redis/integration/示例/文档/禁用面验证通过；开发工作不创建或推送标签，GitHub 仓库改名与真实发布作为外部发布前置。 |
