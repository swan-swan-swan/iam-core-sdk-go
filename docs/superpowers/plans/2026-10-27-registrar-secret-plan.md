# Registrar Secret Catalog 实现计划

> 按用户批准在当前会话执行；四仓均使用 dev。

**Goal:** Catalog 同步及续约使用 Registrar Client Secret，移除 Service Account 前置。
**Architecture:** IAM 注册主体、SDK Basic 传输、Ops 配置注入分层；Manifest v3 及围栏保持。
**Tech Stack:** Go/Gin/GORM、React/TypeScript、GitHub、Docker/Harbor。
**Spec:** ../specs/2026-10-27-registrar-secret-design.md

## Global Constraints

- 仅定向单元测试与构建；不部署、不做浏览器/集群测试。
- 保护现有未提交文件，所有开发与最后工作区均为 dev。
- SDK 标签成功后才更新 Ops Gateway go.mod/go.sum。

- [ ] SDK：registry.go 新增 Credentials 源；client.go 同步/心跳同一 Basic；新增轮换、拒绝混合配置、错误脱敏用例；go test ./runtime/httpcatalog；发布 v3.5.0。
- [ ] IAM Server：DTO/model/repository 支持 registrar；handler/service 抽取凭据认证与版本化发布；保留审计；前向扩展 CHECK；增加定向用例并 go test ./internal/handlers ./internal/services ./internal/repositories。
- [ ] IAM Web：服务类型与 Registrar 创建表单、独立启停、隐藏 OAuth/Groups；定向 vitest 与 pnpm typecheck、build。
- [ ] Ops Gateway：go get v3.5.0；runtime.go 注入 Credentials，移除换令牌代码与相关旧用例；拆分 /livez 与就绪；go test ./internal/iam ./internal/config ./internal/observability/otel ./internal/routers，构建。
- [ ] 发布：各仓只提交任务文件、推送 dev、PR 合并 main、生成新 release tag；构建并推送 Harbor 新 tag 镜像；各仓回 dev，不部署。
