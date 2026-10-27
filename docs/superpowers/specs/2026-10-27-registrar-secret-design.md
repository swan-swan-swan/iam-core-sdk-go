# Registrar Secret Catalog 认证修复设计

用户已批准在各仓 dev 分支实施、定向单元测试及构建，沿用 GitHub dev→main。禁止集群部署和浏览器集成测试，不在 mini-pivot 添加测试脚本。

## 协议

Catalog PUT /registration、POST /registration/heartbeat、GET /registration/readiness 统一 HTTPS Basic Client Authentication，主体为 client_mode=registrar、confidential 的 *-catalog-registrar Client，固定 Application 和 catalog_service。凭据过期、撤销、Client 停用立即拒绝。Application 业务启停独立，不要求已有 Resource Server、Service Account、角色或策略；不接受 OAuth grant，不授予业务 API 权限。Manifest schema_version=3、代次围栏、hash 校验和审计保留。

## SDK 兼容

新增 Credentials 凭据源，读取当前 Registrar ClientID/ClientSecret，不换取或缓存 token。Tokens 保留为显式旧调用编译/旧服务端兼容入口并标记 Deprecated，不能同时配置、不自动回退；新 IAM 端点只接受 Registrar Basic。SDK 版本 v3.5.0。

## 交付

先 SDK 实现测试、提交 dev、自动合并 main 并确认 v3.5.0。Ops Gateway 随后正式 go get 该 tag，不使用 replace。IAM Server/Web、Ops Gateway 在 dev 开发，提交推送后通过 GitHub PR 合并 main，按现有 release tag 规则发布；按新 tag 构建推送 Harbor，最后保持四仓 dev。

## 边界

保留 IAM Server 工作区现有 service_account_service.go 和 service_account_service_test.go 未提交改动，不纳入本任务提交。结构扩展使用前向迁移，无业务种子及手写派生授权规则。
