# IAM Core SDK v3.1.0 机器身份契约

本版本延续 [v3.0.0 业务授权契约](iam-core-v3.0.0-contract.md)的四字段 RouteSpec 和 Manifest v3。
新增 IAM Core Service Account 机器主体校验，Catalog 登记使用调用方注入的短期机器 Access Token。

## 机器主体

`core.AuthContext` 暴露已验证的 `SubjectType` 和 `AuthorizedParty`。机器 Access Token 的
`subject_type` 必须为 `service_account`，`sub` 必须是稳定的 `op_sa_` 公开 ID，`azp` 必须是
实际认证的机器 Client ID；缺失、未知或矛盾声明失败关闭。新用户 Token 的类型为 `user`；
升级前已签发且缺少类型声明的用户 Token 只在原有效期内兼容，不得被推断为机器主体。

## Catalog 机器凭据

`httpcatalog.Config` 要求 `Tokens core.TokenSource`。Registry 每次 `Sync` 向该接口获取当前
Access Token，并使用 `Authorization: Bearer <token>` 登记完整 Manifest。SDK 不接收 Client Secret，
不获取、不缓存、不刷新 Token，也不重试失败的同步。调用方在自己的 IAM 适配层通过 OAuth 2.0
`client_credentials` 获取并短期缓存机器 Token；Client 的固定 Audience 和 Service Account 授权
由 IAM Core 配置决定。

`v3.0.0` 的 `httpcatalog.Config.ClientID` 和 `ClientSecret` 已移除，旧代码必须改用 `Tokens`。
IAM Core 需要启用机器 Client、Service Account 和按 `Application + service` 隔离的 Catalog
登记，旧的 Registrar Basic 同步方式不能直接用于本版本。

## MFA 上下文

已验证 ID Token 的 `auth_time` 与 `amr` 保存在 BFF Session 中；刷新缺少新 ID Token 时保留
旧值，有新 ID Token 时必须验证与原 Session 一致。缺少这些声明只表示认证方式未知，调用方
不得把它当作 MFA 已完成。
