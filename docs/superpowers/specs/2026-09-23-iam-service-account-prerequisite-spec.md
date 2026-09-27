# IAM Core Service Account 前置规格

日期：2026-09-23

状态：服务端已实施，作为 `GOAL-20260927-001` 的 SDK 冻结规格来源。

## 本 Goal 范围

- 本 Goal 只在 `iam-core-sdk-go` 实现机器主体声明解析与注入式 `TokenSource` Catalog Bearer 登记。
- `iam-core-server` 的 Service Account、机器 OIDC Client、`client_credentials`、机器主体授权与审计，以及按 service 隔离的 HTTP Catalog 服务端合同已由 `GOAL-20260925-001` 交付。
- `iam-core-web` 的管理控制台、三个塔哨后端和统一管理后台由后续独立 Goal 实施；这些下游合同保留在本文中用于约束 SDK 输出，但不属于本 Goal 的完成条件。

## 目标

在 IAM Core 中增加面向服务间调用的机器身份能力，使塔哨平台在不恢复独立静态 Bearer Token 模式的前提下，通过 OAuth 2.0 `client_credentials` 完成 Alertmanager 接入、服务间调用、IAM 人员目录访问和多服务 HTTP Catalog 登记。

## 应用边界

- 整个塔哨平台在 IAM Core 中对应一个 Application。
- `beacon-admin-web` 使用交互式 OIDC Client，经 `authorization_code` 和 `refresh_token` 建立 BFF 会话。
- `beacon-server`、`notify-server`、`inbox-server` 在统一后台域名下共享该交互式 Client 和 Redis BFF Session；只有 `beacon-server` 对外暴露登录、回调与退出，三个服务分别解析同一用户 Session 并执行自己的 PDP。
- `beacon-server`、`notify-server`、`inbox-server` 分别使用独立的机器 OIDC Client 和 Service Account；不得共用 Client Secret。
- Alertmanager 使用专用机器 OIDC Client 和 Service Account 调用告警接入接口。
- Application 同时拥有 Resource Server、Audience、OIDC Client 和 Service Account。
- Service Account 属于 Application 的能力集，不进入用户、人员、部门或组织目录，也不能进行交互式登录。

## Application Capability

- 新增稳定能力键 `service_account`。
- `service_account` 依赖 `http_authorization`，不依赖 `oidc_login`。
- 未启用 `service_account` 的 Application 不得创建 Service Account、机器 OIDC Client 或签发 `client_credentials` Token。
- IAM 管理控制台只在能力启用后展示 Service Account 与机器 Client 管理入口。

## OIDC Client 隔离

OIDC Client 必须具有明确模式，并在创建后保持模式语义稳定：

| 模式 | 允许的 Grant | 主体 | Refresh Token | Redirect URI / PKCE |
| --- | --- | --- | --- | --- |
| `interactive` | `authorization_code`、`refresh_token` | IAM 用户 | 支持 | 按现有规则要求 |
| `machine` | `client_credentials` | 绑定的 Service Account | 不支持 | 不适用且不得配置 |

- 同一个 OIDC Client 不得同时用于用户登录和机器访问。
- 本期一个机器 OIDC Client 必须且只能绑定一个 Service Account。
- 一个 Service Account 可拥有多个机器 OIDC Client，以便按调用方或用途隔离凭据。
- 本期一个机器 OIDC Client 只绑定一个目标 Resource Server Audience；需要访问不同 Audience 时创建不同机器 Client，不允许调用方在 Token 请求中临时扩大 Audience。
- 用于 HTTP Catalog 登记的机器 Client 还可绑定一个稳定 `catalog_service`；登记时 Manifest 的 `service` 必须与该值完全一致。Alertmanager 等不登记 Catalog 的机器 Client 不配置该字段。
- Client Secret 仍属于 OIDC Client；一个 Client 支持多个并存的 Secret 版本，用于无停机轮换。
- Secret 只在创建或轮换时展示一次，持久化使用不可逆摘要；日志、审计详情和列表不得返回明文。

## Service Account 与授权

- Service Account 是独立机器主体，具有 Application 内稳定公开标识、名称、描述、启用状态和审计字段。
- Service Account 公开标识沿用 IAM Core 公开 ID 机制并使用 `op_sa_` 前缀；本期不提供删除，只支持启用和停用。
- Service Account 复用现有“角色 → Policy Document”授权体系，不新增直接权限清单。
- Service Account 与角色的绑定必须限制在同一个 Application 内，禁止跨 Application 绑定。
- 用户角色绑定与 Service Account 角色绑定分别持久化，现有用户目录和人员搜索不得混入机器主体。
- PDP 对用户主体和 Service Account 主体使用同一策略编译与判定入口，但主体解析、角色投影、决定审计、查询筛选和展示都必须显式保留主体类型，不能继续把机器主体写入 `user_open_id`。

## Token 合同

- Token Endpoint 接受 `grant_type=client_credentials`，机器 Client 使用现有 confidential Client 凭据校验机制。
- 机器 Client 不配置用户 OIDC Scope；`client_credentials` 请求不得携带非空 `scope`。机器调用的访问范围由固定 Audience、Service Account 角色与 Policy Document 决定。
- 成功响应只包含短期 Access Token、`token_type=Bearer` 和 `expires_in`，不得返回 ID Token 或 Refresh Token。
- Access Token 的 `sub` 是 Service Account 的稳定公开标识，`subject_type=service_account`，`azp` 或等价声明记录实际 Client ID，`aud` 固定为该机器 Client 预先绑定的 Resource Server Audience。
- 对机器 Token，PDP 以 `azp` 解析调用 Client，以 `aud` 解析目标 Resource Server；不得沿用当前用户 Token 的“以 Audience 反查交互式 Client”路径。用户 Token 的现有 Client/Audience 合同保持不变。
- IAM Core 后续签发的用户 Access Token 显式包含 `subject_type=user`；SDK 对升级前仍在 TTL 内且缺少该声明的既有用户 Token 保持短期兼容，任何非空未知类型都失败关闭，机器 Token 不允许省略该声明。
- 机器 Token 不包含用户资料、用户组或人员联系方式声明；角色或授权信息遵循 IAM Core 现有最小声明策略。
- Token TTL 使用机器 Client 独立配置，不沿用交互式 Client 的 ID Token 配置；默认 `300` 秒，允许范围为闭区间 `60`～`3600` 秒。
- 停用 Application、Service Account、机器 Client 或当前凭据后立即禁止签发新 Token；已经签发的短期 Access Token 继续有效至自然过期。
- 机器 Token 的 PDP 判定继续使用当前角色、Policy Document、Resource 与 Action 状态，但不因签发后发生的 Application、Service Account、Client 或凭据停用而把该 Token 提前视为失效；如需立即撤销属于后续独立能力，本期不实现。
- Service Account 和机器 Client 不支持 Refresh Token，因此系统恢复或 Token 到期后必须重新执行 `client_credentials`。

## 多服务 HTTP Catalog

- 塔哨多个后端服务共享一个 Application，但每个服务只拥有并提交自己的完整 HTTP 路由清单。
- Catalog 的替换边界调整为 `Application + service`；同一服务的新清单完整替换该服务旧清单，其他服务的路由保持不变。
- `service` 是必填稳定标识，塔哨使用 `beacon-server`、`notify-server`、`inbox-server`；服务标识变更按显式迁移处理，不通过提交空清单退役。
- Catalog Hash、容量统计、系统 Policy Document 协调和审计必须基于合并后的 Application 全量目录，同时保留每个服务的版本、更新时间和提交主体。
- Catalog 登记请求使用绑定 Service Account 的机器 Token；不得继续依赖前端凭据，也不得让多个服务上传彼此的路由。
- Catalog Handler 从已验证 Token 的 `azp` 读取机器 Client，并校验其 `catalog_service` 与 Manifest 完全一致；不得依赖 Client ID 命名后缀或 Service Account 显示名推断归属。
- 同一服务的滚动发布仍要求声明一致；不同服务并发登记不得互相删除目录项。

## 塔哨接入规则

- 浏览器侧保持现有 BFF 模式，不保存 Access Token、Client Secret 或 Service Account 凭据。
- IAM Core Go SDK 保持调用方注入凭据的既有边界：SDK 不获取、缓存、刷新或持久化机器 Token。
- 每个塔哨后端在自己的 `internal/iam` 适配层调用 Token Endpoint、短期缓存 Access Token，并实现 SDK 的 `core.TokenSource`；刷新采用单航班，失败不得覆盖仍有效的缓存 Token。
- SDK 负责验证并暴露 `subject_type`、`azp` 等机器主体声明，并让 HTTP Catalog 接受调用方注入的 `core.TokenSource` 后发送 Bearer Token。
- Alertmanager 使用 OAuth 2.0 客户端凭据访问 `POST /api/v1/integrations/alertmanager/events`；接口校验塔哨 Audience、Service Account 主体及精确 Action。
- `beacon-server` 查询 IAM 人员目录、`notify-server` 查询联系方式时，各自使用自己的 Service Account 权限，不冒用最终用户身份。
- Kafka 消息携带业务来源、租户隔离键和审计关联标识，但不把上游自报字段当作已经认证的 IAM 主体。

## 管理控制台

- Application 详情增加 Service Account 列表、创建、编辑、启停和角色绑定入口。
- 机器 OIDC Client 创建表单必须选择一个同 Application 的 Service Account，并固定显示仅支持 `client_credentials`。
- 交互式 Client 页面不展示 Service Account 绑定；机器 Client 页面不展示 Redirect URI、PKCE、前端退出或用户组映射配置。
- Secret 创建、轮换、撤销沿用现有一次性展示与审计交互。
- 塔哨管理后台不增加 Service Account 或 Client Secret 管理页面，这些能力统一在 IAM Core 管理控制台维护。

## 服务端管理 API

- `GET/POST /api/v1/applications/:application_open_id/service-accounts`
- `GET/PUT /api/v1/applications/:application_open_id/service-accounts/:service_account_open_id`
- `PUT /api/v1/applications/:application_open_id/service-accounts/:service_account_open_id/status`
- `PUT /api/v1/applications/:application_open_id/service-accounts/:service_account_open_id/roles`

查询使用 `iam:service_account:select`，创建使用 `iam:service_account:create`，资料和启停使用 `iam:service_account:update`，角色替换使用 `iam:service_account:bind`。路径中的 Application 与 Service Account、绑定角色必须属于同一 Application。

## 审计与安全

- Service Account 创建、更新、启停、角色绑定，机器 Client 创建、绑定、Secret 轮换/撤销，Token 签发失败和 Catalog 登记均写审计记录。
- 授权决定审计使用通用 `subject_type + subject_open_id` 标识用户或 Service Account，并额外保留机器 Client ID；查询接口和 IAM 控制台不得把 Service Account 链接到用户详情。
- 管理与签发审计记录包含 Application、Service Account、Client、操作主体、结果、时间和请求关联标识；不得记录 Secret 或完整 Token。
- Client、Service Account、角色、Audience 或 Application 不匹配时必须 fail closed。
- Token Endpoint 的客户端认证失败保持 OAuth 2.0 标准错误语义，不能暴露 Client、Service Account 或 Secret 是否存在。

## 非目标

- 不恢复独立静态 Bearer Token 鉴权模式。
- 不允许 Service Account 登录管理后台或出现在人员选择器中。
- 不实现 Service Account 的部门、用户组、手机号、邮箱或飞书身份资料。
- 不允许一个 Client 同时支持交互式与机器授权。
- 不提供长期不失效的机器 Token，也不提供机器 Refresh Token。
- 不在塔哨前端管理 IAM Client Secret。

## 本 Goal 验收基线

1. 未启用 `service_account` 能力的 Application 无法创建机器主体或使用 `client_credentials`。
2. 交互式 Client 请求 `client_credentials`、机器 Client 请求授权码或 Refresh Token 均返回 `unsupported_grant_type` 或等价的受控 OAuth 错误。
3. 机器 Client 只能为绑定且启用的 Service Account 获取短期 Access Token，响应不含 ID Token 和 Refresh Token。
4. 机器 Client 未显式设置 TTL 时使用 `300` 秒，低于 `60` 秒或高于 `3600` 秒的配置被拒绝，Token 响应的 `expires_in` 与实际签发期限一致。
5. Service Account 通过绑定角色获得精确 API 权限；解除角色后既有 Token 的后续 PDP 判定立即失去对应权限，停用主体后不再签发新 Token，但不提前撤销既有短期 Token。
6. 多个 Secret 可在轮换窗口内并存，撤销旧 Secret 后旧 Secret 不能再换取 Token，新 Secret 保持可用。
7. `beacon-server` 与 `notify-server` 分别登记自己的 Catalog 后，两者路由同时存在；任一服务更新清单不会删除另一服务路由。
8. Alertmanager 使用专用机器身份可以异步提交告警，无权限或 Audience 错误时请求在写入 Kafka 前被拒绝。
9. IAM 用户搜索只返回人员，Service Account 不会出现在值班成员或通知接收人选择结果中。
10. 用户和 Service Account 的授权决定均可按主体类型与主体公开 ID 查询，机器主体记录不依赖用户表且不会生成用户详情跳转。
11. 未配置 `catalog_service` 的机器 Client 不能登记 Catalog；已配置 Client 不能提交其他 service 的清单。

## 下游验收合同

- Beacon 浏览器构建产物、运行配置和日志中不得存在机器 Client Secret。
- IAM Core SDK 不提供 Client Secret 配置或 Token 获取缓存实现；塔哨后端注入 `core.TokenSource` 后，Catalog 使用 Bearer Token 登记。

以上两项由后续 SDK 和塔哨接入 Goal 验收，本 Goal 只保证对应服务端接口、声明和认证合同可供下游实现。
