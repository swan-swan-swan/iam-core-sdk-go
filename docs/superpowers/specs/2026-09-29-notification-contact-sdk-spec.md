# IAM Core SDK 人员目录与通知资料客户端规格

## 目标

在 `iam-core-sdk-go` 的 `management` 边界增加最小人员目录与通知目的地批量解析客户端。业务后端通过调用方注入的 `core.TokenSource` 查询明确 IAM 用户及其所需通知渠道；SDK 不获取 Token、不保存联系方式，也不承担飞书同步或管理员资料维护。

## 已冻结的服务端依赖

服务端 `GOAL-20260925-002` 已完成并在本地 Kubernetes 验收。SDK 只消费以下既有 HTTP 合同，不修改服务端：

| 能力 | Method 与 Path | 权限 |
| --- | --- | --- |
| 搜索活动用户 | `GET /api/v1/user-directory/users` | `iam:user_directory:select` |
| 批量校验用户 | `POST /api/v1/user-directory/users:batch-get` | `iam:user_directory:select` |
| 批量解析通知目的地 | `POST /api/v1/notification-contacts:batch-resolve` | `iam:notification_contact:select` |

## 人员目录客户端

- 新建 `management/userdirectory`，公开 `New(transport)`、`Search(ctx, query, limit)`、`BatchGet(ctx, subjectIDs)`。
- 搜索条件最长 128 个字符，limit 取值为 1–50；结果只包含 `subject_id`、`username`、`display_name`。
- 批量校验一次最多 100 个明确 subject，去重后保持首次出现顺序。
- 批量结果区分 `active`、`inactive`、`not_found`；非活动和不存在用户不得被伪装成活动用户。
- 公开模型不得包含账号邮箱、手机号、角色、部门、用户组或 Service Account 字段。

## 通知资料客户端

- 新建 `management/notificationcontacts`，公开 `New(transport)` 与 `BatchResolve(ctx, input)`。
- `BatchResolveInput` 一次最多包含 100 个明确 subject；重复 subject 去重并保持首次出现顺序。
- 渠道只允许 `email`、`sms`、`feishu_app`，未知渠道在发送请求前失败。
- 每个结果保留 `subject_id` 和 `status`。邮件与短信目的地以 `available/value` 表达；飞书应用消息以 `available/tenant_key/app_id/open_id` 表达。
- 活动用户缺少某一目的地时，该渠道返回不可用，不影响同一用户其他渠道，也不把用户整体判为不存在。
- SDK 不缓存响应、不重试业务请求、不解析部门/角色/标签/用户组，也不根据手机号或显示名推断飞书身份。

## Transport 与安全边界

- 两个领域包复用现有 `management/client.Transport`、`management.Metadata`、错误解码和 Observer。
- 调用方负责提供机器 Access Token；SDK 不接收 Client Secret，不调用 Token Endpoint，不持久化或刷新 Token。
- HTTP 401、403、5xx、无效 JSON、取消请求和 Observer 不得泄露 Authorization、手机号、邮箱、飞书 open_id 或完整响应正文。
- 调用方法不得修改调用方传入的 slice 或结构体。
- 合同 fixture 必须登记且只登记本 Goal 的三个新端点，并保持现有依赖方向。

## 验收基线

1. 搜索、批量用户校验和通知目的地解析使用精确 Method/Path，并返回现有 `management.Metadata`。
2. 输入边界、去重顺序、状态语义与渠道枚举均由测试覆盖。
3. 公开目录模型不包含敏感联系方式或组织解析字段。
4. 敏感值不会进入错误、Observer、日志或测试失败输出。
5. 全仓测试、race、vet、示例构建和差异检查通过。

## 非目标

- 不实现管理员通知资料维护、飞书同步或人工绑定。
- 不实现 Client Credentials Token 获取、缓存或刷新。
- 不发布新 SDK 版本、不创建 tag、不修改服务端或 IAM Web。
- 不增加部门、角色、标签、用户组或 Service Account 接收人解析。
