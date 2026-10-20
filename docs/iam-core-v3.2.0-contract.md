# IAM Core SDK v3.2.0 通知资料契约

本版本延续 [v3.1.0 机器身份契约](iam-core-v3.1.0-contract.md)和
[v3.0.0 业务授权契约](iam-core-v3.0.0-contract.md)，新增只供受控服务调用的最小用户目录与通知资料
Management Client。

## 最小用户目录

`management/userdirectory` 支持搜索活动 IAM 用户和批量校验明确的用户 subject。响应只包含稳定
subject、用户名、显示名称和活动状态，不返回邮箱、手机号、部门、角色、标签、用户组或 Service
Account。调用方不得用显示名称推断稳定身份。

## 通知资料解析

`management/notificationcontacts.BatchResolve` 接收一至一百个明确 IAM subject，以及实际通知任务
选择的 `email|sms|feishu_app` 渠道。结果逐 subject 区分：

- `active`：活动用户；所选渠道分别返回 `available=true|false`；
- `inactive`：用户存在但已停用；
- `not_found`：subject 不存在。

活动用户缺少某个渠道的资料不会阻断其他渠道。邮箱和手机号只在请求对应渠道时返回。飞书结果必须
同时包含租户、应用和该应用范围的 `open_id`；SDK 不调用飞书通讯录，不按显示名称或手机号临时解析
`open_id`。

## 凭据和安全边界

两个 Client 复用 `management/client.Transport`，由调用方注入机器 `TokenSource`。SDK 不接收 Client
Secret，不获取、刷新或缓存 Access Token，不缓存联系人，也不自动重试。生产 Base URL 必须使用
HTTPS；仅 loopback 测试允许 HTTP。Token、Secret、完整响应正文以及邮箱、手机号、飞书标识不得进入
错误、Observer 或失败断言输出。

通知资料不是第二套用户主数据。SDK 不提供部门、角色、标签或用户组接收人解析，也不承担业务系统的
通知对象选择。
