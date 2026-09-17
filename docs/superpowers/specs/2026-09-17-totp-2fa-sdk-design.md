# IAM Core Go SDK MFA 认证上下文设计

## 冻结来源

本设计派生自 iam-core-server 的 docs/superpowers/specs/2026-09-17-totp-2fa-design.md，源提交为 2b1db1fcf053e22d21565f17859232b7e0a31604。

## 目标

SDK 安全解析并透传 IAM Core ID Token 的 auth_time 与 amr，让下游应用判断当前会话的认证方式，同时保持刷新和 BFF 会话中的原始认证上下文。

## 公共模型

runtime/core.AuthContext 新增：

- AuthTime time.Time
- AuthenticationMethods []string

AuthenticationMethods 是防御性复制的只读事实。SDK 不根据角色、scope 或当前时间推断 MFA，也不把未知 amr 值丢弃。应用可判断是否含 otp 或 recovery_code，但 SDK 不将 recovery_code 等同于 otp。

## Token 规则

- auth_time 必须是有效 OIDC NumericDate；存在 amr 时必须同时有有效 auth_time。
- amr 必须是非空字符串数组，去除重复项但保留首见顺序。
- IAM Core 预期值为 pwd、otp、recovery_code；SDK保留合法未知扩展值以兼容未来认证方式。
- Access Token 不承担 MFA 上下文权威；BFF callback 从已验证的 ID Token 取得 AuthTime/AuthenticationMethods，再与 access token 的主体、issuer、audience 绑定。
- 刷新响应含 ID Token 时验证并采用其认证上下文，但要求与当前会话一致；缺少新 ID Token 时保留原会话上下文。
- 刷新、序列化、clone 和 adapter 传递过程中不得静默清空、升级或降级认证上下文。

## 兼容性

新增字段对已有 Go 调用方保持源码兼容。没有 auth_time/amr 的旧 IAM Core token 仍可验证，并产生零值 AuthTime 与空 AuthenticationMethods；但不能被应用视为已完成 MFA。公共契约、README 和 COMPATIBILITY.md 必须说明该行为。

## 安全与测试

- token、验证码、恢复码和密钥不得进入日志或错误。
- 单元测试覆盖 malformed claim、合法扩展值、防御性复制、callback 取 ID Token 上下文、refresh 保留/一致性拒绝。
- session conformance suite 覆盖内存与 Redis adapter 的往返保存。
- testkit issuer 可以显式签发 auth_time/amr，默认行为保持现有测试兼容。
