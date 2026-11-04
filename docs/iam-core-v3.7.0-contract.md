# IAM Core SDK v3.7.0 无限期凭据契约

在 v3.6.0 的 ApiKey 在线解析/PDP 上增加显式无限期：IAM 返回 never_expires:true 且 expires_at:null。必须同时存在；缺失到期信息、null 标志、无限期附带日期等矛盾输入失败关闭。有限期仍要求非零未来时间，兼容无 never_expires 字段的旧 IAM 响应。

core.AuthContext.NeverExpires 仅用于已在线确认的 API Key。ExpiresAt 在无限期时为零值，不能据此推断用户 JWT/Session 无限期。每次请求继续 resolve/PDP，无身份或 Allow 缓存；撤销、主体停用和策略拒绝保持在线生效。

先升级 SDK 消费者才能使用无限期 Key；旧 v3.6.0 消费者将拒绝此类凭据。新 IAM 对有限期响应省略 false 标志，不改变旧响应字段。Registrar Basic、Manifest v3、人员登录和 Management 直传 Key 无变更。
