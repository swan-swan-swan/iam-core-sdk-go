# IAM Core SDK v3.0.0 业务授权契约

## 范围

v3 保留 Runtime、Management、OIDC/BFF、HTTP PDP、Gin 与 Redis Adapter 的既有安全边界，
破坏性变更只针对业务权限命名、RouteSpec 与 HTTP Catalog Manifest。

## MFA 认证上下文

已验证 ID Token 的 `auth_time` 与 `amr` 分别映射为 `core.AuthContext.AuthTime` 和
`AuthenticationMethods`。`auth_time` 必须是合法 OIDC NumericDate；`amr` 必须是至少包含一个
非空字符串的数组，并要求同时存在合法 `auth_time`。SDK 按首见顺序去重，保留 `pwd`、`otp`、
`recovery_code` 以及合法未知扩展值。

BFF callback 使用 Access Token 提供授权事实，使用 ID Token 提供 MFA 认证上下文。刷新未返回新
ID Token 时继承当前 Session 的认证上下文；返回新 ID Token 时必须完整验证，且时间与方法列表均
与当前 Session 一致，否则失败关闭并保持原 Session 不变。刷新不得把新增方法当作带内 MFA 升级。
内存与 Redis Session adapter 必须无损保存字段并防止切片别名。

旧服务端省略两个 claim 时仍兼容：`AuthTime` 为零值，`AuthenticationMethods` 为空。应用必须把该
状态解释为“MFA 未被证明”，分别判断 `otp` 与 `recovery_code`，不得从角色、scope 或当前时间推断
MFA，也不得把恢复码等同于 OTP。Token、验证码、恢复码和密钥不得进入日志、错误或 Observer。

## 单一声明

业务服务必须为每条受保护 API 创建一次 `httpauthz.RouteSpec`，字段仅包含：

- `Name`：稳定 Route Name；
- `Method`：标准大写 HTTP Method；
- `RouteTemplate`：框架使用的绝对路径模板；
- `Action`：稳定业务能力。

同一个声明同时驱动框架路由注册、PDP 保护和 Catalog 注册。YAML/values 只保存连接与部署配置，
不得维护 Action 到 HTTP API 的第二份映射。一个 Action 可以对应多个 API，每条 API 使用独立 Route Name。

## 命名与派生

Action 格式为 `<server>:<domain>:<verb>`。server 是小写字母开头的小写字母数字 token。
保留 server `iam` 使用 lower-snake domain，例如 `iam:oidc_client:select`；其他业务 server 使用
lower-kebab domain，例如 `opsgw:iam-core:access`，不接受下划线或旧 `00/01` 转义名称。

Route Name 至少三段点分，每段为 lower-kebab，总长不超过 64，例如
`portal.app.iam-core.open`。业务 Canonical Resource 直接派生为
`http:opsgw:portal.app.iam-core.open`。IAM 内部 Resource 继续使用既有 lower-snake 坐标。

## Manifest v3

Catalog 注册固定发送字符串版本 `"3"`：

```json
{
  "schema_version": "3",
  "application": "opsgw",
  "service": "ops-gateway",
  "release": "dev",
  "routes": [{
    "name": "portal.app.iam-core.open",
    "method": "GET",
    "route_template": "/api/v1/apps/:id/open",
    "action": "opsgw:iam-core:access"
  }]
}
```

协议不接受调用方提供 `resource_server` 或 `resource`。SDK 与 IAM Core 必须分别从 Action 和 Route
Name 重算相同坐标，防止路由保护与 Catalog 注册漂移。Manifest v2 调用方必须协调升级，不保留永久双轨。
