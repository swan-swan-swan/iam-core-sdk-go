# IAM Core SDK v3.0.0 业务授权契约

## 范围

v3 保留 Runtime、Management、OIDC/BFF、HTTP PDP、Gin 与 Redis Adapter 的既有安全边界，
破坏性变更只针对业务权限命名、RouteSpec 与 HTTP Catalog Manifest。

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
lower-kebab domain，例如 `opsws:iam-core:access`，不接受下划线或旧 `00/01` 转义名称。

Route Name 至少三段点分，每段为 lower-kebab，总长不超过 64，例如
`portal.app.iam-core.open`。业务 Canonical Resource 直接派生为
`http:opsws:portal.app.iam-core.open`。IAM 内部 Resource 继续使用既有 lower-snake 坐标。

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
    "action": "opsws:iam-core:access"
  }]
}
```

协议不接受调用方提供 `resource_server` 或 `resource`。SDK 与 IAM Core 必须分别从 Action 和 Route
Name 重算相同坐标，防止路由保护与 Catalog 注册漂移。Manifest v2 调用方必须协调升级，不保留永久双轨。
