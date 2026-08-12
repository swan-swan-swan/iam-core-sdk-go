# HTTP Authorization 三级 Action 漂移校验设计

## 状态

- 日期：2026-08-12
- 状态：已获用户批准
- 适用仓库：`iam-core-server`、`iam-core-sdk-go`、`ops-gateway-server`、`scaffolding-gin-go`、`scaffolding-saas-web`

## 目标

统一业务权限为三个小写段：`system:resource:action`。例如 Ops Gateway 管理入口为
`opsws:admin:access`，通用脚手架管理入口为 `app:admin:access`。

IAM Core 继续以服务端 HTTP Catalog 为唯一真实来源：

1. 调用方提交 `resource_server`、`resource`、`http_method` 和可选的 `expected_action`。
2. IAM Core 根据前三项从 Catalog 派生实际 Action。
3. 提供 `expected_action` 时，实际 Action 必须与它完全相等；不一致时拒绝。
4. 决策响应返回实际 `action`。
5. 新 SDK 对启用 Action 的 Route 再核对允许响应中的实际 Action。

调用方不能通过 `expected_action` 指定或覆盖服务端 Action。

## 协议兼容

- `expected_action` 是请求的可选字段，旧 SDK 请求继续有效。
- `action` 是响应 data 的新增字段，旧 SDK 已允许增量响应字段。
- 新 SDK 的 `RouteSpec.Action` 采用三级格式；迁移后的 Route 必须提供。
- 未迁移的 Route 可以暂时省略 Action，并保持 v0.5 行为。
- 允许结果若缺少 Action 或与 Route Action 不一致，新 SDK 以协议错误失败关闭。
- 拒绝结果不要求 Action 相等；拒绝本身已经失败关闭，并保留准确 reason code。

## 命名规则

- 格式：`^[a-z][a-z0-9]*(?::[a-z][a-z0-9]*){2}$`
- 恰好三个段，冒号是唯一分隔符。
- 不允许连字符、下划线、点、大小写字母或空白。
- IAM Core 不硬编码 `opsws`、`app` 或具体业务权限。

## IAM Core 行为

- 非法 `expected_action` 返回参数错误。
- Catalog 无匹配 Resource/Action 时保持现有拒绝原因。
- Catalog 派生 Action 与 `expected_action` 不一致时返回 `allowed=false`、
  `reason_code=action_mismatch`，审计记录实际 Action。
- Policy 仍基于 Catalog 映射和编译结果执行，不直接使用调用方字段。
- 响应 `action` 来自 Catalog 快照；无法派生时为空。

## SDK 行为

- `RouteSpec`、内部 `Route` 和决策请求增加 Action。
- Manifest 校验非空 Action 时必须满足三级格式。
- 请求字段名为 `expected_action`。
- `Decision` 增加服务端返回的实际 Action。
- 仅当决策允许且 Route 配置了 Action 时，Action 缺失或不一致返回协议错误。
- Method/Resource Server/Resource 的唯一性规则保持不变。

## 下游迁移

Ops Gateway：

```yaml
purpose: admin.access
routeName: admin.access
httpMethod: GET
resourceServer: opsws
resource: admin
action: opsws:admin:access
```

通用脚手架使用 `app:admin:access`。配置字段统一为 `action`，删除含义混淆的
`operation`。后端授权投影从绑定 Action 读取，前端环境变量保存同一值，测试保证两端一致。

## 发布顺序

1. 发布兼容旧请求的 IAM Core Server。
2. 发布新增 Action 能力的 Go SDK。
3. 下游升级 SDK 并迁移配置。
4. 在 IAM Core Catalog/Policy 中预配对应三级 Action 后启用新配置。

## 非目标

- 不允许客户端覆盖 Catalog Action。
- 不把用户名、角色名或管理员账号硬编码为权限判断。
- 不改变 OIDC、BFF Session 或 token 协议。
- 不自动写入 IAM Core Catalog/Policy 数据。
