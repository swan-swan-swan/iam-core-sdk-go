# IAM Core Go SDK

- 开始任务前读取根 `SPEC.md`、本文件和相关 package 的 `README.md`；公开 API 变更同时更新兼容矩阵与版本契约。
- 最低 Go 版本为 1.24，仓库保持单一根 Module。`runtime/*` 面向业务请求链路，`management/*` 仅面向受控管理调用，两者不得相互渗透。
- Runtime Client 不获取、持久化或记录 Token；调用方必须通过 `core.TokenSource` 注入当前凭据。HTTP Client 必须禁止重定向、清除 Cookie Jar、限制响应体和总超时。
- 新增行为严格执行 RED/GREEN/REFACTOR；测试优先验证公开协议、真实序列化和安全边界，不断言 mock 自身。
- 新增公开声明使用中文 `//` 注释；错误、日志和 Observer 不得包含 Token、Secret、Cookie、Session ID、完整查询串或完整响应正文。
- 版本遵循语义化版本。发布前运行 `go test ./... -count=1`、`go test -race ./... -count=1`、`go vet ./...` 和 `go build ./examples/...`；本地开发任务不得自行创建或推送 tag。
- 只提交当前任务文件，保留工作区中与任务无关的用户改动。
- 业务授权 v3 契约随 SDK v3.0.0 发布；Manifest v2 调用方在协调窗口迁移，不保留永久双轨。
- v3 的根 module 固定为 `github.com/swan-swan-swan/iam-core-sdk-go/v3`；生产、测试和示例统一使用 `/v3` import，不增加旧路径兼容 module 或 replace。现有 integration 仅是非发布测试 module。
- 公共命名必须复用 `runtime/authzcontract`：Action 为三段 `<server>:<domain>:<verb>`，总长不超过 64，不得 trim、lowercase 或编码转换。保留 server `iam` 使用 lower-snake domain；其他业务 server 使用 lower-kebab domain，并拒绝旧 `00/01` 转义名称。
- Action 动词仅允许 access、discover、select、create、update、delete、execute、preview、publish、approve、bind、revoke、rotate、reveal、export、import；读取不使用 list/get/read/view。
- Route Name 至少三段点分、每段 lower-kebab、总长不超过 64；业务 Canonical Resource 固定为 `http:<server>:<route-name>`。IAM 内部既有 lower-snake Resource 仅由保留 profile 派生。Route Template 必须是无 scheme/host/query/fragment 的绝对路径。
- 使用 `NewRouteSpec` 构造只包含 Name、Method、RouteTemplate、Action 的单一声明，由应用统一包装器完成框架路由注册、PDP 保护与 Registry 登记；禁止业务层分离维护声明，禁止在 YAML/values 写 Action 到 HTTP API 的第二份映射。
- 一个 Action 可对应多条逻辑路由；每条 API 的 Route Name 唯一且稳定，Route Template 可以变化。Manifest 固定发送 schema_version 字符串 "3"，route JSON 不包含 resource_server 或 resource。
- 授权事实关系是 `User -> Role <- policy_document_bindings -> Policy Document`；Application 只是 OIDC Client、HTTP Catalog 与 Policy Document 的归属边界，不是用户会员关系。`policy_compiled_rules` 与 Casbin `p` 都是 IAM Core 单一编译器的派生产物，SDK 和业务平台不得直接维护。
