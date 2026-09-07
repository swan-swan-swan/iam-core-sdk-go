# IAM Core Go SDK

- 开始任务前读取根 `SPEC.md`、本文件和相关 package 的 `README.md`；公开 API 变更同时更新兼容矩阵与版本契约。
- 最低 Go 版本为 1.24，仓库保持单一根 Module。`runtime/*` 面向业务请求链路，`management/*` 仅面向受控管理调用，两者不得相互渗透。
- Runtime Client 不获取、持久化或记录 Token；调用方必须通过 `core.TokenSource` 注入当前凭据。HTTP Client 必须禁止重定向、清除 Cookie Jar、限制响应体和总超时。
- 新增行为严格执行 RED/GREEN/REFACTOR；测试优先验证公开协议、真实序列化和安全边界，不断言 mock 自身。
- 新增公开声明使用中文 `//` 注释；错误、日志和 Observer 不得包含 Token、Secret、Cookie、Session ID、完整查询串或完整响应正文。
- 版本遵循语义化版本。发布前运行 `go test ./... -count=1`、`go test -race ./... -count=1`、`go vet ./...` 和 `go build ./examples/...`；本地开发任务不得自行创建或推送 tag。
- 只提交当前任务文件，保留工作区中与任务无关的用户改动。
- 统一授权契约计划随 SDK v2.0.0 发布；Manifest v1 调用方在协调窗口迁移，不保留永久双轨。
- v2 的根 module 固定为 `github.com/swan-swan-swan/iam-core-sdk-go/v2`；生产、测试和示例统一使用 `/v2` import，不增加旧路径兼容 module 或 replace。现有 integration 仅是非发布测试 module。
- 公共命名必须复用 runtime/authzcontract：Action 为三段 lower_snake，总长不超过 64，token 正则为 `^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`，不得 trim 或 lowercase。
- Action 动词仅允许 access、discover、select、create、update、delete、execute、preview、publish、approve、bind、revoke、rotate、reveal、export、import；读取不使用 list/get/read/view。
- Route Name 匹配 `^[a-z0-9]+(?:\.[a-z0-9]+){2,}$`，总长不超过 64；Resource 只能将 Route Name 的点替换为下划线，不能手写覆盖。Route Template 必须是无 scheme/host/query/fragment 的绝对路径。
- 使用 NewRouteSpec 构造单一完整声明，由应用统一包装器完成路由注册、PDP 保护与 Registry 登记；禁止业务层分离维护声明或在 YAML 写 route/action/resource 绑定。
- 一个 Action 可对应多条逻辑路由；动态路由可共享 Method + Route Template，但 Route Name 与派生 Resource 必须唯一。Manifest 固定发送 schema_version 为字符串 "2" 和完整 route_template。
