# IAM Core Go SDK

- 开始任务前读取根 `SPEC.md`、本文件和相关 package 的 `README.md`；公开 API 变更同时更新兼容矩阵与版本契约。
- 最低 Go 版本为 1.24，仓库保持单一根 Module。`runtime/*` 面向业务请求链路，`management/*` 仅面向受控管理调用，两者不得相互渗透。
- Runtime Client 不获取、持久化或记录 Token；调用方必须通过 `core.TokenSource` 注入当前凭据。HTTP Client 必须禁止重定向、清除 Cookie Jar、限制响应体和总超时。
- 新增行为严格执行 RED/GREEN/REFACTOR；测试优先验证公开协议、真实序列化和安全边界，不断言 mock 自身。
- 新增公开声明使用中文 `//` 注释；错误、日志和 Observer 不得包含 Token、Secret、Cookie、Session ID、完整查询串或完整响应正文。
- 版本遵循语义化版本。发布前运行 `go test ./... -count=1`、`go test -race ./... -count=1`、`go vet ./...` 和 `go build ./examples/...`；本地开发任务不得自行创建或推送 tag。
- 只提交当前任务文件，保留工作区中与任务无关的用户改动。
