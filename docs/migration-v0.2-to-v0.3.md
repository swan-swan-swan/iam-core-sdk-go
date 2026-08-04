# 从 v0.2 迁移到 v0.3

`v0.3.0` 将仓库与根 Module 更名为 `iam-core-sdk-go`，把现有运行时能力迁入 `runtime/`，
并新增平台接入 Management Client。这是一次破坏性迁移；不存在 deprecated wrapper、转发
package 或旧 import 兼容层。

## 精确 import 映射

```text
github.com/swan-swan-swan/iam-core-client-sdk-go/core -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/core
github.com/swan-swan-swan/iam-core-client-sdk-go/bff -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff
github.com/swan-swan-swan/iam-core-client-sdk-go/httpauthz -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz
github.com/swan-swan-swan/iam-core-client-sdk-go/testkit -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/testkit
github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/gin -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin
github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis -> github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis
```

## 迁移顺序

1. 先移除旧 Module 及旧 Gin/Redis adapter 依赖。
2. 按上表一次性替换 import，不要保留两代 SDK 或自建 wrapper。
3. 加入新的根 Module，以及实际使用的独立 adapter Module。
4. 运行所有模块的普通测试、race、vet 和示例构建。

```bash
go get github.com/swan-swan-swan/iam-core-client-sdk-go@none
go get github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/gin@none
go get github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis@none

go get github.com/swan-swan-swan/iam-core-sdk-go@v0.3.0
go get github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin@v0.3.0
go get github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis@v0.3.0
go mod tidy
```

如果项目没有使用某个 adapter，不要添加对应依赖。仓库内 `go.work` 只服务联合开发和 CI，
消费项目不能依赖它提供的 replace。

## 行为兼容与新能力

Runtime 的 PKCE S256、JWT/JWKS、BFF Session、refresh fencing、Route Manifest、单次 PDP、
fail-closed、无授权缓存和无自动重试语义保持不变。目录和 Module 发生变化，安全语义没有提供
兼容开关。

Management 是新增的显式控制面能力。它由受控管理服务、专用 CLI 或 CI/CD 使用，调用方注入
高权限 TokenSource；management 不参与普通业务请求链路，也不在业务启动时自动 Provision。

Go 脚手架的 `auth.mode=none` 仍由调用方处理：不初始化 Runtime SDK，不建立本地账号体系，
不伪造 IAM 身份。SDK 不提供“鉴权失败后降级为无鉴权”的开关。

RPC 暂不支持。`users`、`organizations`、`global roles`、Cloud Provider 和 audits 也不属于
v0.3 Management 范围。

## 发布标签

三个 Module 使用不同的 Git tag，但版本都为 `v0.3.0`：

```text
v0.3.0
runtime/adapters/gin/v0.3.0
runtime/adapters/redis/v0.3.0
```

这些标签由发布 workflow 在同一个验证通过的 release merge commit 上原子创建和推送。
