# v0.3 → v0.4 迁移指南

`v0.4.0` 将 Runtime、Management、Gin Adapter 和 Redis Adapter 合并为单一根 Go Module：

```text
github.com/swan-swan-swan/iam-core-sdk-go
```

公开 package 的 import 路径没有变化。变化只涉及消费项目的 Module 依赖和版本标签。

## 升级步骤

先删除 v0.3 的两个嵌套 Adapter Module 依赖，再升级根 Module：

```bash
go get github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin@none
go get github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis@none
go get github.com/swan-swan-swan/iam-core-sdk-go@v0.4.0
go mod tidy
```

应用代码继续使用原 import 路径：

```go
import (
	ginadapter "github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin"
	redisadapter "github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis"
)
```

## 发布标签

从 v0.4 开始，每个 SDK 版本只创建一个根标签：

```text
v0.4.0
```

历史 `runtime/adapters/gin/v0.3.0` 和 `runtime/adapters/redis/v0.3.0` 标签继续保留，以保证
已有 v0.3 消费项目仍可解析原来的独立 Adapter Module。

## 依赖边界

根 Module 的依赖图从 v0.4 开始包含 Gin 和 go-redis。未 import Adapter package 的程序不会
编译或链接 Adapter。Docker、Moby 和 Testcontainers 仍只存在于不发布的 `integration` 测试
Module 中。
