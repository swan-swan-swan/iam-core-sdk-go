# IAM Core SDK v3.2.0 HTTP Catalog 心跳契约

`runtime/httpcatalog.Registry` 在完整 `Sync` 成功后保存服务端返回的当前目录 hash。
调用方须在宿主生命周期内运行 `RunHeartbeat(ctx)`；默认间隔 24 小时，可通过
`Config.HeartbeatInterval` 配置。`HeartbeatOnce(ctx)` 可供受控调度或检测使用。

续约调用 `POST /api/v1/http-resource-catalog/registration/heartbeat`，仅发送
`catalog_hash`，每次从 `core.TokenSource` 获取当前机器令牌。SDK 不缓存令牌，也不将其写入
日志或 Observer。服务端返回 409 时，SDK 以完整 Manifest 再次 `Sync`，让服务端重新确认
该服务的目录和自动策略。其他失败按 `HeartbeatRetryDelay` 进行最多三次有界退避尝试，
仍失败则返回通用错误，宿主负责后续重启与告警；失败的心跳不代表
目录已成功续约。旧实例的 hash 不得覆盖新版本目录。

`RunHeartbeat` 在 `ctx` 取消后退出。业务宿主应在启动完成注册后运行它，并在停机时取消
同一个生命周期 context。`Sync` 仍是完整覆盖，不提供逐条资源追加或策略覆盖入口。
