# IAM Core SDK v3.4.0 HTTP Catalog 部署代次契约

`runtime/httpcatalog.Config.DeploymentGeneration` 是宿主为每个 `(application, service)` 身份
分配的 `uint64` 代次。零值也会作为 `deployment_generation: 0` 显式发送。CI 或 Helm 必须使
每次内容变更、滚动部署和回滚使用更高代次；`release` 只是展示信息，不参与比较或摘要。

启动时先用封闭的 RouteSpec Registry 执行完整 `Sync`。Manifest 保持 `schema_version: "3"`，
路由只包含 `name`、`method`、`route_template`、`action`。`manifest_hash` 是上述协议版本、
Application、Service 和按 Route Name 排序路由的固定字段顺序 JSON 的 SHA-256，
排除 release、deployment_generation 和传输顺序。SDK 校验成功响应中的
`application`、`deployment_generation`、`manifest_hash`、`catalog_hash`，
并保存服务端已发布的两个 hash；`catalog_hash` 是另一独立的目录投影版本。

成功 Sync 后，`HeartbeatOnce` 重新计算本地 Manifest 摘要，发送
`deployment_generation`、`manifest_hash`、`catalog_hash`。每个请求重新读取
`core.TokenSource`，不会在 Registry 中保存机器令牌。服务端成功响应还包含 `heartbeat_at`。
本地 Manifest 变化时停止续约，返回 `ErrManifestChanged`；宿主须用新代次创建 Registry 并
重新完整 Sync。低代次或同代次不同内容返回 `40901`，其 `data.reason_code` 为
`catalog_generation_conflict`；SDK 返回 `ErrGenerationConflict`，保持不健康，绝不自动 Sync。
`RunHeartbeat` 在未成功 Sync 时也不发起注册。

其他暂时失败由 `RunHeartbeat` 最多尝试三次，每次仍获取当前 Token，并遵守宿主 context。
错误和 Observer 只暴露非敏感操作结果，不包含凭据、Cookie 或完整响应正文。新版 Server 应先
上线并确认部署代次栅栏；在其接受新版代次前，所有旧 SDK 副本的冲突自动重注册行为必须停止。
