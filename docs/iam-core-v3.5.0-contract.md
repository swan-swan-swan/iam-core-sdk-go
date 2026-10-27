# IAM Core SDK v3.5.0 契约

根模块继续 github.com/swan-swan-swan/iam-core-sdk-go/v3，最低 Go 1.24；发布一个根标签 v3.5.0。

## Catalog 基础设施认证

Config.Credentials 接收 RegistrarCredentialSource，每次 Sync/HeartbeatOnce 重新读取 RegistrarCredentials{ClientID, ClientSecret}。ClientID 必须为非空前缀加 -catalog-registrar，客户端通过 HTTPS Basic 调用既有 PUT /api/v1/http-resource-catalog/registration 与 POST /registration/heartbeat，不换取或缓存 token。认证器在 IAM Core 校验 registrar 模式、有效凭据和 Application/service 绑定，Registrar 与业务启停独立。

Config.Tokens 已弃用，仅保留旧服务端显式兼容，下一主版本移除；与 Credentials 不能同时配置，不发生失败后回退。其余 Runtime/BFF/PDP/Management 的凭据契约不变。

## 目录及错误

Manifest schema_version 保持字符串 3；API 仅含 Name/Method/RouteTemplate/Action。部署代次与 hash 校验、409 停止旧实例续约机制不变。非成功响应可返回 HTTP 数字状态，不包含远端正文、Secret 或 Token；凭据源错误不透传。HTTP Client 禁止重定向、清除 Cookie Jar，保留超时及响应体限制。

## 升级

宿主改用 Credentials，移除自建 Catalog 机器令牌缓存。先完成 IAM Core 新协议版本与宿主协调发布，再切换认证；新 IAM Core 不接受旧 Catalog Bearer。源码新增字段不删除旧 Tokens 字段，以保留旧调用方编译兼容。
