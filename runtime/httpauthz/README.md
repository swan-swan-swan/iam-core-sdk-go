
## 服务账号 API Key（v3.6.0）

将同一个 `PDPClient` 注入 `Config.APIKeyAuthenticator` 与 `Config.APIKeyAuthorizer`，才能接受 `Authorization: ApiKey …`。`Authenticate` 在线 resolve 身份；`Require` 另执行一次路由 PDP。凭据和允许结果不缓存、不换取 Token。自有就绪包装器需要实现并转发两个接口，不能绕过就绪保护。参阅 `docs/iam-core-v3.6.0-contract.md`。
