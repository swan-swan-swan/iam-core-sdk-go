# v3.6.0：服务账号直接 API Key

服务账号业务调用使用 `Authorization: ApiKey iak_<ULID>.<base64url-32-bytes>`。Key 由 IAM 控制台创建，仅返回一次明文；列表只返回公开 ID、名称、有效期和撤销状态。SDK 不创建、持久化或记录 Key。

## Runtime

在既有 `httpauthz.Config` 中显式注入 `APIKeyAuthenticator: pdp` 和 `APIKeyAuthorizer: pdp`，两者必须同时提供。`PDPClient` 实现这两个接口；保留自己的 Catalog 就绪包装器时，包装器必须转发相应方法并执行同一就绪检查。

`Authenticate` 每次调用 `/authorization/v1/credentials/resolve` 在线解析身份；`Require` 在此基础上恰好调用一次既有 `/authorization/v1/decisions`。决策请求体仍是单一路由声明派生的四个字段，不允许调用方指定身份。Key 无 Token 交换、无身份或允许结果缓存；服务端每次决策重查有效期、撤销和应用归属。

`core.AuthContext` 新增 `AuthenticationMethod`、`CredentialOpenID`、`ApplicationOpenID`，程序身份不借用人员 ID 或 OAuth Client ID。人员 Bearer/Session 和 Registrar Basic 互相独立。存在人员 Session 与显式 Authorization 时拒绝混合凭据；网络失败、协议错误、重定向均失败关闭。

## Management

`management/client.Config` 在 `TokenSource` 和 `APIKeySource` 中恰好选择一个。`APIKeySource.APIKey(context.Context) (string,error)` 直接提供凭据，目录和通知联系人客户端复用该 Transport。不要把 API Key 填入 TokenSource；不要发送 Cookie。凭据源错误、HTTP 错误、Observer 和响应诊断不得回显原 Key。

## 协调迁移

先发布 SDK，再升级各消费仓源码。升级 IAM Server 前需要备份并执行独立 API Key DDL；维护窗口内升级 Server/Web、创建 Key、更新声明式 Secret、升级业务后端。新 Server 不签发或接受旧 Service Account client_credentials JWT；旧机器实现以 Deprecated/DO NOT DELETE 注释保存。交互 OIDC 和 Catalog Registrar Secret 不变，不将 API Key 用于浏览器登录或 Catalog 注册。

Key 只能访问所属 Application 中经角色策略授权的 API。所有入口支持的前提是各业务部署已升级且显式接线；单独发布 SDK 不代表旧部署已支持。撤销后不回退 Token；进行中的 Handler 不会被追溯中止。

原始 JWT 声明解析函数保留历史只读兼容；新服务器的认证与决策边界拒绝机器 Bearer。Manifest 固定 schema_version="3"，策略事实及编译器不变。
