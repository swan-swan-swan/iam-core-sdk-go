# IAM Core Go Client SDK

本仓库提供面向 IAM Core v1.8.1 的 Go SDK。v0.2 是一次干净的破坏性重写，
不与 v0.1 源码兼容；请按[迁移指南](docs/migration-v0.1-to-v0.2.md)替换旧根 Client，
不要在旧接口外再包一层适配器。

当前只支持三个入口：服务端 Core/BFF 浏览器流程、基于 `net/http` 的 HTTP Resource
Server，以及可选的 Gin/Redis 独立 adapter。RPC 暂不支持，IAM 管理 API 不受支持；
SDK 不创建 Application、OIDC Client、资源目录、Policy 或审计对象。

最低 Go 版本为 1.24。协议和安全边界见
[IAM Core v1.8.1 契约](docs/iam-core-v1.8.1-contract.md)，版本矩阵见
[COMPATIBILITY.md](COMPATIBILITY.md)。

## 安装

根模块、Gin adapter 与 Redis adapter 是三个独立发布模块，按实际需要分别安装：

```bash
go get github.com/swan-swan-swan/iam-core-client-sdk-go@v0.2.0
go get github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/gin@v0.2.0
go get github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis@v0.2.0
```

根模块不会传递引入 Gin、go-redis、Docker、Moby 或 Testcontainers。Redis 和 Gin
adapter 也必须使用各自的 module tag，不能只安装根模块后假定它们存在。

## 入口一：Core/BFF 浏览器流程

完整可编译配置在 [`examples/bff`](examples/bff)。启动期先用 `core.New` 完成 Discovery，
再把 Runtime、Confidential Client 配置和 Session Backend 交给 `bff.New`：

```go
// Transport 留空会使用 net/http 默认的代理、连接池和 TLS 校验行为；
// Client Timeout 为所有 IAM 出站请求再加一层总时限。
iamHTTPClient := &http.Client{Timeout: 15 * time.Second}
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

runtime, err := core.New(ctx, core.Config{
    IssuerURL: issuerURL,
    Audiences: []string{clientID},
    HTTPClient: iamHTTPClient,
})
if err != nil {
    return err
}

backend := memory.New(memory.Options{}) // 只用于开发、测试和单进程
client, err := bff.New(bff.Config{
    Core:         runtime,
    ClientID:     clientID,
    ClientSecret: bff.SecretProviderFunc(func(context.Context) (string, error) {
        return clientSecret, nil
    }),
    RedirectURL: redirectURL,
    Scopes:      bff.DefaultScopes(),
	Backend:     backend,
	HTTPClient:  iamHTTPClient,
	TokenTimeout:      5 * time.Second,
	UserInfoTimeout:   5 * time.Second,
	EndSessionTimeout: 5 * time.Second,
    SessionCookie: http.Cookie{
        Name:        "__Host-example_session",
        Value:       "",
        Path:        "/",
        Domain:      "",
        HttpOnly:    true,
        Secure:      true,
        SameSite:    http.SameSiteLaxMode,
        MaxAge:      0,
        Expires:     time.Time{},
        Partitioned: false,
    },
    FlowCookie: http.Cookie{
        Name:        "__Host-example_flow",
        Value:       "",
        Path:        "/",
        Domain:      "",
        HttpOnly:    true,
        Secure:      true,
        SameSite:    http.SameSiteLaxMode,
        MaxAge:      0,
        Expires:     time.Time{},
        Partitioned: false,
    },
})
```

`TokenTimeout`、`UserInfoTimeout` 和 `EndSessionTimeout` 为零时各自使用 5 秒安全默认值；
负值会在构造期被拒绝，更短的调用方 context deadline 优先。SDK 会复制而不会修改注入的
`http.Client`，每个远端操作仍只尝试一次。

Cookie 名称没有平台级默认值，调用方必须显式提供。生产 Cookie 必须是 host-only
（`Domain` 留空）、`Path=/`、`HttpOnly`、`Secure`、`SameSite=Lax`，且名称使用
`__Host-` 前缀。示例中的 `__Host-example_session` 和 `__Host-example_flow` 分别承载
不透明 Session ID 与一次性 Flow ID；Token、Client Secret、PKCE verifier、nonce 和
state 均不进入 Cookie。示例的内部 HTTP listener 必须部署在可信 TLS 终止代理之后，
浏览器访问地址和注册的 redirect URL 必须是 HTTPS；不要为了本地直连而移除 Secure。

默认 scopes 恰好是 `openid profile email groups`。roles 不被接受，也不会作为
`groups` 的回退来源。返回身份只反映实际 granted scope；refresh 会原子替换 Token、
AuthContext、Groups 和 Granted Scopes，绝不回退到 requested scopes。

BFF 强制 PKCE S256，不支持 plain 或无 PKCE。state、nonce、精确 redirect URL、
return target、一次性 Flow 和 Cookie 边界都失败关闭。注册的 Handler 方法边界为：

```go
mux.Handle("GET /auth/login", client.LoginHandler())
mux.Handle("GET /auth/callback", client.CallbackHandler())
mux.Handle("GET /me", client.MeHandler())
mux.Handle("POST /auth/logout/local", client.LocalLogoutHandler())
mux.Handle("POST /auth/logout/central", client.CentralLogoutHandler())
```

本地登出只删除当前应用的服务端 Session 并清 Cookie，不声称退出其他平台。集中登出先完成
同样的本地删除，再调用 IAM Core end-session；远端失败不会恢复已经删除的本地 Session。

`bff/session/memory` 仅用于开发、测试和单进程。多副本生产部署应选用下文的 Redis
adapter 或实现完整 `bff/session.Backend` 契约。

## 入口二：HTTP Resource Server

可运行示例位于 [`examples/nethttp`](examples/nethttp)。路由必须先在 Manifest 中以稳定
Method、Resource Server code 和 Resource code 声明，再通过 Binder 完成唯一绑定和启动期
完整性校验：

```go
manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{
    Name: "list_orders", Method: http.MethodGet,
    ResourceServer: "orders_api", Resource: "orders",
}})
if err != nil {
    return err
}
binder := manifest.NewBinder()
route, err := binder.Bind("list_orders")
if err != nil {
    return err
}

pdp, err := httpauthz.NewPDPClient(httpauthz.PDPConfig{
    IssuerURL: issuerURL,
    HTTPClient: iamHTTPClient,
})
if err != nil {
    return err
}
service, err := httpauthz.New(httpauthz.Config{
    Verifier: runtime,
    PDP:      pdp,
    Sessions: client,
})
if err != nil {
    return err
}
protected, err := service.Require(route, http.HandlerFunc(listOrders))
if err != nil {
    return err
}
if err := binder.Validate(); err != nil {
    return err
}
```

未编译、未绑定、重复或未完全绑定的路由在启动期被拒绝。`Require` 先验证唯一 credential，
再对该请求执行恰好一次 PDP 调用（一次 PDP），只有合法 `allowed=true` 才执行下游 Handler。
deny、401、503、超时、网络错误、审计失败和畸形 envelope 全部失败关闭；不缓存 allow/deny，
不使用 groups 或本地规则降级。PDP 401 不会刷新凭证或重试 PDP。

上例通过 `Sessions: client` 配置了 BFF SessionResolver，因此同时出现 Bearer 与该 resolver
平台 Cookie 名称时会直接返回 credential conflict；即使 Cookie 值畸形也不先解析或比较
两份凭证内容。
Session resolver 只允许在 PDP 调用之前按本地过期窗口主动 refresh；PDP 返回后授权链路
不会再改变凭证。未配置 SessionResolver 的 Bearer-only Service 只解析 Authorization
Header，并忽略无关 Cookie；它不会凭 Cookie 自动启用 BFF Session 认证。

## 入口三：可选 Gin/Redis adapters

Gin adapter 是 `httpauthz.Service` 的薄适配层，不重新实现认证或授权：

```go
handler, err := ginadapter.Require(service, route)
router.GET("/orders", handler, listOrders)
```

示例位于 [`adapters/gin/example`](adapters/gin/example)，必须从
`github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/gin` 独立安装。

Redis adapter 实现 `bff/session.Backend`。它用 AES-256-GCM 加密完整 Flow/Session
payload，并使用 generation-bound、fenced、server-time leases 保护 refresh 原子提交。
这些存储细节不是公共 API；调用方只需构造 `Codec` 与 Backend，并自行管理
`redis.UniversalClient` 生命周期：

```go
import (
    "crypto/rand"

    redisadapter "github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis"
    "github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

codec, err := redisadapter.NewAESGCMCodec(
    redisadapter.Key{ID: keyID, Bytes: keyBytes},
    fallbackKeys,
)
if err != nil {
    return err
}
backend, err := redisadapter.New(redisClient, redisadapter.Options{
    Prefix: prefix,
    Codec:  codec,
    Clock:  core.RealClock{},
    Random: rand.Reader,
})
if err != nil {
    return err
}
```

以上片段位于一个返回 `error` 的构造函数中，并假定 `redisClient`、prefix 和 keyring 已从
受控配置构造。每个 AES key 必须是 32 字节；新写入只使用 primary，fallback 只用于解密轮换期旧数据。
密钥、Token、Cookie、Session/Flow ID 与原始 Redis 错误不得记录。示例位于
[`adapters/redis/example`](adapters/redis/example)，模块路径为
`github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis`。

## 安全与错误边界

- OIDC Access Token 与 ID Token 只接受 RS256，并验证 `kid/iss/aud/sub/jti/iat/exp`、
  可选 `nbf`，登录 ID Token 还验证 nonce。
- Discovery/JWKS 可以缓存；未知 `kid` 仅受控刷新。可信 JWKS 不能替代新的 PDP allow。
- Token、Refresh 和 PDP 都不做 SDK 级自动重试；Authorization Code 与 Refresh Token
  具有一次性或轮换语义。
- 错误与观测只公开稳定分类和低基数字段，不包含 Token、Authorization Header、
  Client Secret、授权码、PKCE verifier、Cookie、Session/Flow ID 或完整 URL query。
- SDK 不支持 no-PKCE、bare decision、dual-credential 或 legacy roles 兼容模式，也没有
  打开这些模式的配置开关。
