# IAM Core Go Client SDK

`github.com/swan-swan-swan/iam-core-client-sdk-go` 为 Go Web/BFF 和 HTTP API
提供 OIDC 登录、服务端 Session、Bearer 认证及逐请求 PDP 权限决策。本文与示例使用
IAM Core Issuer `https://iam.wuhl-goose.top`；库本身要求显式配置 `IssuerURL`。最低
支持 Go 1.24。

## 十分钟 Quickstart

### 1. 准备 IAM Core 配置

开始编码前，在 IAM Core 中完成以下配置：

1. 创建 Application 和 Confidential OIDC Client，并安全保存 Client ID、Client Secret。
2. 注册业务回调地址，例如 `https://asset.example.com/auth/callback`。它必须与 SDK 的
   `RedirectURL` 完全一致。
3. 允许 `openid profile email roles` Scope；`openid` 是必需项，其余 Scope 决定可见的
   身份字段。
4. 在 Application 的资源目录中登记 Resource Server、Resource 和允许的 HTTP Method，
   例如 `asset-api`、`assets`、`GET`。

SDK 不会自动创建这些管理面对象。

### 2. 安装

```bash
go get github.com/swan-swan-swan/iam-core-client-sdk-go@v0.1.0
```

### 3. 配置 Redis 与 AES-256-GCM Session

生产或多副本部署应使用 Redis Backend。当前 AES 密钥必须是随机的 32 字节；以下命令
生成 base64 配置值，请放入 Secret Manager 或 Kubernetes Secret，不要提交到仓库：

```bash
openssl rand -base64 32
```

```go
package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "os"
    "time"

    goredis "github.com/redis/go-redis/v9"
    "github.com/swan-swan-swan/iam-core-client-sdk-go/session"
    redisstore "github.com/swan-swan-swan/iam-core-client-sdk-go/session/redis"
)

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func newSessionBackend() (*redisstore.Backend, goredis.UniversalClient, error) {
    key, err := base64.StdEncoding.DecodeString(os.Getenv("IAMCORE_SESSION_AES_KEY"))
    if err != nil || len(key) != 32 {
        return nil, nil, fmt.Errorf("IAMCORE_SESSION_AES_KEY must encode exactly 32 bytes")
    }
    codec, err := session.NewAESGCMCodec(
        session.Key{ID: "2026-07", Bytes: key},
        nil,
    )
    if err != nil {
        return nil, nil, err
    }
    redisClient := goredis.NewUniversalClient(&goredis.UniversalOptions{
        Addrs:    []string{os.Getenv("IAMCORE_REDIS_ADDR")},
        Username: os.Getenv("IAMCORE_REDIS_USERNAME"),
        Password: os.Getenv("IAMCORE_REDIS_PASSWORD"),
    })
    backend, err := redisstore.New(redisClient, redisstore.Options{
        Prefix: "iamcore",
        Codec:  codec,
        Clock:  wallClock{},
        Random: rand.Reader,
    })
    if err != nil {
        _ = redisClient.Close()
        return nil, nil, err
    }
    return backend, redisClient, nil
}
```

调用方负责在进程退出时关闭 `redis.UniversalClient`。`session/memory` 仅适用于测试、
开发和单进程：它不会在多个副本间共享 Session 或 Refresh Lock。

### 4. 构造根 Client

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

client, err := iamcore.New(ctx, iamcore.Config{
    IssuerURL:            "https://iam.wuhl-goose.top",
    ClientID:             os.Getenv("IAMCORE_CLIENT_ID"),
    ClientSecretProvider: iamcore.StaticSecret(os.Getenv("IAMCORE_CLIENT_SECRET")),
    RedirectURL:          "https://asset.example.com/auth/callback",
    Scopes:               []string{"openid", "profile", "email", "roles"},
    Session: iamcore.SessionConfig{
        Backend: redisBackend,
    },
})
if err != nil {
    return err
}
```

`iamcore.New` 会校验配置并执行 OIDC Discovery。默认超时分别是 Discovery/JWKS 5 秒、
Token/UserInfo 10 秒、PDP 3 秒、Refresh Lock 15 秒；调用方更早的 Context Deadline
优先。生产 Cookie 默认是 `__Host-iam_core_session`，并启用 `Secure`、`HttpOnly`、
`SameSite=Lax` 和 `Path=/`。

### 5. 注册登录、回调与登出

```go
mux := http.NewServeMux()
mux.Handle("/auth/login", client.LoginHandler())
mux.Handle("/auth/callback", client.CallbackHandler())
mux.Handle("/auth/logout", client.LogoutHandler())
```

浏览器访问 `/auth/login?return_to=%2Fprofile` 开始登录。`return_to` 默认只接受以一个
斜杠开头的站内相对地址；绝对地址必须预先配置到 `AllowedReturnToURLs`。回调会一次性
消费 state/nonce 登录事务，建立新 Session 后跳回已验证地址。登出先删除本地 Session，
再请求 IAM Core 远端登出；不会因远端错误恢复本地会话。

### 6. 从 Context 读取身份

```go
profile := client.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    identity, ok := iamcore.IdentityFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthenticated", http.StatusUnauthorized)
        return
    }
    _ = json.NewEncoder(w).Encode(identity)
}))
mux.Handle("/profile", profile)
```

还可使用 `CredentialSourceFromContext` 区分 Session/Bearer，或在授权 Handler 内通过
`DecisionFromContext` 获取 PDP 的 Decision ID、Reason Code、Request ID 和 Trace ID。
这些 Helper 返回防御性副本。

### 7. 显式声明资源权限

`net/http` 根 Client 的真实签名接收一个 `iamcore.Permission`；HTTP Method 自动取当前
请求，不能由业务方伪造：

```go
mux.Handle("/assets", client.RequirePermission(iamcore.Permission{
    ResourceServer: "asset-api",
    Resource:       "assets",
})(http.HandlerFunc(listAssets)))
```

Gin 适配器的签名是 `ginmw.RequirePermission(client, resourceServer, resource)`：

```go
router.GET(
    "/assets",
    ginmw.RequirePermission(client, "asset-api", "assets"),
    listAssets,
)
```

`RequirePermission` 已包含认证，不需要再叠加 `Authenticate`。它每次请求都会调用 PDP，
不缓存 allow/deny，并在 IAM Core、PDP、审计或响应协议异常时失败关闭。

### 8. Session Cookie 与 Bearer 行为

- Session Cookie 仅保存随机 Session ID；Token 和身份数据保存在后端并加密。
- `Authorization: Bearer <access_token>` 通过 UserInfo 在线验证，不创建 Session，也不会
  自动刷新。
- Cookie 和 Bearer 同时出现时，仅当 Bearer 与当前 Session Access Token 完全一致才接受；
  不一致返回 `401 credential_conflict`。
- Session Access Token 临近过期时在分布式锁保护下刷新。PDP 首次返回 401 时，Session
  最多强制刷新并重新决策一次；Bearer 不执行该恢复。
- SDK 不对 Token、Refresh、PDP 超时或 5xx 隐式重试。

### 9. Roles 不是授权依据

`identity.Roles` 只用于身份展示和非安全 UX。Access Token 不携带角色，角色变化也不能
替代资源策略。SDK 不提供本地角色授权；所有安全放行必须使用
`RequirePermission`/PDP。

### 10. v0.1 限制

- 仅支持 Authorization Code + Confidential Client；IAM Core 当前没有可依赖的 PKCE
  契约，因此 SDK 不提供 Public Client 或 PKCE。
- UserInfo 当前没有稳定的 organization Claim。未知字段可从 `Identity.ExtraClaims`
  读取，但不能把它当作已承诺的强类型组织模型。
- 不包含用户、角色、Application、资源目录、策略或审计管理 API。
- 不支持 SPA、移动端、CLI、Echo、Fiber，也不自动注册 IAM Core 配置。

### 11. 密钥轮换、TLS 与可观测性

Client Secret 应由实现 `iamcore.ClientSecretProvider` 的动态 Provider 从 Secret Manager
读取，以支持轮换；`iamcore.StaticSecret` 只适合固定生命周期的进程配置。Provider 不得
记录返回值。

AES Keyring 轮换时，把新密钥设为 primary，把仍可能存在于 Redis 的旧密钥放入
fallback：

```go
codec, err := session.NewAESGCMCodec(
    session.Key{ID: "2026-08", Bytes: newKey},
    []session.Key{{ID: "2026-07", Bytes: oldKey}},
)
```

新写入只使用 primary；fallback 仅用于解密。确认旧 Session/Flow 全部过期或已重写后，
才能移除旧密钥。Key ID 不是秘密，密钥字节本身不得进入日志、错误、指标或 Trace。

私有 CA 通过 `Config.HTTPClient` 注入自定义 `tls.Config.RootCAs`；SDK 不提供跳过证书
校验的配置。保留 TLS 验证与合理超时，例如：

```go
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.TLSClientConfig = &tls.Config{
    MinVersion: tls.VersionTLS12,
    RootCAs:    privateCAPool,
}
config.HTTPClient = &http.Client{
    Transport: transport,
    CheckRedirect: func(*http.Request, []*http.Request) error {
        return http.ErrUseLastResponse
    },
}
```

注入的 Client 会保留调用方定义的重定向行为；不要移除上述失败关闭策略，否则远端
重定向可能扩大凭证发送边界。

`Config.Hooks` 接受实现 `Observe(context.Context, iamcore.Observation)` 的 Hook，可桥接
Prometheus/OpenTelemetry。事件只包含低基数的 operation、outcome、credential source
和 duration；不要附加 Token、Cookie、Client Secret、授权码、Session ID 或完整身份。
SDK 会传播 `traceparent`、`tracestate` 与 `X-Request-ID`。

## 可运行示例

- `go run ./examples/nethttp`
- `go run ./examples/gin`
- `go run ./examples/redis`

示例通过环境变量读取配置，且不会输出 Secret。Redis 示例要求
`IAMCORE_SESSION_AES_KEY` 是 base64 编码的精确 32 字节密钥。版本支持范围见
[COMPATIBILITY.md](COMPATIBILITY.md)，版本变更见 [CHANGELOG.md](CHANGELOG.md)。
