# IAM Core v1.8.1 SDK Contract

本文冻结 IAM Core Go SDK v0.3 的 IAM Core v1.8.1 Runtime 契约与 Management 契约。
Runtime 覆盖 OIDC/BFF 和 HTTP PDP；Management 覆盖已批准的平台接入控制面。RPC 暂不支持。

## Discovery 与端点

| 能力 | 契约 |
| --- | --- |
| Discovery | `GET /.well-known/openid-configuration` |
| Authorization | `GET /oidc/authorize` |
| Token / Refresh | `POST /oidc/token` |
| UserInfo | `GET /oidc/userinfo` |
| JWKS | `GET /oidc/jwks` |
| End Session | `GET /oidc/logout` |
| HTTP PDP | `POST /authorization/v1/decisions` |

Discovery 必须返回与配置规范化后一致的 `issuer`，以及绝对的
`authorization_endpoint`、`token_endpoint`、`userinfo_endpoint`、`jwks_uri` 和
`end_session_endpoint`。`code_challenge_methods_supported` 必须包含 `S256`，
`id_token_signing_alg_values_supported` 必须包含 `RS256`。生产 issuer/endpoints 必须是
HTTPS；仅 loopback 测试边界允许 HTTP。

## Authorization Code + PKCE S256

Authorization Request 使用 `response_type=code`，并精确传递 `client_id`、`redirect_uri`、
实际 requested `scope`、`state`、`nonce`、`code_challenge` 与
`code_challenge_method=S256`。SDK 不支持 plain、缺失 PKCE 或 Public Client 模式。

默认 requested scopes 恰好为：

```text
openid profile email groups
```

`openid` 必需，`roles` 被拒绝。state、nonce、PKCE verifier、Client ID、精确 redirect
URL、return target、创建/过期时间保存在有界、一次性服务端 Flow 中。浏览器 Flow Cookie
只保存不透明 Flow ID。

Authorization Code exchange 向 `POST /oidc/token` 发送
`grant_type=authorization_code`、`code`、`redirect_uri`、`client_id`、`client_secret` 和
`code_verifier`。Refresh 发送 `grant_type=refresh_token`、`refresh_token`、`client_id` 与
`client_secret`。两者均不自动重试。

Token、UserInfo 与 End Session 各有独立有限操作超时，默认均为 5 秒；调用方可以配置正值，
更短的 caller context deadline 优先。SDK 不修改注入的 `http.Client`。

成功 Token Response 必须提供 `access_token`、`token_type=Bearer`、正数 `expires_in`；
首次 exchange 还必须提供 `id_token`，可提供 `refresh_token` 与 `scope`。Refresh 可轮换
refresh token、返回新 ID token 和缩减 scope。Token Response `scope` 优先；已验证 Access/
ID Token 中出现的 scope 必须与其他来源规范化后一致。没有可信 granted-scope 来源时失败，
绝不回退到 requested scopes。

OAuth 错误采用 `error`（可带 `error_description`，但 SDK 不向业务错误暴露远端详情）。
`invalid_grant`、`access_denied` 和 `temporarily_unavailable` 保留不同的安全分类；
`invalid_grant` 删除仍绑定同一 refresh generation 的本地 Session，网络或临时错误不提交
部分刷新状态。

## JWT、JWKS 与 UserInfo

Access Token 和 ID Token 只接受单一 RS256 签名及非空 `kid`。JWKS key 必须有效；`use`
若存在必须为 `sig`，`alg` 若存在必须为 `RS256`。验证覆盖 `sub`、`iss`、`aud`、`jti`、
`iat`、`exp`、可选 `nbf`；`iat` 不得晚于验证时刻。首次登录 ID Token 还必须精确匹配 nonce。Access Token 和
ID Token subject 必须一致，并且 audience 必须包含当前 Client ID。

`GET /oidc/userinfo` 使用一个 `Authorization: Bearer <access_token>`。响应必须包含非空
`sub`，且与已验证 Token subject 相同；`profile` 控制 `username/display_name`，`email`
控制 `email`，`groups` 控制规范化后的 `groups`。没有 mapping 时 groups 是空集合，不能
从 roles 或其他 Client 回填。

新 Session 的版本必须精确为 1，绝对过期与 idle 过期均为必填时效。完整 Session payload
包含 TokenSet、AuthContext、实际 Granted Scopes 和时效。Refresh
在 generation-bound fencing lease 下重新验证全部 Token/Claim，再以一次 CAS 原子替换；
lease 失效或 Session 版本变化时不得提交。

## End Session

集中登出先清 Cookie 并删除本地 Session，再向 `GET /oidc/logout` 发送
`id_token_hint`，有 Access Token 时同时发送 Bearer Authorization Header。任意远端失败
不得恢复本地 Session。本地登出不会调用该端点。

## HTTP PDP

调用方必须通过编译 Manifest 和 Binder 固定 Route。每个请求体只包含三个字段：

```json
{
  "resource_server": "orders_api",
  "resource": "orders",
  "http_method": "GET"
}
```

`POST /authorization/v1/decisions` 使用当前请求唯一 credential 的 Access Token。成功只接受
HTTP 200 且以下 IAM envelope：

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "decision_id": "dec_example",
    "allowed": true,
    "reason_code": "allowed"
  },
  "request_id": "req_optional",
  "trace_id": "trace_optional"
}
```

`code`、`message`、`data.decision_id`、`data.allowed` 与 `data.reason_code` 必需且类型固定；
`request_id`、`trace_id` 可选。同一 v1.8.x 可增加不冲突字段；重复 key、大小写冲突 key、
尾随 JSON、裸 decision、非零 code、缺失字段或非法字符串全部是协议错误。

每个通过本地认证的受保护请求恰好进行一次 PDP 调用：

| 结果 | SDK 行为 |
| --- | --- |
| 200 + `allowed=true` | 注入 Decision/AuthContext，执行一次 Handler |
| 200 + `allowed=false` | 403，Handler 不执行 |
| 400 或畸形响应 | 协议/配置失败，Handler 不执行 |
| 401 | 未认证；不 refresh、不重试 PDP |
| 503、超时、网络错误 | IAM unavailable；失败关闭 |

SDK 不缓存 allow/deny，不使用陈旧 allow、groups 或本地规则降级。配置 SessionResolver 后，
原始请求中出现该平台 Session Cookie 名称与 Bearer 即视为 credential conflict，即使 Cookie
值畸形也由 conflict 先行失败关闭。未配置
SessionResolver 的 Bearer-only Service 不检查浏览器 Session，只解析 Authorization Header
并忽略无关 Cookie。

## Management 契约

Management 冻结 42 个 IAM Core v1.8.1 HTTP 端点，分布在 `applications`、`oidcclients`、
`admission`、`groupmappings`、`catalog` 和 `policies` 六个领域。领域 Client 只依赖共享
`management/client` Transport，不相互依赖，也不依赖 Runtime。

共享 Client 只接受调用方注入的 `TokenSource`。每次调用读取一次 Access Token，最多发送
一次 HTTP 请求，不刷新 Token、不自动重试，也不自动生成幂等键。生产 Base URL 必须使用
HTTPS；仅 loopback 测试允许 HTTP。Client 复制注入的 `http.Client`、清除 Cookie Jar、
禁止重定向，并应用有限总超时。

所有响应都必须是统一 envelope，并包含 `code`、`message` 和 `data`。成功响应要求 HTTP 2xx、
`code=0` 和方法所需的数据；错误响应不解码领域结果。解码拒绝重复 JSON key、尾随 JSON、
类型错误、超限 body 和缺失必需字段，但允许同一 IAM Core v1.8.x 增加不冲突字段。
`request_id` 与 `trace_id` 仅作为低敏元数据返回。

revision/hash 是对应写方法的显式输入或输出。409 冲突保留服务端明确提供的最新 revision/hash
和脱敏影响摘要；SDK 不自动重新读取或再次提交。Catalog 发布是无请求体的单次 POST，
不从 Runtime Manifest 自动写入。Policy Document 作为完整对象传递，SDK 不实现本地编译器、
Casbin evaluator 或降级授权。

OIDC Credential Secret 只在创建响应建模为 `SensitiveString`。`String()`、`GoString()`、
默认格式化和 JSON 均输出 `[REDACTED]`；调用方必须显式调用 `Reveal()`。后续凭据查询不包含
Secret，Observer、错误和元数据也不会复制它。

Management 不包括 users、organizations、global roles、Cloud Provider、登录准入 audits 或
授权决策 audits；不提供跨领域一键 Provision，也不在普通业务请求链路或业务启动时写 IAM。

## 数据与可观测性边界

普通业务 Context 只公开强类型 AuthContext/Decision。Access Token 仅经受控 TokenSource
在请求生命周期内使用。Token、Authorization Header、Client Secret、OIDC Credential Secret、授权码、PKCE
verifier、Cookie、Session/Flow ID、nonce/state 与完整 URL query 不得进入错误、日志、
Hook、Trace baggage 或 metrics label。

HTTP Service 只记录稳定的 `httpauthz.service.authenticate` / `httpauthz.service.require`
操作、终态 outcome、credential source 与 duration；不会记录凭证、标识符、完整错误或 URL。

Management Observer 只公开稳定 operation、终态 outcome、status、IAM code、request ID、
trace ID 和 duration；每次调用最多产生一个终态事件。Observer panic 被隔离，不改变调用结果，
也不会触发额外 HTTP 请求。
