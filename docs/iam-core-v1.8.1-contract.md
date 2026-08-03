# IAM Core v1.8.1 Client Contract

本文冻结 IAM Core Go Client SDK v0.2 实际实现的 v1.8.1 HTTP 契约。它是客户端边界，
不是 IAM Core 管理面 API 清单。RPC 不在本 SDK v0.2 的支持范围内。

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
`iat`、`exp`、可选 `nbf`；首次登录 ID Token 还必须精确匹配 nonce。Access Token 和
ID Token subject 必须一致，并且 audience 必须包含当前 Client ID。

`GET /oidc/userinfo` 使用一个 `Authorization: Bearer <access_token>`。响应必须包含非空
`sub`，且与已验证 Token subject 相同；`profile` 控制 `username/display_name`，`email`
控制 `email`，`groups` 控制规范化后的 `groups`。没有 mapping 时 groups 是空集合，不能
从 roles 或其他 Client 回填。

完整 Session payload 包含 TokenSet、AuthContext、实际 Granted Scopes 和时效。Refresh
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
resolver 识别的 Session Cookie 与 Bearer 同时出现才视为 credential conflict。未配置
SessionResolver 的 Bearer-only Service 不检查浏览器 Session，只解析 Authorization Header
并忽略无关 Cookie。

## 数据与可观测性边界

普通业务 Context 只公开强类型 AuthContext/Decision。Access Token 仅经受控 TokenSource
在请求生命周期内使用。Token、Authorization Header、Client Secret、授权码、PKCE
verifier、Cookie、Session/Flow ID、nonce/state 与完整 URL query 不得进入错误、日志、
Hook、Trace baggage 或 metrics label。

IAM Application、OIDC Client、Resource Catalog、Policy、用户、组织、角色与审计查询/管理
接口都不属于本 SDK。SDK 不自动创建、修改或注册任何管理面对象。
