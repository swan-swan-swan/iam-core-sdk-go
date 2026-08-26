# 当前浏览器全局退出与可配置会话期限实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to execute this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 IAM Core 当前浏览器全局退出编排、绝对 7 天/空闲 12 小时双期限会话语义，并为第一方 BFF 与 Bytebase/JumpServer SSO 插件提供可复用的协议能力。

**Architecture:** IAM Core Server 是会话与退出协议的权威：配置层提供双期限，OP/BFF/refresh token 继承不可变绝对截止时间，OIDC Client 注册保存固定 front-channel 元数据，`/oidc/logout` 清理 IAM 本地状态并渲染短生命周期并行编排页。SDK 提供顶层重定向退出、签名退出令牌校验和同源 Cookie 清理 Handler；两个 SSO 插件只以环境变量消费策略，保持 Bytebase/JumpServer Core 不变。

**Tech Stack:** Go 1.24、Gin、GORM/MySQL、Redis、React/TypeScript、`iam-core-sdk-go`、Python 3.12/httpx、标准 OIDC/JWT、Vitest/Pytest。

**Spec:** `iam-core-server/docs/superpowers/specs/2026-08-26-current-browser-global-logout-session-policy-design.md`

**Frozen Goal:** `GOAL-20260826-001`

## Global Constraints

- 默认策略固定为 `absoluteTTL=168h`、`idleTTL=12h`，两项必须为正且满足 `idleTTL <= absoluteTTL`；业务代码不直接读取环境变量。
- 每个平台独立创建本地会话。刷新只能更新 `lastActivityAt`，不得重置 `createdAt` 或 `absoluteDeadline`。
- IAM 每次退出调用全部启用目标；不创建会话映射表、Outbox、消息队列、后台重试或持久化退出事务。
- `frontchannel_logout_uri` 和执行模式只来自受信任注册元数据；请求参数不得覆盖目标 URL、Origin、受众或退出后地址。
- 协议目标使用短期、目标专属 `logout_token`；日志不得包含 token、Cookie、用户标识、session ID 或完整查询串。
- Bytebase Core、JumpServer Core 均不得修改；SSO 插件不得新增独立配置文件。
- Ingress 不在本 Goal 的业务实现范围内；部署路由由后续部署计划负责。

```yaml
kind: standalone-goal
goal_id: GOAL-20260826-001
target_repos:
  - client-sdk
  - server
  - web
  - sso-bytebase-plugin
  - sso-jumpserver-plugin
repository_dependencies:
  client-sdk: []
  server: []
  web:
    - server
  sso-bytebase-plugin:
    - client-sdk
    - server
  sso-jumpserver-plugin:
    - server
verification:
  client-sdk:
    - go test ./... -count=1
    - go vet ./...
  server:
    - go test ./... -count=1
    - go vet ./...
    - go build ./cmd/server
  web:
    - pnpm vitest run
    - pnpm typecheck
    - pnpm lint
  sso-bytebase-plugin:
    - go test ./... -count=1
    - go vet ./...
    - go build ./cmd/server
  sso-jumpserver-plugin:
    - pytest -q
```

---

### Task 1: 建立 IAM Server 双期限配置契约

**Files:**
- Modify: `iam-core-server/internal/config/config.go`
- Modify: `iam-core-server/internal/config/config_test.go`
- Modify: `iam-core-server/configs/application.yaml`
- Modify: `iam-core-server/configs/README.md`

**Interfaces:**

```go
type SessionPolicyConfig struct {
    AbsoluteTTL time.Duration `mapstructure:"absoluteTTL" yaml:"absoluteTTL"`
    IdleTTL     time.Duration `mapstructure:"idleTTL" yaml:"idleTTL"`
}

func (c SessionPolicyConfig) Validate() error
```

- [ ] **Step 1: RED** — 在 `internal/config/config_test.go` 添加默认值、`SGG_SESSION_POLICY_ABSOLUTE_TTL`/`SGG_SESSION_POLICY_IDLE_TTL` 覆盖、非法格式、非正数及 `idle > absolute` 的失败用例。
- [ ] **Step 2: 运行 RED**

  ```bash
  cd iam-core-server
  go test ./internal/config -run 'Test.*SessionPolicy' -count=1
  ```

  Expected: FAIL，因为 `Config.SessionPolicy` 与校验尚不存在。

- [ ] **Step 3: GREEN** — 增加 `SessionPolicyConfig`、168h/12h 默认值、Viper/env 绑定和 fail-fast `Validate`；示例配置写正式 `sessionPolicy`，不写 Secret。
- [ ] **Step 4: VERIFY** — 重跑聚焦测试并执行 `go test ./configs -count=1`、`git diff --check`。
- [ ] **Step 5: Commit**

  ```bash
  cd iam-core-server
  git add internal/config configs
  git commit -m "feat(iam): configure session policy deadlines"
  ```

---

### Task 2: 对 IAM OP 浏览器会话执行绝对与空闲截止时间

**Files:**
- Modify: `iam-core-server/internal/services/authorization_service.go`
- Modify: `iam-core-server/internal/services/oidc_op_storage.go`
- Modify: `iam-core-server/internal/handlers/oidc_handler.go`
- Create: `iam-core-server/internal/services/session_policy_test.go`
- Create: `iam-core-server/internal/handlers/oidc_handler_test.go`

**Interfaces:**

```go
type opBrowserSession struct {
    Token            string
    Username         string
    UserOpenID       string
    AuthTime         time.Time
    CreatedAt        time.Time
    LastActivityAt   time.Time
    AbsoluteDeadline time.Time
}

func sessionDeadline(createdAt, lastActivityAt time.Time, policy config.SessionPolicyConfig) time.Time
```

- [ ] **Step 1: RED** — 用可控时钟证明：活动前后空闲截止时间移动，但 `AbsoluteDeadline` 不变；绝对或空闲任一到期均删除服务端记录并拒绝会话；无效 Cookie 被清理。
- [ ] **Step 2: 运行 RED**

  ```bash
  cd iam-core-server
  go test ./internal/services ./internal/handlers -run 'Test.*(OPBrowserSession|SessionDeadline)' -count=1
  ```

- [ ] **Step 3: GREEN** — 删除硬编码 `opBrowserSessionTTL`/`opBrowserSessionMaxAge`，以策略计算 Redis TTL 和 Cookie 生命周期；后端接受的认证活动原子更新 `LastActivityAt`，并以 `min(absolute, idle)` 保存。
- [ ] **Step 4: VERIFY** — 覆盖首次创建、有效 touch、空闲过期、绝对过期、重复清理和时钟边界。
- [ ] **Step 5: Commit**

  ```bash
  cd iam-core-server
  git add internal/services internal/handlers
  git commit -m "feat(iam): enforce browser session deadlines"
  ```

---

### Task 3: 修正两条刷新令牌链路的绝对期限继承

**Files:**
- Modify: `iam-core-server/internal/services/oidc_op_storage.go`
- Modify: `iam-core-server/internal/services/token_service.go`
- Modify: `iam-core-server/internal/services/story_1_1_test.go`
- Create: `iam-core-server/internal/services/refresh_session_deadline_test.go`

**Interfaces:**

```go
type RefreshSessionDeadline struct {
    CreatedAt        time.Time
    LastActivityAt   time.Time
    AbsoluteDeadline time.Time
}

func remainingTokenTTL(now time.Time, deadline RefreshSessionDeadline, idleTTL time.Duration) (time.Duration, error)
```

- [ ] **Step 1: RED** — 分别覆盖 Zitadel OP storage 与自有 `TokenService`：连续轮换不得产生新的七天窗口，过空闲/绝对期限拒绝刷新，新 access/ID/refresh token TTL 不得超过剩余绝对时间。
- [ ] **Step 2: 运行 RED**

  ```bash
  cd iam-core-server
  go test ./internal/services -run 'Test.*Refresh.*(Absolute|Idle|Deadline|Rotation)' -count=1
  ```

- [ ] **Step 3: GREEN** — 在刷新记录中保存不可变 `AbsoluteDeadline` 与可变 `LastActivityAt`；轮换复制首次截止时间并只在成功刷新时推进活动时间；Redis 正向、反向和 sid 索引使用相同剩余 TTL。
- [ ] **Step 4: VERIFY** — 补充并发轮换、到期瞬间、存量记录兼容策略。存量缺少 deadline 的记录按“读取时创建不超过当前配置的新截止时间”迁移，不得无限续期。
- [ ] **Step 5: Commit**

  ```bash
  cd iam-core-server
  git add internal/services
  git commit -m "fix(iam): preserve refresh session deadline"
  ```

---

### Task 4: 让 IAM 管理后台 BFF 会话具备刷新与双期限

**Files:**
- Modify: `iam-core-server/internal/services/auth_bff_session_service.go`
- Modify: `iam-core-server/internal/services/auth_bff_service.go`
- Modify: `iam-core-server/internal/handlers/auth_bff_handler.go`
- Modify: `iam-core-server/internal/routers/router.go`
- Create: `iam-core-server/internal/services/auth_bff_session_policy_test.go`
- Create: `iam-core-server/internal/handlers/auth_bff_handler_test.go`

**Interfaces:**

```go
type AuthBFFSession struct {
    // existing identity/token fields
    RefreshToken     string
    CreatedAt        time.Time
    LastActivityAt   time.Time
    ExpiresAt        time.Time
    IdleExpiresAt    time.Time
}
```

- [ ] **Step 1: RED** — 证明现有五分钟 access token 到期后 BFF 能在双期限内刷新；空闲或绝对期限到达后刷新被拒绝且 Cookie 被清理；刷新失败不恢复旧 session。
- [ ] **Step 2: 运行 RED**

  ```bash
  cd iam-core-server
  go test ./internal/services ./internal/handlers -run 'Test.*AuthBFF.*(Refresh|SessionPolicy|Logout)' -count=1
  ```

- [ ] **Step 3: GREEN** — callback 保存 refresh token 与双期限；`/api/auth/me` 在接近 access token 到期时刷新并原子保存，所有 token TTL 受绝对截止时间约束；日志和响应不暴露 refresh token。
- [ ] **Step 4: VERIFY** — 覆盖 Redis/memory backend、并发刷新、过期 Cookie、无 session 幂等行为。
- [ ] **Step 5: Commit**

  ```bash
  cd iam-core-server
  git add internal/services internal/handlers internal/routers
  git commit -m "feat(iam): refresh admin bff within session bounds"
  ```

---

### Task 5: 为 OIDC Client 增加受信任 front-channel 元数据

**Files:**
- Modify: `iam-core-server/internal/models/oidc_client.go`
- Modify: `iam-core-server/internal/repositories/oidc_client_repository.go`
- Modify: `iam-core-server/internal/services/oidc_client_service.go`
- Modify: `iam-core-server/internal/services/oidc_client_admin_service.go`
- Modify: `iam-core-server/internal/handlers/oidc_client_admin_handler.go`
- Modify: `iam-core-server/internal/bootstrap/bootstrap.go`
- Modify: `iam-core-server/docs/openapi.yaml`
- Modify: `iam-core-server/docs/swagger.yaml`
- Create: `iam-core-server/sql/prd-v1.9.0/DDL/2026-08_frontchannel-logout.sql`
- Create: `iam-core-server/sql/prd-v1.9.0/DDL/frontchannel_logout_test.go`
- Create: `iam-core-server/internal/services/frontchannel_registration_test.go`

**Interfaces:**

```go
const (
    FrontchannelModeSignedPostMessage = "signed_postmessage"
    FrontchannelModeNativeGET         = "native_get"
)

type FrontchannelLogoutRegistration struct {
    PlatformID string
    URI        string
    Mode       string
    Enabled    bool
}
```

- [ ] **Step 1: RED** — 覆盖 URI 必须 HTTPS（仅测试 loopback 可 HTTP）、无 userinfo/query/fragment、平台标识稳定、mode 枚举严格、URI/mode 成对出现，以及 CRUD/list 响应不丢字段。
- [ ] **Step 2: 运行 RED**

  ```bash
  cd iam-core-server
  go test ./internal/models ./internal/repositories ./internal/services ./internal/handlers -run 'Test.*Frontchannel' -count=1
  ```

- [ ] **Step 3: GREEN** — 模型、repository、service、DTO/OpenAPI 和迁移脚本增加 `frontchannel_logout_uri`、`frontchannel_logout_mode`、稳定 `frontchannel_platform_id`；禁止请求临时覆盖注册值。
- [ ] **Step 4: VERIFY** — 运行 SQL 与注释治理检查，并确认 AutoMigrate 注册与显式 SQL 一致。
- [ ] **Step 5: Commit**

  ```bash
  cd iam-core-server
  git add internal sql/prd-v1.9.0/DDL/2026-08_frontchannel-logout.sql sql/prd-v1.9.0/DDL/frontchannel_logout_test.go docs/openapi.yaml docs/swagger.yaml
  git commit -m "feat(iam): register trusted frontchannel logout targets"
  ```

---

### Task 6: 实现签名退出令牌与 IAM 并行编排页

**Files:**
- Create: `iam-core-server/internal/services/frontchannel_logout_service.go`
- Create: `iam-core-server/internal/services/frontchannel_logout_service_test.go`
- Modify: `iam-core-server/internal/handlers/oidc_handler.go`
- Create: `iam-core-server/internal/handlers/frontchannel_logout_test.go`
- Modify: `iam-core-server/internal/bootstrap/bootstrap.go`
- Modify: `iam-core-server/internal/observability/metrics/metrics.go`

**Interfaces:**

```go
type LogoutTokenClaims struct {
    Issuer    string `json:"iss"`
    Audience  string `json:"aud"`
    ExpiresAt int64  `json:"exp"`
    TxID      string `json:"tx_id"`
    Purpose   string `json:"purpose"`
}

type FrontchannelTarget struct {
    PlatformID string
    Origin     string
    URI        string
    Mode       string
    Token      string // only signed_postmessage
}
```

- [ ] **Step 1: RED** — 测试 IAM 无本地 session 仍列出全部目标、协议目标签发不同 `aud` 的短期 token、原生目标不附 token、非法注册被拒、目标并行且单目标约三秒超时。
- [ ] **Step 2: RED** — Handler 测试错误 Origin/platform/`tx_id` 消息不能结算目标；全部协议成功+原生已发起为 `complete`，任一 timeout/failure 为 `complete_with_warnings`，IAM 本地清理/初始化失败才为 `failed`。
- [ ] **Step 3: 运行 RED**

  ```bash
  cd iam-core-server
  go test ./internal/services ./internal/handlers -run 'Test.*FrontchannelLogout' -count=1
  ```

- [ ] **Step 4: GREEN** — service 从 repository 加载固定目标并签发 token；`GET /oidc/logout` 先幂等清理 OP/BFF/token session，再渲染 `Cache-Control: no-store` 的顶层编排页。页面用受限 iframe/请求并行执行，校验 `event.origin`、platform、`tx_id`，整体完成后只跳转服务端允许的安全页面。
- [ ] **Step 5: VERIFY** — 指标仅记录平台枚举、结果与耗时；源码和测试断言不存在持久化事务、后台重试及任意 URL 参数。
- [ ] **Step 6: Commit**

  ```bash
  cd iam-core-server
  git add internal
  git commit -m "feat(iam): orchestrate current browser logout"
  ```

---

### Task 7: 扩展 Go SDK 的全局退出与 front-channel receiver

**Files:**
- Modify: `iam-core-sdk-go/runtime/bff/client.go`
- Modify: `iam-core-sdk-go/runtime/bff/client_test.go`
- Modify: `iam-core-sdk-go/runtime/bff/logout.go`
- Modify: `iam-core-sdk-go/runtime/bff/logout_test.go`
- Create: `iam-core-sdk-go/runtime/bff/frontchannel_logout.go`
- Create: `iam-core-sdk-go/runtime/bff/frontchannel_logout_test.go`
- Modify: `iam-core-sdk-go/runtime/core/verify.go`
- Modify: `iam-core-sdk-go/runtime/core/verify_test.go`
- Modify: `iam-core-sdk-go/README.md`

**Interfaces:**

```go
type FrontchannelLogoutConfig struct {
    PlatformID      string
    IAMOrigin       string
    Audience        string
    SessionCookie   http.Cookie
}

func (c *Client) GlobalLogoutHandler() http.Handler
func (c *Client) FrontchannelLogoutHandler(cfg FrontchannelLogoutConfig) http.Handler
func (r *Runtime) VerifyLogoutToken(ctx context.Context, raw, audience string) (txID string, err error)
```

- [ ] **Step 1: RED** — 将默认 idle 从 8h 改为 12h，并添加 `idle > absolute` 构造失败用例；验证现有 session resolver 不越过绝对截止时间。
- [ ] **Step 2: RED** — `GlobalLogoutHandler` 在有/无本地 session 时均清 Cookie并 `303` 到 discovery 中的受信任 end-session endpoint；不做 server-to-server Cookie 退出。保留 `LocalLogoutHandler` 与旧 `CentralLogoutHandler` 兼容行为。
- [ ] **Step 3: RED** — receiver 拒绝伪造签名、错误 issuer/aud/purpose、过期 token；成功时幂等删除 session、清 Host-only Cookie，并只向配置的 IAM Origin postMessage `{type, platform, tx_id, status}`。
- [ ] **Step 4: 运行 RED**

  ```bash
  cd iam-core-sdk-go
  go test ./runtime/bff ./runtime/core -run 'Test.*(SessionTTL|GlobalLogout|Frontchannel|LogoutToken)' -count=1
  ```

- [ ] **Step 5: GREEN** — 实现上述公开接口、no-store 响应和受限 HTML；所有 URL 来自 discovery/config，不接受请求覆盖。
- [ ] **Step 6: VERIFY**

  ```bash
  gofmt -w runtime/bff runtime/core
  go test ./... -count=1
  go vet ./...
  git diff --check
  ```

- [ ] **Step 7: Commit and tag candidate**

  ```bash
  cd iam-core-sdk-go
  git add runtime README.md
  git commit -m "feat(sdk): support browser global logout"
  ```

  发布新的兼容版本，供 IAM Server、Ops Gateway 与插件使用；不得复用尚未包含新 API 的 `v0.9.2`。

---

### Task 8: 接入 IAM 管理前端的注册字段与默认全局退出

**Files:**
- Modify: `iam-core-web/src/services/oidcClients.ts`
- Modify: `iam-core-web/src/features/oidcClient/OidcClientConsole.tsx`
- Create: `iam-core-web/src/features/oidcClient/frontchannelLogout.test.tsx`
- Modify: `iam-core-web/src/services/auth.ts`
- Modify: `iam-core-web/src/app.tsx`
- Modify: `iam-core-web/src/app.test.ts`

**Interfaces:**

```ts
export function beginGlobalLogout(): void {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = '/api/auth/logout';
  document.body.append(form);
  form.submit();
}
```

- [ ] **Step 1: RED** — OIDC Client 表单覆盖平台标识、URI、mode 的显示/提交/清空和后端错误；退出测试证明使用顶层 form POST 而非 `fetch`/iframe。
- [ ] **Step 2: 运行 RED**

  ```bash
  cd iam-core-web
  npm test -- --run src/features/oidcClient/frontchannelLogout.test.tsx src/app.test.ts
  ```

- [ ] **Step 3: GREEN** — 管理页编辑可信元数据；IAM 菜单退出直接提交 `/api/auth/logout`，后端完成本地清理后 303 到 `/oidc/logout`。
- [ ] **Step 4: VERIFY** — `npm test -- --run`、`npm run typecheck`、`npm run lint`、`git diff --check`。
- [ ] **Step 5: Commit**

  ```bash
  cd iam-core-web
  git add src
  git commit -m "feat(web): manage and start global logout"
  ```

---

### Task 9: 扩展 Bytebase SSO 插件的期限与退出接收能力

**Files:**
- Modify: `sso-bytebase-plugin/internal/config/config.go`
- Modify: `sso-bytebase-plugin/internal/config/config_test.go`
- Create: `sso-bytebase-plugin/internal/session/deadline.go`
- Create: `sso-bytebase-plugin/internal/session/deadline_test.go`
- Create: `sso-bytebase-plugin/internal/httpserver/frontchannel_logout.go`
- Create: `sso-bytebase-plugin/internal/httpserver/frontchannel_logout_test.go`
- Create: `sso-bytebase-plugin/internal/httpserver/auth_relay.go`
- Create: `sso-bytebase-plugin/internal/httpserver/auth_relay_test.go`
- Modify: `sso-bytebase-plugin/internal/httpserver/handler.go`
- Modify: `sso-bytebase-plugin/cmd/server/main.go`
- Modify: `sso-bytebase-plugin/cmd/server/main_test.go`
- Modify: `sso-bytebase-plugin/README.md`

**Interfaces:**

```go
const FrontchannelLogoutPathValue = "/_iam/logout/bytebase"

type SessionPolicy struct {
    AbsoluteTTL time.Duration
    IdleTTL     time.Duration
}
```

- [ ] **Step 1: RED** — 环境变量缺省为 168h/12h，非法格式、非正数、`idle > absolute` 初始化失败；不得读取配置文件。
- [ ] **Step 2: RED** — handoff 写入仅含签名期限的 HttpOnly Cookie；固定 Bytebase refresh/logout relay 只代理认证路径、更新有效活动并把 Bytebase `access-token`/`refresh-token` Cookie 截止时间钳制到剩余期限，不成为通用 DMS 代理。
- [ ] **Step 3: RED** — front-channel 验证 logout token 后幂等清理 Bytebase auth Cookie 与插件期限 Cookie；未登录视为成功；错误 token 不清理且不 postMessage 成功。
- [ ] **Step 4: 运行 RED**

  ```bash
  cd sso-bytebase-plugin
  go test ./... -run 'Test.*(SessionPolicy|Deadline|AuthRelay|FrontchannelLogout)' -count=1
  ```

- [ ] **Step 5: GREEN** — 复用 SDK/core verifier 或最小公开 verifier API，固定路径注册到现有 `http.Server`；Cookie 属性与 DMS 原 Cookie 对齐，不记录值。
- [ ] **Step 6: VERIFY** — `go test ./... -count=1`、`go vet ./...`、`go build ./cmd/server`、`git diff --check`，并检查 Bytebase Core 仓无 diff。
- [ ] **Step 7: Commit**

  ```bash
  cd sso-bytebase-plugin
  git add internal cmd README.md
  git commit -m "feat(bytebase-sso): enforce session bounds and logout"
  ```

---

### Task 10: 为 JumpServer SSO 插件增加轻量退出接收进程

**Files:**
- Modify: `sso-jumpserver-plugin/src/iam_jumpserver_plugin/config.py`
- Create: `sso-jumpserver-plugin/src/iam_jumpserver_plugin/logout_config.py`
- Create: `sso-jumpserver-plugin/src/iam_jumpserver_plugin/logout_server.py`
- Modify: `sso-jumpserver-plugin/pyproject.toml`
- Create: `sso-jumpserver-plugin/tests/test_logout_config.py`
- Create: `sso-jumpserver-plugin/tests/test_logout_server.py`
- Modify: `sso-jumpserver-plugin/README.md`

**Interfaces:**

```python
@dataclass(frozen=True)
class LogoutConfig:
    iam_issuer: str
    iam_origin: str
    audience: str
    absolute_ttl_seconds: int
    idle_ttl_seconds: int

# console script
iam-jumpserver-logout = "iam_jumpserver_plugin.logout_server:main"
```

- [ ] **Step 1: RED** — 解析 Go duration 兼容的 `SSO_SESSION_ABSOLUTE_TTL`/`SSO_SESSION_IDLE_TTL`，默认 168h/12h；非法值 fail-fast，无配置文件回退。
- [ ] **Step 2: RED** — 固定 `/_iam/logout/jumpserver` 仅接受有效目标 token；成功/未登录均清 `sessionid` 及匹配的 CSRF Cookie并返回受限 postMessage HTML；错误 token 不清 Cookie。
- [ ] **Step 3: 运行 RED**

  ```bash
  cd sso-jumpserver-plugin
  pytest -q tests/test_logout_config.py tests/test_logout_server.py
  ```

- [ ] **Step 4: GREEN** — 使用现有 Python 包新增独立轻量 HTTP console script，不改变 reconciler、Custom SSO Hook 或 JumpServer Core；原生 12h hard session 由部署层提供更严格上限。
- [ ] **Step 5: VERIFY** — `pytest -q`、wheel build/import smoke、`git diff --check`，并检查 JumpServer Core/PVC Hook 内容无业务补丁。
- [ ] **Step 6: Commit**

  ```bash
  cd sso-jumpserver-plugin
  git add src tests pyproject.toml README.md
  git commit -m "feat(jumpserver-sso): receive frontchannel logout"
  ```

---

### Task 11: 跨仓兼容验证与版本冻结

**Files:**
- Modify: `iam-core-server/docs/superpowers/plans/2026-08-26-current-browser-global-logout-session-policy.md`
- Modify version/changelog files only where each repository's release policy requires them.

- [ ] 按依赖顺序验证并冻结：SDK → IAM Server → IAM Web → Bytebase plugin → JumpServer plugin。
- [ ] 在 IAM Server 使用已发布 SDK 版本，不用 `replace` 指向未提交目录；插件镜像版本与提交 SHA 可追溯。
- [ ] 执行：

  ```bash
  cd iam-core-server && go test ./... -count=1 && go vet ./... && go build ./cmd/server
  cd ../iam-core-sdk-go && go test ./... -count=1 && go vet ./...
  cd ../iam-core-web && npm test -- --run && npm run typecheck && npm run lint
  cd ../sso-bytebase-plugin && go test ./... -count=1 && go vet ./... && go build ./cmd/server
  cd ../sso-jumpserver-plugin && pytest -q
  git -C ../iam-core-server diff --check
  git -C ../iam-core-sdk-go diff --check
  git -C ../iam-core-web diff --check
  git -C ../sso-bytebase-plugin diff --check
  git -C ../sso-jumpserver-plugin diff --check
  ```

- [ ] 用短期限集成测试记录绝对/空闲/轮换证据；用伪造签名、错误 aud、过期 token、错误 Origin/tx 验证拒绝路径。
- [ ] 确认不存在 Bytebase Core、JumpServer Core、Ingress 业务逻辑、会话映射表、Outbox、MQ 或持久重试的变更。
- [ ] 更新本计划 checkbox 与实际命令结果，创建 Goal 最终单一集成提交或按各目标仓已冻结提交记录完成交付。

## Deployment Handoff

本 Goal 完成后才允许执行：

1. `GOAL-20260826-002`（Ops Gateway 消费接入）；
2. `goose-charts/docs/superpowers/plans/2026-08-26-global-logout-session-policy-deployment.md`；
3. `mini-pivot/application` 的声明式版本/配置更新与 `docker-desktop` 验收。

本计划不授权上述部署动作。
