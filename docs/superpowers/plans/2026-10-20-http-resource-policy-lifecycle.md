# HTTP Resource and Policy Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The standalone Goal Loop controls repository order, commits, verification and acceptance.

**Goal:** 让完整 HTTP Manifest 与逐资源生命周期共同决定 SDK 资源、自动策略贡献和授权结果，并阻止旧副本覆盖新目录。

**Architecture:** Server 为每个 `(application_open_id, service)` 保存已发布代次、Manifest hash、逐路由与策略贡献状态；候选目录发布前不可被授权读路径看到。SDK 只为同一已发布 Manifest 续约，Web 只展示 Server 给出的生命周期事实。失联任务标记资源，授权快照在 Casbin 前拒绝已废弃 API。

**Tech Stack:** Go 1.24、GORM/MySQL、JobKit、Casbin、Umi Max 4、React 19、TypeScript、Ant Design 6、Vitest。

**Spec:** `docs/superpowers/specs/2026-10-20-http-resource-policy-lifecycle-design.md`

## Global Constraints

- 以 `(application_open_id, service)` 隔离注册；部署代次单调递增，`release` 不参与排序。同代次不同 Manifest 冲突，旧代次注册和心跳均拒绝。
- 心跳只更新时间，不能更改目录、Policy Document、绑定或编译规则；过期后只有完整注册能恢复。
- 15 天按 Server UTC 时间判定；历史无可靠证明的记录为 `unknown`，不自动废弃。IAM Core 内置目录不走 SDK。
- 废弃 API 在 IAM Core 授权入口失败关闭；已绑定策略保留文档、绑定和派生规则，无绑定且无规则引用才自动清理。
- 新 SQL 使用 snake_case、完整 COMMENT、业务唯一索引、无物理外键；不修改历史归档 SQL。新增公开 Go 声明写中文注释；SDK Runtime 不获取或缓存 Token。
- 每仓只修改本 Goal 的文件，保留当前不相关的未提交改动。每项先执行 RED，再做 GREEN 和 focused VERIFY，最后执行该仓冻结验证。

```yaml
kind: standalone-goal
goal_id: GOAL-20261020-001
target_repos:
  - server
  - client-sdk
  - web
repository_dependencies:
  server: []
  client-sdk:
    - server
  web:
    - server
verification:
  server:
    - go test ./internal/models ./internal/repositories ./internal/services ./internal/handlers ./internal/cron ./internal/authorization -count=1
    - go test ./... -count=1
    - go vet ./...
    - git diff --check
  client-sdk:
    - go test ./... -count=1
    - go test -race ./... -count=1
    - go vet ./...
    - go build ./examples/...
    - git diff --check
  web:
    - pnpm vitest run
    - pnpm typecheck
    - pnpm lint
    - pnpm build:prod
    - git diff --check
```

## File map and interfaces

| Repository | Files / responsibility |
| --- | --- |
| server | `sql/standalone/GOAL-20261020-001/DDL/001-http-resource-lifecycle.sql`: forward schema and indexes; `internal/models/http_catalog_service_registration.go`, `internal/models/http_catalog_route_lifecycle.go`, `internal/models/policy_document_provenance.go`: persistence facts; `internal/repositories/http_resource_catalog_repository.go`, `internal/repositories/policy_document_source_repository.go`, `internal/repositories/http_catalog_policy_retirement_repository.go`: conditional registration, durable contributions and detector reads |
| server | `internal/services/http_catalog_registration_service.go`, `http_resource_catalog_service.go`: versioned publication and API contract; `internal/dto/http_catalog_registration.go`, `internal/handlers/http_catalog_registration_handler.go`: generation/hash request and response; `internal/services/http_catalog_policy_retirement.go`, `internal/cron/cron.go`: timed reconciliation |
| server | `internal/repositories/authorization_decision_repository.go`, `internal/services/authorization_decision_service.go`: published lifecycle snapshot and reject-before-Casbin; `internal/handlers/http_resource_catalog_handler.go` and existing policy query DTO/service: management status and filters |
| client-sdk | `runtime/httpcatalog/registry.go`, `client.go`: generation configuration, canonical Manifest digest, Sync/heartbeat state machine; `runtime/httpcatalog/*_test.go`: protocol and old replica regression; `README.md`, `COMPATIBILITY.md`: rollout contract |
| web | `src/services/httpCatalogRegistration.ts`, `src/services/system/policies.ts`: response contract; `src/features/system/applications/HTTPResourceCatalog.tsx`, `src/pages/System/Policy/index.tsx`: badges, reasons, filters and evidence; adjacent tests: displayed server facts |

Public protocol shape: full Sync adds `deployment_generation: uint64` and replies with `deployment_generation`, `manifest_hash`, `catalog_hash`; heartbeat carries all three and rejects mismatch with `409` and a stable reason code. Admin resource rows return `lifecycle_status`, `lifecycle_reason`, `last_confirmed_at`, `deprecated_at`; policy rows return lifecycle and existing `cleanup_status` separately. Exact DTO names must follow existing snake_case wire conventions and be checked in the same package's contract tests.

## Tasks

### Task 1: Server schema and generation fence (AC2, AC3, AC7)

- [ ] Task 1: Server schema and generation fence (AC2, AC3, AC7)

**Files:** `sql/standalone/GOAL-20261020-001/DDL/001-http-resource-lifecycle.sql`, `internal/models/http_catalog_service_registration.go`, `internal/models/http_catalog_route_lifecycle.go`, `internal/models/policy_document_provenance.go`, `internal/repositories/http_resource_catalog_repository.go`, adjacent model/repository tests.

**Interfaces:** produce an atomic repository operation that compares `(deployment_generation, manifest_hash)` for one registered service and returns accepted/idempotent/conflict; produce lifecycle rows keyed by service, route name and HTTP method. The existing `catalog_hash` remains a separate published projection hash.

  - [ ] **Step 1 RED:** Add repository tests for lower generation, same generation/different hash, same generation/same hash, empty historical state, route tombstone identity and no cross-service writes. Assert a lower generation cannot advance `heartbeat_at` or change catalog rows.
  - [ ] **Step 2 RED verify:** Run `go test ./internal/models ./internal/repositories -run 'CatalogGeneration|HTTPRouteLifecycle' -count=1`; capture the expected failing assertions before production edits.
  - [ ] **Step 3 GREEN:** Add forward DDL, models and transactional compare-and-swap methods with `SELECT ... FOR UPDATE` or equivalent conditional update. Add unique business keys and a scan index for SDK heartbeat expiry; no physical foreign keys.
  - [ ] **Step 4 VERIFY:** Rerun the focused command and inspect `SHOW CREATE TABLE` against model field names in an isolated test database. Keep historical rows `unknown` until a new complete publication.

### Task 2: Server versioned full registration and heartbeat protocol (AC1, AC3, AC8, AC9)

- [ ] Task 2: Server versioned full registration and heartbeat protocol (AC1, AC3, AC8, AC9)

**Files:** `internal/dto/http_catalog_registration.go`, `internal/services/http_catalog_registration_service.go`, `internal/services/http_resource_catalog_service.go`, `internal/handlers/http_catalog_registration_handler.go`, `internal/repositories/http_resource_catalog_repository.go`, adjacent service/handler tests.

**Interfaces:** consume Task 1 generation fence; compute SHA-256 over schema version, identity and route fields sorted by Route Name; return accepted generation, Manifest hash and published catalog hash. Keep a versioned candidate separate from the published authorization read model. A recovery from expiry must execute full registration and publication.

  - [ ] **Step 1 RED:** Add HTTP contract tests for canonical hash order independence, `release` exclusion, same-generation conflict, low-generation rejection, legacy writer rejection after upgrade, heartbeat field-only update, and `sdk_pending` publish failure. Assert authorization reads old published snapshot while a candidate is pending.
  - [ ] **Step 2 RED verify:** Run `go test ./internal/services ./internal/handlers -run 'CatalogManifest|CatalogPublication|RegistrationHeartbeat' -count=1` and confirm behavior failures.
  - [ ] **Step 3 GREEN:** Extend DTO/handler and registration service; use existing transaction and snapshot publisher, adding versioned candidate isolation or an equivalent atomic publication boundary. Do not expose direct table changes to authorization reads before publication; on failure restore or retain the prior published version. Make exact-repeat Sync idempotent.
  - [ ] **Step 4 VERIFY:** Rerun focused tests, then test failed publication and concurrent newer/older Sync. Confirm no response claims an unpublished hash.

### Task 3: Server route and policy contribution reconciliation (AC1, AC4, AC5, AC7)

- [ ] Task 3: Server route and policy contribution reconciliation (AC1, AC4, AC5, AC7)

**Files:** `internal/repositories/policy_document_source_repository.go`, `internal/repositories/http_catalog_system_policy_repository.go`, `internal/services/http_catalog_system_policy.go`, `internal/services/http_resource_catalog_service.go`, `internal/models/policy_document_provenance.go`, adjacent tests.

**Interfaces:** full published Manifest changes a service's route and policy contributions to `active`; missing prior contributions become `deprecated/manifest_removed` instead of being deleted. Effective auto policy status uses all contributions; manual, builtin and unknown provenance are excluded from automatic cleanup.

  - [ ] **Step 1 RED:** Add tests for one removed route, one removed policy contribution, two services sharing a policy, a manually created policy of the same name, an unknown historical row, and re-add via a newer complete Manifest. Assert absence of binding/rule mutation during reconciliation.
  - [ ] **Step 2 RED verify:** Run `go test ./internal/repositories ./internal/services -run 'PolicyContributionLifecycle|CatalogManifestRemoval' -count=1` and record the missing lifecycle failures.
  - [ ] **Step 3 GREEN:** Replace destructive contribution deletion with state transitions, preserve tombstone coordinates for removed routes, aggregate effective contributors, and update policy provenance independently from `cleanup_status`. Reuse the existing system policy reconciler without synthesizing contributions from stale catalog rows.
  - [ ] **Step 4 VERIFY:** Rerun focused tests and compare source rows and document states before/after a repeated Manifest.

### Task 4: Server timeout detector and safe cleanup (AC2, AC4, AC5, AC7, AC8)

- [ ] Task 4: Server timeout detector and safe cleanup (AC2, AC4, AC5, AC7, AC8)

**Files:** `internal/repositories/http_catalog_policy_retirement_repository.go`, `internal/services/http_catalog_policy_retirement.go`, `internal/cron/cron.go`, bootstrap wiring and adjacent tests.

**Interfaces:** JobKit scans published SDK registrations with `heartbeat_at <= nowUTC - 15 days`, locks each identity, rechecks version/time, and marks its active routes and contributions `deprecated/heartbeat_expired`. It never edits bindings or compiled rules. Policy deletion requires a locked recheck of zero active/unknown contributors, zero binding, zero compiled/published rule reference and `sdk_auto` provenance.

  - [ ] **Step 1 RED:** Test 14d23h versus 15d, null heartbeat, legacy/builtin/manual exclusion, repeat detector, concurrent heartbeat, concurrent binding, unbound cleanup with audit, bound `pending_manual_cleanup`, anomalous `needs_review`, and full-registration recovery.
  - [ ] **Step 2 RED verify:** Run `go test ./internal/repositories ./internal/services ./internal/cron -run 'CatalogLifecycleDetector|PolicyRetirement' -count=1` and confirm expected failures.
  - [ ] **Step 3 GREEN:** Extend the existing retirement service/repository and JobKit registration. Use indexed stable-cursor batches and UTC. Schedule hourly; publish lifecycle changes and authorization revision safely. Keep failed identities retriable without mutating unrelated services.
  - [ ] **Step 4 VERIFY:** Rerun focused tests and assert bindings, compiled rules, Casbin rows and manual/builtin rows remain unchanged in bound and historical cases.

### Task 5: Server authorization gate and management contract (AC1, AC6, AC8)

- [ ] Task 5: Server authorization gate and management contract (AC1, AC6, AC8)

**Files:** `internal/repositories/authorization_decision_repository.go`, `internal/services/authorization_decision_service.go`, `internal/handlers/http_resource_catalog_handler.go`, existing catalog/policy query DTO and services, adjacent tests.

**Interfaces:** published lifecycle participates in the same decision snapshot/revision as catalog resolution. For a bound machine client, consider only its resource server; for ordinary users, allow a canonical route only if at least one consistent active contributor exists. A tombstone without a current `http_resources` row still produces `resource_deprecated`; historic unknown alone preserves old behavior. Status API returns reason and UTC timestamps.

  - [ ] **Step 1 RED:** Add real PDP tests where Casbin Allow plus a bound retired document still denies the deprecated route, while a separate active route allows; cover shared route, machine audience, removed catalog row, unknown migration row, revision race and cache invalidation failure. Add admin response serialization/filter tests.
  - [ ] **Step 2 RED verify:** Run `go test ./internal/repositories ./internal/services ./internal/handlers -run 'DeprecatedResourceDecision|CatalogLifecycleQuery' -count=1` and confirm a stale Allow is currently possible.
  - [ ] **Step 3 GREEN:** Add lifecycle resolution before `EnforceDecision`, stable reason code and audit fields; couple lifecycle publication to authorization revision/cache invalidation, falling back to authoritative read or deny on uncertain freshness. Extend existing catalog and policy list/detail APIs, not a second management API.
  - [ ] **Step 4 VERIFY:** Rerun focused tests, then exercise all user, service-account and delegated-user decision entry points against the same state.

### Task 6: SDK generation-aware registry and heartbeat (AC1, AC3, AC9)

- [x] Task 6: SDK generation-aware registry and heartbeat (AC1, AC3, AC9)

**Files:** `runtime/httpcatalog/registry.go`, `runtime/httpcatalog/client.go`, `runtime/httpcatalog/heartbeat_test.go`, `runtime/httpcatalog/registry_test.go`, `README.md`, `COMPATIBILITY.md`.

**Interfaces:** `Config` receives a deployment generation from the host; Sync serializes it with the same canonical hash as Server. Heartbeat rehashes the current sealed RouteSpec snapshot and carries generation, Manifest hash and catalog hash. `409` never calls Sync automatically; a changed local Manifest stops renewal until the host supplies a new generation and completes Sync.

  - [ ] **Step 1 RED:** Using `httptest.Server`, assert wire JSON and digest stability, startup Sync before heartbeat, lower generation conflict with no second Sync request, same-generation local change as unhealthy, per-request TokenSource use, context cancellation and bounded retry.
  - [ ] **Step 2 RED verify:** Run `go test ./runtime/httpcatalog -run 'Generation|ManifestDigest|HeartbeatConflict' -count=1` and capture failures caused by the current auto-resync behavior.
  - [ ] **Step 3 GREEN:** Extend Registry state and HTTP client without caching credentials or changing the RouteSpec schema. Remove automatic conflict resync; expose a stable error/Observer signal. Document how CI or Helm supplies monotonically increasing generation, including rollback and mixed SDK replicas.
  - [ ] **Step 4 VERIFY:** Rerun focused tests and race tests for the package; verify published examples compile against the changed Config.

### Task 7: Web lifecycle evidence and filters (AC1, AC5, AC7)

- [ ] Task 7: Web lifecycle evidence and filters (AC1, AC5, AC7)

**Files:** `src/services/httpCatalogRegistration.ts`, `src/services/system/policies.ts`, `src/features/system/applications/HTTPResourceCatalog.tsx`, `src/pages/System/Policy/index.tsx`, adjacent tests.

**Interfaces:** display Server `lifecycle_status`, `lifecycle_reason`, `last_confirmed_at`, `deprecated_at` and `cleanup_status`; filters pass exact values to domain services through `src/services/request.ts`. Browser time never decides 15-day state.

  - [ ] **Step 1 RED:** Add service and component tests for active/deprecated/unknown resources, `manifest_removed`/`heartbeat_expired` evidence, bound `pending_manual_cleanup`, shared active policy and filtered requests. Assert manual cleanup controls use existing permissions and no automatic unbind action appears.
  - [ ] **Step 2 RED verify:** Run `pnpm exec vitest run src/features/system/applications/HTTPResourceCatalog.test.tsx src/pages/System/Policy` and confirm missing status/filter behavior.
  - [ ] **Step 3 GREEN:** Extend typed service responses and existing Ant Design table filters/badges. Preserve current light tag palette and page composition; do not infer resource identity, strategy source or expiry in React.
  - [ ] **Step 4 VERIFY:** Rerun focused tests and `pnpm typecheck`; inspect both pages in a real browser with active, deprecated and unknown fixtures, including tooltip and narrow viewport.

## Integration and acceptance

All three repositories use this Goal's frozen Plan as the acceptance source; only the currently executing repository checks its own task after TDD, focused verification, frozen verification and commit. The Plan file must exist at the same path in each target checkout as a working copy. Server schema precedes Server protocol and authorization changes; SDK/Web depend on the Server contract. Do not deploy during Goal Completion. A later deployment must apply DDL first, then Server, SDK consumers with fresh deployment generations, Web, and finally enable detector/cleanup flags after observing migrated identities.

Review AC1–AC9 against a real full registration, a removed route, a 15-day timeout, an old replica, a shared policy and a bound policy with a Casbin Allow. Record database lifecycle rows, authorization reason, unchanged binding/rule rows, and UI evidence. Test migration with legacy unknown rows and run the exact frozen commands per repository. If an environment is unavailable, record that limit; never infer production safety from a mock-only assertion.

## Three-pass self-review

Context coverage: Tasks 1–5 cover Server schema, protocol, reconciliation, detector, PDP and management contract; Task 6 covers SDK; Task 7 covers Web. All AC1–AC9 have a test owner.

TDD executability: Each task defines a failing behavior, focused command, implementation boundary and verification. Shared DTO changes require same-package contract tests to compile; real PDP tests verify effect rather than only labels.

Adversarial boundaries: Old replicas are fenced; candidate publication cannot leak; tombstones survive catalog replacement; legacy unknown and builtin/manual data are excluded; bound strategies retain bindings and rules while the resource gate denies stale Allow.
