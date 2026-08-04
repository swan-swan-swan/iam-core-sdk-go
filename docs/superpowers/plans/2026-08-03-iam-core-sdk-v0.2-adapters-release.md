# IAM Core SDK v0.2.0 Adapters and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the v0.2.0 rewrite with a safe testkit, isolated Gin and Redis modules, Redis conformance, examples, legacy-code deletion, dependency cleanup, and release documentation.

**Architecture:** The root module remains dependency-light. Gin and Redis are independently versioned nested modules joined by `go.work`; Docker/Testcontainers exist only in the non-production `integration` module. Legacy v0.1 packages and tests are deleted only after the new modules pass their complete contract suites.

**Tech Stack:** Go 1.24 workspaces, Gin 1.11, go-redis 9.21, Testcontainers Redis 0.40 in integration only, Redis 6.2/7.4, Markdown docs and examples.

## Global Constraints

- Complete the Core+BFF and HTTP Authorization plans first.
- Root module must not require Gin, Redis, Docker, OpenTelemetry Docker helpers, or Testcontainers.
- Fake PDP defaults to deny; tests opt into allow explicitly.
- Redis payloads containing Flow verifier or Session tokens are encrypted with AES-256-GCM.
- Redis refresh commit validates lease owner, fence, expiry, and Session version in the same Lua operation as mutation/deletion.
- Gin adapter defines no security semantics; it only adapts compiled Routes and Context.
- `integration` is not a production dependency and is the only module that requires Testcontainers.
- Delete all legacy root facade, old packages, old examples, old tests, legacy roles, ExtraClaims, and bare PDP decoding before release.
- RPC remains absent.
- Design source: `docs/superpowers/specs/2026-08-03-iam-core-go-client-sdk-v0.2-design.md`.

---

## File Map

| Path | Responsibility |
| --- | --- |
| `testkit/issuer.go` | Fake Discovery/JWKS/Token/UserInfo issuer |
| `testkit/pdp.go` | Default-deny Fake PDP and call recorder |
| `testkit/token.go` | Deterministic RS256 token fixtures |
| `testkit/clock.go` | Thread-safe fixed clock |
| `testkit/leak.go` | Sensitive-value output assertions |
| `adapters/redis/go.mod` | Redis-only published module |
| `adapters/redis/codec.go` | AES-256-GCM encrypted payload codec |
| `adapters/redis/backend.go` | Session/Flow/lease backend |
| `adapters/redis/scripts.go` | Atomic fenced commit/delete scripts |
| `adapters/gin/go.mod` | Gin-only published module |
| `adapters/gin/gin.go` | Gin middleware bridge |
| `integration/go.mod` | Testcontainers-only module |
| `integration/redis/redis_test.go` | Redis 6.2/7.4 conformance |
| `go.work` | Root/adapters/integration development workspace |

### Task 1: Build a Default-Deny TestKit

**Files:**
- Create: `testkit/clock.go`
- Create: `testkit/issuer.go`
- Create: `testkit/issuer_test.go`
- Create: `testkit/token.go`
- Create: `testkit/pdp.go`
- Create: `testkit/pdp_test.go`
- Create: `testkit/leak.go`
- Create: `testkit/leak_test.go`

**Interfaces:**
- Consumes: `core.Metadata`, `core.Clock`, `httpauthz.Decision` wire contract.
- Produces: `FixedClock`, `Issuer`, `PDP`, signed tokens, recorded OAuth/PDP calls, leakage assertion.

- [ ] **Step 1: Write failing default-deny and deterministic tests**

```go
func TestPDPDefaultsToDeny(t *testing.T) {
    fake := testkit.NewPDP(t)
    defer fake.Close()
    response, err := http.Post(fake.URL()+"/authorization/v1/decisions", "application/json", strings.NewReader(`{"resource_server":"orders_api","resource":"orders","http_method":"GET"}`))
    if err != nil { t.Fatal(err) }
    defer response.Body.Close()
    var envelope struct { Data struct { Allowed bool `json:"allowed"` } `json:"data"` }
    if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil { t.Fatal(err) }
    if envelope.Data.Allowed { t.Fatal("default fake PDP allowed") }
}

func TestFixedClockIsThreadSafe(t *testing.T) {
    clock := testkit.NewFixedClock(time.Unix(100,0))
    clock.Advance(time.Second)
    if got := clock.Now(); !got.Equal(time.Unix(101,0)) { t.Fatalf("now=%s", got) }
}
```

- [ ] **Step 2: Run tests and verify undefined testkit failures**

Run: `go test ./testkit -count=1`

Expected: FAIL because `testkit` does not exist.

- [ ] **Step 3: Implement exact public test helpers**

```go
type FixedClock struct { mu sync.RWMutex; now time.Time }
func NewFixedClock(now time.Time) *FixedClock
func (c *FixedClock) Now() time.Time
func (c *FixedClock) Advance(delta time.Duration)

type TokenResponse struct { Scope string; Groups []string; OAuthError string; HTTPStatus int }
type Calls struct { Authorize, Token, Refresh, UserInfo, EndSession int; LastTokenForm url.Values }
type Issuer struct {
    t testing.TB
    server *httptest.Server
    key *rsa.PrivateKey
    mu sync.Mutex
    tokenResponse TokenResponse
    calls Calls
}
func NewIssuer(t testing.TB) *Issuer
func (i *Issuer) URL() string
func (i *Issuer) HTTPClient() *http.Client
func (i *Issuer) SetTokenResponse(TokenResponse)
func (i *Issuer) Calls() Calls
func (i *Issuer) Close()

type HTTPDecision struct { HTTPStatus, Code int; Message, DecisionID, ReasonCode string; Allowed bool; Delay time.Duration }
type PDPCall struct { Authorization string; ResourceServer, Resource, HTTPMethod string }
type PDP struct {
    t testing.TB
    server *httptest.Server
    mu sync.Mutex
    queued []HTTPDecision
    calls []PDPCall
}
func NewPDP(t testing.TB) *PDP
func (p *PDP) URL() string
func (p *PDP) Enqueue(HTTPDecision)
func (p *PDP) Calls() []PDPCall
func (p *PDP) Close()
```

`NewIssuer` publishes S256/RS256 Discovery and generates an in-memory RSA test key. `NewPDP` returns a valid envelope with `allowed=false` and `reason_code=default_deny` unless a response was explicitly enqueued. All `Calls` methods return defensive copies. `AssertNoLeak(t, output, secrets...)` fails when any nonempty secret is a substring.

- [ ] **Step 4: Migrate duplicated new-package fakes to testkit without cycles**

Replace only external-package tests (`core_test`, `bff_test`, `httpauthz_test`) with `testkit` helpers. Keep package-internal decoder/unit helpers local where importing testkit would cause an import cycle. Assert existing call counts and leakage behavior remain unchanged.

- [ ] **Step 5: Run root security and race tests**

Run: `gofmt -w testkit && go test ./core ./bff/... ./httpauthz ./testkit -count=1 && go test -race ./testkit -count=1`

Expected: PASS.

- [ ] **Step 6: Commit testkit**

```bash
git add core bff httpauthz testkit
git commit -m "test: add default-deny IAM Core testkit"
```

### Task 2: Create the Redis Adapter Module and Fenced Lua Backend

**Files:**
- Create: `adapters/redis/go.mod`
- Create: `adapters/redis/codec.go`
- Create: `adapters/redis/codec_test.go`
- Create: `adapters/redis/backend.go`
- Create: `adapters/redis/backend_test.go`
- Create: `adapters/redis/scripts.go`
- Create: `adapters/redis/example/main.go`
- Create: `go.work`

**Interfaces:**
- Consumes: root `bff/session.Backend`, `sessiontest.Run`, go-redis `UniversalClient`.
- Produces: `redis.Options`, `redis.Key`, `redis.NewAESGCMCodec`, `redis.New`.

- [ ] **Step 1: Write failing codec and mocked Redis conformance tests**

```go
func TestCodecEncryptsVerifierAndTokens(t *testing.T) {
    codec, err := redisadapter.NewAESGCMCodec(redisadapter.Key{ID:"primary", Bytes:bytes.Repeat([]byte{1},32)}, nil)
    if err != nil { t.Fatal(err) }
    plaintext := []byte(`{"code_verifier":"verifier-secret","access_token":"access-secret"}`)
    sealed, err := codec.Seal(plaintext)
    if err != nil { t.Fatal(err) }
    if bytes.Contains(sealed, []byte("verifier-secret")) || bytes.Contains(sealed, []byte("access-secret")) { t.Fatal("ciphertext contains plaintext") }
    opened, err := codec.Open(sealed)
    if err != nil || !bytes.Equal(opened, plaintext) { t.Fatalf("open=%q err=%v", opened, err) }
}
```

Use the existing repository's Redis fake/mocked command approach to verify exact key namespace, TTL, one-time Flow delete, lease acquisition, fenced CAS script arguments, stale lease rejection, and secret-free errors without Docker.

- [ ] **Step 2: Run adapter tests and verify missing module/package failures**

Run: `cd adapters/redis && go test ./... -count=1`

Expected: FAIL because the module and implementation do not exist.

- [ ] **Step 3: Create the nested module and exact public configuration**

```go
module github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/redis

go 1.24.0

require (
    github.com/redis/go-redis/v9 v9.21.0
    github.com/swan-swan-swan/iam-core-client-sdk-go v0.2.0
)
```

Create the initial workspace before running adapter tests:

```go
go 1.24.0

use (
    .
    ./adapters/redis
)
```

```go
type Key struct { ID string; Bytes []byte }
type Codec interface { Seal([]byte) ([]byte,error); Open([]byte) ([]byte,error) }
func NewAESGCMCodec(primary Key, fallback []Key) (Codec, error)

type Options struct {
    Prefix string
    Codec Codec
    Clock core.Clock
    Random io.Reader
}
func New(client redis.UniversalClient, opts Options) (session.Backend, error)
```

Require a nonempty prefix, codec, clock, random source, valid non-nil Redis client, unique key IDs, and exactly 32-byte AES keys. Key IDs are serialized but key bytes never are.

- [ ] **Step 4: Port and narrow the existing Redis safety implementation**

Port the algorithms from `session/redis/backend.go` and `session/redis/scripts.go` to the new module, adapting names to the Task 3 Session contract. Retain encrypted payloads, namespaced keys, bounded TTLs, random lease owner, fencing counter, and atomic Lua.

The commit script must validate, in one `EVAL`: current lease owner, fence, lease expiry, current Session version, then write the new encrypted Session and delete the lease. The delete script performs the same validations before deleting Session and lease. Return typed `session.ErrLeaseLost` or `session.ErrConflict`; never include Redis values or script arguments in errors.

- [ ] **Step 5: Run adapter unit and race tests**

Run: `gofmt -w adapters/redis && (cd adapters/redis && go test ./... -count=1 && go test -race ./... -count=1 && go vet ./...)`

Expected: PASS without Docker.

- [ ] **Step 6: Commit Redis adapter**

```bash
git add adapters/redis go.work
git commit -m "feat(redis): isolate encrypted session adapter"
```

### Task 3: Create the Gin Adapter Module

**Files:**
- Create: `adapters/gin/go.mod`
- Create: `adapters/gin/gin.go`
- Create: `adapters/gin/gin_test.go`
- Create: `adapters/gin/example/main.go`

**Interfaces:**
- Consumes: `httpauthz.Service`, `httpauthz.Route`, `core.AuthContext`, `httpauthz.Decision`.
- Produces: `ginadapter.Authenticate`, `ginadapter.Require`, `ginadapter.AuthContext`, `ginadapter.Decision`.

- [ ] **Step 1: Write failing Gin allow/deny/context tests**

```go
func TestRequireAdaptsGinWithoutChangingAuthorizationSemantics(t *testing.T) {
    router := gin.New()
    service, route, pdp := newGinService(t, true)
    middleware, err := ginadapter.Require(service, route)
    if err != nil { t.Fatal(err) }
    router.GET("/orders", middleware, func(c *gin.Context) {
        auth, ok := ginadapter.AuthContext(c)
        if !ok || auth.Subject != "op_usr_1" { t.Fatalf("auth=%#v ok=%v", auth, ok) }
        c.Status(http.StatusNoContent)
    })
    response := httptest.NewRecorder()
    request := signedRequest(t, http.MethodGet, "/orders")
    router.ServeHTTP(response, request)
    if response.Code != http.StatusNoContent || pdp.Calls() != 1 { t.Fatalf("status=%d calls=%d", response.Code, pdp.Calls()) }
}
```

Add deny/401/503 cases proving Gin Handler is not called and PDP counts match root middleware.

Implement local helpers in `gin_test.go`: `newGinService(t, allowed) (*httpauthz.Service,httpauthz.Route,*countingAuthorizer)` uses a fake `core.AccessTokenVerifier` and an atomic-count Authorizer; `signedRequest(t,method,path) *http.Request` sets one canonical Bearer header. The deny/401/503 table varies only the Authorizer result and asserts exact status, PDP count, and Gin Handler count.

- [ ] **Step 2: Run adapter tests and verify missing module failures**

Run: `cd adapters/gin && go test ./... -count=1`

Expected: FAIL because the module and package do not exist.

- [ ] **Step 3: Create the nested Gin module**

```go
module github.com/swan-swan-swan/iam-core-client-sdk-go/adapters/gin

go 1.24.0

require (
    github.com/gin-gonic/gin v1.11.0
    github.com/swan-swan-swan/iam-core-client-sdk-go v0.2.0
)
```

- [ ] **Step 4: Implement thin net/http-to-Gin bridging**

```go
func Authenticate(service *httpauthz.Service) (gin.HandlerFunc, error)
func Require(service *httpauthz.Service, route httpauthz.Route) (gin.HandlerFunc, error)
func AuthContext(c *gin.Context) (core.AuthContext, bool)
func Decision(c *gin.Context) (httpauthz.Decision, bool)
```

Each constructor validates non-nil service and invokes the root net/http middleware constructor around a terminal Handler that calls `c.Next()`, propagating construction errors. Abort Gin processing when the root middleware does not reach the terminal Handler. Context helpers read from `c.Request.Context()` and return root defensive copies. Do not duplicate credential parsing, status mapping, PDP calls, logging, or decision headers.

Update `go.work` to include `./adapters/gin` before running this module's tests.

- [ ] **Step 5: Run Gin adapter verification**

Run: `gofmt -w adapters/gin && (cd adapters/gin && go test ./... -count=1 && go test -race ./... -count=1 && go vet ./...)`

Expected: PASS.

- [ ] **Step 6: Commit Gin adapter**

```bash
git add adapters/gin go.work
git commit -m "feat(gin): isolate HTTP authorization adapter"
```

### Task 4: Extend go.work with a Docker-Only Integration Module

**Files:**
- Modify: `go.work`
- Create: `integration/go.mod`
- Create: `integration/redis/redis_test.go`

**Interfaces:**
- Consumes: root module, Redis adapter, Testcontainers Redis module.
- Produces: local workspace orchestration and Redis 6.2/7.4 conformance evidence.

- [ ] **Step 1: Write the Redis version-matrix integration test**

```go
func TestRedisConformance(t *testing.T) {
    for _, image := range []string{"redis:6.2-alpine", "redis:7.4-alpine"} {
        t.Run(image, func(t *testing.T) {
            container, err := rediscontainer.Run(t.Context(), image)
            if err != nil { t.Fatal(err) }
            testcontainers.CleanupContainer(t, container)
            endpoint, err := container.ConnectionString(t.Context())
            if err != nil { t.Fatal(err) }
            parsed, err := url.Parse(endpoint)
            if err != nil { t.Fatal(err) }
            password, _ := parsed.User.Password()
            client := goredis.NewClient(&goredis.Options{Addr:parsed.Host,Password:password})
            t.Cleanup(func(){ _ = client.Close() })
            sessiontest.Run(t, func(t testing.TB, clock *sessiontest.Clock) session.Backend {
                codec, err := redisadapter.NewAESGCMCodec(redisadapter.Key{ID:"test",Bytes:bytes.Repeat([]byte{1},32)}, nil)
                if err != nil { t.Fatal(err) }
                backend, err := redisadapter.New(client, redisadapter.Options{Prefix:"conformance:"+strings.NewReplacer(":","_","/","_").Replace(t.Name()), Codec:codec, Clock:clock, Random:rand.Reader})
                if err != nil { t.Fatal(err) }
                return backend
            })
        })
    }
}
```

- [ ] **Step 2: Create workspace and integration module manifests**

`go.work`:

```go
go 1.24.0

use (
    .
    ./adapters/gin
    ./adapters/redis
    ./integration
)
```

`integration/go.mod` must require root `v0.2.0`, Redis adapter `v0.2.0`, go-redis `v9.21.0`, Testcontainers core/modules Redis `v0.40.0`, and contain no production package.

- [ ] **Step 3: Run Redis 6.2/7.4 conformance on a Docker-capable runner**

Run: `(cd integration && go test ./redis -count=1)`

Expected: PASS for both images. If Docker is unavailable, record the environment failure and run this exact command in CI; do not weaken or skip assertions in code.

- [ ] **Step 4: Commit workspace integration**

```bash
git add go.work integration
git commit -m "test: add isolated Redis integration matrix"
```

### Task 5: Delete Legacy v0.1 and Clean the Root Dependency Graph

**Files:**
- Delete: `authn/`
- Delete: `authz/`
- Delete: `middleware/`
- Delete: `oidc/`
- Delete: `session/`
- Delete: `observability/`
- Delete: `internal/`
- Delete: `client.go`, `client_test.go`, `config.go`, `identity.go`, `errors.go`, `errors_test.go`, `hooks.go`
- Delete: `examples/gin/`, `examples/nethttp/`, `examples/redis/`
- Rename: `examples/nethttp-v2/` to `examples/nethttp/`
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Consumes: all new root/adapters/integration packages.
- Produces: a root module containing only v0.2 packages and dependency-light requirements.

- [ ] **Step 1: Prove new APIs pass before deletion**

Run: `go test ./core ./bff/... ./httpauthz ./testkit ./examples/nethttp-v2 -count=1`

Expected: PASS.

- [ ] **Step 2: Delete the exact legacy paths**

Use `git rm -r` only on the paths listed in this Task after validating each with `git status --short` and `git ls-files <path>`. Do not delete `docs/superpowers`, new `examples/nethttp-v2`, new `core`, `bff`, `httpauthz`, or `testkit`.

After deleting the legacy `examples/nethttp`, run `git mv examples/nethttp-v2 examples/nethttp` so the final public example path matches the design.

- [ ] **Step 3: Reduce root go.mod and tidy every module**

Root `go.mod` retains only dependencies actually imported by `core`, `bff`, `httpauthz`, and `testkit`; expected direct libraries are `go-jose/v4`, `golang-jwt/jwt/v5`, and `x/oauth2` if the final code imports them. Run:

```bash
go mod tidy
go work sync
(cd adapters/gin && go mod tidy)
(cd adapters/redis && go mod tidy)
(cd integration && go mod tidy)
```

- [ ] **Step 4: Assert forbidden root dependencies are absent**

Run:

```bash
if GOWORK=off go list -m all | rg 'gin-gonic|go-redis|docker|testcontainers'; then exit 1; fi
if GOWORK=off go list -deps ./... | rg 'gin-gonic|go-redis|docker|testcontainers'; then exit 1; fi
```

Expected: no matches and zero final exit status.

- [ ] **Step 5: Run all non-Docker module tests after deletion**

Run:

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
(cd adapters/gin && go test ./... -count=1 && go vet ./...)
(cd adapters/redis && go test ./... -count=1 && go vet ./...)
```

Expected: PASS.

- [ ] **Step 6: Commit destructive cleanup**

```bash
git add -A
git commit -m "refactor!: remove legacy v0.1 SDK surface"
```

### Task 6: Rewrite Documentation and Execute Release Gates

**Files:**
- Modify: `README.md`
- Modify: `COMPATIBILITY.md`
- Modify: `CHANGELOG.md`
- Create: `docs/iam-core-v1.8.1-contract.md`
- Create: `docs/migration-v0.1-to-v0.2.md`
- Create: `documentation_test.go`
- Create: `examples/bff/main.go`
- Create: `examples/bff/main_test.go`
- Create: `.github/workflows/ci.yml` if absent, otherwise modify existing workflow

**Interfaces:**
- Consumes: final public APIs and module paths.
- Produces: accurate quickstarts, compatibility statement, breaking-change notice, and CI matrix.

- [ ] **Step 1: Write documentation and example verification tests**

```go
func TestV02DocumentationContract(t *testing.T) {
    read := func(path string) string { raw, err := os.ReadFile(path); if err != nil { t.Fatal(err) }; return string(raw) }
    readme := read("README.md")
    for _, required := range []string{"PKCE S256", "openid profile email groups", "一次 PDP", "RPC 暂不支持", "/adapters/gin", "/adapters/redis"} {
        if !strings.Contains(readme, required) { t.Errorf("README missing %q", required) }
    }
    for _, forbidden := range []string{"openid profile email roles", "iamcore.New(", "PDP 401 时刷新并重试"} {
        if strings.Contains(readme, forbidden) { t.Errorf("README contains legacy claim %q", forbidden) }
    }
    compatibility := read("COMPATIBILITY.md")
    if !strings.Contains(compatibility, "v0.2.x") || !strings.Contains(compatibility, "v1.8.1") || !strings.Contains(compatibility, "不兼容 v0.1") { t.Fatal("compatibility matrix is incomplete") }
}
```

`examples/bff/main_test.go` and `examples/nethttp/main_test.go` run `go build .` in their package directories. Gin/Redis module tests build their local `example` packages.

- [ ] **Step 2: Rewrite README around three supported entry points**

Document only Core/BFF, HTTP Resource Server, and optional Gin/Redis adapters. State explicitly that RPC and IAM management APIs are absent. Show explicit platform Cookie names, default scopes, Manifest binding, one-PDP semantics, local vs central logout, and separate module installation commands.

Implement `examples/bff/main.go` with `core.New`, `bff.New`, `session/memory.New`, explicit `__Host-example_session` and `__Host-example_flow` cookies, and Login/Callback/Me/local-logout/central-logout routes. It reads issuer, Client ID, Client Secret, and Redirect URL from environment and never prints them.

- [ ] **Step 3: Freeze compatibility and migration statements**

`COMPATIBILITY.md` must state `v0.1.x = IAM Core v1.7.1 only` and `v0.2.x = IAM Core v1.8.1`, with no source compatibility. `docs/migration-v0.1-to-v0.2.md` must direct users to replace—not wrap—the root Client and must not offer no-PKCE, roles, bare decision, or dual-credential compatibility flags.

- [ ] **Step 4: Configure CI module matrix**

CI runs root test/vet/race, Gin test/vet, Redis unit test/vet, example builds, dependency forbidden-match checks, and Docker Redis 6.2/7.4 integration on a Docker-capable runner. No job may silently skip a failed security test.

- [ ] **Step 5: Run final release verification from fresh command output**

Run:

```bash
go test ./... -count=1
go vet ./...
go test -race ./... -count=1
(cd adapters/gin && go test ./... -count=1 && go vet ./...)
(cd adapters/redis && go test ./... -count=1 && go vet ./...)
(cd integration && go test ./redis -count=1)
go build ./examples/...
git diff --check
git status --short
```

Expected: all checks pass; status shows only intended Task 6 documentation/CI changes before commit; no secret value appears in output.

- [ ] **Step 6: Commit release documentation**

```bash
git add README.md COMPATIBILITY.md CHANGELOG.md docs documentation_test.go examples/bff .github
git commit -m "docs: prepare IAM Core SDK v0.2.0 release"
```

## Plan Completion Gate

The rewrite is complete only when all module tests and release gates pass, root dependency scans are empty, Redis 6.2/7.4 conformance passes, and `rg -n 'package (authn|authz|middleware|oidc)|type Client struct'` finds no legacy SDK package or root facade. Do not create a release tag or push without a separate explicit user request.
