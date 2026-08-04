# IAM Core SDK v0.2.0 HTTP Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a framework-neutral HTTP Resource Server package with explicit route binding, local JWT authentication, exactly one IAM Core PDP call for every authenticated protected request, and fail-closed net/http middleware.

**Architecture:** `httpauthz` imports `core` but not `bff`. Bearer credentials are verified through `core.Runtime`; BFF Session support is injected through a structural `SessionResolver` interface implemented by `bff.Client`. A compiled local Manifest produces immutable Routes consumed by a strict v1.8.1 PDP client and middleware.

**Tech Stack:** Go 1.24, `net/http`, strict `encoding/json`, root-module `core` and `bff`, table-driven/fuzz/race tests.

## Global Constraints

- Complete `2026-08-03-iam-core-sdk-v0.2-core-bff.md` first.
- PDP endpoint: `POST /authorization/v1/decisions`.
- PDP request body contains exactly `resource_server`, `resource`, and `http_method`.
- Application, Client, subject, roles, groups, Action, route path, and route template never enter the PDP body.
- Every authenticated protected request calls PDP exactly once; invalid/missing/conflicting credentials call PDP zero times.
- Middleware never calls UserInfo, never retries PDP, never reacts to PDP 401 by refreshing, and never caches allow/deny.
- Only HTTP 200 + envelope `code=0` + valid decision + `allowed=true` invokes the Handler.
- Cookie plus Bearer is always `credential_conflict`, even if both refer to the same token.
- Unknown non-conflicting fields in a valid v1.8.x envelope are allowed; duplicate keys, trailing JSON, bare decisions, and invalid required fields are rejected.
- No Gin or Redis dependency in the root module.
- Design source: `docs/superpowers/specs/2026-08-03-iam-core-go-client-sdk-v0.2-design.md`.

---

## File Map

| Path | Responsibility |
| --- | --- |
| `httpauthz/decision.go` | Decision and request models |
| `httpauthz/client.go` | Strict PDP HTTP client |
| `httpauthz/decode.go` | Duplicate-safe v1.8.1 envelope decoder |
| `httpauthz/manifest.go` | Manifest compilation and binding coverage |
| `httpauthz/credential.go` | Bearer/Session credential selection |
| `httpauthz/service.go` | Construction and dependency validation |
| `httpauthz/middleware.go` | net/http authentication/authorization middleware |
| `httpauthz/context.go` | Decision Context helpers |
| `httpauthz/responder.go` | Safe default and custom error responses |

### Task 1: Implement the Strict IAM Core v1.8.1 PDP Client

**Files:**
- Create: `httpauthz/decision.go`
- Create: `httpauthz/client.go`
- Create: `httpauthz/client_test.go`
- Create: `httpauthz/decode.go`
- Create: `httpauthz/decode_test.go`
- Create: `httpauthz/decode_fuzz_test.go`

**Interfaces:**
- Consumes: `core.Error`, `core.Observer`, `core.TokenSource`.
- Produces: opaque `httpauthz.Route`, `httpauthz.Decision`, `httpauthz.PDPConfig`, `httpauthz.PDPClient`, `NewPDPClient`, `Decide`.

- [ ] **Step 1: Write failing request-shape, response, and single-attempt tests**

```go
// client_test.go uses package httpauthz so it can construct an internal compiled Route fixture.
func TestDecideSendsOnlyFrozenThreeFields(t *testing.T) {
    var body map[string]json.RawMessage
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/authorization/v1/decisions" || r.Method != http.MethodPost { t.Fatalf("request=%s %s", r.Method, r.URL.Path) }
        if got := r.Header.Get("Authorization"); got != "Bearer access-token" { t.Fatalf("authorization=%q", got) }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil { t.Fatal(err) }
        w.Header().Set("Content-Type", "application/json")
        io.WriteString(w, `{"code":0,"message":"success","data":{"decision_id":"dec-1","allowed":true,"reason_code":"policy_allow"},"request_id":"req-1","trace_id":"trace-1"}`)
    }))
    defer server.Close()
    client, err := NewPDPClient(PDPConfig{IssuerURL: server.URL, HTTPClient: server.Client()})
    if err != nil { t.Fatal(err) }
    decision, err := client.Decide(t.Context(), core.TokenSourceFunc(func(context.Context)(string,error){ return "access-token", nil }), Route{method:"GET", resourceServer:"orders_api", resource:"orders", compiled:true})
    if err != nil || !decision.Allowed { t.Fatalf("decision=%#v err=%v", decision, err) }
    if got := slices.Sorted(maps.Keys(body)); !slices.Equal(got, []string{"http_method","resource","resource_server"}) { t.Fatalf("keys=%v", got) }
}

func TestDecideNeverRetries(t *testing.T) {
    var calls atomic.Int32
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); http.Error(w, "unavailable", http.StatusServiceUnavailable) }))
    defer server.Close()
    client, _ := NewPDPClient(PDPConfig{IssuerURL: server.URL, HTTPClient: server.Client()})
    tokens := core.TokenSourceFunc(func(context.Context)(string,error){ return "token", nil })
    _, _ = client.Decide(t.Context(), tokens, Route{method:"GET",resourceServer:"orders_api",resource:"orders",compiled:true})
    if calls.Load() != 1 { t.Fatalf("calls=%d", calls.Load()) }
}
```

Add table tests for allow, deny, 400, 401, 503, timeout, network error, non-JSON body, oversized body, nonzero code, missing/empty message, missing/empty decision ID, missing/empty reason code, wrong `allowed` type, bare response, duplicate keys, trailing JSON, and additive unknown fields.

- [ ] **Step 2: Run focused tests and verify undefined package failures**

Run: `go test ./httpauthz -run 'TestDecide|TestDecode' -count=1`

Expected: FAIL because `httpauthz` does not exist.

- [ ] **Step 3: Implement the exact PDP public contract**

```go
type Decision struct {
    ID string
    Allowed bool
    ReasonCode string
    RequestID string
    TraceID string
}
type Route struct { method, resourceServer, resource string; compiled bool }
func (r Route) Method() string { return r.method }
func (r Route) ResourceServer() string { return r.resourceServer }
func (r Route) Resource() string { return r.resource }

type PDPConfig struct {
    IssuerURL string
    HTTPClient *http.Client
    Timeout time.Duration
    Observer core.Observer
    Logger *slog.Logger
}

type PDPClient struct {
    endpoint string
    httpClient *http.Client
    timeout time.Duration
    observer core.Observer
    logger *slog.Logger
}
func NewPDPClient(cfg PDPConfig) (*PDPClient, error)
func (c *PDPClient) Decide(ctx context.Context, tokens core.TokenSource, route Route) (Decision, error)
```

Construct the endpoint as normalized issuer plus `/authorization/v1/decisions`; reject issuer query, fragment, userinfo, non-HTTPS except loopback, and negative timeout. Clone caller HTTP client, clear Jar, and disable redirects.

Encode only this private wire type:

```go
type decisionRequest struct {
    ResourceServer string `json:"resource_server"`
    Resource string `json:"resource"`
    HTTPMethod string `json:"http_method"`
}
```

- [ ] **Step 4: Implement the duplicate-safe envelope decoder**

Use a token-walking helper to reject duplicate keys at both envelope and `data` levels before normal unmarshalling. Require exactly one JSON value. Decode:

```go
type decisionEnvelope struct {
    Code int `json:"code"`
    Message string `json:"message"`
    Data struct {
        DecisionID string `json:"decision_id"`
        Allowed bool `json:"allowed"`
        ReasonCode string `json:"reason_code"`
    } `json:"data"`
    RequestID string `json:"request_id"`
    TraceID string `json:"trace_id"`
}
```

Reject `code != 0`, blank/space-padded required strings, control characters in correlation IDs, and any body larger than 1 MiB. Preserve additive unknown fields. Map 401 to `KindUnauthenticated`, 503/timeout/network to `KindIAMUnavailable`, and 400/other unexpected status to `KindProtocol`; never include response body or token in returned errors.

- [ ] **Step 5: Run client, fuzz, and race tests**

Run: `gofmt -w httpauthz && go test ./httpauthz -run 'TestDecide|TestDecode' -count=1 && go test -race ./httpauthz -run 'TestDecide' -count=1 && go test ./httpauthz -run FuzzDecodeDecision -fuzz FuzzDecodeDecision -fuzztime=5s`

Expected: PASS with one request per `Decide` call and no token/body leakage.

- [ ] **Step 6: Commit the PDP client**

```bash
git add httpauthz
git commit -m "feat(httpauthz): add strict v1.8.1 PDP client"
```

### Task 2: Implement Immutable Route Manifest and Binding Validation

**Files:**
- Create: `httpauthz/manifest.go`
- Create: `httpauthz/manifest_test.go`

**Interfaces:**
- Consumes: `core.Error`.
- Consumes: immutable `Route` values defined by Task 1.
- Produces: `RouteSpec`, `Manifest`, `Binder`, `CompileManifest`, `Bind`, `Validate`.

- [ ] **Step 1: Write failing route and coverage tests**

```go
func TestManifestRejectsInvalidOrDuplicateRoutes(t *testing.T) {
    tests := []struct{name string; specs []httpauthz.RouteSpec}{
        {"lower method", []httpauthz.RouteSpec{{Name:"list", Method:"get", ResourceServer:"orders_api", Resource:"orders"}}},
        {"duplicate name", []httpauthz.RouteSpec{{Name:"list", Method:"GET", ResourceServer:"orders_api", Resource:"orders"},{Name:"list", Method:"POST", ResourceServer:"orders_api", Resource:"orders"}}},
        {"duplicate canonical binding", []httpauthz.RouteSpec{{Name:"one", Method:"GET", ResourceServer:"orders_api", Resource:"orders"},{Name:"two", Method:"GET", ResourceServer:"orders_api", Resource:"orders"}}},
    }
    for _, tt := range tests { t.Run(tt.name, func(t *testing.T) { if _, err := httpauthz.CompileManifest(tt.specs); err == nil { t.Fatal("error=nil") } }) }
}

func TestBinderRequiresEveryManifestRouteExactlyOnce(t *testing.T) {
    manifest, _ := httpauthz.CompileManifest([]httpauthz.RouteSpec{{Name:"list_orders",Method:"GET",ResourceServer:"orders_api",Resource:"orders"}})
    binder := manifest.NewBinder()
    if err := binder.Validate(); err == nil { t.Fatal("unbound route accepted") }
    if _, err := binder.Bind("list_orders"); err != nil { t.Fatal(err) }
    if _, err := binder.Bind("list_orders"); err == nil { t.Fatal("duplicate bind accepted") }
    if err := binder.Validate(); err != nil { t.Fatal(err) }
}
```

- [ ] **Step 2: Run manifest tests and verify failures**

Run: `go test ./httpauthz -run 'TestManifest|TestBinder' -count=1`

Expected: FAIL with undefined manifest symbols.

- [ ] **Step 3: Implement the exact manifest types**

```go
type RouteSpec struct { Name, Method, ResourceServer, Resource string }
type Manifest struct { routes map[string]Route }
type Binder struct { manifest *Manifest; mu sync.Mutex; bound map[string]struct{} }

func CompileManifest(specs []RouteSpec) (*Manifest, error)
func (m *Manifest) NewBinder() *Binder
func (b *Binder) Bind(name string) (Route, error)
func (b *Binder) Validate() error
```

Allow standard methods `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `CONNECT`, `OPTIONS`, and `TRACE`. Reject empty/trim-changing values, duplicate names, and duplicate `(Method,ResourceServer,Resource)` tuples. Copy every input into `Route{method:spec.Method,resourceServer:spec.ResourceServer,resource:spec.Resource,compiled:true}`. `Bind` returns a value-only immutable Route and records the name once under mutex. `Validate` returns invalid-config until every declared name is bound once. No public API can manufacture a Route without Manifest compilation.

- [ ] **Step 4: Run manifest and race tests**

Run: `gofmt -w httpauthz/manifest*.go && go test ./httpauthz -run 'TestManifest|TestBinder' -count=1 && go test -race ./httpauthz -run TestBinder -count=1`

Expected: PASS.

- [ ] **Step 5: Commit Route Manifest**

```bash
git add httpauthz/manifest.go httpauthz/manifest_test.go
git commit -m "feat(httpauthz): compile explicit route manifest"
```

### Task 3: Implement Credential Selection and Fail-Closed net/http Middleware

**Files:**
- Create: `httpauthz/context.go`
- Create: `httpauthz/context_test.go`
- Create: `httpauthz/credential.go`
- Create: `httpauthz/credential_test.go`
- Create: `httpauthz/credential_fuzz_test.go`
- Create: `httpauthz/responder.go`
- Create: `httpauthz/responder_test.go`
- Create: `httpauthz/service.go`
- Create: `httpauthz/service_test.go`
- Create: `httpauthz/middleware.go`
- Create: `httpauthz/middleware_test.go`

**Interfaces:**
- Consumes: `core.AccessTokenVerifier`, `core.Credential`, `core.TokenSource`, `PDPClient`, `Route`.
- Produces: `SessionResolver`, `ErrorResponder`, `Config`, `Service`, `New`, `Authenticate`, `Require`, `DecisionFromContext`.

- [ ] **Step 1: Write failing credential-conflict and middleware call-count tests**

```go
func TestRequirePermissionCallCounts(t *testing.T) {
    tests := []struct{name string; decision httpauthz.Decision; pdpErr error; wantStatus, wantPDP, wantHandler int}{
        {"allow", httpauthz.Decision{ID:"d1",Allowed:true,ReasonCode:"policy_allow"}, nil, 200, 1, 1},
        {"deny", httpauthz.Decision{ID:"d2",Allowed:false,ReasonCode:"default_deny"}, nil, 403, 1, 0},
        {"unauthorized", httpauthz.Decision{}, core.NewError(core.KindUnauthenticated,"httpauthz.decide",401,false,nil), 401, 1, 0},
        {"unavailable", httpauthz.Decision{}, core.NewError(core.KindIAMUnavailable,"httpauthz.decide",503,true,nil), 503, 1, 0},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            verifier := &fakeVerifier{auth:core.AuthContext{Subject:"op_usr_1",Issuer:"https://iam.example",Audience:[]string{"portal"},TokenID:"jti-1",ExpiresAt:time.Now().Add(time.Minute),Scopes:[]string{"openid"}}}
            pdp := &fakeAuthorizer{decision:tt.decision, err:tt.pdpErr}
            service, err := httpauthz.New(httpauthz.Config{Verifier:verifier,PDP:pdp})
            if err != nil { t.Fatal(err) }
            var handlerCalls int
            next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request){ handlerCalls++; w.WriteHeader(http.StatusOK) })
            request := httptest.NewRequest(http.MethodGet, "/orders", nil)
            request.Header.Set("Authorization", "Bearer access-token")
            response := httptest.NewRecorder()
            handler, err := service.Require(boundRoute(t), next)
            if err != nil { t.Fatal(err) }
            handler.ServeHTTP(response, request)
            if response.Code != tt.wantStatus || pdp.calls != tt.wantPDP || handlerCalls != tt.wantHandler { t.Fatalf("status/pdp/handler=%d/%d/%d",response.Code,pdp.calls,handlerCalls) }
        })
    }
}

func TestCookieAndBearerAlwaysConflict(t *testing.T) {
    request := httptest.NewRequest(http.MethodGet, "/orders", nil)
    request.Header.Set("Authorization", "Bearer same-token")
    resolver := &fakeSessionResolver{present:true, credential:credentialWithToken("same-token")}
    service, err := httpauthz.New(httpauthz.Config{Verifier:&fakeVerifier{},PDP:&fakeAuthorizer{decision:httpauthz.Decision{ID:"d1",Allowed:true,ReasonCode:"policy_allow"}},Sessions:resolver})
    if err != nil { t.Fatal(err) }
    response := httptest.NewRecorder()
    handler, err := service.Authenticate(http.HandlerFunc(func(http.ResponseWriter,*http.Request){ t.Fatal("handler called") }))
    if err != nil { t.Fatal(err) }
    handler.ServeHTTP(response, request)
    if response.Code != http.StatusUnauthorized || resolver.presentCalls != 1 || resolver.resolveCalls != 0 { t.Fatalf("status/present/resolve=%d/%d/%d", response.Code, resolver.presentCalls, resolver.resolveCalls) }
}

type fakeVerifier struct { auth core.AuthContext; err error; calls int }
func (f *fakeVerifier) VerifyAccessToken(context.Context,string)(core.AuthContext,error){ f.calls++; return f.auth,f.err }
type fakeAuthorizer struct { decision httpauthz.Decision; err error; calls int }
func (f *fakeAuthorizer) Decide(context.Context,core.TokenSource,httpauthz.Route)(httpauthz.Decision,error){ f.calls++; return f.decision,f.err }
type fakeSessionResolver struct { credential core.Credential; present bool; err error; presentCalls, resolveCalls int }
func (f *fakeSessionResolver) SessionPresent(*http.Request)(bool,error){ f.presentCalls++; return f.present,f.err }
func (f *fakeSessionResolver) ResolveSession(*http.Request)(core.Credential,bool,error){ f.resolveCalls++; return f.credential,f.present,f.err }
func credentialWithToken(token string) core.Credential {
    return core.Credential{Source:core.CredentialSession,SessionID:"session-1",Auth:core.AuthContext{Subject:"op_usr_1"},Tokens:core.TokenSourceFunc(func(context.Context)(string,error){return token,nil})}
}
func boundRoute(t *testing.T) httpauthz.Route {
    t.Helper()
    manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{Name:"list_orders",Method:"GET",ResourceServer:"orders_api",Resource:"orders"}})
    if err != nil { t.Fatal(err) }
    binder := manifest.NewBinder()
    route, err := binder.Bind("list_orders")
    if err != nil { t.Fatal(err) }
    if err := binder.Validate(); err != nil { t.Fatal(err) }
    return route
}
```

Add tests for missing token, malformed/multiple Authorization header, local JWT failure, Session-only credential, Bearer-only credential, request Method mismatch, nil Handler/config, Decision/Auth Context defensive copies, Decision ID response-header safety, and zero UserInfo dependency.

- [ ] **Step 2: Run focused middleware tests and verify missing APIs**

Run: `go test ./httpauthz -run 'TestRequire|TestCookieAndBearer|TestAuthenticate|TestResponder|TestDecisionFromContext' -count=1`

Expected: FAIL because `Service` and middleware APIs are undefined.

- [ ] **Step 3: Implement exact construction and extension interfaces**

```go
type SessionResolver interface {
    SessionPresent(*http.Request) (bool, error)
    ResolveSession(*http.Request) (core.Credential, bool, error)
}
type Authorizer interface {
    Decide(context.Context, core.TokenSource, Route) (Decision, error)
}
type ErrorResponder interface {
    Respond(http.ResponseWriter, *http.Request, error)
}
type ErrorResponderFunc func(http.ResponseWriter, *http.Request, error)
func (f ErrorResponderFunc) Respond(w http.ResponseWriter, r *http.Request, err error) { f(w,r,err) }

type Config struct {
    Verifier core.AccessTokenVerifier
    PDP Authorizer
    Sessions SessionResolver
    Responder ErrorResponder
    Observer core.Observer
    Logger *slog.Logger
}
type Service struct {
    verifier core.AccessTokenVerifier
    pdp Authorizer
    sessions SessionResolver
    responder ErrorResponder
    observer core.Observer
    logger *slog.Logger
}
func New(cfg Config) (*Service, error)
func (s *Service) Authenticate(next http.Handler) (http.Handler, error)
func (s *Service) Require(route Route, next http.Handler) (http.Handler, error)
func DecisionFromContext(context.Context) (Decision, bool)
func CredentialSourceFromContext(context.Context) (core.CredentialSource, bool)
```

`Verifier` and `PDP` are mandatory. `Sessions` is optional for Bearer-only APIs. Nil/typed-nil dependencies fail at construction using reflection limited to interface nil detection. `Authenticate` and `Require` reject nil/typed-nil Handler and invalid Route immediately, returning an error instead of an executable configuration-error Handler.

- [ ] **Step 4: Implement deterministic credential selection**

Inspect Authorization header presence and call `Sessions.SessionPresent` once when configured. Reject multiple Authorization values, noncanonical `Bearer ` prefix, whitespace inside token, and any simultaneous Session presence before token verification, Session loading, or refresh. Bearer mode calls `Verifier.VerifyAccessToken` once and creates a request-scoped TokenSource. Session-only mode calls `ResolveSession` once and trusts only the resolver's already-validated AuthContext and TokenSource. Require nonempty subject and TokenSource in both modes.

- [ ] **Step 5: Implement authentication and authorization middleware**

`Authenticate` injects a cloned AuthContext and credential source, then invokes Handler once. `Require` additionally compares `request.Method` to compiled Route Method, calls PDP once, injects Decision plus `DecisionID`/`ReasonCode` into a cloned AuthContext, sets `X-IAM-Decision-ID` only for safe printable values, returns 403 for deny, and invokes Handler only for allow.

Default responder mapping:

```go
switch typed.Kind {
case core.KindUnauthenticated, core.KindCredentialConflict: status = http.StatusUnauthorized
case core.KindForbidden: status = http.StatusForbidden
case core.KindInvalidConfig, core.KindProtocol: status = http.StatusBadRequest
case core.KindIAMUnavailable, core.KindSessionUnavailable: status = http.StatusServiceUnavailable
default: status = http.StatusServiceUnavailable
}
http.Error(w, http.StatusText(status), status)
```

Never serialize `err.Error()`, cause, token, Cookie, or remote response body.

- [ ] **Step 6: Prove `bff.Client` structurally implements SessionResolver**

Add this compile-time assertion to `bff/session_resolver_test.go` without importing `httpauthz` from production BFF code:

```go
var _ httpauthz.SessionResolver = (*bff.Client)(nil)
```

Run: `go test ./bff ./httpauthz -run 'TestCookieAndBearer|TestRequire|TestResolveSession' -count=1`.

Expected: PASS and no import cycle.

- [ ] **Step 7: Run full HTTP authorization verification**

Run: `gofmt -w httpauthz bff/session_resolver_test.go && go test ./httpauthz ./bff -count=1 && go test -race ./httpauthz ./bff -count=1 && go test ./httpauthz -run FuzzCredentialHeader -fuzz FuzzCredentialHeader -fuzztime=5s && go vet ./httpauthz ./bff`

Expected: PASS; each authenticated protected request has PDP count exactly one, UserInfo count zero, and Handler count zero or one according to the matrix.

- [ ] **Step 8: Commit net/http authorization**

```bash
git add httpauthz bff/session_resolver_test.go
git commit -m "feat(httpauthz): enforce one fail-closed PDP decision"
```

### Task 4: Add a Runnable net/http Resource Server Example and Contract Gate

**Files:**
- Create: `examples/nethttp-v2/main.go`
- Create: `examples/nethttp-v2/main_test.go`
- Modify: `contract_v181_test.go`

**Interfaces:**
- Consumes: `core.New`, `httpauthz.CompileManifest`, `httpauthz.NewPDPClient`, `httpauthz.New`.
- Produces: a compiling Bearer-only Resource Server with no BFF/Session/Redis dependency.

- [ ] **Step 1: Write the example compile test**

```go
func TestExampleBuilds(t *testing.T) {
    command := exec.Command("go", "build", ".")
    command.Dir = "."
    if output, err := command.CombinedOutput(); err != nil { t.Fatalf("go build: %v\n%s", err, output) }
}
```

- [ ] **Step 2: Implement the minimal example**

Configure Core with issuer/audience, compile a Manifest containing `list_orders`, bind it once, build PDP/Service, call `protected, err := service.Require(route, http.HandlerFunc(listOrders))`, register `protected` only after `err == nil`, call `binder.Validate()` before `ListenAndServe`, and read configuration only from environment. Do not create a Client Secret, Redirect URL, Cookie, or Session Backend.

- [ ] **Step 3: Activate the root single-PDP contract assertion**

Use a fake Authorizer counter and assert `httpauthz.Service.Require` performs one Decide call for allow and zero calls for invalid bearer. Keep this test self-contained and token-redacted.

- [ ] **Step 4: Run Plan 2 completion gate**

Run:

```bash
go test ./core ./bff/... ./httpauthz ./examples/nethttp-v2 -count=1
go test -race ./core ./bff/... ./httpauthz -count=1
go vet ./core ./bff/... ./httpauthz ./examples/nethttp-v2
```

Expected: PASS.

- [ ] **Step 5: Commit the example and contract gate**

```bash
git add examples/nethttp-v2 contract_v181_test.go
git commit -m "docs: add v0.2 net/http authorization example"
```

## Plan Completion Gate

Do not start adapter/release cleanup until all commands in Task 4 pass and `go list -deps ./examples/nethttp-v2` contains neither Gin, Redis, Docker, nor Testcontainers package paths.
