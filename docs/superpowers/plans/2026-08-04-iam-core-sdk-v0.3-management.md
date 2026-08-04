# IAM Core Go SDK v0.3.0 Management and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all 42 approved IAM Core platform-integration Management endpoints as hand-written, strongly typed Go clients and release them with the migrated Runtime as `v0.3.0`.

**Architecture:** `management/client` owns injected Bearer authentication, one-attempt HTTP transport, strict envelopes, safe errors, metadata, observation, and sensitive values. Six domain packages own paths, queries, request/response models, validation, and conflict payloads; domain packages depend only on the shared client and never call each other. The final task updates examples, compatibility, repository documentation, CI, and three release tags.

**Tech Stack:** Go 1.24, `net/http`, `encoding/json`, `net/url`, `httptest`, existing IAM Core v1.8.1 JSON envelope, GitHub Actions.

## Global Constraints

- Complete `docs/superpowers/plans/2026-08-04-iam-core-sdk-v0.3-runtime-migration.md` first.
- Module path: `github.com/swan-swan-swan/iam-core-sdk-go`.
- Management authentication is only an injected `TokenSource`; no username/password login and no `client_credentials`.
- Every SDK call obtains one token and sends at most one HTTP request; no automatic refresh or retry.
- Scope is limited to applications, OIDC clients and credentials, admission, group mappings, HTTP catalog, and policy documents/compiled rules.
- Users, organizations, global roles, Cloud Provider, login-admission audit, and authorization-decision audit clients are absent.
- No auto-provisioning, aggregate `Ensure*` operation, startup registration, or cross-domain orchestration.
- No RPC package, transport, adapter, example, or direct production dependency.
- Runtime behavior remains unchanged from v0.2.0.
- Design source: `docs/superpowers/specs/2026-08-04-iam-core-sdk-v0.3-runtime-management-design.md`.

---

## File Map

| Path | Responsibility |
| --- | --- |
| `management/client/config.go` | Config, URL and HTTP client validation |
| `management/client/token.go` | Injected TokenSource |
| `management/client/request.go` | Request, Transport, Metadata, shared Page |
| `management/client/transport.go` | One-attempt HTTP execution |
| `management/client/decode.go` | Duplicate-safe envelope decoding |
| `management/client/error.go` | Stable safe error kinds and structured error data |
| `management/client/observe.go` | Low-cardinality observer event |
| `management/client/sensitive.go` | Redacted one-time secret wrapper |
| `management/applications/` | Six Application endpoints |
| `management/oidcclients/` | Seven OIDC Client/security/credential endpoints |
| `management/admission/` | Eight Application/Client admission endpoints |
| `management/groupmappings/` | Four Client group-mapping endpoints |
| `management/catalog/` | Ten HTTP Resource Catalog endpoints |
| `management/policies/` | Seven Policy Document/compiled-rule endpoints |
| `management/testdata/contract-v1.8.1.json` | Frozen list of the 42 supported endpoints |
| `examples/management/` | Injected-token read and revision-controlled write example |

### Task 1: Freeze the Approved Management Endpoint Contract

**Files:**
- Create: `management/testdata/contract-v1.8.1.json`
- Create: `management/contract_test.go`
- Test: `management/contract_test.go`

**Interfaces:**
- Consumes: approved scope and current IAM Core v1.8.1 handlers.
- Produces: an executable exact set of 42 HTTP method/path pairs.

- [ ] **Step 1: Write the failing fixture validation test**

Write `TestApprovedManagementContract` so it loads `testdata/contract-v1.8.1.json`, requires exactly 42 entries, rejects duplicate method/path pairs, rejects unknown domains, and rejects paths outside `/api/v1/`. Do not test for package directories here; package-to-fixture coverage is added after all domains exist in Task 10.

- [ ] **Step 2: Run the test and verify the missing fixture failure**

Run: `go test ./management -run TestApprovedManagementContract -count=1`

Expected: FAIL because `testdata/contract-v1.8.1.json` does not exist.

- [ ] **Step 3: Create the exact endpoint fixture**

Store a JSON array of objects with `domain`, `method`, and `path`. The fixture must contain exactly:

```text
applications GET    /api/v1/applications
applications POST   /api/v1/applications
applications GET    /api/v1/applications/{application_open_id}
applications PUT    /api/v1/applications/{application_open_id}
applications PUT    /api/v1/applications/{application_open_id}/status
applications DELETE /api/v1/applications/{application_open_id}

oidcclients GET    /api/v1/applications/{application_open_id}/oidc-clients
oidcclients POST   /api/v1/applications/{application_open_id}/oidc-clients
oidcclients GET    /api/v1/oidc-clients/{client_id}
oidcclients GET    /api/v1/oidc-clients/{client_id}/security
oidcclients PUT    /api/v1/oidc-clients/{client_id}/security
oidcclients POST   /api/v1/oidc-clients/{client_id}/credentials
oidcclients DELETE /api/v1/oidc-clients/{client_id}/credentials/{credential_id}

admission GET    /api/v1/applications/{application_open_id}/login-admission-rules
admission POST   /api/v1/applications/{application_open_id}/login-admission-rules
admission PUT    /api/v1/applications/{application_open_id}/login-admission-rules/{rule_open_id}
admission DELETE /api/v1/applications/{application_open_id}/login-admission-rules/{rule_open_id}
admission GET    /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules
admission POST   /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules
admission PUT    /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules/{rule_open_id}
admission DELETE /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/login-admission-rules/{rule_open_id}

groupmappings GET    /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings
groupmappings POST   /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings
groupmappings PUT    /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings/{role_open_id}
groupmappings DELETE /api/v1/applications/{application_open_id}/oidc-clients/{client_id}/group-mappings/{role_open_id}

catalog GET    /api/v1/applications/{application_open_id}/http-resource-catalog
catalog POST   /api/v1/applications/{application_open_id}/http-resource-servers
catalog PUT    /api/v1/applications/{application_open_id}/http-resource-servers/{resource_server_open_id}
catalog POST   /api/v1/applications/{application_open_id}/http-resources
catalog PUT    /api/v1/applications/{application_open_id}/http-resources/{resource_open_id}
catalog POST   /api/v1/applications/{application_open_id}/http-actions
catalog PUT    /api/v1/applications/{application_open_id}/http-actions/{action_open_id}
catalog PUT    /api/v1/applications/{application_open_id}/http-method-mappings
catalog POST   /api/v1/applications/{application_open_id}/http-resource-catalog/publish
catalog DELETE /api/v1/applications/{application_open_id}/http-resource-catalog/{entity_type}/{entity_open_id}

policies GET  /api/v1/policy-documents
policies GET  /api/v1/policy-documents/{policy_document_open_id}
policies POST /api/v1/policy-documents
policies PUT  /api/v1/policy-documents/{policy_document_open_id}
policies POST /api/v1/policy-documents/preview
policies PUT  /api/v1/policy-documents/{policy_document_open_id}/bindings
policies GET  /api/v1/policy-compiled-rules
```

- [ ] **Step 4: Run and verify the frozen fixture**

Run: `go test ./management -run TestApprovedManagementContract -count=1`

Expected: PASS with 42 unique approved endpoints.

- [ ] **Step 5: Commit the frozen contract**

```bash
git add management/testdata management/contract_test.go
git commit -m "test(management): freeze v1.8.1 endpoint contract"
```

### Task 2: Implement Safe Shared Types, Errors, and Sensitive Values

**Files:**
- Create: `management/client/token.go`
- Create: `management/client/request.go`
- Create: `management/client/error.go`
- Create: `management/client/observe.go`
- Create: `management/client/sensitive.go`
- Create: `management/client/error_test.go`
- Create: `management/client/sensitive_test.go`

**Interfaces:**
- Produces: `TokenSource`, `Metadata`, `Request`, `Transport`, `Kind`, `Error`, `Observer`, `Event`, `SensitiveString`.

- [ ] **Step 1: Write failing safe-format and error tests**

Cover every `fmt` verb used by `fmt.Sprint`, `fmt.Sprintf("%v")`, `fmt.Sprintf("%+v")`, and `fmt.Sprintf("%#v")`; all must return `[REDACTED]` for a secret. Verify `Error.Error()` contains operation/kind/status but not Token, raw body, query, or Secret. Verify `errors.Is` can match error Kind sentinels.

- [ ] **Step 2: Define the shared public contracts**

```go
type TokenSource interface {
	AccessToken(context.Context) (string, error)
}

type Metadata struct {
	RequestID string
	TraceID   string
}

type Request struct {
	Operation      string
	Method         string
	Path           string
	Query          url.Values
	Body           any
	IdempotencyKey string
}

type Transport interface {
	Do(ctx context.Context, request Request, out any) (Metadata, error)
}

type Page[T any] struct {
	Items    []T
	Page     int
	PageSize int
	Total    int64
}
```

`Request.Path` must be a canonical `/api/v1/...` path without query or fragment. Domain packages pass only validated path segments.

- [ ] **Step 3: Implement exact error kinds**

```go
type Kind string

const (
	KindInvalidConfig Kind = "invalid_config"
	KindInvalidArgument Kind = "invalid_argument"
	KindUnauthenticated Kind = "unauthenticated"
	KindForbidden Kind = "forbidden"
	KindNotFound Kind = "not_found"
	KindConflict Kind = "conflict"
	KindRateLimited Kind = "rate_limited"
	KindIAMUnavailable Kind = "iam_unavailable"
	KindProtocol Kind = "protocol"
)

type Error struct {
	Kind       Kind
	Operation  string
	StatusCode int
	IAMCode    int
	Retryable  bool
	RequestID  string
	TraceID    string
	Data       json.RawMessage
}

var (
	ErrInvalidConfig  = &Error{Kind: KindInvalidConfig}
	ErrInvalidArgument = &Error{Kind: KindInvalidArgument}
	ErrUnauthenticated = &Error{Kind: KindUnauthenticated}
	ErrForbidden       = &Error{Kind: KindForbidden}
	ErrNotFound        = &Error{Kind: KindNotFound}
	ErrConflict        = &Error{Kind: KindConflict}
	ErrRateLimited     = &Error{Kind: KindRateLimited}
	ErrIAMUnavailable  = &Error{Kind: KindIAMUnavailable}
	ErrProtocol        = &Error{Kind: KindProtocol}
)
```

Implement sanitized `Error()`, `Is`, and `ErrorData(err, out) bool`. Copy `Data` defensively, cap it with the response body limit, and never include it in `Error()`.

- [ ] **Step 4: Implement observation and sensitive values**

```go
type Event struct {
	Operation  string
	Outcome    string
	StatusCode int
	Duration   time.Duration
}

type Observer interface {
	Observe(context.Context, Event)
}

type SensitiveString struct{ value string }

func NewSensitiveString(value string) SensitiveString
func (s SensitiveString) Reveal() string
func (s SensitiveString) String() string
func (s SensitiveString) GoString() string
func (s SensitiveString) Format(fmt.State, rune)
```

`Reveal` is the only method returning the raw value. Do not implement JSON or text marshaling that can expose it.

- [ ] **Step 5: Run tests and commit**

```bash
gofmt -w $(rg --files management/client -g '*.go')
go test ./management/client -run 'TestError|TestSensitive' -count=1
go test -race ./management/client -count=1
git add management/client
git commit -m "feat(management): add safe shared client types"
```

### Task 3: Implement Strict One-Attempt HTTP Transport

**Files:**
- Create: `management/client/config.go`
- Create: `management/client/decode.go`
- Create: `management/client/transport.go`
- Create: `management/client/testserver_test.go`
- Create: `management/client/config_test.go`
- Create: `management/client/decode_test.go`
- Create: `management/client/decode_fuzz_test.go`
- Create: `management/client/transport_test.go`

**Interfaces:**
- Consumes: Task 2 shared contracts.
- Produces: `Config`, `Client`, `New`, and `(*Client).Do`.

- [ ] **Step 1: Write failing construction and request-count tests**

Test rejection of empty/non-HTTPS Base URL, URL userinfo/query/fragment, missing TokenSource, negative timeout, redirect responses, oversized responses, and a caller HTTP Client with a Cookie Jar. Verify the SDK clones the client and clears the Jar without mutating the caller.

Use atomics to assert one `AccessToken` call and one server call for success, 401, 409, 429, 503, malformed JSON, and timeout.

- [ ] **Step 2: Define and implement Config**

```go
const defaultTimeout = 10 * time.Second
const maxResponseBytes = 1 << 20

type Config struct {
	BaseURL     string
	TokenSource TokenSource
	HTTPClient  *http.Client
	Timeout     time.Duration
	Observer    Observer
}

type Client struct {
	baseURL     *url.URL
	tokens      TokenSource
	httpClient  *http.Client
	timeout     time.Duration
	observer    Observer
}

func New(cfg Config) (*Client, error)
func (c *Client) Do(ctx context.Context, request Request, out any) (Metadata, error)
```

Allow HTTP only for `localhost`, loopback IPs, and `*.localhost`; reject redirects with `http.ErrUseLastResponse`. A zero timeout selects 10 seconds; a shorter caller deadline wins.

- [ ] **Step 3: Implement request execution**

For each call:

1. Validate operation, method, canonical path, query values, and idempotency key.
2. Call `AccessToken(ctx)` once; reject blank/trim-changing tokens.
3. JSON-encode `Body` once before creating the request.
4. Set `Authorization: Bearer`, `Accept: application/json`, and `Content-Type: application/json` only when a body exists.
5. Set `Idempotency-Key` only from `Request.IdempotencyKey`.
6. Execute `httpClient.Do` once.
7. Read at most 1 MiB plus one byte and reject overflow.
8. Decode one envelope and emit one terminal observation event.

Never attach a Cookie or preserve a caller Jar.

- [ ] **Step 4: Implement duplicate-safe envelope decoding**

Use a token walk to reject duplicate keys at every object level before unmarshalling. Decode the outer shape as:

```go
type envelope struct {
	Code      int             `json:"code"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
	RequestID string          `json:"request_id"`
	TraceID   string          `json:"trace_id"`
}
```

Require one complete JSON value, a nonblank message, safe correlation IDs, and `code == 0` for 2xx. Permit `data:null` only when the method passes `out == nil`. For non-2xx, preserve bounded structured `data` in `Error` and map status exactly: 401 unauthenticated, 403 forbidden, 404 not_found, 409 conflict, 429 rate_limited, 5xx iam_unavailable, other statuses protocol.

- [ ] **Step 5: Run focused, fuzz, race, and leakage tests**

```bash
gofmt -w $(rg --files management/client -g '*.go')
go test ./management/client -run 'TestNew|TestDo|TestDecode' -count=1
go test -race ./management/client -count=1
go test ./management/client -run FuzzDecodeEnvelope -fuzz FuzzDecodeEnvelope -fuzztime=5s
```

Expected: PASS with exactly one token call and one HTTP attempt.

- [ ] **Step 6: Commit the transport**

```bash
git add management/client
git commit -m "feat(management): add strict bearer transport"
```

### Task 4: Implement the Applications Client

**Files:**
- Create: `management/applications/client.go`
- Create: `management/applications/model.go`
- Create: `management/applications/client_test.go`

**Interfaces:**
- Consumes: `client.Transport`, `client.Metadata`.
- Produces: `applications.Client` and six endpoint methods.

- [ ] **Step 1: Write failing method/path/body tests**

Use a fake Transport to capture each `client.Request`. Cover all six fixture endpoints and reject blank or trim-changing Application IDs/names before Transport is called.

- [ ] **Step 2: Define the Application model and inputs**

```go
type Application struct {
	OpenID                  string
	Name                    string
	DisplayName             string
	Description             string
	Status                  string
	Enabled                 bool
	MigrationStatus         string
	Builtin                 bool
	OIDCClientCount         int64
	HTTPResourceServerCount int64
	PolicyDocumentCount     int64
	LoginPolicyRuleCount    int64
	CanDelete               bool
	DeleteBlockReasons      []string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type CreateInput struct { Name, DisplayName, Description string }
type UpdateInput struct { DisplayName, Description string }
type DeleteBlock struct {
	OIDCClientCount, HTTPResourceServerCount, PolicyDocumentCount, LoginPolicyRuleCount int64
	BlockReasons []string
}
```

Give wire structs the exact server JSON tags; convert to public values and defensively copy slices.

- [ ] **Step 3: Implement the six public methods**

```go
func New(transport client.Transport) (*Client, error)
func (c *Client) List(context.Context) ([]Application, client.Metadata, error)
func (c *Client) Get(context.Context, string) (Application, client.Metadata, error)
func (c *Client) Create(context.Context, CreateInput) (Application, client.Metadata, error)
func (c *Client) Update(context.Context, string, UpdateInput) (Application, client.Metadata, error)
func (c *Client) SetEnabled(context.Context, string, bool) (Application, client.Metadata, error)
func (c *Client) HardDelete(context.Context, string) (client.Metadata, error)
```

Use operation names `management.applications.list|get|create|update|set_enabled|hard_delete`. Decode 409 delete data through `client.ErrorData` without changing the shared error Kind.

- [ ] **Step 4: Verify and commit**

```bash
gofmt -w $(rg --files management/applications -g '*.go')
go test ./management/applications -count=1
go test -race ./management/applications -count=1
git add management/applications
git commit -m "feat(management): add applications client"
```

### Task 5: Implement OIDC Client, Security, and Credential Management

**Files:**
- Create: `management/oidcclients/client.go`
- Create: `management/oidcclients/model.go`
- Create: `management/oidcclients/options.go`
- Create: `management/oidcclients/client_test.go`
- Create: `management/oidcclients/credential_leak_test.go`

**Interfaces:**
- Consumes: shared Transport and SensitiveString.
- Produces: seven endpoint methods and explicit idempotency option.

- [ ] **Step 1: Write failing seven-endpoint tests**

Assert exact camelCase JSON fields for OIDC requests, exact Application-scoped list/create paths, exact global Client security/credential paths, one-attempt Transport use, and no Secret in `fmt`, errors, or observer fixtures.

- [ ] **Step 2: Define exact public models**

```go
type OIDCClient struct {
	ID, ApplicationID, ClientID, DisplayName, Description string
	AllowedScopes, RedirectURIs []string
	PKCEPolicy string
	Enabled bool
	CreatedAt, UpdatedAt time.Time
}

type CreateInput struct {
	ClientID, DisplayName, Description string
	AllowedScopes, RedirectURIs []string
	PKCEPolicy string
}

type Security struct {
	ClientID, ClientType, PKCEPolicy string
	AllowedScopes []string
	AccessTokenTTLSeconds, IDTokenTTLSeconds, GroupsTokenTTLSeconds uint32
	LegacyRolesClaim bool
	Revision uint64
	Hash string
}

type UpdateSecurityInput struct {
	ClientType, PKCEPolicy string
	AllowedScopes []string
	AccessTokenTTLSeconds, IDTokenTTLSeconds, GroupsTokenTTLSeconds uint32
	LegacyRolesClaim bool
	Revision uint64
}

type Credential struct {
	ID, ClientID string
	Secret client.SensitiveString
	ExpiresAt, RevokedAt *time.Time
	CreatedAt time.Time
}
```

Define `SecurityConflict{Revision uint64; Hash string; ImpactSummary []string}`.

- [ ] **Step 3: Implement exact methods and idempotency option**

```go
func New(transport client.Transport) (*Client, error)
func (c *Client) List(ctx context.Context, applicationOpenID string) ([]OIDCClient, client.Metadata, error)
func (c *Client) Create(ctx context.Context, applicationOpenID string, in CreateInput) (OIDCClient, client.Metadata, error)
func (c *Client) Get(ctx context.Context, clientID string) (OIDCClient, client.Metadata, error)
func (c *Client) GetSecurity(ctx context.Context, clientID string) (Security, client.Metadata, error)
func (c *Client) UpdateSecurity(ctx context.Context, clientID string, in UpdateSecurityInput) (Security, client.Metadata, error)
func (c *Client) CreateCredential(ctx context.Context, clientID string, expiresAt *time.Time, options ...CredentialOption) (Credential, client.Metadata, error)
func (c *Client) RevokeCredential(ctx context.Context, clientID, credentialID string) (client.Metadata, error)

func WithIdempotencyKey(value string) CredentialOption
```

Reject empty Revision in `UpdateSecurity`. `CreateCredential` sends `expiresAt` and the explicit `Idempotency-Key`; it never retries. Convert the wire Secret immediately to `client.SensitiveString` and clear the temporary wire string before returning.

- [ ] **Step 4: Verify, fuzz sensitive formatting, and commit**

```bash
gofmt -w $(rg --files management/oidcclients -g '*.go')
go test ./management/oidcclients -count=1
go test -race ./management/oidcclients -count=1
git add management/oidcclients
git commit -m "feat(management): add oidc client management"
```

### Task 6: Implement Application and Client Admission Clients

**Files:**
- Create: `management/admission/client.go`
- Create: `management/admission/model.go`
- Create: `management/admission/path.go`
- Create: `management/admission/client_test.go`

**Interfaces:**
- Produces: one Client serving two explicit scopes and eight endpoints.

- [ ] **Step 1: Write failing two-scope path tests**

Test every method for both `ApplicationScope` and `ClientScope`. Assert the Client scope always includes `/oidc-clients/{client_id}` and that an empty Client ID cannot silently fall back to Application scope.

- [ ] **Step 2: Define scope, models, and conflicts**

```go
type Scope struct { ApplicationOpenID, ClientID string }
func ApplicationScope(applicationOpenID string) Scope
func ClientScope(applicationOpenID, clientID string) Scope

type Mutation struct {
	SubjectType, SubjectOpenID, Effect string
	ExpectedRevision uint64
}

type Rule struct {
	OpenID, ApplicationOpenID, ClientID, Scope string
	SubjectType, SubjectOpenID, Effect string
	CreatedAt, UpdatedAt time.Time
}

type Change struct { Rule Rule; Revision uint64; Hash string }
type ListOptions struct { Page, PageSize int; Sort, Order string }
type ListResult struct { Items []Rule; Page, PageSize int; Total int64; Revision uint64; Hash string }
type Conflict struct { Revision uint64; Hash string; Impact Impact }
type Impact struct { Scope, ApplicationOpenID, ClientID, Operation string }
```

- [ ] **Step 3: Implement four operations across both scopes**

```go
func New(transport client.Transport) (*Client, error)
func (c *Client) List(context.Context, Scope, ListOptions) (ListResult, client.Metadata, error)
func (c *Client) Create(context.Context, Scope, Mutation) (Change, client.Metadata, error)
func (c *Client) Update(context.Context, Scope, string, Mutation) (Change, client.Metadata, error)
func (c *Client) SoftDelete(context.Context, Scope, string, uint64) (Change, client.Metadata, error)
```

Use JSON `login_policy_revision` for create/update and query `login_policy_revision` for delete. Use only canonical `login-admission-rules`; do not expose historical `login-access-rules` aliases.

- [ ] **Step 4: Verify conflicts and commit**

```bash
gofmt -w $(rg --files management/admission -g '*.go')
go test ./management/admission -count=1
go test -race ./management/admission -count=1
git add management/admission
git commit -m "feat(management): add login admission clients"
```

### Task 7: Implement OIDC Client Group Mappings

**Files:**
- Create: `management/groupmappings/client.go`
- Create: `management/groupmappings/model.go`
- Create: `management/groupmappings/client_test.go`

**Interfaces:**
- Produces: four revision-controlled group-mapping endpoints.

- [ ] **Step 1: Write failing request-shape tests**

Assert camelCase JSON `roleOpenId`, `groupValue`, `revision`; DELETE query uses `revision`; every success returns a full Snapshot.

- [ ] **Step 2: Define public models**

```go
type Mapping struct { RoleOpenID, GroupValue string }
type Snapshot struct {
	ApplicationOpenID, ClientID string
	Mappings []Mapping
	Revision uint64
	Hash string
}
type Conflict struct { Revision uint64; Hash string; Impact Impact }
type Impact struct { Action string; AffectedMappings int }
```

- [ ] **Step 3: Implement four methods**

```go
func New(transport client.Transport) (*Client, error)
func (c *Client) Get(context.Context, string, string) (Snapshot, client.Metadata, error)
func (c *Client) Create(context.Context, string, string, string, string, uint64) (Snapshot, client.Metadata, error)
func (c *Client) Update(context.Context, string, string, string, string, uint64) (Snapshot, client.Metadata, error)
func (c *Client) SoftDelete(context.Context, string, string, string, uint64) (Snapshot, client.Metadata, error)
```

Parameters after context are Application Open ID, Client ID, Role Open ID, Group Value where applicable, and expected revision. Validate Client ID and group using the server-safe character sets; do not check Role existence locally.

- [ ] **Step 4: Verify and commit**

```bash
gofmt -w $(rg --files management/groupmappings -g '*.go')
go test ./management/groupmappings -count=1
go test -race ./management/groupmappings -count=1
git add management/groupmappings
git commit -m "feat(management): add client group mappings"
```

### Task 8: Implement HTTP Resource Catalog Management

**Files:**
- Create: `management/catalog/client.go`
- Create: `management/catalog/model.go`
- Create: `management/catalog/validate.go`
- Create: `management/catalog/client_test.go`

**Interfaces:**
- Produces: ten Catalog endpoint methods; no Runtime Manifest import.

- [ ] **Step 1: Write failing ten-endpoint tests**

Cover Catalog Get; Resource Server create/update; Resource create/update; Action create/update; Method Mapping put; no-body Publish; and typed Deactivate entity path. Assert the request body never contains path-owned `application_open_id` or entity `open_id` unless the server JSON contract explicitly expects it; the current handlers overwrite those fields from path, so SDK request bodies contain only editable fields.

- [ ] **Step 2: Define exact Catalog models**

```go
type ResourceServer struct { OpenID, ApplicationOpenID, Code, Name string; Active bool }
type Resource struct {
	OpenID, ApplicationOpenID, ResourceServerOpenID string
	Code, Name, RouteTemplate, CanonicalResource string
	Active bool
}
type Action struct { OpenID, ApplicationOpenID, ResourceServerOpenID, Code, Name string; Active bool }
type MethodMapping struct { OpenID, ApplicationOpenID, ResourceOpenID, ActionOpenID, Method string; Active bool }
type Catalog struct {
	ResourceServers []ResourceServer
	Resources []Resource
	Actions []Action
	MethodMappings []MethodMapping
	Mode string
	SystemManaged, ReadOnly bool
	Version, Hash, SyncStatus string
}
type EntityType string
const (
	EntityResourceServer EntityType = "resource_server"
	EntityResource EntityType = "resource"
	EntityAction EntityType = "action"
	EntityMethodMapping EntityType = "method_mapping"
)
```

Define focused create/update inputs matching `code`, `name`, `resource_server_open_id`, `route_template`, `resource_open_id`, `action_open_id`, and `method`.

- [ ] **Step 3: Implement ten methods**

```go
func New(transport client.Transport) (*Client, error)
func (c *Client) Get(context.Context, string) (Catalog, client.Metadata, error)
func (c *Client) CreateResourceServer(context.Context, string, ResourceServerInput) (ResourceServer, client.Metadata, error)
func (c *Client) UpdateResourceServer(context.Context, string, string, ResourceServerInput) (ResourceServer, client.Metadata, error)
func (c *Client) CreateResource(context.Context, string, ResourceInput) (Resource, client.Metadata, error)
func (c *Client) UpdateResource(context.Context, string, string, ResourceInput) (Resource, client.Metadata, error)
func (c *Client) CreateAction(context.Context, string, ActionInput) (Action, client.Metadata, error)
func (c *Client) UpdateAction(context.Context, string, string, ActionInput) (Action, client.Metadata, error)
func (c *Client) PutMethodMapping(context.Context, string, MethodMappingInput) (MethodMapping, client.Metadata, error)
func (c *Client) Publish(context.Context, string) (client.Metadata, error)
func (c *Client) Deactivate(context.Context, string, EntityType, string) (client.Metadata, error)
```

`Publish` sends a bodyless POST and does not invent revision/hash. Validate Methods against the nine standard uppercase HTTP methods. Do not import `runtime/httpauthz` or auto-convert a Runtime Manifest.

- [ ] **Step 4: Verify and commit**

```bash
gofmt -w $(rg --files management/catalog -g '*.go')
go test ./management/catalog -count=1
go test -race ./management/catalog -count=1
git add management/catalog
git commit -m "feat(management): add http resource catalog client"
```

### Task 9: Implement Policy Document Management

**Files:**
- Create: `management/policies/client.go`
- Create: `management/policies/model.go`
- Create: `management/policies/query.go`
- Create: `management/policies/client_test.go`
- Create: `management/policies/document_fuzz_test.go`

**Interfaces:**
- Produces: seven Policy endpoints with opaque JSON documents and typed results.

- [ ] **Step 1: Write failing seven-endpoint tests**

Test list query names exactly (`application_open_id`, `policy_type`, `name`, `display_name`, `keyword`, `role_open_id`, `status`, `page`, `page_size`); detail uses Application Open ID as query; compiled-rule filters use server names; request documents remain byte-for-byte valid JSON values.

- [ ] **Step 2: Define Policy models**

```go
type BoundRole struct { ID, OpenID, Name, DisplayName string }
type Document struct {
	ID, OpenID, ApplicationOpenID, Name, DisplayName, PolicyType, Status string
	Editable bool
	BoundRoles []BoundRole
	Body json.RawMessage
	CompiledHash string
	AuthorizationRevision uint64
	AuthorizationHash string
	CreatedAt, UpdatedAt time.Time
}
type UpsertInput struct {
	ApplicationOpenID, Name, DisplayName, PolicyType string
	RoleOpenIDs []string
	Document json.RawMessage
	Publish bool
}
type PreviewInput struct { ApplicationOpenID string; RoleOpenIDs []string; Document json.RawMessage }
type BindingsInput struct { ApplicationOpenID string; RoleOpenIDs []string }
type CompiledRule struct {
	PolicyDocumentOpenID, PolicyDocumentName, PolicyDocumentDisplayName, PolicyType string
	RoleOpenID, RoleName, RoleDisplayName string
	StatementIndex uint16
	Subject, Domain, Object, Action, Effect, Checksum string
	UpdatedAt time.Time
}
```

Also define `ListOptions`, `CompiledRuleOptions`, `Preview`, `Impact`, and preview `CompiledRule` with exact server fields. Treat policy JSON as opaque; validate that it is one complete JSON object and copy bytes defensively.

- [ ] **Step 3: Implement seven methods**

```go
func New(transport client.Transport) (*Client, error)
func (c *Client) List(context.Context, ListOptions) (client.Page[Document], client.Metadata, error)
func (c *Client) Get(context.Context, string, string) (Document, client.Metadata, error)
func (c *Client) Create(context.Context, UpsertInput) (Document, client.Metadata, error)
func (c *Client) Update(context.Context, string, UpsertInput) (Document, client.Metadata, error)
func (c *Client) Preview(context.Context, PreviewInput) (Preview, client.Metadata, error)
func (c *Client) SetBindings(context.Context, string, BindingsInput) (Document, client.Metadata, error)
func (c *Client) ListCompiledRules(context.Context, CompiledRuleOptions) (client.Page[CompiledRule], client.Metadata, error)
```

Do not implement a local compiler, Casbin evaluator, automatic publish, or RPC-specific API. `Domain` is an opaque server response/filter string; the SDK does not open an RPC connection or define RPC behavior.

- [ ] **Step 4: Fuzz JSON boundaries, verify, and commit**

```bash
gofmt -w $(rg --files management/policies -g '*.go')
go test ./management/policies -count=1
go test -race ./management/policies -count=1
go test ./management/policies -run FuzzPolicyDocument -fuzz FuzzPolicyDocument -fuzztime=5s
git add management/policies
git commit -m "feat(management): add policy document client"
```

### Task 10: Close Contract Coverage and Cross-Package Security Gates

**Files:**
- Modify: `management/contract_test.go`
- Create: `management/security_test.go`
- Create: `management/dependency_test.go`
- Test: all Management packages.

**Interfaces:**
- Consumes: all six domain packages and contract fixture.
- Produces: proof that all 42 endpoints are implemented exactly once and scope exclusions remain absent.

- [ ] **Step 1: Register each public method against the fixture**

Add a static test registry containing domain, method, path template, and operation. Compare it set-for-set with `contract-v1.8.1.json`; fail on missing, extra, or duplicate entries.

- [ ] **Step 2: Add forbidden-scope and dependency checks**

Walk `management/` and reject public packages named `users`, `organizations`, `roles`, `cloudproviders`, `audits`, or `rpc`. Parse imports and reject Runtime, Gin, Redis, Docker, Testcontainers, Dubbo, Triple, and direct gRPC imports.

- [ ] **Step 3: Add global leakage fixtures**

Exercise one success and every shared error status with marker strings for Token, Authorization Header, Secret, raw body, and URL query. Assert markers are absent from errors, event fields, `fmt` output, test snapshots, and `slog` capture.

- [ ] **Step 4: Run full Management verification**

```bash
go test ./management/... -count=1
go test -race ./management/... -count=1
go vet ./management/...
```

Expected: PASS and fixture count remains 42.

- [ ] **Step 5: Commit coverage gates**

```bash
git add management
git commit -m "test(management): enforce contract and security coverage"
```

### Task 11: Add Examples, Migration Documentation, and v0.3 Release Gates

**Files:**
- Create: `examples/management/main.go`
- Create: `examples/management/main_test.go`
- Create: `docs/migration-v0.2-to-v0.3.md`
- Modify: `README.md`
- Modify: `COMPATIBILITY.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/iam-core-v1.8.1-contract.md`
- Modify: `documentation_test.go`
- Modify: `release_workflow_test.go`
- Modify: `.github/workflows/ci.yml`
- Modify: `VERSION`

**Interfaces:**
- Consumes: completed Runtime migration and Management clients.
- Produces: compiling examples and a release-ready `v0.3.0` contract.

- [ ] **Step 1: Write a safe Management example and failing documentation assertions**

The example must construct `management/client.Config` with an injected TokenSource, create `applications.Client`, perform `List`, then create `admission.Client` and perform a revision-controlled `Update` only when an explicit example flag is true. It must never read a username/password, print a Token/Secret, create a default administrator, or auto-provision on startup.

Documentation tests must require these strings:

```text
github.com/swan-swan-swan/iam-core-sdk-go/runtime/core
github.com/swan-swan-swan/iam-core-sdk-go/management/client
management 不参与普通业务请求链路
RPC 暂不支持
不自动 Provision
```

- [ ] **Step 2: Write the exact migration mapping**

Document:

```text
.../iam-core-client-sdk-go/core              -> .../iam-core-sdk-go/runtime/core
.../iam-core-client-sdk-go/bff               -> .../iam-core-sdk-go/runtime/bff
.../iam-core-client-sdk-go/httpauthz         -> .../iam-core-sdk-go/runtime/httpauthz
.../iam-core-client-sdk-go/testkit           -> .../iam-core-sdk-go/runtime/testkit
.../iam-core-client-sdk-go/adapters/gin      -> .../iam-core-sdk-go/runtime/adapters/gin
.../iam-core-client-sdk-go/adapters/redis    -> .../iam-core-sdk-go/runtime/adapters/redis
```

State that no wrapper exists and consumers must remove the old module before adding the new one.

- [ ] **Step 3: Update compatibility and changelog**

Set compatibility to:

```text
v0.2.x = github.com/swan-swan-swan/iam-core-client-sdk-go, IAM Core v1.8.1, Runtime only
v0.3.x = github.com/swan-swan-swan/iam-core-sdk-go, IAM Core v1.8.1, Runtime + approved platform-integration Management
```

Changelog must list the breaking module/import move, six Management domains, injected TokenSource, no retries, one-time Secret redaction, 42-endpoint contract, and unsupported RPC/users/organizations/global roles/Cloud Provider/audits.

- [ ] **Step 4: Update CI and final release tags**

Set `VERSION` to one line:

```text
0.3.0
```

Remove or replace the Runtime plan's temporary prerelease-stage guard in the same commit. The exact new-module + `0.2.0` success-without-release branch must not remain once `VERSION` becomes `0.3.0`; replace it with the final release preflight below so a dev push can reach the three-tag flow only after all v0.3 metadata checks pass.

Update the release job to preflight and atomically push:

```text
v0.3.0
runtime/adapters/gin/v0.3.0
runtime/adapters/redis/v0.3.0
```

Each tag must point to the same verified release merge commit. Reject if any tag exists, if module paths mismatch, if GitHub repository metadata is not `swan-swan-swan/iam-core-sdk-go`, or if `VERSION` bytes are not exactly `0.3.0\n`.

- [ ] **Step 5: Run every module and documentation gate**

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./examples/...
(cd runtime/adapters/gin && go test ./... -count=1 && go test -race ./... -count=1 && go vet ./...)
(cd runtime/adapters/redis && go test ./... -count=1 && go test -race ./... -count=1 && go vet ./...)
(cd integration && go test ./redis -run '^$' -count=1 && go vet ./...)
git diff --check
```

On a Docker-enabled runner also run:

```bash
(cd integration && go test ./redis -count=1)
(cd integration && go test -race ./redis -count=1)
```

After the three v0.3.0 tags are published, a separate post-release job must verify consumers can resolve each published module with `GOWORK=off`; this check is intentionally not a pre-tag developer-workstation gate.

- [ ] **Step 6: Search final forbidden surfaces**

Run:

```bash
(
  go list -f '{{range .Imports}}{{println .}}{{end}}' ./...
  cd runtime/adapters/gin && go list -f '{{range .Imports}}{{println .}}{{end}}' ./...
  cd ../redis && go list -f '{{range .Imports}}{{println .}}{{end}}' ./...
  cd ../../../integration && go list -f '{{range .Imports}}{{println .}}{{end}}' ./...
) | if grep -F 'github.com/swan-swan-swan/iam-core-client-sdk-go'; then
  exit 1
fi
! rg -n 'github.com/swan-swan-swan/iam-core-client-sdk-go' \
  --glob 'go.mod' --glob 'go.work' --glob '.github/**'
find . -type d -name rpc -not -path './.git/*'
```

Expected: no live old imports, no old module path in current module/workflow metadata, and no SDK RPC directory. Contract tests and historical docs may name the old module only as migration/compatibility data.

- [ ] **Step 7: Commit the release candidate**

```bash
git add VERSION README.md COMPATIBILITY.md CHANGELOG.md docs examples/management documentation_test.go release_workflow_test.go .github/workflows/ci.yml
git commit -m "chore(release): prepare iam core sdk v0.3.0"
```

Do not create or push tags from a developer workstation; the verified release workflow owns the atomic merge and tag operation.
