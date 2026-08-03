# IAM Core SDK v0.2.0 Core and BFF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the dependency-light `core` security runtime and a PKCE-S256 BFF with server-side sessions, exact granted scopes, atomic refresh, and separate local/central logout.

**Architecture:** The root module exposes no facade. `core` owns discovery, JWKS/JWT verification, typed authentication context, sanitized errors, transport, and observation. `bff` composes `core` with OAuth endpoints and a focused `bff/session.Backend`; HTTP authorization is implemented by the next plan.

**Tech Stack:** Go 1.24, `github.com/go-jose/go-jose/v4`, `github.com/golang-jwt/jwt/v5`, `golang.org/x/oauth2`, `net/http`, `crypto/rand`, table-driven tests, fuzz tests.

## Global Constraints

- Target IAM Core Server contract: v1.8.1, verified against server commit `05770eef8b506a44a2b422a656a550dee1cb58da`.
- Target SDK release: `v0.2.0`; no v0.1 source compatibility or root facade.
- Go version floor: `1.24.0`.
- Default scopes: exactly `openid profile email groups`; never request or expose `roles`.
- OIDC signing algorithm: RS256 only; PKCE method: S256 only.
- Never log or expose access tokens, ID tokens, refresh tokens, authorization codes, client secrets, PKCE verifiers, Cookie values, Session IDs, or Flow IDs.
- Browser state contains only opaque Flow/Session cookie IDs; token and verifier state remains server side.
- Network exchanges are single-attempt; no implicit token, UserInfo, logout, or refresh retry.
- RPC, IAM management APIs, PDP authorization, Gin, Redis, Docker, and Testcontainers are outside this plan.
- Design source: `docs/superpowers/specs/2026-08-03-iam-core-go-client-sdk-v0.2-design.md`.

---

## File Map

| Path | Responsibility |
| --- | --- |
| `core/error.go` | Sanitized typed errors and `errors.Is` sentinels |
| `core/observe.go` | Low-cardinality observation contract |
| `core/context.go` | Immutable `AuthContext`, credentials, TokenSource, Context helpers |
| `core/transport.go` | Hardened single-attempt JSON HTTP transport and correlation extraction |
| `core/discovery.go` | v1.8.1 OIDC discovery and S256/RS256 validation |
| `core/jwks.go` | Cached RS256 JWKS verification with coalesced unknown-kid refresh |
| `core/verify.go` | Access/ID token registered-claim verification and typed claims |
| `bff/session/model.go` | Flow, TokenSet, Session, lease and backend contracts |
| `bff/session/memory/backend.go` | Single-process reference backend with fenced refresh commits |
| `bff/session/sessiontest/conformance.go` | Reusable Backend conformance suite and controllable clock |
| `bff/client.go` | BFF construction and dependency validation |
| `bff/oauth.go` | authorize, token, refresh, UserInfo and end-session protocol calls |
| `bff/login.go` | PKCE BeginLogin and login handler |
| `bff/callback.go` | One-time Flow callback and Session creation |
| `bff/refresh.go` | Proactive fenced refresh and atomic claim replacement |
| `bff/session_resolver.go` | Cookie Session to request-scoped `core.Credential` |
| `bff/logout.go` | local and central logout semantics |
| `bff/me.go` | same-origin authenticated profile endpoint |

### Task 1: Freeze the Core Contract and Sanitized Primitives

**Files:**
- Create: `core/error.go`
- Create: `core/error_test.go`
- Create: `core/observe.go`
- Create: `core/context.go`
- Create: `core/context_test.go`
- Create: `core/clock.go`
- Create: `doc.go`
- Create: `contract_v181_test.go`

**Interfaces:**
- Consumes: only the Go standard library.
- Produces: `core.Kind`, `core.Error`, `core.Event`, `core.Observer`, `core.AuthContext`, `core.Credential`, `core.TokenSource`, `core.Clock`.

- [ ] **Step 1: Write the failing v1.8.1 contract and primitive tests**

```go
// contract_v181_test.go
package iamcore_test

import (
    "testing"
    "github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestV181FrozenContract(t *testing.T) {
    if core.ContractVersion != "v1.8.1" { t.Fatalf("contract version=%q", core.ContractVersion) }
}
```

```go
// core/context_test.go
func TestAuthContextFromContextReturnsDefensiveCopy(t *testing.T) {
    original := core.AuthContext{Subject: "op_usr_1", Audience: []string{"portal"}, Scopes: []string{"openid", "groups"}, Groups: []string{"ops"}}
    ctx := core.ContextWithAuthContext(context.Background(), original)
    got, ok := core.AuthContextFromContext(ctx)
    if !ok { t.Fatal("AuthContextFromContext() ok = false") }
    got.Audience[0], got.Scopes[0], got.Groups[0] = "changed", "changed", "changed"
    again, _ := core.AuthContextFromContext(ctx)
    if again.Audience[0] != "portal" || again.Scopes[0] != "openid" || again.Groups[0] != "ops" {
        t.Fatalf("stored context was aliased: %#v", again)
    }
}

func TestErrorStringNeverIncludesCause(t *testing.T) {
    secret := "secret-access-token"
    err := core.NewError(core.KindProtocol, "core.verify", 0, false, errors.New(secret))
    if strings.Contains(err.Error(), secret) { t.Fatalf("error leaked cause: %q", err) }
}
```

- [ ] **Step 2: Run the new tests and verify they fail because `core` does not exist**

Run: `go test ./core . -run 'TestV181FrozenContract|TestAuthContext|TestErrorString' -count=1`

Expected: FAIL with an import/build error for `github.com/swan-swan-swan/iam-core-client-sdk-go/core`.

- [ ] **Step 3: Implement the exact public primitive types**

```go
// core/error.go
package core

import (
    "errors"
    "fmt"
)

type Kind string
type Reason string
const ContractVersion = "v1.8.1"

const (
    KindInvalidConfig Kind = "invalid_config"
    KindProtocol Kind = "protocol_error"
    KindUnauthenticated Kind = "unauthenticated"
    KindForbidden Kind = "forbidden"
    KindIAMUnavailable Kind = "iam_unavailable"
    KindSessionUnavailable Kind = "session_unavailable"
    KindCredentialConflict Kind = "credential_conflict"
    ReasonInvalidGrant Reason = "invalid_grant"
    ReasonAccessDenied Reason = "access_denied"
    ReasonTemporarilyUnavailable Reason = "temporarily_unavailable"
)

var (
    ErrUnauthenticated = errors.New("iamcore: unauthenticated")
    ErrForbidden = errors.New("iamcore: forbidden")
    ErrUnavailable = errors.New("iamcore: unavailable")
    ErrInvalidGrant = errors.New("iamcore: invalid grant")
)

type Error struct {
    Kind Kind
    Reason Reason
    Operation string
    HTTPStatus int
    RequestID string
    TraceID string
    DecisionID string
    Retryable bool
    cause error
}

func NewError(kind Kind, operation string, status int, retryable bool, cause error) *Error {
    return &Error{Kind: kind, Operation: operation, HTTPStatus: status, Retryable: retryable, cause: cause}
}
func (e *Error) Error() string {
    if e == nil { return "" }
    if e.Operation == "" { return string(e.Kind) }
    return fmt.Sprintf("%s: %s", e.Operation, e.Kind)
}
func (e *Error) Is(target error) bool {
    switch target {
    case ErrUnauthenticated: return e != nil && e.Kind == KindUnauthenticated
    case ErrForbidden: return e != nil && e.Kind == KindForbidden
    case ErrUnavailable: return e != nil && (e.Kind == KindIAMUnavailable || e.Kind == KindSessionUnavailable)
    case ErrInvalidGrant: return e != nil && e.Reason == ReasonInvalidGrant
    default: return false
    }
}
```

```go
// core/context.go
package core

import (
    "context"
    "time"
)

type AuthContext struct {
    Subject string
    Issuer string
    Audience []string
    TokenID string
    IssuedAt time.Time
    NotBefore time.Time
    ExpiresAt time.Time
    Scopes []string
    Groups []string
    Username string
    DisplayName string
    Email string
    DecisionID string
    ReasonCode string
    TraceID string
}

type CredentialSource string
const (
    CredentialBearer CredentialSource = "bearer"
    CredentialSession CredentialSource = "session"
)

type TokenSource interface { AccessToken(context.Context) (string, error) }
type TokenSourceFunc func(context.Context) (string, error)
func (f TokenSourceFunc) AccessToken(ctx context.Context) (string, error) { return f(ctx) }

type Credential struct {
    Source CredentialSource
    SessionID string
    Auth AuthContext
    Tokens TokenSource
}

type authContextKey struct{}
func ContextWithAuthContext(ctx context.Context, auth AuthContext) context.Context {
    if ctx == nil { ctx = context.Background() }
    return context.WithValue(ctx, authContextKey{}, cloneAuthContext(auth))
}
func AuthContextFromContext(ctx context.Context) (AuthContext, bool) {
    if ctx == nil { return AuthContext{}, false }
    auth, ok := ctx.Value(authContextKey{}).(AuthContext)
    if !ok { return AuthContext{}, false }
    return cloneAuthContext(auth), true
}
func cloneAuthContext(auth AuthContext) AuthContext {
    auth.Audience = append([]string(nil), auth.Audience...)
    auth.Scopes = append([]string(nil), auth.Scopes...)
    auth.Groups = append([]string(nil), auth.Groups...)
    return auth
}
```

```go
// core/observe.go
package core
import ("context"; "time")
type Event struct { Operation, Outcome, CredentialSource string; Duration time.Duration }
type Observer interface { Observe(context.Context, Event) }
type ObserverFunc func(context.Context, Event)
func (f ObserverFunc) Observe(ctx context.Context, event Event) { f(ctx, event) }
type NopObserver struct{}
func (NopObserver) Observe(context.Context, Event) {}
```

```go
// core/clock.go
package core
import "time"
type Clock interface { Now() time.Time }
type RealClock struct{}
func (RealClock) Now() time.Time { return time.Now() }
```

```go
// doc.go
// Package iamcore marks the module root. Public SDK APIs live in focused subpackages.
package iamcore
```

- [ ] **Step 4: Run primitive tests and format the package**

Run: `gofmt -w core/*.go contract_v181_test.go && go test ./core . -run 'TestV181FrozenContract|TestAuthContext|TestErrorString' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit the core contract**

```bash
git add core doc.go contract_v181_test.go
git commit -m "feat(core): define v1.8.1 security primitives"
```

### Task 2: Implement Discovery, Hardened Transport, JWKS, and JWT Verification

**Files:**
- Create: `core/transport.go`
- Create: `core/transport_test.go`
- Create: `core/discovery.go`
- Create: `core/discovery_test.go`
- Create: `core/jwks.go`
- Create: `core/jwks_test.go`
- Create: `core/verify.go`
- Create: `core/verify_test.go`
- Create: `core/testserver_test.go`

**Interfaces:**
- Consumes: `core.Error`, `core.AuthContext`, `core.Clock`, `core.Observer` from Task 1.
- Produces: `core.Config`, `core.Metadata`, `core.Runtime`, `core.New`, `(*Runtime).VerifyAccessToken`, `(*Runtime).VerifyIDToken`, `(*Runtime).VerifyRefreshedIDToken`.

- [ ] **Step 1: Write failing Discovery and token-verification tests**

```go
func TestNewRequiresS256AndRS256(t *testing.T) {
    issuer := newCoreIssuer(t, core.Metadata{
        CodeChallengeMethodsSupported: []string{"plain"},
        IDTokenSigningAlgValuesSupported: []string{"RS256"},
    })
    _, err := core.New(t.Context(), core.Config{IssuerURL: issuer.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Client()})
    if err == nil { t.Fatal("New() error = nil, want S256 rejection") }
}

func TestVerifyAccessTokenReturnsTypedGroupsAndActualScope(t *testing.T) {
    runtime, signer := newCoreRuntime(t)
    raw := signer.AccessToken(t, map[string]any{
        "sub":"op_usr_1", "iss":signer.Issuer, "aud":"portal", "jti":"jti-1",
        "iat":time.Now().Add(-time.Minute).Unix(), "exp":time.Now().Add(time.Minute).Unix(),
        "scope":"groups openid profile", "groups":[]string{"ops", "ops", "dev"},
    })
    got, err := runtime.VerifyAccessToken(t.Context(), raw)
    if err != nil { t.Fatal(err) }
    if !slices.Equal(got.Scopes, []string{"groups", "openid", "profile"}) || !slices.Equal(got.Groups, []string{"dev", "ops"}) {
        t.Fatalf("auth = %#v", got)
    }
}
```

Add table cases for wrong issuer/audience/kid/alg/signature, missing `sub`/`jti`/`iat`/`exp`, future `nbf`, expired token, duplicate protected-header key, unknown kid refresh count, concurrent unknown-kid coalescing, and sensitive-value redaction.

Implement `core/testserver_test.go` with `coreIssuer{Server *httptest.Server, Key *rsa.PrivateKey, Metadata core.Metadata, JWKSCalls atomic.Int32}`, `newCoreIssuer(t, metadata) *coreIssuer`, `tokenSigner{PrivateKey *rsa.PrivateKey, Issuer, Audience, KeyID string}`, and `newCoreRuntime(t) (*core.Runtime,*tokenSigner)`. The issuer fills missing endpoint URLs from its own server URL and signs RS256 tokens with `kid=test-key`.

- [ ] **Step 2: Run focused tests and verify missing API failures**

Run: `go test ./core -run 'TestNewRequires|TestVerifyAccessToken|TestVerifyIDToken|TestUnknownKID' -count=1`

Expected: FAIL because `core.Config`, `core.Runtime`, and verification methods are undefined.

- [ ] **Step 3: Implement the public Runtime and metadata contract**

```go
type Metadata struct {
    Issuer string `json:"issuer"`
    AuthorizationEndpoint string `json:"authorization_endpoint"`
    TokenEndpoint string `json:"token_endpoint"`
    UserInfoEndpoint string `json:"userinfo_endpoint"`
    JWKSURI string `json:"jwks_uri"`
    EndSessionEndpoint string `json:"end_session_endpoint"`
    ScopesSupported []string `json:"scopes_supported"`
    CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
    IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

type Config struct {
    IssuerURL string
    Audiences []string
    HTTPClient *http.Client
    DiscoveryTimeout time.Duration
    JWKSTimeout time.Duration
    UnknownKIDRefreshInterval time.Duration
    Clock Clock
    Observer Observer
    Logger *slog.Logger
}

type Runtime struct {
    metadata Metadata
    audiences map[string]struct{}
    transport transportClient
    keys *keySet
    clock Clock
    observer Observer
    logger *slog.Logger
}

type AccessTokenVerifier interface {
    VerifyAccessToken(context.Context, string) (AuthContext, error)
}

func New(ctx context.Context, cfg Config) (*Runtime, error)
func (r *Runtime) Metadata() Metadata
func (r *Runtime) AcceptsAudience(audience string) bool
func (r *Runtime) VerifyAccessToken(ctx context.Context, raw string) (AuthContext, error)
func (r *Runtime) VerifyIDToken(ctx context.Context, raw, expectedNonce string) (AuthContext, error)
func (r *Runtime) VerifyRefreshedIDToken(ctx context.Context, raw string) (AuthContext, error)
```

Implement `New` by fetching `strings.TrimRight(IssuerURL, "/") + "/.well-known/openid-configuration"` once, rejecting redirects, limiting the body to 1 MiB, requiring exact issuer equality after trailing-slash normalization, HTTPS except loopback test servers, S256 presence, and RS256 presence. Clone injected `http.Client`, set `Jar=nil`, and set `CheckRedirect` to `http.ErrUseLastResponse` without mutating the caller's instance.

- [ ] **Step 4: Port the hardened JWKS and JWT algorithms with v1.8.1 claims**

Move the algorithms—not package APIs—from `oidc/jwks.go` and `oidc/verify.go` into `core/jwks.go` and `core/verify.go`. Keep duplicate protected-header rejection, RS256-only `jose.ParseSigned`, single-signature enforcement, single/string-array audience decoding, rational NumericDate parsing, and coalesced fetches. Add these exact wire claims:

```go
type tokenClaims struct {
    Subject string `json:"sub"`
    Issuer string `json:"iss"`
    Audience json.RawMessage `json:"aud"`
    TokenID string `json:"jti"`
    IssuedAt json.RawMessage `json:"iat"`
    NotBefore json.RawMessage `json:"nbf"`
    ExpiresAt json.RawMessage `json:"exp"`
    Nonce string `json:"nonce"`
    Scope string `json:"scope"`
    Groups []string `json:"groups"`
    Username string `json:"username"`
    DisplayName string `json:"display_name"`
    Email string `json:"email"`
}
```

Normalize scopes with `strings.Fields`, trim groups, discard empty group strings, sort, and deduplicate. Require `sub`, `iss`, allowed `aud`, `jti`, `iat`, and `exp` for access tokens and ID tokens; callback ID tokens additionally require a matching non-empty nonce. `AcceptsAudience` trims its input and checks the immutable configured audience set. Only expose profile fields when `profile` is granted, email when `email` is granted, and groups when `groups` is granted.

- [ ] **Step 5: Run core security, race, and fuzz tests**

Run: `gofmt -w core && go test ./core -count=1 && go test -race ./core -count=1`

Expected: PASS; unknown-kid test records one JWKS refresh for concurrent verifications and zero token values in errors/logs.

- [ ] **Step 6: Commit the core runtime**

```bash
git add core
git commit -m "feat(core): verify IAM Core v1.8.1 tokens"
```

### Task 3: Define Focused Session Contracts and the Memory Backend

**Files:**
- Create: `bff/session/model.go`
- Create: `bff/session/backend.go`
- Create: `bff/session/errors.go`
- Create: `bff/session/sessiontest/conformance.go`
- Create: `bff/session/memory/backend.go`
- Create: `bff/session/memory/backend_test.go`

**Interfaces:**
- Consumes: `core.AuthContext`.
- Produces: `session.Flow`, `session.TokenSet`, `session.Session`, `session.Lease`, `session.Backend`, `sessiontest.Run`.

- [ ] **Step 1: Write failing memory-backend conformance tests**

```go
func TestMemoryBackendConformance(t *testing.T) {
    sessiontest.Run(t, func(t testing.TB, clock *sessiontest.Clock) session.Backend {
        return memory.New(memory.Options{Clock: clock, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 4096))})
    })
}
```

Conformance subtests must cover one-time Flow consumption, expiry, defensive copies, Session version CAS, mutually exclusive refresh leases, expired lease rejection, stale fencing rejection, `DeleteWithLease`, and concurrent refresh ownership.

- [ ] **Step 2: Run the conformance test and verify missing package failures**

Run: `go test ./bff/session/... -count=1`

Expected: FAIL because the new session packages do not exist.

- [ ] **Step 3: Implement exact session models and interfaces**

```go
type Flow struct {
    ID, State, Nonce, CodeVerifier, ClientID, RedirectURL, ReturnTo string
    CreatedAt, ExpiresAt time.Time
}
type TokenSet struct {
    AccessToken, TokenType, RefreshToken, IDToken string
    AccessTokenExpiry time.Time
    GrantedScopes []string
}
type Session struct {
    ID string
    Version uint64
    Tokens TokenSet
    Auth core.AuthContext
    CreatedAt, UpdatedAt, LastSeenAt, ExpiresAt, IdleExpiresAt time.Time
}
type Lease interface {
    Valid(context.Context) bool
    Release(context.Context) error
}
type Backend interface {
    PutFlow(context.Context, *Flow) error
    ConsumeFlow(context.Context, string) (*Flow, error)
    Create(context.Context, *Session) error
    Get(context.Context, string) (*Session, error)
    CompareAndSwap(context.Context, string, uint64, *Session) error
    Delete(context.Context, string) error
    AcquireRefreshLease(context.Context, string, time.Duration) (Lease, error)
    CompareAndSwapWithLease(context.Context, Lease, string, uint64, *Session) error
    DeleteWithLease(context.Context, Lease, string, uint64) error
}
```

Define `ErrNotFound`, `ErrExpired`, `ErrConflict`, and `ErrLeaseLost`. Every Backend method must clone all slices and structs on ingress and egress. `sessiontest.Clock` implements `core.Clock` with mutex-protected `Now`, `Set`, and `Advance`; `sessiontest.Run(t, factory)` contains the named conformance subtests from Step 1 and is used unchanged by Memory and Redis.

- [ ] **Step 4: Implement the memory backend with monotonic fencing numbers**

Use one mutex, maps for Flow/Session/lease state, and a monotonically increasing `uint64` fence. `AcquireRefreshLease` rejects a live lease, replaces expired leases, and embeds `{sessionID,fence,expiresAt,owner}` in the returned lease. `CompareAndSwapWithLease` validates owner, fence, lease expiry, Session ID, and Session version while holding the same mutex that performs the mutation.

- [ ] **Step 5: Run conformance and race tests**

Run: `gofmt -w bff/session && go test ./bff/session/... -count=1 && go test -race ./bff/session/... -count=1`

Expected: PASS with no race reports.

- [ ] **Step 6: Commit session contracts**

```bash
git add bff/session
git commit -m "feat(bff): define fenced session backend"
```

### Task 4: Implement PKCE BeginLogin and One-Time Callback

**Files:**
- Create: `bff/client.go`
- Create: `bff/client_test.go`
- Create: `bff/oauth.go`
- Create: `bff/oauth_test.go`
- Create: `bff/cookies.go`
- Create: `bff/login.go`
- Create: `bff/login_test.go`
- Create: `bff/callback.go`
- Create: `bff/callback_test.go`
- Create: `bff/scope.go`
- Create: `bff/scope_test.go`
- Create: `bff/testserver_test.go`
- Create: `bff/return_to_fuzz_test.go`
- Create: `bff/cookie_fuzz_test.go`

**Interfaces:**
- Consumes: `core.Runtime`, `core.Error`, `core.Observer`, `session.Backend`.
- Produces: `bff.Config`, `bff.Client`, `bff.New`, `LoginHandler`, `CallbackHandler`, and an authenticated server Session.

- [ ] **Step 1: Write failing PKCE, callback, scope, and leakage tests**

```go
func TestBeginLoginStoresVerifierAndSendsS256Challenge(t *testing.T) {
    client, backend, issuer := newBFFTestClient(t)
    response := httptest.NewRecorder()
    request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2Fprofile", nil)
    client.LoginHandler().ServeHTTP(response, request)
    location, _ := url.Parse(response.Header().Get("Location"))
    query := location.Query()
    if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" { t.Fatalf("query=%v", query) }
    flow := backend.LastFlow()
    digest := sha256.Sum256([]byte(flow.CodeVerifier))
    if query.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) { t.Fatal("challenge mismatch") }
    if strings.Contains(location.String(), flow.CodeVerifier) || issuer.LogContains(flow.CodeVerifier) { t.Fatal("verifier leaked") }
}

func TestCallbackNeverElevatesRequestedScope(t *testing.T) {
    client, _, issuer := newBFFTestClient(t)
    issuer.TokenScope = "openid groups"
    issuer.AccessTokenScope = "openid groups"
    session := completeLogin(t, client, issuer)
    if !slices.Equal(session.Tokens.GrantedScopes, []string{"groups", "openid"}) { t.Fatalf("scopes=%v", session.Tokens.GrantedScopes) }
}
```

Add tests for Discovery without S256, invalid/plain/mismatched verifier, missing/mismatched state, wrong nonce, code replay, Flow expiry, OAuth errors, UserInfo subject mismatch, inconsistent scope sources, groups normalization, unsafe return-to, insecure production Cookie, and secret scanning of errors/observer/logger.

Implement `bff/testserver_test.go` with `bffIssuer{Server *httptest.Server, Key *rsa.PrivateKey, TokenScope, AccessTokenScope string, TokenCalls atomic.Int32}`, `recordingBackend` wrapping `memory.Backend` and retaining a cloned last Flow, `newBFFTestClient(t) (*Client,*recordingBackend,*bffIssuer)`, and `completeLogin(t,client,issuer) *session.Session`. The helper performs the real Login redirect and Callback handler sequence through `httptest`, not direct private method calls.

- [ ] **Step 2: Run focused tests and verify they fail**

Run: `go test ./bff -run 'TestBeginLogin|TestCallback|TestDefaultScopes|TestCookie|TestReturnTo' -count=1`

Expected: FAIL because the BFF client is undefined.

- [ ] **Step 3: Implement BFF configuration and protocol interfaces**

```go
type SecretProvider interface { Secret(context.Context) (string, error) }
type SecretProviderFunc func(context.Context) (string, error)
func (f SecretProviderFunc) Secret(ctx context.Context) (string, error) { return f(ctx) }

type Config struct {
    Core *core.Runtime
    ClientID string
    ClientSecret SecretProvider
    RedirectURL string
    Scopes []string
    Backend session.Backend
    SessionCookie http.Cookie
    FlowCookie http.Cookie
    FlowTTL, SessionAbsoluteTTL, SessionIdleTTL, RefreshBeforeExpiry, RefreshLeaseTTL time.Duration
    AllowedReturnToURLs []string
    AllowInsecureLoopbackCookies bool
    HTTPClient *http.Client
    Clock core.Clock
    Random io.Reader
    Observer core.Observer
    Logger *slog.Logger
}

func New(cfg Config) (*Client, error)
func DefaultScopes() []string
func (c *Client) LoginHandler() http.Handler
func (c *Client) CallbackHandler() http.Handler
```

`New` requires non-nil Core, ClientSecret, Backend, Clock/Random defaults, exact Redirect URL, distinct explicit Cookie names, and default scopes only when `Scopes` is empty. Reject ClientID not accepted by `Core.AcceptsAudience`, any configured `roles`, missing `openid`, duplicate scope, Cookie Domain, non-`/` Path, non-HttpOnly Cookie, or production Cookie without `Secure` and `__Host-`.

- [ ] **Step 4: Implement PKCE and exact OAuth request bodies**

Generate verifier from 32 random bytes using `base64.RawURLEncoding`; the result is 43 RFC 7636 characters. Authorization query adds `response_type=code`, `client_id`, exact `redirect_uri`, canonical scope, state, nonce, S256 challenge, and `code_challenge_method=S256`.

Exchange request form contains exactly `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `client_secret`, and `code_verifier`. Use one POST with `application/x-www-form-urlencoded`, reject redirects, limit JSON bodies, and map OAuth errors to sanitized `core.Error` reasons.

- [ ] **Step 5: Implement one-time callback and scope reconciliation**

Consume Flow before validating state. Verify ID Token with Flow nonce, validate Token `token_type=Bearer`, require positive token response `expires_in`, verify Access Token locally, reconcile available scope sources as sorted sets, call UserInfo once, and require matching subject. The verified Access Token `exp` is the stored `AccessTokenExpiry`; `expires_in` may shorten refresh scheduling but may not extend JWT expiry. Build `core.AuthContext` only from verified claims and granted scopes, then create Session with a fresh opaque ID.

Use Access Token claims as the authentication base. ID Token and UserInfo subjects must match it. For granted `profile`/`email`, UserInfo may fill typed profile fields. For granted `groups`, every available Access Token, ID Token, and UserInfo groups source is normalized and must match; a present empty array stays empty and never falls back to roles.

Use this exact reconciliation rule:

```go
func reconcileScopes(tokenResponse string, access, id []string) ([]string, error) {
    sources := make([][]string, 0, 3)
    if strings.TrimSpace(tokenResponse) != "" { sources = append(sources, normalizeScopes(strings.Fields(tokenResponse))) }
    if access != nil { sources = append(sources, normalizeScopes(access)) }
    if id != nil { sources = append(sources, normalizeScopes(id)) }
    if len(sources) == 0 { return nil, core.NewError(core.KindProtocol, "bff.scope", 0, false, nil) }
    for _, source := range sources[1:] { if !slices.Equal(source, sources[0]) { return nil, core.NewError(core.KindProtocol, "bff.scope", 0, false, nil) } }
    return append([]string(nil), sources[0]...), nil
}
```

- [ ] **Step 6: Run BFF login/callback tests**

Run: `gofmt -w bff && go test ./bff ./bff/session/... -run 'Login|Callback|PKCE|Scope|Cookie|ReturnTo' -count=1 && go test ./bff -run FuzzReturnTo -fuzz FuzzReturnTo -fuzztime=5s && go test ./bff -run FuzzCookie -fuzz FuzzCookie -fuzztime=5s`

Expected: PASS; token endpoint call count is one and a second Callback with the same Flow fails before token exchange.

- [ ] **Step 7: Commit the PKCE BFF**

```bash
git add bff
git commit -m "feat(bff): add PKCE S256 login and callback"
```

### Task 5: Implement Atomic Refresh, Session Resolution, Me, and Logout

**Files:**
- Create: `bff/refresh.go`
- Create: `bff/refresh_test.go`
- Create: `bff/session_resolver.go`
- Create: `bff/session_resolver_test.go`
- Create: `bff/me.go`
- Create: `bff/me_test.go`
- Create: `bff/logout.go`
- Create: `bff/logout_test.go`

**Interfaces:**
- Consumes: `bff.Client`, `session.Backend`, `core.Credential`.
- Produces: `(*Client).SessionPresent`, `(*Client).ResolveSession`, `MeHandler`, `LocalLogoutHandler`, `CentralLogoutHandler`.

- [ ] **Step 1: Write failing refresh atomicity and logout semantic tests**

```go
func TestRefreshAtomicallyReplacesTokensIdentityGroupsAndScopes(t *testing.T) {
    client, backend, issuer := newRefreshTestClient(t)
    old := seedExpiringSession(t, backend, []string{"old"}, []string{"openid", "groups"})
    issuer.RefreshGroups = []string{"new"}
    issuer.RefreshScope = "openid groups email"
    request := httptest.NewRequest(http.MethodGet, "/", nil)
    request.AddCookie(&http.Cookie{Name:"__Host-portal_session", Value:old.ID})
    credential, present, err := client.ResolveSession(request)
    if err != nil || !present { t.Fatalf("ResolveSession() = %#v/%v/%v", credential, present, err) }
    stored, _ := backend.Get(t.Context(), old.ID)
    if !slices.Equal(stored.Auth.Groups, []string{"new"}) || !slices.Equal(stored.Tokens.GrantedScopes, []string{"email", "groups", "openid"}) { t.Fatalf("session=%#v", stored) }
}

func TestRefreshValidationFailureCommitsNothing(t *testing.T) {
    client, backend, issuer := newRefreshTestClient(t)
    before := seedExpiringSession(t, backend, []string{"old"}, []string{"openid", "groups"})
    issuer.RefreshAudience = "different-client"
    if _, _, err := client.ResolveSession(requestWithSessionCookie(before.ID)); err == nil { t.Fatal("ResolveSession() error=nil") }
    after, err := backend.Get(t.Context(), before.ID)
    if err != nil || !reflect.DeepEqual(after, before) { t.Fatalf("after=%#v err=%v want=%#v", after, err, before) }
}
func TestInvalidGrantDeletesSessionWithLease(t *testing.T) {
    client, backend, issuer := newRefreshTestClient(t)
    item := seedExpiringSession(t, backend, []string{"old"}, []string{"openid"})
    issuer.RefreshOAuthError = "invalid_grant"
    _, _, err := client.ResolveSession(requestWithSessionCookie(item.ID))
    if !errors.Is(err, core.ErrInvalidGrant) { t.Fatalf("error=%v", err) }
    if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) { t.Fatalf("Get() error=%v", err) }
}
func TestLocalLogoutNeverCallsEndSession(t *testing.T) {
    client, backend, issuer := newRefreshTestClient(t)
    item := seedValidSession(t, backend)
    response := serveWithCookie(t, client.LocalLogoutHandler(), item.ID)
    if response.Code != http.StatusNoContent || issuer.EndSessionCalls() != 0 { t.Fatalf("status=%d calls=%d", response.Code, issuer.EndSessionCalls()) }
}
func TestCentralLogoutDeletesLocalBeforeRemoteFailure(t *testing.T) {
    client, backend, issuer := newRefreshTestClient(t)
    item := seedValidSession(t, backend)
    issuer.EndSessionStatus = http.StatusServiceUnavailable
    response := serveWithCookie(t, client.CentralLogoutHandler(), item.ID)
    if response.Code != http.StatusServiceUnavailable || issuer.EndSessionCalls() != 1 { t.Fatalf("status=%d calls=%d", response.Code, issuer.EndSessionCalls()) }
    if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) { t.Fatalf("session restored: %v", err) }
}
```

Implement the Task 5 local fixture in `bff/refresh_test.go` with these exact helpers: `newRefreshTestClient(t) (*Client,*memory.Backend,*refreshIssuer)`, `seedExpiringSession(t,backend,groups,scopes) *session.Session`, `seedValidSession(t,backend) *session.Session`, `requestWithSessionCookie(id) *http.Request`, and `serveWithCookie(t,handler,id) *httptest.ResponseRecorder`. `refreshIssuer` exposes the mutable fields and `EndSessionCalls()` used above under a mutex.

- [ ] **Step 2: Run focused tests and verify missing method failures**

Run: `go test ./bff -run 'Refresh|ResolveSession|Me|Logout' -count=1`

Expected: FAIL because refresh/session/logout APIs are undefined.

- [ ] **Step 3: Implement proactive refresh with fenced atomic commit**

`ResolveSession` returns `(core.Credential, present bool, error)`. It parses only the configured Session Cookie, loads Session, rejects expiry/idle expiry, and refreshes when `AccessTokenExpiry-Clock.Now() <= RefreshBeforeExpiry`. Refresh acquires a lease, reloads Session, rechecks the window, calls the token endpoint once, verifies all new tokens/claims/UserInfo, and calls `CompareAndSwapWithLease` once.

`SessionPresent(request) (bool,error)` validates only Cookie shape and reports presence without loading Session, refreshing, or exposing the Cookie value. `ResolveSession` updates `LastSeenAt` and idle expiry through versioned CAS after authentication; a conflicting newer Session is reloaded rather than overwritten.

On `invalid_grant`, call `DeleteWithLease` and return an error satisfying `errors.Is(err, core.ErrInvalidGrant)`. On temporary/network failure, release the lease without mutating Session. If another owner completed refresh, reload and return its Session rather than issuing a second refresh.

Return a request-scoped token source that captures the final access token in an unexported closure:

```go
credential := core.Credential{
    Source: core.CredentialSession,
    SessionID: item.ID,
    Auth: item.Auth,
    Tokens: core.TokenSourceFunc(func(context.Context) (string, error) {
        if strings.TrimSpace(item.Tokens.AccessToken) == "" { return "", core.NewError(core.KindUnauthenticated, "bff.session_token", 0, false, nil) }
        return item.Tokens.AccessToken, nil
    }),
}
```

- [ ] **Step 4: Implement Me and separate logout handlers**

`LoginHandler` and `CallbackHandler` accept GET, `MeHandler` accepts GET, and both logout handlers accept POST; other methods return 405 without side effects. `MeHandler` resolves Session and emits only typed AuthContext fields—never tokens, Session ID, Flow ID, nonce, or verifier. `LocalLogoutHandler` clears Cookie and deletes local Session only. `CentralLogoutHandler` clears Cookie, deletes local Session, then sends one end-session request using the prior ID/access token as required by the frozen Server endpoint; remote failure returns sanitized unavailable without restoring local state.

- [ ] **Step 5: Run full core/BFF verification**

Run: `gofmt -w core bff && go test ./core ./bff/... -count=1 && go test -race ./core ./bff/... -count=1 && go vet ./core ./bff/...`

Expected: PASS with refresh token endpoint count one per winning lease, zero partial commits, and distinct local/central logout remote counts.

- [ ] **Step 6: Activate completed assertions in the root v1.8.1 contract test**

Replace the Task 1 log-only contract with `bff.DefaultScopes()` and assert it equals `[]string{"openid","profile","email","groups"}` and excludes `roles`. Mutate the returned slice and assert a second call is unchanged. Run: `go test . ./core ./bff/... -run TestV181FrozenContract -count=1`.

Expected: PASS.

- [ ] **Step 7: Commit Core+BFF completion**

```bash
git add core bff contract_v181_test.go
git commit -m "feat(bff): add atomic refresh and logout semantics"
```

## Plan Completion Gate

Run:

```bash
go test ./core ./bff/... -count=1
go test -race ./core ./bff/... -count=1
go vet ./core ./bff/...
git status --short
```

Expected: all commands pass and status contains only intentional plan-progress changes. Do not delete legacy packages yet; Plan 3 removes them after HTTP authorization and adapters are independently green.
