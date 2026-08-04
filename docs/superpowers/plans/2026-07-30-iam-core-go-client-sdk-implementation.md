# IAM Core Go Client SDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `github.com/swan-swan-swan/iam-core-client-sdk-go` v0.1.0 so a Go web service can complete IAM Core OIDC login, encrypted pluggable sessions, automatic refresh, online identity validation, logout, and fail-closed PDP authorization through `net/http` or Gin.

**Architecture:** The root `iamcore.Client` composes focused public packages for OIDC, sessions, authentication, authorization, and middleware. `net/http` is the behavioral core; Gin is a thin adapter. Shared error, transport, clock, randomness, and observability helpers remain internal so the public API does not expose IAM Core server DTOs.

**Tech Stack:** Go 1.24, `github.com/coreos/go-oidc/v3` v3.17.0, `golang.org/x/oauth2` v0.35.0, `github.com/golang-jwt/jwt/v5` v5.3.1 for deterministic JWT fixtures, `github.com/redis/go-redis/v9` v9.21.0, `github.com/gin-gonic/gin` v1.11.0, `github.com/testcontainers/testcontainers-go/modules/redis` v0.40.0, standard `log/slog`, `net/http`, `crypto/aes`, and `crypto/cipher`.

## Global Constraints

- Module path is exactly `github.com/swan-swan-swan/iam-core-client-sdk-go`.
- Minimum supported Go version is Go 1.24; do not select dependencies requiring Go 1.25.
- Default issuer in examples is `https://iam.wuhl-goose.top`; the library itself must require an explicit issuer.
- Access Tokens never provide authoritative role authorization; do not add `RequireRole`.
- Middleware supports Session Cookie and `Authorization: Bearer`; unequal simultaneous tokens fail with `credential_conflict`.
- Bearer authentication uses online UserInfo by default; local JWT verification is an explicit low-level method only.
- PDP authorization never caches decisions and always fails closed.
- Do not automatically retry Authorization Code, Token refresh, network failures, 5xx responses, or PDP calls.
- The one allowed protocol recovery is: a Session credential receives PDP 401, refresh once, then make one new PDP decision.
- Tokens, Client Secrets, authorization codes, cookies, raw Session IDs, and encryption keys must never enter logs, errors, metrics labels, or traces.
- Production cookies default to `__Host-iam_core_session`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and no Domain.
- `Secure=false` is allowed only for an explicitly enabled localhost/loopback development configuration.
- Redis Session and Flow payloads use AES-256-GCM and hashed identifiers in Redis keys.
- Redis compare-and-swap, Flow consume, lock acquisition, lock ownership checks, and unlock must be atomic.
- Unknown JSON fields and unknown PDP `reason_code` values must remain forward-compatible.
- Keep the IAM Core server repository read-only.
- The local Git remote still uses the legacy repository URL; do not mutate `origin` without explicit user authorization.

## File Map

| Path | Responsibility |
| --- | --- |
| `go.mod`, `go.sum` | Go 1.24 module and pinned dependency graph |
| `errors.go` | Root aliases for stable SDK errors |
| `client.go`, `config.go` | Root composition and convenience API |
| `identity.go` | Root identity/context aliases |
| `hooks.go` | Public low-cardinality observation hook |
| `internal/sdkerr/error.go` | Error construction, redaction, `errors.Is` behavior |
| `observability/hooks.go` | Public low-cardinality operation observations |
| `internal/transport/client.go` | Bounded HTTP execution and correlation extraction |
| `internal/transport/propagation.go` | Allowlisted trace/request header propagation |
| `internal/clock/clock.go` | Production and deterministic test clocks |
| `internal/random/random.go` | Base64url cryptographic identifiers |
| `oidc/client.go` | Discovery, configuration, and endpoint ownership |
| `oidc/token.go` | Authorization URL, code exchange, refresh |
| `oidc/verify.go` | ID Token and explicit Access Token JWT verification |
| `oidc/userinfo.go` | Scope-aware online UserInfo and unknown claims |
| `oidc/logout.go` | IAM Core end-session request |
| `session/backend.go` | SessionStore, FlowStore, RefreshLocker contracts |
| `session/model.go` | Session, Flow, Token lifetime data |
| `session/codec.go` | Codec and AES-256-GCM keyring |
| `session/sessiontest/conformance.go` | Reusable Backend conformance suite |
| `session/memory/backend.go` | Development/test Backend |
| `session/redis/backend.go` | Redis keying and public Backend methods |
| `session/redis/scripts.go` | Atomic Redis Lua scripts |
| `authn/service.go` | Authentication service configuration |
| `authn/login.go`, `authn/callback.go` | Browser OIDC flow |
| `authn/refresh.go` | Distributed refresh rotation |
| `authn/credentials.go` | Cookie/Bearer resolution and online validation |
| `authn/logout.go` | Local-first logout |
| `authn/cookies.go` | Secure Cookie construction and clearing |
| `authz/client.go` | PDP decision protocol |
| `middleware/http.go` | `net/http` authentication and authorization |
| `middleware/responder.go` | Default/custom middleware errors |
| `middleware/gin/gin.go` | Gin adapter |
| `examples/nethttp/main.go` | Standard-library example |
| `examples/gin/main.go` | Gin example |
| `examples/redis/main.go` | Redis Backend construction example |
| `README.md` | Ten-minute Quickstart and security guidance |
| `COMPATIBILITY.md` | IAM Core compatibility matrix |
| `CHANGELOG.md` | v0.1.0 release notes |
| `.github/workflows/ci.yml` | Unit, race, vet, fuzz-smoke, and Redis tests |

---

### Task 1: Initialize the module, stable errors, clock, randomness, and observation hooks

**Files:**
- Create: `go.mod`
- Create: `errors.go`
- Create: `hooks.go`
- Create: `internal/sdkerr/error.go`
- Create: `internal/sdkerr/error_test.go`
- Create: `internal/clock/clock.go`
- Create: `internal/random/random.go`
- Create: `internal/random/random_test.go`
- Create: `observability/hooks.go`

**Interfaces:**
- Produces: `iamcore.Error`, `iamcore.ErrorKind`, root sentinel errors, `observability.Hooks`, `clock.Clock`, and `random.ID(io.Reader, int)`.
- Consumes: only the Go standard library.

- [ ] **Step 1: Create the Go module**

Create `go.mod`:

```go
module github.com/swan-swan-swan/iam-core-client-sdk-go

go 1.24.0
```

Run: `go mod tidy`

Expected: exit 0 and a module with no external requirements.

- [ ] **Step 2: Write failing stable-error tests**

Create `internal/sdkerr/error_test.go`:

```go
package sdkerr

import (
	"errors"
	"net/http"
	"testing"
)

func TestErrorSupportsKindAndSentinelMatching(t *testing.T) {
	cause := errors.New("dial tcp 10.0.0.1:443")
	err := New(KindIAMUnavailable, "oidc.userinfo", http.StatusServiceUnavailable, true, cause)
	err.RequestID = "req-1"

	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("error must match ErrUnavailable")
	}
	if got := err.Error(); got != "oidc.userinfo: iam_unavailable" {
		t.Fatalf("Error() = %q", got)
	}
	if err.Unwrap() != cause {
		t.Fatal("Unwrap() must return cause")
	}
}

func TestErrorStringNeverIncludesSensitiveCause(t *testing.T) {
	err := New(KindUnauthenticated, "authn.callback", http.StatusUnauthorized, false, errors.New("token=secret-value"))
	if got := err.Error(); got != "authn.callback: unauthenticated" {
		t.Fatalf("Error() leaked cause: %q", got)
	}
}
```

- [ ] **Step 3: Run the error tests and confirm the red state**

Run: `go test ./internal/sdkerr -run TestError -count=1`

Expected: FAIL because `New`, error kinds, and sentinels do not exist.

- [ ] **Step 4: Implement the error model and root aliases**

Create `internal/sdkerr/error.go` with:

```go
package sdkerr

import (
	"errors"
	"fmt"
)

type Kind string

const (
	KindInvalidConfig      Kind = "invalid_config"
	KindUnauthenticated    Kind = "unauthenticated"
	KindCredentialConflict Kind = "credential_conflict"
	KindForbidden          Kind = "forbidden"
	KindProtocol           Kind = "protocol_error"
	KindSessionUnavailable Kind = "session_unavailable"
	KindIAMUnavailable     Kind = "iam_unavailable"
)

var (
	ErrUnauthenticated = errors.New("iamcore: unauthenticated")
	ErrForbidden       = errors.New("iamcore: forbidden")
	ErrUnavailable     = errors.New("iamcore: unavailable")
)

type Error struct {
	Kind       Kind
	Operation  string
	HTTPStatus int
	RequestID  string
	TraceID    string
	DecisionID string
	Retryable  bool
	Cause      error
}

func New(kind Kind, operation string, status int, retryable bool, cause error) *Error {
	return &Error{Kind: kind, Operation: operation, HTTPStatus: status, Retryable: retryable, Cause: cause}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Operation == "" {
		return string(e.Kind)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Kind)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *Error) Is(target error) bool {
	switch target {
	case ErrUnauthenticated:
		return e != nil && e.Kind == KindUnauthenticated
	case ErrForbidden:
		return e != nil && e.Kind == KindForbidden
	case ErrUnavailable:
		return e != nil && (e.Kind == KindIAMUnavailable || e.Kind == KindSessionUnavailable)
	default:
		return false
	}
}
```

Create `errors.go`:

```go
package iamcore

import "github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"

type Error = sdkerr.Error
type ErrorKind = sdkerr.Kind

const (
	ErrorInvalidConfig      = sdkerr.KindInvalidConfig
	ErrorUnauthenticated    = sdkerr.KindUnauthenticated
	ErrorCredentialConflict = sdkerr.KindCredentialConflict
	ErrorForbidden          = sdkerr.KindForbidden
	ErrorProtocol           = sdkerr.KindProtocol
	ErrorSessionUnavailable = sdkerr.KindSessionUnavailable
	ErrorIAMUnavailable     = sdkerr.KindIAMUnavailable
)

var (
	ErrUnauthenticated = sdkerr.ErrUnauthenticated
	ErrForbidden       = sdkerr.ErrForbidden
	ErrUnavailable     = sdkerr.ErrUnavailable
)
```

- [ ] **Step 5: Implement deterministic infrastructure helpers**

Create `internal/clock/clock.go`:

```go
package clock

import "time"

type Clock interface {
	Now() time.Time
}

type Real struct{}

func (Real) Now() time.Time { return time.Now() }

type Fixed struct{ Time time.Time }

func (f Fixed) Now() time.Time { return f.Time }
```

Create `internal/random/random.go`:

```go
package random

import (
	"encoding/base64"
	"fmt"
	"io"
)

func ID(source io.Reader, byteCount int) (string, error) {
	if source == nil || byteCount < 16 {
		return "", fmt.Errorf("random source is nil or byte count is below 16")
	}
	value := make([]byte, byteCount)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
```

Create `internal/random/random_test.go`:

```go
package random

import (
	"bytes"
	"testing"
)

func TestIDReturnsBase64URLWithoutPadding(t *testing.T) {
	got, err := ID(bytes.NewReader(make([]byte, 32)), 32)
	if err != nil {
		t.Fatal(err)
	}
	if got != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("ID() = %q", got)
	}
}
```

Create `observability/hooks.go` and root `hooks.go`:

```go
package observability

import (
	"context"
	"time"
)

type Event struct {
	Operation        string
	Outcome          string
	CredentialSource string
	Duration         time.Duration
}

type Hooks interface {
	Observe(context.Context, Event)
}

type Nop struct{}

func (Nop) Observe(context.Context, Event) {}
```

```go
package iamcore

import "github.com/swan-swan-swan/iam-core-client-sdk-go/observability"

type Observation = observability.Event
type Hooks = observability.Hooks
```

- [ ] **Step 6: Verify Task 1**

Run:

```bash
gofmt -w errors.go hooks.go internal/sdkerr/*.go internal/clock/*.go internal/random/*.go observability/*.go
go test ./... -count=1
go vet ./...
git diff --check
```

Expected: all commands exit 0; error and random tests pass.

- [ ] **Step 7: Commit Task 1**

```bash
git add go.mod errors.go hooks.go internal observability
git commit -m "chore: initialize SDK module and core contracts"
```

### Task 2: Add bounded HTTP transport and correlation propagation

**Files:**
- Create: `internal/transport/client.go`
- Create: `internal/transport/client_test.go`
- Create: `internal/transport/propagation.go`
- Create: `internal/transport/propagation_test.go`

**Interfaces:**
- Consumes: `sdkerr.Error`.
- Produces: `transport.Client.Do`, `transport.DecodeJSON`, `transport.Correlation`, `transport.WithHeaders`, and `transport.ApplyHeaders`.

- [ ] **Step 1: Write failing bounded-response and propagation tests**

Create `internal/transport/client_test.go`:

```go
package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"` + strings.Repeat("x", 128) + `"}`))
	}))
	defer server.Close()

	client := Client{HTTP: server.Client(), MaxBodyBytes: 32}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected oversized response error")
	}
}

func TestClientCapturesCorrelation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "req-header")
		_, _ = w.Write([]byte(`{"request_id":"req-body","trace_id":"trace-body"}`))
	}))
	defer server.Close()

	client := Client{HTTP: server.Client(), MaxBodyBytes: 1024}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Correlation.RequestID != "req-header" || response.Correlation.TraceID != "trace-body" {
		t.Fatalf("correlation = %#v", response.Correlation)
	}
}
```

Create `internal/transport/propagation_test.go`:

```go
package transport

import (
	"context"
	"net/http"
	"testing"
)

func TestApplyHeadersForwardsOnlyAllowlistedHeaders(t *testing.T) {
	source := http.Header{
		"Traceparent":   {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		"Tracestate":    {"vendor=value"},
		"X-Request-Id":  {"req-1"},
		"Authorization": {"Bearer must-not-forward"},
		"Cookie":        {"must-not-forward"},
	}
	ctx := WithHeaders(context.Background(), source)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test", nil)
	ApplyHeaders(ctx, req.Header)

	if req.Header.Get("Traceparent") == "" || req.Header.Get("X-Request-ID") != "req-1" {
		t.Fatalf("missing propagation headers: %#v", req.Header)
	}
	if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
		t.Fatalf("sensitive headers propagated: %#v", req.Header)
	}
}
```

- [ ] **Step 2: Run tests to verify the red state**

Run: `go test ./internal/transport -count=1`

Expected: FAIL because transport types and functions are undefined.

- [ ] **Step 3: Implement allowlisted propagation**

Create `internal/transport/propagation.go`:

```go
package transport

import (
	"context"
	"net/http"
	"strings"
)

type propagationKey struct{}

var forwardedHeaders = []string{"Traceparent", "Tracestate", "X-Request-ID"}

func WithHeaders(ctx context.Context, source http.Header) context.Context {
	values := make(http.Header, len(forwardedHeaders))
	for _, name := range forwardedHeaders {
		if value := strings.TrimSpace(source.Get(name)); value != "" {
			values.Set(name, value)
		}
	}
	return context.WithValue(ctx, propagationKey{}, values)
}

func ApplyHeaders(ctx context.Context, destination http.Header) {
	values, _ := ctx.Value(propagationKey{}).(http.Header)
	for _, name := range forwardedHeaders {
		if value := strings.TrimSpace(values.Get(name)); value != "" {
			destination.Set(name, value)
		}
	}
}
```

- [ ] **Step 4: Implement the bounded transport**

Create `internal/transport/client.go` with:

```go
package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const DefaultMaxBodyBytes int64 = 1 << 20

type Correlation struct {
	RequestID string
	TraceID   string
}

type Response struct {
	StatusCode  int
	Header      http.Header
	Body        []byte
	Correlation Correlation
}

type Client struct {
	HTTP         *http.Client
	MaxBodyBytes int64
}

func (c Client) Do(request *http.Request) (Response, error) {
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	limit := c.MaxBodyBytes
	if limit <= 0 {
		limit = DefaultMaxBodyBytes
	}
	ApplyHeaders(request.Context(), request.Header)
	raw, err := httpClient.Do(request)
	if err != nil {
		return Response{}, fmt.Errorf("execute HTTP request: %w", err)
	}
	defer raw.Body.Close()
	mediaType, _, err := mime.ParseMediaType(raw.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return Response{}, fmt.Errorf("unexpected content type %q", raw.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(raw.Body, limit+1))
	if err != nil {
		return Response{}, fmt.Errorf("read HTTP response: %w", err)
	}
	if int64(len(body)) > limit {
		return Response{}, fmt.Errorf("HTTP response exceeds %d bytes", limit)
	}
	correlation := Correlation{RequestID: strings.TrimSpace(raw.Header.Get("X-Request-ID"))}
	var envelope struct {
		RequestID string `json:"request_id"`
		TraceID   string `json:"trace_id"`
	}
	_ = json.Unmarshal(body, &envelope)
	if correlation.RequestID == "" {
		correlation.RequestID = strings.TrimSpace(envelope.RequestID)
	}
	correlation.TraceID = strings.TrimSpace(envelope.TraceID)
	return Response{StatusCode: raw.StatusCode, Header: raw.Header.Clone(), Body: body, Correlation: correlation}, nil
}

func DecodeJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode JSON response: trailing JSON value")
	}
	return nil
}
```

- [ ] **Step 5: Verify Task 2**

Run:

```bash
gofmt -w internal/transport
go test ./internal/transport -count=1
go test ./... -count=1
go vet ./...
git diff --check
```

Expected: all commands exit 0 and both transport tests pass.

- [ ] **Step 6: Commit Task 2**

```bash
git add internal/transport
git commit -m "feat: add safe IAM HTTP transport"
```

### Task 3: Implement OIDC Discovery, authorization URL, code exchange, and refresh

**Files:**
- Create: `oidc/client.go`
- Create: `oidc/token.go`
- Create: `oidc/client_test.go`
- Create: `oidc/token_test.go`
- Create: `oidc/testserver_test.go`

**Interfaces:**
- Consumes: `transport.Client` and `observability.Hooks`.
- Produces: `oidc.New`, `Client.Metadata`, `Client.AuthCodeURL`, `Client.Exchange`, `Client.Refresh`, `SecretProvider`, `StaticSecret`, and `TokenSet`.

- [ ] **Step 1: Pin Go 1.24-compatible OIDC dependencies**

Run:

```bash
go get github.com/coreos/go-oidc/v3@v3.17.0
go get golang.org/x/oauth2@v0.35.0
go get github.com/golang-jwt/jwt/v5@v5.3.1
```

Expected: `go.mod` records exactly those direct versions and retains `go 1.24.0`.

- [ ] **Step 2: Write a reusable fake IAM OIDC server**

Create `oidc/testserver_test.go` with a helper that:

```go
type fakeOIDCServer struct {
	Server       *httptest.Server
	TokenCalls   atomic.Int32
	LastTokenForm url.Values
}
```

The helper must expose:

- `/.well-known/openid-configuration` with issuer, authorization, token, userinfo, JWKS, and logout endpoints;
- `/oidc/token` that requires `client_id`, `client_secret`, and either code or refresh token in form fields;
- `/oidc/jwks` with a generated RSA public key;
- cleanup through `t.Cleanup(server.Close)`.

Use an `http.ServeMux`, a test-only RSA key generated with `rsa.GenerateKey(rand.Reader, 2048)`, and a mutex around `LastTokenForm`.

- [ ] **Step 3: Write failing Discovery and token tests**

Create tests with these exact assertions:

```go
func TestNewRejectsIssuerMismatch(t *testing.T) {
	fake := newFakeOIDCServer(t)
	fake.OverrideDiscoveryIssuer("https://different.example")
	_, err := New(context.Background(), Config{
		IssuerURL: fake.Server.URL,
		ClientID: "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL: "https://app.example/callback",
		Scopes: []string{"openid", "profile"},
		HTTPClient: fake.Server.Client(),
	})
	if err == nil {
		t.Fatal("expected issuer mismatch")
	}
}

func TestAuthCodeURLContainsStateNonceAndScopes(t *testing.T) {
	client := newTestClient(t)
	raw := client.AuthCodeURL("state-1", "nonce-1")
	values, _ := url.Parse(raw)
	query := values.Query()
	if query.Get("state") != "state-1" || query.Get("nonce") != "nonce-1" {
		t.Fatalf("query = %#v", query)
	}
	if query.Get("response_type") != "code" || query.Get("scope") != "openid profile email roles" {
		t.Fatalf("query = %#v", query)
	}
}

func TestExchangeUsesClientSecretInFormAndDoesNotRetry(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	_, err := client.Exchange(context.Background(), "code-1")
	if err != nil {
		t.Fatal(err)
	}
	if fake.TokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d", fake.TokenCalls.Load())
	}
	if fake.LastTokenForm.Get("client_secret") != "secret-1" {
		t.Fatal("client_secret was not sent in form")
	}
}
```

- [ ] **Step 4: Run OIDC tests to verify the red state**

Run: `go test ./oidc -run 'Test(New|AuthCodeURL|Exchange)' -count=1`

Expected: FAIL because OIDC Client APIs do not exist.

- [ ] **Step 5: Implement OIDC configuration and Discovery**

Create `oidc/client.go` defining:

```go
type Metadata struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSURI               string
	EndSessionEndpoint    string
	ScopesSupported       []string
}

type SecretProvider interface {
	Secret(context.Context) (string, error)
}

type SecretProviderFunc func(context.Context) (string, error)

func (f SecretProviderFunc) Secret(ctx context.Context) (string, error) { return f(ctx) }

func StaticSecret(value string) SecretProvider {
	return SecretProviderFunc(func(context.Context) (string, error) {
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("client secret is empty")
		}
		return value, nil
	})
}

type Config struct {
	IssuerURL      string
	ClientID       string
	SecretProvider SecretProvider
	RedirectURL    string
	Scopes         []string
	HTTPClient     *http.Client
	Timeout        time.Duration
	Hooks          observability.Hooks
	Logger         *slog.Logger
}
```

`New` must:

- normalize only a trailing slash for comparison, never rewrite endpoint hosts;
- require HTTPS except when the issuer is an explicit loopback/localhost test server;
- load Discovery with the configured HTTP Client and timeout;
- parse the IAM fields into `Metadata`;
- require exact normalized issuer match and non-empty authorization, token, userinfo, JWKS, and end-session endpoints;
- require `openid` in configured scopes;
- configure `oauth2.Endpoint.AuthStyle = oauth2.AuthStyleInParams`;
- initialize `coreosoidc.NewRemoteKeySet` and an ID Token verifier.
- use a discard `slog.Logger` when nil and log only operation, outcome, duration, and correlation IDs.

Define these shared test helpers in `oidc/testserver_test.go`:

```go
func newFakeOIDCServer(t *testing.T) *fakeOIDCServer
func (f *fakeOIDCServer) OverrideDiscoveryIssuer(issuer string)
func newTestClient(t *testing.T) *Client
func newTestClientAndServer(t *testing.T) (*Client, *fakeOIDCServer)
```

- [ ] **Step 6: Implement authorization URL, exchange, and refresh**

Create `oidc/token.go` defining:

```go
type TokenSet struct {
	AccessToken       string
	TokenType         string
	RefreshToken      string
	IDToken           string
	AccessTokenExpiry time.Time
}
```

Implement:

```go
func (c *Client) AuthCodeURL(state string, nonce string) string
func (c *Client) Exchange(ctx context.Context, code string) (TokenSet, error)
func (c *Client) Refresh(ctx context.Context, refreshToken string) (TokenSet, error)
```

Required behavior:

- require non-empty state, nonce, code, and refresh token;
- obtain the current Client Secret from `SecretProvider` for each token call;
- use form authentication, not Basic Auth;
- issue exactly one HTTP request per method call;
- preserve the existing Refresh Token only when a standards-compliant refresh response omits a replacement;
- map OAuth `error/error_description` and IAM envelope errors to redacted `sdkerr.Error`;
- set `RequestID/TraceID` from transport correlation;
- never include submitted values in errors.

- [ ] **Step 7: Verify Task 3**

Run:

```bash
gofmt -w oidc
go test ./oidc -count=1
go test ./... -count=1
go vet ./...
git diff --check
```

Expected: all OIDC tests pass; fake server observes one form-authenticated request per exchange/refresh.

- [ ] **Step 8: Commit Task 3**

```bash
git add go.mod go.sum oidc
git commit -m "feat: add OIDC discovery and token exchange"
```

### Task 4: Verify ID Tokens, fetch scope-aware UserInfo, and call logout

**Files:**
- Create: `oidc/verify.go`
- Create: `oidc/verify_test.go`
- Create: `oidc/userinfo.go`
- Create: `oidc/userinfo_test.go`
- Create: `oidc/logout.go`
- Create: `oidc/logout_test.go`

**Interfaces:**
- Consumes: `oidc.Client` and its RemoteKeySet/metadata from Task 3.
- Produces: `Identity`, `IDTokenClaims`, `AccessTokenClaims`, `VerifyIDToken`, `VerifyAccessTokenJWT`, `UserInfo`, and `Logout`.

- [ ] **Step 1: Write failing verification and UserInfo tests**

Add tests that generate RS256 tokens with the fake server key and assert:

```go
func TestVerifyIDTokenRejectsNonceMismatch(t *testing.T) {
	client, signer := newVerificationClient(t)
	raw := signer.IDToken(t, map[string]any{
		"iss": client.Metadata().Issuer,
		"aud": []string{"client-1"},
		"sub": "op_usr_0123456789abcdefgjk",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"nonce": "nonce-from-token",
	})
	_, err := client.VerifyIDToken(context.Background(), raw, "different-nonce")
	if err == nil {
		t.Fatal("expected nonce mismatch")
	}
}

func TestUserInfoPreservesUnknownClaims(t *testing.T) {
	client := newUserInfoClient(t, `{
		"sub":"op_usr_0123456789abcdefgjk",
		"username":"alice",
		"roles":["platform_dev"],
		"organization_code":"ops"
	}`)
	identity, err := client.UserInfo(context.Background(), "access-token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "op_usr_0123456789abcdefgjk" {
		t.Fatalf("subject = %q", identity.Subject)
	}
	if string(identity.ExtraClaims["organization_code"]) != `"ops"` {
		t.Fatalf("extra claims = %#v", identity.ExtraClaims)
	}
}
```

Also test:

- wrong issuer, audience, expiry, algorithm, and missing subject;
- UserInfo 401 IAM envelope maps to `ErrUnauthenticated`;
- logout sends `id_token_hint` and Bearer Access Token exactly once.

Define these Task 4 test helpers in package `oidc`:

```go
type testTokenSigner struct {
	PrivateKey *rsa.PrivateKey
	Issuer     string
	ClientID   string
	KeyID      string
}

func newVerificationClient(t *testing.T) (*Client, *testTokenSigner)
func (s *testTokenSigner) IDToken(t *testing.T, claims map[string]any) string
func newUserInfoClient(t *testing.T, responseBody string) *Client
```

- [ ] **Step 2: Run tests to verify the red state**

Run: `go test ./oidc -run 'Test(Verify|UserInfo|Logout)' -count=1`

Expected: FAIL because verification, Identity, UserInfo, and Logout APIs are absent.

- [ ] **Step 3: Implement claims and verification**

Create `oidc/verify.go`:

```go
type Identity struct {
	Subject     string
	Username    string
	Email       string
	DisplayName string
	Roles       []string
	Scopes      []string
	ExtraClaims map[string]json.RawMessage
}

type IDTokenClaims struct {
	Subject string   `json:"sub"`
	Nonce   string   `json:"nonce"`
	SessionID string `json:"sid"`
	Username string   `json:"username"`
	Email string      `json:"email"`
	DisplayName string `json:"display_name"`
	Roles []string    `json:"roles"`
	Scope string      `json:"scope"`
}

type AccessTokenClaims struct {
	Subject  string   `json:"sub"`
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	TokenID  string   `json:"jti"`
	Scope    string   `json:"scope"`
	Expiry   int64    `json:"exp"`
}
```

`VerifyIDToken` must use the `go-oidc` verifier, decode claims, compare nonce with
`subtle.ConstantTimeCompare`, require a non-empty subject, and return only redacted protocol errors.

`VerifyAccessTokenJWT` must call the RemoteKeySet signature verifier, decode registered claims,
require issuer/client audience/expiry/not-before, and document in its Go comment that signature validity
does not prove revocation status or authorization.

- [ ] **Step 4: Implement online UserInfo**

Create `oidc/userinfo.go`:

- send exactly one GET with `Authorization: Bearer <token>`;
- require non-empty Access Token;
- decode a raw `map[string]json.RawMessage`;
- extract `sub`, `username`, `email`, `display_name`, and `roles`;
- derive Scopes from the Access Token metadata available to the caller or leave it as the configured granted Scope set;
- delete known keys from the copied map and return the remainder as `ExtraClaims`;
- require non-empty `sub`;
- map 401 to `ErrUnauthenticated`, 5xx to retryable `iam_unavailable`, and malformed 2xx to `protocol_error`.

- [ ] **Step 5: Implement logout**

Create `oidc/logout.go`:

```go
func (c *Client) Logout(ctx context.Context, accessToken string, idTokenHint string) error
```

It must:

- require non-empty ID Token Hint;
- build the end-session query with `url.Values`;
- add Bearer only when an Access Token is present;
- make one GET request;
- treat 2xx as success;
- decode IAM envelope errors without logging credentials;
- never retry.

- [ ] **Step 6: Verify Task 4**

Run:

```bash
gofmt -w oidc
go test ./oidc -count=1
go test ./... -count=1
go vet ./...
git diff --check
```

Expected: all verification, UserInfo, logout, and previous OIDC tests pass.

- [ ] **Step 7: Commit Task 4**

```bash
git add oidc
git commit -m "feat: verify IAM tokens and user information"
```

### Task 5: Define Session contracts, AES-256-GCM codec, Memory Backend, and conformance suite

**Files:**
- Create: `session/model.go`
- Create: `session/backend.go`
- Create: `session/errors.go`
- Create: `session/codec.go`
- Create: `session/codec_test.go`
- Create: `session/sessiontest/conformance.go`
- Create: `session/memory/backend.go`
- Create: `session/memory/backend_test.go`

**Interfaces:**
- Consumes: `oidc.TokenSet`, `oidc.Identity`, a public `session.Clock`, and `random.ID`.
- Produces: `session.Backend`, `SessionStore`, `FlowStore`, `RefreshLocker`, `Codec`, `NewAESGCMCodec`, and `memory.New`.

- [ ] **Step 1: Define failing Backend conformance tests**

Create `session/sessiontest/conformance.go`:

```go
package sessiontest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

type Factory func(t *testing.T) session.Backend

func Run(t *testing.T, factory Factory) {
	t.Helper()
	t.Run("session compare and swap", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		item := &session.Session{ID: "session-1", Version: 1, ExpiresAt: time.Now().Add(time.Hour)}
		if err := backend.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
		next := *item
		next.Version = 2
		if err := backend.CompareAndSwap(ctx, item.ID, 1, &next); err != nil {
			t.Fatal(err)
		}
		if err := backend.CompareAndSwap(ctx, item.ID, 1, &next); !errors.Is(err, session.ErrVersionConflict) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("flow is consumed once", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		flow := &session.Flow{ID: "flow-1", State: "state-1", ExpiresAt: time.Now().Add(time.Minute)}
		if err := backend.PutFlow(ctx, flow); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.ConsumeFlow(ctx, flow.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("lock enforces ownership", func(t *testing.T) {
		backend := factory(t)
		ctx := context.Background()
		lock, err := backend.Lock(ctx, "session-1", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !lock.Valid(ctx) {
			t.Fatal("lock must be valid")
		}
		if _, err := backend.Lock(ctx, "session-1", time.Second); !errors.Is(err, session.ErrLocked) {
			t.Fatalf("error = %v", err)
		}
		if err := lock.Unlock(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
```

Add subtests for expired Session, expired Flow, delete idempotency, lock expiry, and copying returned values so callers cannot mutate stored state.

- [ ] **Step 2: Define Session models and Backend interfaces**

Create `session/model.go` and `session/backend.go`:

```go
type Session struct {
	ID                  string
	Version             uint64
	TokenSet            oidc.TokenSet
	Identity            oidc.Identity
	GrantedScopes       []string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	LastSeenAt          time.Time
	ExpiresAt           time.Time
	IdleExpiresAt       time.Time
	IdentityValidatedAt time.Time
}

type Flow struct {
	ID        string
	State     string
	Nonce     string
	ReturnTo  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type SessionStore interface {
	Create(context.Context, *Session) error
	Get(context.Context, string) (*Session, error)
	CompareAndSwap(context.Context, string, uint64, *Session) error
	Delete(context.Context, string) error
}

type FlowStore interface {
	PutFlow(context.Context, *Flow) error
	ConsumeFlow(context.Context, string) (*Flow, error)
}

type Lock interface {
	Valid(context.Context) bool
	Unlock(context.Context) error
}

type RefreshLocker interface {
	Lock(context.Context, string, time.Duration) (Lock, error)
}

type Backend interface {
	SessionStore
	FlowStore
	RefreshLocker
}

type Clock interface {
	Now() time.Time
}
```

Define `ErrNotFound`, `ErrExpired`, `ErrVersionConflict`, `ErrLocked`, and `ErrLockLost`.

- [ ] **Step 3: Write failing AES keyring tests**

Create `session/codec_test.go`:

```go
package session

import (
	"bytes"
	"testing"
)

func TestAESGCMCodecEncryptsAndRotatesKeys(t *testing.T) {
	oldKey := Key{ID: "old", Bytes: bytes.Repeat([]byte{1}, 32)}
	newKey := Key{ID: "new", Bytes: bytes.Repeat([]byte{2}, 32)}
	oldCodec, err := NewAESGCMCodec(oldKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := oldCodec.Encode([]byte(`{"access_token":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("secret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	rotated, err := NewAESGCMCodec(newKey, []Key{oldKey})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := rotated.Decode(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != `{"access_token":"secret"}` {
		t.Fatalf("plaintext = %q", plaintext)
	}
}
```

- [ ] **Step 4: Implement the AES-256-GCM Codec**

Create `session/codec.go` defining:

```go
type Codec interface {
	Encode([]byte) ([]byte, error)
	Decode([]byte) ([]byte, error)
}

type Key struct {
	ID    string
	Bytes []byte
}

func NewAESGCMCodec(primary Key, fallbacks []Key) (Codec, error)
```

Use an envelope:

```go
type encryptedEnvelope struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}
```

Require unique, non-empty Key IDs and exactly 32 bytes per key. Generate a fresh GCM Nonce from
`crypto/rand.Reader`, use the Key ID and version as additional authenticated data, and use
`base64.RawURLEncoding` for binary fields.

- [ ] **Step 5: Implement Memory Backend and run the conformance suite**

Create `session/memory/backend.go` with mutex-protected maps for Session, Flow, and locks.
Deep-copy values by JSON round-trip or dedicated copy functions on every store/read boundary.
Use an injected `session.Clock`; remove expired records on access and expose `Prune()` for explicit cleanup.

Create `session/memory/backend_test.go`:

```go
package memory

import (
	"crypto/rand"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/clock"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/sessiontest"
)

func TestBackendConformance(t *testing.T) {
	sessiontest.Run(t, func(t *testing.T) session.Backend {
		t.Helper()
		return New(Options{Clock: clock.Real{}, Random: rand.Reader})
	})
}
```

- [ ] **Step 6: Verify Task 5**

Run:

```bash
gofmt -w session
go test ./session/... -count=1
go test -race ./session/...
go test ./... -count=1
go vet ./...
git diff --check
```

Expected: codec rotation and all Memory Backend conformance cases pass, including race detection.

- [ ] **Step 7: Commit Task 5**

```bash
git add session
git commit -m "feat: add encrypted session backend contracts"
```

### Task 6: Implement the Redis Backend with atomic scripts

**Files:**
- Create: `session/redis/backend.go`
- Create: `session/redis/scripts.go`
- Create: `session/redis/backend_test.go`
- Create: `session/redis/integration_test.go`

**Interfaces:**
- Consumes: `session.Backend`, `session.Codec`, `session/sessiontest.Run`.
- Produces: `redisstore.New(redis.UniversalClient, Options)`.

- [ ] **Step 1: Pin Redis and integration-test dependencies**

Run:

```bash
go get github.com/redis/go-redis/v9@v9.21.0
go get github.com/testcontainers/testcontainers-go/modules/redis@v0.40.0
```

Expected: both versions are direct requirements and `go.mod` remains Go 1.24.

- [ ] **Step 2: Write Redis key and constructor tests**

Create `session/redis/backend_test.go`:

```go
package redisstore

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestKeyNeverContainsRawIdentifier(t *testing.T) {
	backend := &Backend{prefix: "iamcore"}
	raw := "session-secret-id"
	got := backend.sessionKey(raw)
	sum := sha256.Sum256([]byte(raw))
	want := "iamcore:session:" + hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
	if got == raw {
		t.Fatal("raw identifier exposed")
	}
}
```

Add constructor cases for nil Redis Client, nil Codec, empty Prefix, and Prefix normalization.

- [ ] **Step 3: Implement Redis keying and Lua scripts**

Create `session/redis/scripts.go` with `redis.NewScript` values for:

1. Session create: fail if key exists; HSET `version` and encrypted `payload`; PEXPIRE.
2. Session CAS: compare `version`; HSET next version/payload; PEXPIRE.
3. Flow consume: GET encrypted payload then DEL in one script.
4. Lock acquire: `SET key token NX PX ttl`.
5. Lock valid: compare GET value to ownership token.
6. Unlock: compare GET value then DEL.

Return numeric status codes and translate them to the exact `session` sentinel errors. Do not decode
Session payloads inside Lua.

- [ ] **Step 4: Implement the Redis Backend**

Create `session/redis/backend.go`:

```go
type Options struct {
	Prefix string
	Codec  session.Codec
	Clock  session.Clock
	Random io.Reader
}

func New(client goredis.UniversalClient, options Options) (*Backend, error)
```

Required behavior:

- hash Session/Flow/lock identifiers with SHA-256 before forming keys;
- JSON-encode models, then encrypt with Codec;
- store Session version in a separate Redis Hash field for CAS;
- use millisecond TTL derived from the earlier of Session `ExpiresAt` and `IdleExpiresAt`; Flow uses
  its `ExpiresAt`;
- return `ErrExpired` when expiration is not in the future;
- use a 32-byte random ownership token for locks;
- return a lock object whose `Valid` and `Unlock` call ownership scripts;
- wrap Redis availability errors as Session Backend errors without including keys or payloads.

- [ ] **Step 5: Run the shared conformance suite against real Redis**

Create `session/redis/integration_test.go` using Testcontainers Redis with image
`redis:7.4-alpine`. Build an AES Codec from a fixed test key, create a fresh Prefix per test,
and call:

```go
for _, image := range integrationImages() {
	t.Run(image, func(t *testing.T) {
		sessiontest.Run(t, func(t *testing.T) session.Backend {
			t.Helper()
			return newIntegrationBackend(t, image)
		})
	})
}
```

Define:

```go
func newIntegrationBackend(t *testing.T, image string) session.Backend
func integrationImages() []string
```

Run the suite for `redis:6.2-alpine` and `redis:7.4-alpine`. When
`IAMCORE_TEST_REDIS_IMAGE` is non-empty, run only that exact image so CI can use a matrix.
Skip only when `testing.Short()` is true; do not silently skip because Docker is unavailable in
the integration job.

- [ ] **Step 6: Verify Task 6**

Run:

```bash
gofmt -w session/redis
go test ./session/redis -short -count=1
go test ./session/redis -run TestBackendConformance -count=1 -timeout=5m
go test -race ./session/redis -short
go test ./... -short -count=1
go vet ./...
git diff --check
```

Expected: unit tests pass without Docker; conformance passes against Redis 6.2 and 7.4.

- [ ] **Step 7: Commit Task 6**

```bash
git add go.mod go.sum session/redis
git commit -m "feat: add atomic Redis session backend"
```

### Task 7: Implement browser login and callback

**Files:**
- Create: `authn/service.go`
- Create: `authn/cookies.go`
- Create: `authn/login.go`
- Create: `authn/callback.go`
- Create: `authn/login_test.go`
- Create: `authn/callback_test.go`
- Create: `authn/testservice_test.go`

**Interfaces:**
- Consumes: `oidc.Client`, `session.Backend`, an `authn.Clock`, `random.ID`, and `observability.Hooks`.
- Produces: `authn.New`, `Service.LoginHandler`, `Service.CallbackHandler`, `BeginLogin`, and `CompleteCallback`.

- [ ] **Step 1: Write failing login security tests**

Create tests asserting:

```go
func TestLoginHandlerStoresFlowAndSetsSecureCookie(t *testing.T) {
	service, backend := newTestService(t)
	request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2Fassets", nil)
	response := httptest.NewRecorder()
	service.LoginHandler().ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	cookie := response.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie = %#v", cookie)
	}
	if backend.FlowCount() != 1 {
		t.Fatalf("flow count = %d", backend.FlowCount())
	}
}

func TestLoginRejectsExternalReturnTo(t *testing.T) {
	service, _ := newTestService(t)
	request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=https://evil.example", nil)
	response := httptest.NewRecorder()
	service.LoginHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}
```

Add cases for scheme-relative `//evil.example`, backslash variants, control characters, and allowed
relative paths. Add one exact Allowlist acceptance for `https://app.example/post-login` and one
rejection for `https://app.example.evil.test/post-login`.

- [ ] **Step 2: Write failing callback tests**

Test:

- missing Flow Cookie;
- state mismatch consumes the Flow and creates no Session;
- OIDC error creates no Session;
- nonce mismatch creates no Session;
- UserInfo subject mismatch creates no Session;
- successful callback creates a new random Session ID, clears Flow Cookie, sets Session Cookie,
  and redirects to stored ReturnTo;
- a pre-existing attacker-chosen Session Cookie is never reused.

- [ ] **Step 3: Implement Service and Cookie validation**

Create `authn/service.go`:

```go
type Config struct {
	OIDC                     *oidc.Client
	Backend                  session.Backend
	RedirectURL              string
	AllowedReturnToURLs      []string
	SessionCookie            http.Cookie
	FlowCookie               http.Cookie
	FlowTTL                  time.Duration
	SessionAbsoluteTTL       time.Duration
	SessionIdleTTL           time.Duration
	IdentityRecheckInterval  time.Duration
	RefreshBeforeExpiry      time.Duration
	RefreshLockTTL           time.Duration
	AllowInsecureLocalCookie bool
	LogoutRemoteFailureIsSuccess bool
	Clock                    Clock
	Random                   io.Reader
	Logger                   *slog.Logger
	Hooks                    observability.Hooks
}

type Clock interface {
	Now() time.Time
}

func New(config Config) (*Service, error)
```

Defaults:

- Flow TTL 10 minutes;
- Session absolute TTL 7 days;
- Session idle TTL 8 hours;
- identity recheck 30 seconds;
- refresh window 60 seconds;
- refresh lock TTL 15 seconds;
- Session Cookie `__Host-iam_core_session`;
- Flow Cookie `__Host-iam_core_flow`.

Reject insecure cookies unless explicitly enabled and the request/redirect hosts are loopback or
localhost. Cookie clearing must preserve Name, Path, Domain, Secure, HttpOnly, and SameSite.
ReturnTo validation accepts safe relative paths by default and exact string matches from
`AllowedReturnToURLs`; it never performs suffix or wildcard host matching.

Define shared authn test helpers in `authn/testservice_test.go`:

```go
type inspectableBackend struct {
	session.Backend
	flowCount atomic.Int32
}

func (b *inspectableBackend) FlowCount() int
func newTestService(t *testing.T) (*Service, *inspectableBackend)
func newConcurrentRefreshService(t *testing.T) (*Service, *atomic.Int32)
func newCredentialService(t *testing.T, sessionAccessToken string) *Service
```

- [ ] **Step 4: Implement login**

`BeginLogin` must:

- validate ReturnTo as a relative path beginning with one `/`, without host, scheme, control
  characters, or backslashes, or as an exact configured Allowlist entry;
- generate independent 32-byte Flow ID, state, and nonce;
- store a Flow with absolute expiration;
- set the Flow Cookie;
- redirect to `OIDC.AuthCodeURL`.

Use these exact method signatures:

```go
func (s *Service) BeginLogin(w http.ResponseWriter, request *http.Request, returnTo string) error
func (s *Service) LoginHandler() http.Handler
```

`LoginHandler` maps invalid ReturnTo to 400 and Backend/IAM failures to 503 through a private,
redacted auth error writer.

- [ ] **Step 5: Implement callback**

`CompleteCallback` must:

- read Flow ID from the Flow Cookie and call `ConsumeFlow` before accepting the callback;
- compare state in constant time;
- reject provider error query values;
- exchange the code exactly once;
- require and verify ID Token with the Flow nonce;
- call UserInfo exactly once;
- require ID Token and UserInfo subjects to match in constant time;
- generate a new 32-byte Session ID;
- set Session Version 1, configured scopes, absolute/idle expiration, and identity validation time;
- store Session before writing the Session Cookie;
- clear Flow Cookie on every terminal callback outcome.

Use these exact method signatures:

```go
func (s *Service) CompleteCallback(w http.ResponseWriter, request *http.Request) (*session.Session, error)
func (s *Service) CallbackHandler() http.Handler
```

- [ ] **Step 6: Verify Task 7**

Run:

```bash
gofmt -w authn
go test ./authn -run 'Test(Login|Callback)' -count=1
go test -race ./authn
go test ./... -short -count=1
go vet ./...
git diff --check
```

Expected: all login/callback security cases pass and no Session is created on failure.

- [ ] **Step 7: Commit Task 7**

```bash
git add authn
git commit -m "feat: add secure OIDC browser login flow"
```

### Task 8: Implement refresh rotation, credential resolution, online validation, and local-first logout

**Files:**
- Create: `authn/refresh.go`
- Create: `authn/refresh_test.go`
- Create: `authn/credentials.go`
- Create: `authn/credentials_test.go`
- Create: `authn/logout.go`
- Create: `authn/logout_test.go`

**Interfaces:**
- Consumes: `authn.Service`, `session.RefreshLocker`, OIDC Refresh/UserInfo/Logout.
- Produces: `Credential`, `CredentialSource`, `Service.Authenticate`, `Service.ForceRefresh`, and `Service.LogoutHandler`.

- [ ] **Step 1: Write failing distributed-refresh tests**

Use a fake Backend lock and blocking fake Token endpoint to prove:

```go
func TestConcurrentRefreshUsesRefreshTokenOnce(t *testing.T) {
	service, tokenCalls := newConcurrentRefreshService(t)
	var group sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := service.refreshSession(context.Background(), "session-1", false)
			errs <- err
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d", tokenCalls.Load())
	}
}
```

Also test:

- lock loss before commit returns unavailable and does not CAS;
- CAS conflict re-reads the winning Session;
- `invalid_grant` deletes Session;
- network failure preserves Session;
- refreshed ID Token failure preserves the last known Session but returns unavailable.

- [ ] **Step 2: Implement refresh rotation**

Create `authn/refresh.go` with:

```go
func (s *Service) ForceRefresh(ctx context.Context, sessionID string) (*session.Session, error)
func (s *Service) refreshSession(ctx context.Context, sessionID string, force bool) (*session.Session, error)
```

Implement the seven-step lock/re-read/refresh/ownership-check/verify/CAS/unlock flow from the design.
Use `defer` for unlock, but preserve the primary operation error. Do not commit if `lock.Valid(ctx)` is
false. Increment Session Version exactly once per successful refresh.

- [ ] **Step 3: Write failing credential-source tests**

Test:

```go
func TestAuthenticateRejectsDifferentCookieAndBearerTokens(t *testing.T) {
	service := newCredentialService(t, "session-token")
	request := httptest.NewRequest(http.MethodGet, "/assets", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-iam_core_session", Value: "session-1"})
	request.Header.Set("Authorization", "Bearer different-token")
	_, err := service.Authenticate(request)
	var sdkError *sdkerr.Error
	if !errors.As(err, &sdkError) || sdkError.Kind != sdkerr.KindCredentialConflict {
		t.Fatalf("error = %#v", err)
	}
}
```

Add cases for Cookie only, Bearer only, same token in both, malformed Bearer, expired Session,
Access Token inside refresh window, and identity recheck after 30 seconds.

- [ ] **Step 4: Implement credential resolution**

Create:

```go
type CredentialSource string

const (
	CredentialSession CredentialSource = "session"
	CredentialBearer  CredentialSource = "bearer"
)

type Credential struct {
	Source      CredentialSource
	SessionID   string
	AccessToken string
	Identity    oidc.Identity
}

func (s *Service) Authenticate(request *http.Request) (Credential, error)
```

Rules:

- Bearer parsing accepts one case-sensitive `Bearer ` scheme and rejects whitespace inside the token;
- Cookie-only loads Session, checks absolute/idle expiry, refreshes near Access Token expiry, and
  revalidates UserInfo on the configured interval;
- Bearer-only calls UserInfo for every authentication;
- same Cookie/Bearer token uses the Session identity and online revalidation rules;
- unequal tokens return `credential_conflict` before forwarding either identity;
- successful Session access updates last-seen/idle expiry with Version CAS without shortening absolute expiry.

- [ ] **Step 5: Implement local-first logout**

`LogoutHandler` must:

1. load Session if present;
2. delete it before the remote call;
3. clear Session Cookie unconditionally;
4. call OIDC Logout once with retained Access/ID Tokens;
5. never recreate local Session;
6. return configurable success on remote failure while exposing the failure to a Hook/logger without secrets.

Expose a low-level `Logout(ctx, sessionID) error` that returns the remote failure after local deletion.

- [ ] **Step 6: Verify Task 8**

Run:

```bash
gofmt -w authn
go test ./authn -count=1
go test -race ./authn
go test ./... -short -count=1
go vet ./...
git diff --check
```

Expected: refresh endpoint is called once under concurrency; credential and logout tests pass.

- [ ] **Step 7: Commit Task 8**

```bash
git add authn
git commit -m "feat: refresh sessions and resolve credentials"
```

### Task 9: Implement the fail-closed Authorization Decision Client

**Files:**
- Create: `authz/client.go`
- Create: `authz/client_test.go`

**Interfaces:**
- Consumes: `transport.Client` and `observability.Hooks`.
- Produces: `authz.Permission`, `authz.Decision`, `authz.New`, and `Client.Decide`.

- [ ] **Step 1: Write failing request and response tests**

Create tests:

```go
func TestDecideSendsOnlyThreeAllowedFields(t *testing.T) {
	server, captured := newDecisionServer(t, http.StatusOK, `{
		"code":0,
		"message":"success",
		"data":{"decision_id":"dec-1","allowed":true,"reason_code":"allowed"},
		"request_id":"req-1",
		"trace_id":"trace-1"
	}`)
	client := newDecisionClient(t, server)
	decision, err := client.Decide(context.Background(), "access-token", Permission{
		ResourceServer: "asset-api",
		Resource: "assets",
		HTTPMethod: http.MethodGet,
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.Load().(string) != `{"resource_server":"asset-api","resource":"assets","http_method":"GET"}` {
		t.Fatalf("body = %s", captured.Load())
	}
	if !decision.Allowed || decision.ID != "dec-1" || decision.RequestID != "req-1" {
		t.Fatalf("decision = %#v", decision)
	}
}
```

Define test helpers in `authz/client_test.go`:

```go
func newDecisionServer(t *testing.T, status int, responseBody string) (*httptest.Server, *atomic.Value)
func newDecisionClient(t *testing.T, server *httptest.Server) *Client
```

Add tests for direct Decision JSON, unknown Reason Code, deny as a successful result, 400 protocol
error, 401 unauthenticated, 503 retryable unavailable, malformed 2xx, and exactly one HTTP call.

- [ ] **Step 2: Run tests to verify the red state**

Run: `go test ./authz -count=1`

Expected: FAIL because authz APIs do not exist.

- [ ] **Step 3: Implement Permission validation and Decide**

Create `authz/client.go` defining:

```go
type Permission struct {
	ResourceServer string
	Resource       string
	HTTPMethod     string
}

type Decision struct {
	ID         string
	Allowed    bool
	ReasonCode string
	RequestID  string
	TraceID    string
}

type Config struct {
	IssuerURL  string
	Endpoint   string
	HTTPClient *http.Client
	Timeout    time.Duration
	Hooks      observability.Hooks
	Logger     *slog.Logger
}

func New(config Config) (*Client, error)
func (c *Client) Decide(ctx context.Context, accessToken string, permission Permission) (Decision, error)
```

Rules:

- default Endpoint is normalized Issuer + `/authorization/v1/decisions`;
- require non-empty Access Token and all Permission fields;
- derive valid method from the caller and require uppercase standard HTTP methods;
- encode a private request struct with exactly three JSON fields;
- set Bearer and JSON Content-Type;
- decode both IAM envelope `data` and direct Decision responses;
- require non-empty Decision ID and Reason Code;
- treat deny as `Decision{Allowed:false}` with nil error;
- never retry or cache.

- [ ] **Step 4: Verify Task 9**

Run:

```bash
gofmt -w authz
go test ./authz -count=1
go test ./... -short -count=1
go vet ./...
git diff --check
```

Expected: all authz protocol/error cases pass.

- [ ] **Step 5: Commit Task 9**

```bash
git add authz
git commit -m "feat: add fail-closed authorization decisions"
```

### Task 10: Compose the root Client and implement `net/http` middleware

**Files:**
- Create: `config.go`
- Create: `client.go`
- Create: `client_test.go`
- Create: `identity.go`
- Create: `middleware/http.go`
- Create: `middleware/http_test.go`
- Create: `middleware/responder.go`
- Create: `middleware/responder_test.go`

**Interfaces:**
- Consumes: OIDC, Session, Authn, Authz, and stable errors.
- Produces: `iamcore.New`, convenience handlers, `Authenticate`, `RequirePermission`, `OIDC`, `Authorization`, and Context helpers.

- [ ] **Step 1: Write failing middleware behavior tests**

Test:

```go
func TestRequirePermissionAllowsAndStoresDecision(t *testing.T) {
	authenticator := &fakeAuthenticator{credential: authn.Credential{
		Source: authn.CredentialBearer,
		AccessToken: "access-token",
		Identity: oidc.Identity{Subject: "op_usr_0123456789abcdefgjk"},
	}}
	authorizer := &fakeAuthorizer{decision: authz.Decision{
		ID: "dec-1", Allowed: true, ReasonCode: "allowed",
	}}
	handler := RequirePermission(authenticator, authorizer, authz.Permission{
		ResourceServer: "asset-api",
		Resource: "assets",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision, ok := DecisionFromContext(r.Context())
		if !ok || decision.ID != "dec-1" {
			t.Fatalf("decision = %#v ok=%v", decision, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/assets", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}
```

Add tests for:

- authentication 401;
- deny 403 with Decision ID/Reason Code;
- PDP unavailable 503;
- Session PDP 401 invokes `ForceRefresh` once and makes one new decision;
- Bearer PDP 401 never refreshes;
- request method overrides a prefilled Permission method;
- Context includes Identity and Credential Source;
- default response contains no Cause text or credentials.

Define test doubles in `middleware/http_test.go`:

```go
type fakeAuthenticator struct {
	credential   authn.Credential
	err          error
	refreshed    *session.Session
	refreshErr   error
	refreshCalls int
}

func (f *fakeAuthenticator) Authenticate(*http.Request) (authn.Credential, error) {
	return f.credential, f.err
}

func (f *fakeAuthenticator) ForceRefresh(context.Context, string) (*session.Session, error) {
	f.refreshCalls++
	return f.refreshed, f.refreshErr
}

type fakeAuthorizer struct {
	decision authz.Decision
	err      error
	calls    int
}

func (f *fakeAuthorizer) Decide(context.Context, string, authz.Permission) (authz.Decision, error) {
	f.calls++
	return f.decision, f.err
}
```

- [ ] **Step 2: Implement middleware Context and responder**

Create private typed Context keys and:

```go
func IdentityFromContext(context.Context) (oidc.Identity, bool)
func CredentialSourceFromContext(context.Context) (authn.CredentialSource, bool)
func DecisionFromContext(context.Context) (authz.Decision, bool)
```

Create:

```go
type ErrorResponder interface {
	Respond(http.ResponseWriter, *http.Request, error)
}

type ErrorResponderFunc func(http.ResponseWriter, *http.Request, error)
```

Default JSON uses only `error`, `decision_id`, `reason_code`, `request_id`, and `trace_id`; apply
`Content-Type: application/json` and the mapped 400/401/403/503 status.

Define middleware options:

```go
type Option func(*options)

func WithErrorResponder(responder ErrorResponder) Option
func WithHooks(hooks observability.Hooks) Option
func WithLogger(logger *slog.Logger) Option
```

- [ ] **Step 3: Implement `Authenticate` and `RequirePermission`**

Define narrow interfaces:

```go
type Authenticator interface {
	Authenticate(*http.Request) (authn.Credential, error)
	ForceRefresh(context.Context, string) (*session.Session, error)
}

type Authorizer interface {
	Decide(context.Context, string, authz.Permission) (authz.Decision, error)
}
```

`Authenticate` injects Identity/Source and calls next.

Use these constructors:

```go
func Authenticate(authenticator Authenticator, options ...Option) func(http.Handler) http.Handler
func RequirePermission(authenticator Authenticator, authorizer Authorizer, permission authz.Permission, options ...Option) func(http.Handler) http.Handler
```

`RequirePermission`:

- authenticates first;
- replaces Permission HTTPMethod with `request.Method`;
- performs one decision;
- on deny responds 403 and stores Decision for responder access;
- on Session-only 401, calls `ForceRefresh` then performs exactly one new decision;
- never recovers Bearer 401, timeout, 400, 5xx, malformed response, or deny;
- writes `X-IAM-Decision-ID` for allow and deny when available.

- [ ] **Step 4: Write failing root composition tests**

Test that `iamcore.New` rejects:

- missing issuer/client/secret/redirect/backend;
- scope without `openid`;
- insecure non-loopback cookie;
- Discovery issuer mismatch.

Test a successful Client returns non-nil `OIDC()` and `Authorization()`, and its convenience
handlers/middleware delegate to the composed services.

- [ ] **Step 5: Implement root configuration and Client**

Create root aliases:

```go
type Identity = oidc.Identity
type Permission = authz.Permission
type Decision = authz.Decision
type CredentialSource = authn.CredentialSource
```

Create:

```go
type SessionConfig struct {
	Backend                  session.Backend
	SessionCookie            http.Cookie
	FlowCookie               http.Cookie
	FlowTTL                  time.Duration
	AbsoluteTTL              time.Duration
	IdleTTL                  time.Duration
	IdentityRecheckInterval  time.Duration
	RefreshBeforeExpiry      time.Duration
	AllowedReturnToURLs      []string
	AllowInsecureLocalCookie bool
	LogoutRemoteFailureIsSuccess bool
}

type Config struct {
	IssuerURL           string
	ClientID            string
	ClientSecretProvider oidc.SecretProvider
	RedirectURL         string
	Scopes              []string
	HTTPClient          *http.Client
	Session             SessionConfig
	Timeouts            TimeoutConfig
	Logger              *slog.Logger
	Hooks               Hooks
	ErrorResponder      middleware.ErrorResponder
}

type TimeoutConfig struct {
	DiscoveryJWKS time.Duration
	TokenUserInfo time.Duration
	PDP           time.Duration
	RefreshLock   time.Duration
}

type ClientSecretProvider = oidc.SecretProvider

func StaticSecret(value string) ClientSecretProvider {
	return oidc.StaticSecret(value)
}

func New(ctx context.Context, config Config) (*Client, error)
```

Compose OIDC, Authn, Authz, and middleware without duplicating protocol logic. Expose:

```go
func (c *Client) OIDC() *oidc.Client
func (c *Client) Authorization() *authz.Client
func (c *Client) LoginHandler() http.Handler
func (c *Client) CallbackHandler() http.Handler
func (c *Client) LogoutHandler() http.Handler
func (c *Client) Authenticate(http.Handler) http.Handler
func (c *Client) RequirePermission(Permission) func(http.Handler) http.Handler
```

Use `slog.New(slog.NewTextHandler(io.Discard, nil))` when Logger is nil.
Pass the same redacted Logger and Hooks to OIDC, Authn, Authz, and middleware. Add a
buffer-backed JSON `slog.Handler` test and assert submitted token, secret, code, and Session values
never appear.
Before authentication, copy the incoming request Context through
`transport.WithHeaders(request.Context(), request.Header)` so only `traceparent`, `tracestate`, and
`X-Request-ID` can reach OIDC/PDP calls. Pass a configured `ErrorResponder` to both root middleware
constructors; use the default responder when nil.

Implement root Context helpers as direct delegates:

```go
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	return middleware.IdentityFromContext(ctx)
}

func CredentialSourceFromContext(ctx context.Context) (CredentialSource, bool) {
	return middleware.CredentialSourceFromContext(ctx)
}

func DecisionFromContext(ctx context.Context) (Decision, bool) {
	return middleware.DecisionFromContext(ctx)
}
```

- [ ] **Step 6: Verify Task 10**

Run:

```bash
gofmt -w config.go client.go client_test.go identity.go middleware
go test ./middleware ./... -short -count=1
go test -race ./middleware ./authn ./authz
go vet ./...
git diff --check
```

Expected: root construction and all middleware allow/deny/recovery cases pass.

- [ ] **Step 7: Commit Task 10**

```bash
git add config.go client.go client_test.go identity.go middleware
git commit -m "feat: compose net/http IAM middleware"
```

### Task 11: Add the Gin adapter

**Files:**
- Create: `middleware/gin/gin.go`
- Create: `middleware/gin/gin_test.go`

**Interfaces:**
- Consumes: root `iamcore.Client` and root Context helpers.
- Produces: `ginmw.Authenticate`, `ginmw.RequirePermission`, `ginmw.Identity`, and `ginmw.Decision`.

- [ ] **Step 1: Pin the Go 1.24-compatible Gin version**

Run: `go get github.com/gin-gonic/gin@v1.11.0`

Expected: `go.mod` adds Gin v1.11.0 and keeps Go 1.24.

- [ ] **Step 2: Write failing Gin parity tests**

Create tests that:

- run Gin in test mode;
- compare status/body for unauthenticated, deny, unavailable, and allow paths to the `net/http`
  middleware behavior;
- verify the wrapped request Context reaches the Gin Handler;
- verify aborted requests never execute the Handler;
- verify `ginmw.Identity(c)` and `ginmw.Decision(c)` read root Context values.

The allow test Handler must return:

```go
func(c *gin.Context) {
	identity, ok := Identity(c)
	if !ok {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sub": identity.Subject})
}
```

- [ ] **Step 3: Run Gin tests to verify the red state**

Run: `go test ./middleware/gin -count=1`

Expected: FAIL because the Gin adapter is absent.

- [ ] **Step 4: Implement the thin adapter**

Implement a helper that executes a root `net/http` middleware around a terminal Handler:

```go
func adapt(wrap func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		reached := false
		terminal := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			reached = true
			c.Request = request
		})
		wrap(terminal).ServeHTTP(c.Writer, c.Request)
		if !reached {
			c.Abort()
			return
		}
		c.Next()
	}
}
```

Expose:

```go
func Authenticate(client *iamcore.Client) gin.HandlerFunc
func RequirePermission(client *iamcore.Client, resourceServer string, resource string) gin.HandlerFunc
func Identity(c *gin.Context) (iamcore.Identity, bool)
func Decision(c *gin.Context) (iamcore.Decision, bool)
```

Reject nil Client during middleware construction with a panic containing only a static programming
error message; this is a startup misuse, not a request error.

- [ ] **Step 5: Verify Task 11**

Run:

```bash
gofmt -w middleware/gin
go test ./middleware/gin -count=1
go test -race ./middleware/gin
go test ./... -short -count=1
go vet ./...
git diff --check
```

Expected: Gin and net/http behavior is equivalent for all tested outcomes.

- [ ] **Step 6: Commit Task 11**

```bash
git add go.mod go.sum middleware/gin
git commit -m "feat: add Gin IAM middleware adapter"
```

### Task 12: Add examples, security documentation, compatibility matrix, CI, and release verification

**Files:**
- Modify: `README.md`
- Create: `examples/nethttp/main.go`
- Create: `examples/gin/main.go`
- Create: `examples/redis/main.go`
- Create: `COMPATIBILITY.md`
- Create: `CHANGELOG.md`
- Create: `.github/workflows/ci.yml`
- Create: `internal/transport/fuzz_test.go`
- Create: `authn/return_to_fuzz_test.go`

**Interfaces:**
- Consumes: all public v0.1.0 APIs.
- Produces: buildable examples, ten-minute Quickstart, compatibility/release records, and automated gates.

- [ ] **Step 1: Write buildable examples**

Each example must read configuration from environment variables without printing secrets.

`examples/nethttp/main.go` must:

- create an explicit Memory Backend;
- construct `iamcore.Client`;
- register login/callback/logout/profile/PDP-protected routes;
- use `http.Server` with ReadHeaderTimeout;
- document that Memory Backend is not for multiple replicas.

`examples/gin/main.go` must:

- use `ginmw.Authenticate` and `ginmw.RequirePermission`;
- retrieve Identity from Gin Context;
- use an injected Session Backend.

`examples/redis/main.go` must:

- parse a base64-encoded 32-byte current AES key;
- create `redis.UniversalClient`;
- create AES Codec and Redis Backend;
- never log the key or Client Secret.

Run: `go test ./examples/... -count=1`

Expected: all examples compile.

- [ ] **Step 2: Replace README with the ten-minute Quickstart**

Document, in order:

1. IAM Core prerequisites: Application, OIDC Client, redirect URI, allowed scopes, resource catalog.
2. Installation:

```bash
go get github.com/swan-swan-swan/iam-core-client-sdk-go@v0.1.0
```

3. Redis/AES Session setup.
4. Root Client construction using issuer `https://iam.wuhl-goose.top`.
5. Login/callback/logout routes.
6. Identity access.
7. Explicit `RequirePermission("asset-api", "assets")`.
8. Session Cookie versus Bearer behavior.
9. Roles are non-authoritative.
10. PKCE, organization Claim, and management API limitations.
11. Secret rotation, AES keyring rotation, TLS roots, and observability Hooks.

- [ ] **Step 3: Add compatibility and release documents**

Create `COMPATIBILITY.md` table:

| SDK | IAM Core baseline | Go | Redis | Notes |
| --- | --- | --- | --- | --- |
| v0.1.x | v1.7.1 runtime contract | 1.24+ | 6.2+, tested 6.2/7.4 | Confidential Client; no PKCE; no organization Claim |

Create `CHANGELOG.md` with an `Unreleased` section and a `v0.1.0` section listing OIDC, Session,
PDP, net/http, Gin, security, and known limitations.

- [ ] **Step 4: Add Fuzz tests**

`internal/transport/fuzz_test.go` must seed:

- valid IAM envelope;
- valid OAuth error;
- truncated JSON;
- duplicate top-level values;
- oversized strings.

Assert decoder never panics and never accepts trailing JSON.

`authn/return_to_fuzz_test.go` must seed:

- `/`;
- `/assets?page=1`;
- `https://evil.example`;
- `//evil.example`;
- `/\evil`;
- values with CR/LF and NUL.

Assert accepted values parse to no scheme/host and begin with exactly one forward slash.

- [ ] **Step 5: Add CI**

Create `.github/workflows/ci.yml` with:

- Go 1.24 setup;
- `go test ./... -short -count=1`;
- `go test -race ./... -short`;
- `go vet ./...`;
- `git diff --check`;
- fuzz smoke for both Fuzz targets with `-fuzztime=10s`;
- Redis integration matrix using `redis:6.2-alpine` and `redis:7.4-alpine`;
- module cache keyed by `go.sum`;
- no secrets or live IAM Core credentials.

- [ ] **Step 6: Run full local verification**

Run:

```bash
rg --files -g '*.go' -0 | xargs -0 gofmt -w
go mod tidy
go test ./... -short -count=1
go test -race ./... -short
go vet ./...
go test ./internal/transport -run '^$' -fuzz=FuzzDecodeJSON -fuzztime=10s
go test ./authn -run '^$' -fuzz=FuzzReturnTo -fuzztime=10s
go test ./session/redis -run TestBackendConformance -count=1 -timeout=5m
git diff --check
git status --short
```

Expected:

- formatting produces no follow-up diff;
- unit, race, vet, fuzz-smoke, and Redis conformance commands exit 0;
- `git diff --check` exits 0;
- status lists only the Task 12 files before commit.

- [ ] **Step 7: Inspect the public API and sensitive-data boundary**

Run:

```bash
go doc github.com/swan-swan-swan/iam-core-client-sdk-go
go list -deps ./... >/dev/null
if rg -n 'fmt\\.(Print|Printf|Println)|log\\.(Print|Printf|Println|Fatal|Panic)|InsecureSkipVerify|RequireRole' --glob '*.go' .; then exit 1; fi
rg -n 'access_token|refresh_token|client_secret|authorization_code|session_id' --glob '*.go' .
```

Expected:

- public root API contains Client, Config, Error, Identity, Permission, Decision, Context helpers,
  handlers, and middleware constructors;
- no `InsecureSkipVerify` or `RequireRole`;
- sensitive field matches are limited to protocol structs, test fixtures, and explicitly redacted
  handling; no logging statement accepts them.

- [ ] **Step 8: Commit Task 12**

```bash
git add README.md COMPATIBILITY.md CHANGELOG.md .github examples internal/transport/fuzz_test.go authn/return_to_fuzz_test.go go.mod go.sum
git commit -m "docs: add SDK quickstart and release gates"
```

## Final Release Gate

Spec coverage after plan self-review:

| Design area | Implementing tasks |
| --- | --- |
| Stable errors, timeouts, secrets, hooks, propagation | Tasks 1-3, 10 |
| OIDC Discovery, login, Token, JWT/JWKS, UserInfo, logout | Tasks 3, 4, 7, 8 |
| Session contracts, encryption, Memory, Redis, refresh locking | Tasks 5, 6, 8 |
| Cookie/Bearer authentication and identity extensions | Tasks 4, 7, 8, 10 |
| PDP decisions, failure closure, audit correlation | Tasks 9, 10 |
| net/http and Gin adapters | Tasks 10, 11 |
| Security, race, integration, fuzz, documentation, compatibility | Tasks 1-12, with release gates in Task 12 |

No design requirement is deferred into an unspecified implementation task. PKCE, organization
strong types, management APIs, and additional Web frameworks remain explicitly out of v0.1.0 scope.

After all task commits:

```bash
go test ./... -short -count=1
go test -race ./... -short
go vet ./...
go test ./session/redis -run TestBackendConformance -count=1 -timeout=5m
git diff --check
git status --short --branch
git log --oneline --decorate -15
git remote -v
```

Expected:

- all verification commands exit 0;
- worktree is clean;
- branch contains one focused commit per task;
- module path is `github.com/swan-swan-swan/iam-core-client-sdk-go`;
- if `origin` still points to `iam-core-client-sdk.git`, report it and request authorization before
  changing the remote or pushing.
