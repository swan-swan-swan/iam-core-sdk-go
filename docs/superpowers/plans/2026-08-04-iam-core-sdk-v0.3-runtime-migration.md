# IAM Core Go SDK v0.3.0 Runtime Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the Go module to `iam-core-sdk-go` and move the complete v0.2 Runtime surface under `runtime/` without changing its security behavior.

**Architecture:** This is a mechanical breaking migration. Existing Core, BFF, HTTP authorization, TestKit, Gin, Redis, examples, and integration tests move as intact units; imports, nested modules, workspace configuration, and CI paths change together. The root module remains free of Gin, Redis, Docker, Moby, and Testcontainers production dependencies.

**Tech Stack:** Go 1.24, `net/http`, go-jose, golang-jwt, Gin adapter module, go-redis adapter module, Testcontainers-only integration module, GitHub Actions.

## Global Constraints

- Root module: `github.com/swan-swan-swan/iam-core-sdk-go`.
- Runtime packages live only under `runtime/`; no forwarding packages remain at the old paths.
- Preserve all v0.2 PKCE, JWT, BFF Session, refresh fencing, Route Manifest, exactly-one-PDP, fail-closed, no-retry, and sensitive-data behavior.
- Do not create an RPC package, interface, example, or direct production dependency.
- `runtime/adapters/gin` and `runtime/adapters/redis` remain separately published modules.
- `integration` remains an unpublished test-only module.
- Do not bump `VERSION` or enable a v0.3 release in this plan; the Management plan performs the final release cut after both subsystems pass.
- Design source: `docs/superpowers/specs/2026-08-04-iam-core-sdk-v0.3-runtime-management-design.md`.

---

## File Map

| Current path | Target path | Responsibility |
| --- | --- | --- |
| `core/` | `runtime/core/` | Discovery, JWKS, JWT, AuthContext, transport, errors, observation |
| `bff/` | `runtime/bff/` | OIDC/BFF flows and Session contracts |
| `httpauthz/` | `runtime/httpauthz/` | HTTP credential selection, Manifest, PDP, middleware |
| `testkit/` | `runtime/testkit/` | Default-deny IAM fixtures |
| `internal/nilcheck/` | `runtime/internal/nilcheck/` | Runtime-only nil validation helper |
| `internal/random/` | `runtime/internal/random/` | Runtime-only cryptographic random helper |
| `adapters/gin/` | `runtime/adapters/gin/` | Independent Gin adapter module |
| `adapters/redis/` | `runtime/adapters/redis/` | Independent Redis Session adapter module |
| `examples/bff/` | `examples/runtime/bff/` | BFF example |
| `examples/nethttp/` | `examples/runtime/nethttp/` | HTTP Resource Server example |
| `integration/redis/` | unchanged | Redis 6.2/7.4 adapter conformance against new paths |
| `go.mod`, `go.work` | modified in place | New root module and nested module workspace |
| `.github/workflows/ci.yml` | modified in place | New nested module and example paths |

### Task 1: Freeze the New Module and Layout Contract

**Files:**
- Create: `module_layout_v030_test.go`
- Modify: `release_workflow_test.go`
- Test: `module_layout_v030_test.go`

**Interfaces:**
- Consumes: repository filesystem, `go.mod`, nested `go.mod`, `go.work`, `VERSION`.
- Produces: a failing executable contract for the new module and directory layout.

- [ ] **Step 1: Write the failing layout test**

Create a table-driven test in package `iamcore_test` that asserts:

```go
func TestV030ModuleLayout(t *testing.T) {
	rootModule := readFile(t, "go.mod")
	if !strings.Contains(rootModule, "module github.com/swan-swan-swan/iam-core-sdk-go\n") {
		t.Fatalf("root module was not renamed: %s", rootModule)
	}

	required := []string{
		"runtime/core", "runtime/bff", "runtime/httpauthz", "runtime/testkit",
		"runtime/adapters/gin/go.mod", "runtime/adapters/redis/go.mod",
		"examples/runtime/bff", "examples/runtime/nethttp",
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("required path %s: %v", path, err)
		}
	}

	forbidden := []string{"core", "bff", "httpauthz", "testkit", "adapters/gin", "adapters/redis", "rpc"}
	for _, path := range forbidden {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("legacy or forbidden path still exists: %s", path)
		}
	}
}
```

Add local `readFile(t, path)` and `repositoryRoot(t)` helpers; do not import implementation packages from the old module path.

- [ ] **Step 2: Add module-content assertions**

Assert the nested module declarations are exactly:

```text
module github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin
module github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis
module github.com/swan-swan-swan/iam-core-sdk-go/integration
```

Assert every `go.mod`, non-historical Go source file, current README, current compatibility document, and GitHub workflow contains no import of `github.com/swan-swan-swan/iam-core-client-sdk-go`. Exclude `docs/superpowers/`, `CHANGELOG.md` historical release text, and the v0.2-to-v0.3 migration guide because those files must name the old module.

- [ ] **Step 3: Run the focused tests and verify failure**

Run: `go test . -run 'TestV030ModuleLayout' -count=1`

Expected: FAIL because the root module and directories still use the v0.2 layout.

- [ ] **Step 4: Commit the red contract test**

```bash
git add module_layout_v030_test.go release_workflow_test.go
git commit -m "test: freeze v0.3 runtime module layout"
```

### Task 2: Move Runtime Packages and Rewrite Root Imports

**Files:**
- Move: `core/` → `runtime/core/`
- Move: `bff/` → `runtime/bff/`
- Move: `httpauthz/` → `runtime/httpauthz/`
- Move: `testkit/` → `runtime/testkit/`
- Move: `internal/nilcheck/` → `runtime/internal/nilcheck/`
- Move: `internal/random/` → `runtime/internal/random/`
- Move: `contract_v181_test.go` → `runtime/contract_v181_test.go`
- Modify: `go.mod`, `doc.go`, `documentation_test.go`, `module_layout_v030_test.go`
- Test: all moved `*_test.go` files.

**Interfaces:**
- Consumes: all existing v0.2 Runtime public APIs and tests.
- Produces: identical APIs under `github.com/swan-swan-swan/iam-core-sdk-go/runtime/{core,bff,httpauthz,testkit}`.

- [ ] **Step 1: Move each package as one Git unit**

Run these moves without copying files:

```bash
mkdir -p runtime/internal
git mv core runtime/core
git mv bff runtime/bff
git mv httpauthz runtime/httpauthz
git mv testkit runtime/testkit
git mv internal/nilcheck runtime/internal/nilcheck
git mv internal/random runtime/internal/random
git mv contract_v181_test.go runtime/contract_v181_test.go
```

Remove the empty root `internal/` directory if Git no longer tracks content there.

- [ ] **Step 2: Change the module and all Runtime imports**

Set `go.mod` to:

```go
module github.com/swan-swan-swan/iam-core-sdk-go

go 1.24.0

require (
	github.com/go-jose/go-jose/v4 v4.1.3
	github.com/golang-jwt/jwt/v5 v5.3.1
)
```

Mechanically replace imports using this exact mapping:

```text
.../iam-core-client-sdk-go/core               -> .../iam-core-sdk-go/runtime/core
.../iam-core-client-sdk-go/bff                -> .../iam-core-sdk-go/runtime/bff
.../iam-core-client-sdk-go/bff/session        -> .../iam-core-sdk-go/runtime/bff/session
.../iam-core-client-sdk-go/httpauthz          -> .../iam-core-sdk-go/runtime/httpauthz
.../iam-core-client-sdk-go/testkit            -> .../iam-core-sdk-go/runtime/testkit
.../iam-core-client-sdk-go/internal/nilcheck  -> .../iam-core-sdk-go/runtime/internal/nilcheck
.../iam-core-client-sdk-go/internal/random    -> .../iam-core-sdk-go/runtime/internal/random
```

Do not rename Go package declarations such as `package core`, `package bff`, or `package httpauthz`.

- [ ] **Step 3: Update the root package documentation**

Replace `doc.go` with a documentation-only root package and no facade symbols:

```go
// Package iamcoresdk documents the IAM Core Go SDK module.
// Runtime and Management capabilities are exposed through explicit subpackages.
package iamcoresdk
```

Update root tests to use `package iamcoresdk_test`. The root package must export no Client, Config, Session, authentication, authorization, or RPC symbols.

- [ ] **Step 4: Format, tidy, and run Runtime tests**

Run:

```bash
gofmt -w $(rg --files runtime -g '*.go') doc.go module_layout_v030_test.go documentation_test.go
go mod tidy
go test ./runtime/... -count=1
go test -race ./runtime/... -count=1
go vet ./runtime/...
```

Expected: all pre-migration Runtime behavior tests PASS under their new import paths.

- [ ] **Step 5: Run the root dependency boundary**

Run:

```bash
GOWORK=off go list -m all
GOWORK=off go list -deps ./runtime/...
```

Expected: no Gin, go-redis, Docker, Moby, Testcontainers, Dubbo, Triple, or direct gRPC module appears in the root Runtime dependency graph.

- [ ] **Step 6: Commit the Runtime package move**

```bash
git add go.mod go.sum doc.go documentation_test.go module_layout_v030_test.go runtime
git commit -m "refactor(runtime): move v0.2 APIs under runtime"
```

### Task 3: Move Gin and Redis Adapter Modules

**Files:**
- Move: `adapters/gin/` → `runtime/adapters/gin/`
- Move: `adapters/redis/` → `runtime/adapters/redis/`
- Modify: both nested `go.mod` and `go.sum` files.
- Test: all adapter tests and examples.

**Interfaces:**
- Consumes: `runtime/httpauthz`, `runtime/bff/session`, `runtime/core`.
- Produces: separately versioned Gin and Redis modules at the new paths.

- [ ] **Step 1: Move both modules**

```bash
mkdir -p runtime/adapters
git mv adapters/gin runtime/adapters/gin
git mv adapters/redis runtime/adapters/redis
```

- [ ] **Step 2: Rewrite Gin module metadata and imports**

The Gin `go.mod` module line must be:

```go
module github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/gin
```

Its root dependency and all source imports must use `github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz`. Preserve the existing Gin version and all current behavior tests.

- [ ] **Step 3: Rewrite Redis module metadata and imports**

The Redis `go.mod` module line must be:

```go
module github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis
```

Its root dependency and all source imports must use `runtime/core` and `runtime/bff/session`. Preserve encryption, generation fencing, server-time leases, validation, and secret-sanitization tests unchanged apart from imports.

- [ ] **Step 4: Tidy and verify both standalone modules**

Run:

```bash
(cd runtime/adapters/gin && GOWORK=off go mod tidy && GOWORK=off go test ./... -count=1 && GOWORK=off go test -race ./... -count=1 && GOWORK=off go vet ./...)
(cd runtime/adapters/redis && GOWORK=off go mod tidy && GOWORK=off go test ./... -count=1 && GOWORK=off go test -race ./... -count=1 && GOWORK=off go vet ./...)
```

Expected: both modules build and test without the workspace.

- [ ] **Step 5: Commit adapter migration**

```bash
git add runtime/adapters
git commit -m "refactor(runtime): move adapter modules"
```

### Task 4: Move Runtime Examples and Update Integration Module

**Files:**
- Move: `examples/bff/` → `examples/runtime/bff/`
- Move: `examples/nethttp/` → `examples/runtime/nethttp/`
- Modify: `integration/go.mod`, `integration/redis/redis_test.go`
- Modify: `go.work`, `go.work.sum`
- Test: example tests and Redis integration tests.

**Interfaces:**
- Consumes: new Runtime and adapter module paths.
- Produces: compiling Runtime examples and Redis conformance wired to the new modules.

- [ ] **Step 1: Move examples and rewrite imports**

```bash
mkdir -p examples/runtime
git mv examples/bff examples/runtime/bff
git mv examples/nethttp examples/runtime/nethttp
```

Update imports to `runtime/core`, `runtime/bff`, `runtime/bff/session/memory`, and `runtime/httpauthz`. Preserve all explicit secure Cookie, PKCE, scope, Manifest, and one-PDP example behavior.

- [ ] **Step 2: Rewrite the integration module**

Set its module line and direct requirements to the new paths:

```go
module github.com/swan-swan-swan/iam-core-sdk-go/integration

require (
	github.com/swan-swan-swan/iam-core-sdk-go v0.3.0
	github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis v0.3.0
)
```

Keep existing Testcontainers versions. Update Redis integration imports to `runtime/bff/session`, `runtime/bff/session/sessiontest`, and `runtime/adapters/redis`.

- [ ] **Step 3: Rewrite the workspace**

Set `go.work` to:

```go
go 1.24.0

use (
	.
	./runtime/adapters/gin
	./runtime/adapters/redis
	./integration
)

replace github.com/swan-swan-swan/iam-core-sdk-go v0.3.0 => .

replace github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis v0.3.0 => ./runtime/adapters/redis
```

Do not add the Gin adapter as a root replacement because no other module requires it.

- [ ] **Step 4: Verify examples and integration compilation**

Run:

```bash
go build ./examples/runtime/...
go test ./examples/runtime/... -count=1
(cd integration && GOWORK=off go mod tidy && go test ./redis -run '^$' -count=1)
```

Expected: examples PASS; the integration package compiles without starting Docker when `-run '^$'` selects no tests.

- [ ] **Step 5: Commit examples and integration wiring**

```bash
git add examples/runtime integration go.work go.work.sum
git commit -m "refactor(runtime): migrate examples and integration paths"
```

### Task 5: Update CI Paths and Add Runtime Migration Gates

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `release_workflow_test.go`
- Modify: `documentation_test.go`
- Test: `release_workflow_test.go`, `documentation_test.go`, `module_layout_v030_test.go`.

**Interfaces:**
- Consumes: new module paths and directories.
- Produces: CI that tests root, both nested adapters, examples, and integration under the v0.3 layout.

- [ ] **Step 1: Update all CI working directories and cache paths**

Replace:

```text
adapters/gin       -> runtime/adapters/gin
adapters/redis     -> runtime/adapters/redis
./examples/...     -> ./examples/runtime/...
```

Keep normal, race, vet, standalone, and dependency-boundary steps. Extend the root forbidden dependency regex to reject `dubbo|triple` while allowing Testcontainers' transitive gRPC only inside `integration`.

- [ ] **Step 2: Make release tests expect three eventual tags**

Update the release workflow tests so the final Management plan must create these tags from a single release revision:

```text
v0.3.0
runtime/adapters/gin/v0.3.0
runtime/adapters/redis/v0.3.0
```

At this stage the release workflow may still be red because `VERSION` remains `0.2.0`; keep the tag assertions in the test and let the Management release task make them green.

- [ ] **Step 3: Add a no-RPC public surface check**

In `module_layout_v030_test.go`, walk non-historical directories and reject a directory named `rpc` or direct `go.mod` requirements whose module path contains `dubbo`, `triple`, or a direct root `google.golang.org/grpc`. Explicitly skip `integration/go.sum` and indirect integration dependencies.

- [ ] **Step 4: Run all non-release migration gates**

Run:

```bash
go test . -run 'TestV030ModuleLayout|TestDocumentation' -count=1
go test ./runtime/... ./examples/runtime/... -count=1
go test -race ./runtime/... -count=1
go vet ./runtime/... ./examples/runtime/...
git diff --check
```

Expected: all migration gates PASS; any test explicitly waiting for Management packages or final v0.3 release metadata remains assigned to the next plan, not disabled.

- [ ] **Step 5: Commit CI migration**

```bash
git add .github/workflows/ci.yml release_workflow_test.go documentation_test.go module_layout_v030_test.go
git commit -m "ci: validate v0.3 runtime layout"
```

### Task 6: Runtime Migration Review Gate

**Files:**
- Verify only; modify files only to fix failures introduced by Tasks 1–5.

**Interfaces:**
- Consumes: complete migrated Runtime tree.
- Produces: a stable base for the Management implementation plan.

- [ ] **Step 1: Search for unexpected old imports**

Run:

```bash
rg -n 'github.com/swan-swan-swan/iam-core-client-sdk-go' \
  --glob '*.go' --glob 'go.mod' --glob 'go.work' --glob '.github/**' \
  --glob '!docs/superpowers/**'
```

Expected: no output.

- [ ] **Step 2: Run the complete non-Docker verification**

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
(cd runtime/adapters/gin && GOWORK=off go test ./... -count=1 && GOWORK=off go vet ./...)
(cd runtime/adapters/redis && GOWORK=off go test ./... -count=1 && GOWORK=off go vet ./...)
(cd integration && GOWORK=off go test ./redis -run '^$' -count=1 && GOWORK=off go vet ./...)
git diff --check
```

Expected: PASS.

- [ ] **Step 3: Compare public Runtime behavior**

Review the diff excluding path/import-only changes. Reject any change to Runtime request fields, error mapping, Cookie validation, Session persistence, JWT verification, PDP call count, retry policy, or sensitive-data behavior unless a pre-existing test proves the old code was already inconsistent with v0.2 documentation.

- [ ] **Step 4: Commit any review-only corrections**

If verification required changes:

```bash
git add runtime examples/runtime integration go.mod go.sum go.work go.work.sum .github
git commit -m "fix(runtime): complete v0.3 migration verification"
```

If no changes were required, do not create an empty commit.
