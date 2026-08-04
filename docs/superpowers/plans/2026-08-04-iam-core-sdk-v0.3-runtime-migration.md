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

### Task 1: Freeze the New Module Contract and Migrate Runtime Packages

**Files:**
- Create: `module_layout_v030_test.go`
- Modify: `release_workflow_test.go`
- Test: `module_layout_v030_test.go`

**Interfaces:**
- Consumes: repository filesystem, `go.mod`, nested `go.mod`, `go.work`, `VERSION`.
- Produces: an executable contract for the new module and directory layout, made green by the migration in this same task.

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
		"runtime/internal/nilcheck", "runtime/internal/random",
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("required path %s: %v", path, err)
		}
	}

	forbidden := []string{"core", "bff", "httpauthz", "testkit", "rpc"}
	for _, path := range forbidden {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("legacy or forbidden path still exists: %s", path)
		}
	}
}
```

Add local `readFile(t, path)` and `repositoryRoot(t)` helpers; do not import implementation packages from the old module path.

- [ ] **Step 2: Add task-scoped module-content assertions**

Assert the root module declaration is exactly:

```text
module github.com/swan-swan-swan/iam-core-sdk-go
```

Assert the moved `runtime/` Go sources and root Go files contain no import of `github.com/swan-swan-swan/iam-core-client-sdk-go`. This task deliberately excludes adapters, examples, integration, README/compatibility documents, and GitHub workflows because their paths and imports are owned by Tasks 2–4.

- [ ] **Step 3: Run the focused tests and verify failure**

Run: `go test . -run 'TestV030ModuleLayout' -count=1`

Expected: FAIL because the root module and directories still use the v0.2 layout.

- [ ] **Step 4: Record the RED result and continue without committing**

Do not commit a knowingly failing branch state. Preserve the RED output as TDD evidence, then complete the package migration below before committing the task.

#### Part 2: Move Runtime Packages and Rewrite Root Imports

**Files:**
- Move: `core/` → `runtime/core/`
- Move: `bff/` → `runtime/bff/`
- Move: `httpauthz/` → `runtime/httpauthz/`
- Move: `testkit/` → `runtime/testkit/`
- Move: `internal/nilcheck/` → `runtime/internal/nilcheck/`
- Move: `internal/random/` → `runtime/internal/random/`
- Move: `contract_v181_test.go` → `runtime/contract_v181_test.go`
- Modify: Runtime imports under `examples/bff/` and `examples/nethttp/` without moving those directories yet.
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

Because `examples/bff` and `examples/nethttp` are still packages in the root module until Task 3 moves them, mechanically update only their Runtime imports to the new `runtime/*` paths in this task. Do not move the example directories or change example behavior yet.

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
go test ./examples/... -count=1
go test -race ./runtime/... -count=1
go vet ./runtime/... ./examples/...
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
git add go.mod go.sum doc.go documentation_test.go module_layout_v030_test.go runtime examples/bff examples/nethttp
git commit -m "refactor(runtime): move v0.2 APIs under runtime"
```

### Task 2: Move Gin and Redis Adapter Modules

**Files:**
- Move: `adapters/gin/` → `runtime/adapters/gin/`
- Move: `adapters/redis/` → `runtime/adapters/redis/`
- Modify: both nested `go.mod` and `go.sum` files.
- Modify: `module_layout_v030_test.go`
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

Extend `module_layout_v030_test.go` to require both new adapter `go.mod` paths, forbid the old `adapters/gin` and `adapters/redis` paths, and assert both nested module declarations exactly match their new module paths.

- [ ] **Step 4: Tidy and verify both modules in the development workspace**

Because Go 1.24 `go mod tidy` is module-scoped and does not resolve the unpublished root through `go.work`, run tidy with a temporary local replace that is removed by an exit trap and must never be committed:

```bash
(
  cd runtime/adapters/gin
  go mod edit -replace=github.com/swan-swan-swan/iam-core-sdk-go=../../..
  trap 'go mod edit -dropreplace=github.com/swan-swan-swan/iam-core-sdk-go' EXIT
  go mod tidy
)
(
  cd runtime/adapters/redis
  go mod edit -replace=github.com/swan-swan-swan/iam-core-sdk-go=../../..
  trap 'go mod edit -dropreplace=github.com/swan-swan-swan/iam-core-sdk-go' EXIT
  go mod tidy
)
! rg -n '^replace ' runtime/adapters/gin/go.mod runtime/adapters/redis/go.mod
(cd runtime/adapters/gin && go test ./... -count=1 && go test -race ./... -count=1 && go vet ./...)
(cd runtime/adapters/redis && go test ./... -count=1 && go test -race ./... -count=1 && go vet ./...)
```

Expected: tidy and all tests PASS, and neither committed nested `go.mod` contains a `replace`. Tests resolve the local v0.3 root through `go.work`; do not use `GOWORK=off` before `v0.3.0` exists remotely because standalone module resolution is a post-tag release verification.

- [ ] **Step 5: Commit adapter migration**

```bash
git add runtime/adapters
git commit -m "refactor(runtime): move adapter modules"
```

### Task 3: Move Runtime Examples and Update Integration Module

**Files:**
- Move: `examples/bff/` → `examples/runtime/bff/`
- Move: `examples/nethttp/` → `examples/runtime/nethttp/`
- Modify: `integration/go.mod`, `integration/redis/redis_test.go`
- Modify: `go.work`, `go.work.sum`
- Modify: `module_layout_v030_test.go`
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

The Runtime import rewrite may already have been completed in Task 1 so the renamed root module could be tidied. Verify the imports here and keep this step limited to the directory move plus any remaining path-only correction.

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

Extend `module_layout_v030_test.go` to require both new example directories and assert the integration module declaration is exactly `module github.com/swan-swan-swan/iam-core-sdk-go/integration`.

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
(
  cd integration
  go mod edit -replace=github.com/swan-swan-swan/iam-core-sdk-go=..
  go mod edit -replace=github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis=../runtime/adapters/redis
  trap 'go mod edit -dropreplace=github.com/swan-swan-swan/iam-core-sdk-go; go mod edit -dropreplace=github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis' EXIT
  go mod tidy
)
! rg -n '^replace ' integration/go.mod
(cd integration && go test ./redis -run '^$' -count=1)
```

Expected: examples PASS; integration tidy PASS with both temporary unpublished-module replaces removed afterward; the integration package compiles through `go.work` without starting Docker when `-run '^$'` selects no tests. Do not commit a replace in `integration/go.mod`.

- [ ] **Step 5: Commit examples and integration wiring**

```bash
git add examples/runtime integration go.work go.work.sum
git commit -m "refactor(runtime): migrate examples and integration paths"
```

### Task 4: Update CI Paths and Add Runtime Migration Gates

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

- [ ] **Step 2: Keep release assertions green until the final release task**

Update only path-sensitive release fixtures needed by the Runtime move. Do not make this task assert unreleased v0.3 metadata or tags. The final Management release task owns the exact three-tag contract:

```text
v0.3.0
runtime/adapters/gin/v0.3.0
runtime/adapters/redis/v0.3.0
```

Keep `VERSION` at `0.2.0` and every committed test green. Management Task 11 adds the final tag assertions and changes `VERSION` atomically.

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

### Task 5: Runtime Migration Review Gate

**Files:**
- Verify only; modify files only to fix failures introduced by Tasks 1–5.

**Interfaces:**
- Consumes: complete migrated Runtime tree from Tasks 1–4.
- Produces: a stable base for the Management implementation plan.

- [ ] **Step 1: Search for unexpected old imports**

Inspect compiled package imports structurally, then search module/workflow metadata. This avoids treating the intentional legacy-module string in migration contract tests as a live import:

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
```

Expected: no live old imports and no old module path in current module/workflow metadata. Test fixtures and historical/migration documents may still name the old module as data.

- [ ] **Step 2: Run the complete non-Docker verification**

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
(cd runtime/adapters/gin && go test ./... -count=1 && go vet ./...)
(cd runtime/adapters/redis && go test ./... -count=1 && go vet ./...)
(cd integration && go test ./redis -run '^$' -count=1 && go vet ./...)
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
