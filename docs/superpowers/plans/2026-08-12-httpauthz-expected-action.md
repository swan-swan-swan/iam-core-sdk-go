# HTTP Authorization Expected Action Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans and apply superpowers:test-driven-development task by task.

**Goal:** Add a backward-compatible expected Action drift check to IAM Core and its Go SDK, then migrate Ops Gateway and both scaffolds to canonical three-level permissions.

**Architecture:** IAM Core remains authoritative: it derives Action from the HTTP Catalog and compares it with optional `expected_action`. The SDK carries the expected Action and verifies allowed responses. Downstreams use the same canonical Action for IAM binding and UI projection.

**Tech Stack:** Go 1.24, Gin, IAM Core Go SDK, YAML, Umi/TypeScript, Vitest.

---

### Task 1: IAM Core Server protocol and decision behavior

**Files:**
- Modify: `internal/dto/authorization_decision.go`
- Modify: `internal/services/authorization_decision_service.go`
- Modify: relevant `internal/services/story_9_6_test.go`
- Modify: relevant `internal/handlers/story_9_6_test.go`
- Regenerate/modify: `docs/docs.go`, `docs/openapi.yaml`, `docs/swagger.json`, `docs/swagger.yaml`

- [ ] RED: cover valid expected Action, invalid format, Catalog mismatch, legacy omission, response Action and audit Action.
- [ ] GREEN: add optional request field, response Action, three-level validation and `action_mismatch` deny behavior without trusting caller input.
- [ ] Verify service, handler, router and repository packages; run Swagger generation/check required by repository rules.
- [ ] Commit one server implementation revision.

### Task 2: Go SDK Route and response verification

**Files:**
- Modify: `runtime/httpauthz/manifest.go`
- Modify: `runtime/httpauthz/decision.go`
- Modify: `runtime/httpauthz/client.go`
- Modify: `runtime/httpauthz/decode.go`
- Modify: focused tests under `runtime/httpauthz/`
- Modify: testkit and examples that assert the wire contract

- [ ] RED: cover RouteSpec Action, `expected_action` request encoding, additive response Action and allowed-response mismatch.
- [ ] GREEN: add optional canonical Action and fail closed only for allowed decisions with configured Action.
- [ ] Preserve old RouteSpec/request behavior when Action is empty.
- [ ] Run `go test ./... -count=1`, `go vet ./...`, `git diff --check`.
- [ ] Commit one SDK implementation revision and prepare the next SDK release version.

### Task 3: Migrate Ops Gateway backend

**Files:**
- Modify: `internal/config/config.go` and focused tests
- Modify: `internal/iam/runtime.go` and focused tests
- Modify: `internal/routers/router.go` and focused tests
- Modify: `configs/application.yaml` and documentation describing bindings
- Modify: `go.mod`/`go.sum` when the SDK release is available

- [ ] Replace `operation` with `action`; require canonical three-level Action for migrated bindings.
- [ ] Use `opsws/admin/opsws:admin:access` for Admin Access.
- [ ] Expose the bound Action by purpose and project it into permissions/menus instead of hardcoding it.
- [ ] Verify config, IAM, router packages and repository checks.

### Task 4: Migrate backend scaffold

**Files:**
- Modify: `internal/config/config.go` and tests
- Modify: `internal/iam/runtime.go` and tests
- Modify: `internal/routers/router.go` and tests
- Modify: `configs/application.yaml`, `configs/README.md`, `internal/iam/README.md`
- Modify: `go.mod`/`go.sum` when the SDK release is available

- [ ] Add generic `admin.access` binding with `app:admin:access`.
- [ ] Keep GooseCase API bindings independent and convert their operation labels to canonical Actions.
- [ ] Project the Admin permission from the binding and preserve clean-example behavior.
- [ ] Run all Go tests, vet, clean-example regression and diff check.

### Task 5: Migrate frontend scaffold

**Files:**
- Modify: `.env.development`, `.env.staging`, `.env.production`
- Modify: route configuration and route tests
- Modify: environment type/define declarations only if required by Umi

- [ ] Define `ADMIN_ACCESS_PERMISSION=app:admin:access` in all environments.
- [ ] Read the environment value with a fail-safe canonical fallback.
- [ ] Run focused tests, all Vitest tests, typecheck, lint and diff check.

### Task 6: Cross-repository review and release boundary

- [ ] Confirm server accepts legacy requests and new expected Action requests.
- [ ] Confirm new SDK works against new server and fails closed on allowed Action drift.
- [ ] Confirm Ops Gateway uses `opsws:admin:access` end to end.
- [ ] Confirm scaffolds use `app:admin:access` end to end.
- [ ] Record SDK version/tag publication as a release prerequisite; do not push without explicit authorization.
