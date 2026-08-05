# Lua-free Redis Session Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all Lua-backed Redis BFF Session Backend operations with Redis 6.2+ native commands while preserving the public API, security boundary, conflict semantics, and Redis Cluster support.

**Architecture:** `Backend` continues to accept a `goredis.UniversalClient`; applications supply their single-node, Sentinel, or Cluster client. Flow operations use `SET NX PX` and `GETDEL`; all Session/Lease mutations watch the existing same-slot Session and Lease keys and commit with `MULTI/EXEC`. A watched-key abort maps directly to `session.ErrConflict` without retry.

**Tech Stack:** Go 1.24, go-redis/v9, Redis 6.2/7.4, Testcontainers, AES-256-GCM.

## Global Constraints

- Delete `runtime/adapters/redis/scripts.go` and all `EVAL`, `EVALSHA`, `SCRIPT LOAD`, and `redis.NewScript` usage.
- Preserve `redisadapter.New(client, options)` and every `session.Backend` / `session.Lease` public signature.
- Require Redis 6.2+; no old Lua/new native SDK rolling coexistence in one BFF Redis namespace.
- Preserve Flow/Session/Lease key formats, encryption, prefix isolation, Redis Cluster hash tags, and data compatibility.
- Do not retry a `WATCH` conflict; return `session.ErrConflict`.
- Treat Redis `PTTL` as the authority for lease validity.

---

### Task 1: Replace the complete Redis Backend with native commands

**Files:**
- Delete: `runtime/adapters/redis/scripts.go`
- Modify: `runtime/adapters/redis/backend.go`
- Modify: `runtime/adapters/redis/backend_test.go`

**Interfaces:**
- Consumes: `goredis.UniversalClient.Watch(ctx, fn, keys...)`, `goredis.Tx`, `TxPipelined`, `goredis.TxFailedErr`, and the existing `session.Backend` interface.
- Produces: no-Lua implementations of all Backend and Lease methods; fake Redis test support for native commands and optimistic transactions.

- [ ] **Step 1: Add native-command tests before replacing implementation**

Add focused tests which:
- record every Redis command and fail on `eval`, `evalsha`, or `script`;
- prove Flow creation sends `SET ... NX PX`, Flow consumption sends one `GETDEL`, and a second consume returns `session.ErrNotFound`;
- force a watched Session mutation before `EXEC` and assert `session.ErrConflict` without a partial Session update;
- cover create, normal CAS, logical expiry cleanup, single winning lease acquisition, stale owner/generation/fence rejection, fenced CAS/delete/release, `uint64` fence exhaustion, and server-`PTTL` lease expiry.

```go
if _, err := backend.ConsumeFlow(ctx, flow.ID); err != nil { t.Fatal(err) }
if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrNotFound) {
	t.Fatalf("second consume error = %v", err)
}
if err := backend.CompareAndSwap(ctx, id, 1, replacement); !errors.Is(err, session.ErrConflict) {
	t.Fatalf("watch abort error = %v", err)
}
```

- [ ] **Step 2: Run the new tests and confirm the current Lua implementation fails**

Run: `go test ./runtime/adapters/redis -run 'TestBackendUsesNoLuaCommands|TestNativeFlow|TestNativeSession|TestNativeLease' -count=1`

Expected: FAIL because the existing implementation invokes Lua.

- [ ] **Step 3: Replace all operations in one compiling change**

Implement a small transaction helper that preserves domain errors and maps only Redis transaction failure to `session.ErrConflict`.

```go
func (b *Backend) watchSession(ctx context.Context, id string, fn func(*goredis.Tx) error) error {
	err := b.client.Watch(ctx, fn, b.sessionKey(id), b.leaseKey(id))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, goredis.TxFailedErr):
		return session.ErrConflict
	case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired),
		errors.Is(err, session.ErrLeaseLost), errors.Is(err, ErrFenceExhausted),
		errors.Is(err, ErrDecodeFailed):
		return err
	default:
		return backendError(err)
	}
}
```

Use the exact replacements below:
- `PutFlow`: `SetArgs(..., goredis.SetArgs{Mode: "NX", TTL: ttl})`; map a non-`OK` result to `session.ErrConflict`.
- `ConsumeFlow`: `GetDel`; decode and validate the returned encrypted Flow.
- `Create`, expiry cleanup, `CompareAndSwap`, `CompareAndSwapWithLease`, `DeleteWithLease`, and `Release`: inspect preconditions while watched, then queue `HSET`, `PEXPIRE`, and `DEL` in `TxPipelined`.
- `AcquireRefreshLease`: watch Session/Lease, validate positive Session `PTTL`, no valid Lease, and generation; increment Session `last_fence` in Go as an unsigned decimal, then queue new lease fields plus `PEXPIRE` and the new `last_fence`.
- `refreshLease.Valid`: check Lease `PTTL`, Session generation, and owner/fence fields; do not trust a local expiration timestamp.
- Remove the global fence key, Lua time metadata, script-only status mappers, all script tests, fake `Eval`/`EvalSha` support, and `scripts.go`.

```go
nextFence, err := incrementFence(lastFence)
if errors.Is(err, errFenceOverflow) { return ErrFenceExhausted }
pipe.HSet(ctx, sessionKey, "last_fence", strconv.FormatUint(nextFence, 10))
pipe.HSet(ctx, leaseKey, "owner", owner, "fence", nextFence, "generation", generation)
pipe.PExpire(ctx, leaseKey, leaseTTL)
```

- [ ] **Step 4: Run focused, conformance, race, and static tests**

Run: `go test ./runtime/adapters/redis -count=1 && go test -race ./runtime/adapters/redis -count=1 && go vet ./runtime/adapters/redis && rg -n '(NewScript|EvalSha|Eval|\\bLua\\b)' runtime/adapters/redis --glob '*.go'`

Expected: all tests and vet pass; the final search returns no production Lua API use.

- [ ] **Step 5: Commit the complete native Backend**

```bash
git add runtime/adapters/redis/backend.go runtime/adapters/redis/backend_test.go runtime/adapters/redis/scripts.go
git commit -m "feat(redis): replace Lua backend with native commands"
```

### Task 2: Prove Redis-version/Cluster behavior and document the operational change

**Files:**
- Modify: `integration/redis/redis_test.go`
- Create: `integration/redis/cluster_test.go`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `documentation_test.go`

**Interfaces:**
- Consumes: unchanged `redisadapter.New(goredis.UniversalClient, redisadapter.Options)` and the native implementation from Task 1.
- Produces: Redis 6.2/7.4 native command evidence, Redis Cluster transaction evidence, and user-facing requirements.

- [ ] **Step 1: Add real Redis 6.2/7.4 no-Lua integration coverage**

Attach a go-redis hook that rejects `eval`, `evalsha`, and `script`, then execute Flow `GETDEL`, conformance, refresh lease, and lease CAS against the existing Redis 6.2 and 7.4 Testcontainers.

```go
func (rejectLuaHook) ProcessHook(next goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		switch strings.ToLower(cmd.Name()) {
		case "eval", "evalsha", "script":
			return fmt.Errorf("forbidden Redis command: %s", cmd.Name())
		}
		return next(ctx, cmd)
	}
}
```

- [ ] **Step 2: Add a real three-node Redis Cluster integration test**

Start three `redis:7.4-alpine` containers in one Testcontainers network with stable aliases and `--cluster-enabled yes --cluster-config-file nodes.conf`. Initialize them using:

```bash
redis-cli --cluster create redis-0:6379 redis-1:6379 redis-2:6379 --cluster-replicas 0 --cluster-yes
```

Build a `goredis.NewClusterClient`, run `sessiontest.Run` plus a lease CAS through the public adapter, and fail if any operation returns `CROSSSLOT` or emits a forbidden Lua command.

- [ ] **Step 3: Document and test the published operational contract**

State that the Redis adapter is optional BFF Session storage, applications supply their own go-redis Client/FailoverClient/ClusterClient, Redis 6.2+ is required, and the adapter performs no Lua evaluation. Add a changelog entry marking Lua removal as an operationally breaking change and extend `documentation_test.go` to require these claims.

- [ ] **Step 4: Run final verification**

Run: `go test ./... && go test -race ./... && go vet ./... && go run golang.org/x/vuln/cmd/govulncheck@latest ./... && (cd integration && go test ./...) && git diff --check`

Expected: every command exits 0; the root scan reports no reachable vulnerabilities; real Redis 6.2, 7.4, and Cluster tests pass.

- [ ] **Step 5: Commit integration and documentation evidence**

```bash
git add integration/redis/redis_test.go integration/redis/cluster_test.go README.md CHANGELOG.md documentation_test.go
git commit -m "test(redis): verify native commands on Redis Cluster"
```
