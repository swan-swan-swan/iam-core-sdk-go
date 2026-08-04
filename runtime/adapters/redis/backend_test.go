package redis

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session/sessiontest"
)

func TestBackendConformanceAgainstLogicalClassificationHarness(t *testing.T) {
	sessiontest.Run(t, func(t testing.TB, clock *sessiontest.Clock) session.Backend {
		t.Helper()
		client := newFakeRedisClient(clock.Now)
		client.enableLogicalClassificationHarness()
		backend, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{1}, 4096))))
		if err != nil {
			t.Fatal("construct backend")
		}
		return backend
	})
}

func TestNewRejectsNilDependenciesAndUnsafePrefixes(t *testing.T) {
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	valid := validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	var typedNilClient *fakeRedisClient
	var typedNilCodec *identityCodec
	var typedNilClock *sessiontest.Clock
	var typedNilRandom *bytes.Reader

	tests := []struct {
		name   string
		client goredis.UniversalClient
		opts   Options
	}{
		{name: "nil client", opts: valid},
		{name: "typed nil client", client: typedNilClient, opts: valid},
		{name: "nil codec", client: client, opts: withCodec(valid, nil)},
		{name: "typed nil codec", client: client, opts: withCodec(valid, typedNilCodec)},
		{name: "nil clock", client: client, opts: withClock(valid, nil)},
		{name: "typed nil clock", client: client, opts: withClock(valid, typedNilClock)},
		{name: "nil random", client: client, opts: withRandom(valid, nil)},
		{name: "typed nil random", client: client, opts: withRandom(valid, typedNilRandom)},
	}
	for _, prefix := range []string{
		"", " ", " iamcore", "iamcore ", ":iamcore", "iamcore:", "iam::core",
		"iam{core", "iam}core", "iam/core", "iam\ncore", strings.Repeat("a", 257),
	} {
		tests = append(tests, struct {
			name   string
			client goredis.UniversalClient
			opts   Options
		}{name: "unsafe prefix " + strconv.Quote(prefix), client: client, opts: withPrefix(valid, prefix)})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend, err := New(test.client, test.opts)
			if backend != nil || !errors.Is(err, ErrInvalidOptions) {
				t.Fatal("invalid options returned the wrong result")
			}
			if strings.Contains(err.Error(), "iam") {
				t.Fatal("options error exposed configuration")
			}
		})
	}

	for _, prefix := range []string{"iamcore", "iam-core.v2", "tenant_1:iam-core"} {
		if _, err := New(client, withPrefix(valid, prefix)); err != nil {
			t.Fatalf("safe prefix %q rejected", prefix)
		}
	}
}

func TestKeysAreDistinctNamespacedDigestsAndClusterCompatible(t *testing.T) {
	backend := &Backend{prefix: "tenant:iam"}
	raw := "raw-session-secret"
	sessionKey := backend.sessionKey(raw)
	flowKey := backend.flowKey(raw)
	leaseKey := backend.leaseKey(raw)
	fenceKey := backend.fenceKey()

	for kind, key := range map[string]string{
		"session": sessionKey,
		"flow":    flowKey,
		"lease":   leaseKey,
		"fence":   fenceKey,
	} {
		if strings.Contains(key, raw) {
			t.Fatalf("%s key exposed raw identifier", kind)
		}
	}
	if sessionKey == flowKey || sessionKey == leaseKey || flowKey == leaseKey || fenceKey == sessionKey {
		t.Fatal("Redis namespaces collided")
	}
	if !strings.HasPrefix(sessionKey, "tenant:iam:session:{") || !strings.HasPrefix(leaseKey, "tenant:iam:lease:{") {
		t.Fatal("session and lease keys lack namespaced hash tags")
	}
	sessionTag := sessionKey[strings.IndexByte(sessionKey, '{'):]
	leaseTag := leaseKey[strings.IndexByte(leaseKey, '{'):]
	if sessionTag != leaseTag {
		t.Fatal("session and lease keys do not share an exact Redis Cluster hash tag")
	}
	if fenceKey != "tenant:iam:fence" {
		t.Fatalf("fence key = %q", fenceKey)
	}
}

func TestCommandsUseExactKeysTTLsAndFencedArguments(t *testing.T) {
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	backendInterface, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{9}, 256))))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendInterface.(*Backend)
	ctx := context.Background()

	item := testSession("command-session", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	create := client.lastEval(t, scriptMarkerCreate)
	assertStringSliceEqual(t, create.keys, []string{backend.sessionKey(item.ID), backend.leaseKey(item.ID)})
	assertArgStrings(t, create.args, 0, "1")
	if !validOpaqueToken(argString(create.args[2]), generationByteLength) {
		t.Fatal("create did not send a valid Session generation")
	}
	assertArgStrings(t, create.args, 3, strconv.FormatInt(time.Hour.Milliseconds(), 10))
	if payload, ok := create.args[1].([]byte); !ok || bytes.Contains(payload, []byte(item.Tokens.AccessToken)) {
		t.Fatal("create did not send an encrypted payload")
	}

	flow := &session.Flow{ID: "command-flow", State: "state-secret", CodeVerifier: "verifier-secret", ExpiresAt: clock.Now().Add(1500*time.Millisecond + time.Nanosecond)}
	if err := backend.PutFlow(ctx, flow); err != nil {
		t.Fatal(err)
	}
	put := client.lastEval(t, scriptMarkerFlowPut)
	assertStringSliceEqual(t, put.keys, []string{backend.flowKey(flow.ID)})
	assertArgStrings(t, put.args, 1, "1501")
	if payload, ok := put.args[0].([]byte); !ok || bytes.Contains(payload, []byte(flow.CodeVerifier)) {
		t.Fatal("flow command exposed verifier plaintext")
	}
	if _, err := backend.ConsumeFlow(ctx, flow.ID); err != nil {
		t.Fatal(err)
	}
	consume := client.lastEval(t, scriptMarkerFlowConsume)
	assertStringSliceEqual(t, consume.keys, []string{backend.flowKey(flow.ID)})
	if len(consume.args) != 0 {
		t.Fatal("flow consume sent unexpected arguments")
	}

	leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute+time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	owned := leaseValue.(*refreshLease)
	if owned.owner == "" || owned.fence != 1 {
		t.Fatal("lease did not receive owner and first global fence")
	}
	fence := client.lastEval(t, scriptMarkerFenceNext)
	assertStringSliceEqual(t, fence.keys, []string{backend.fenceKey()})
	acquire := client.lastEval(t, scriptMarkerLeaseAcquire)
	assertStringSliceEqual(t, acquire.keys, []string{backend.sessionKey(item.ID), backend.leaseKey(item.ID)})
	assertArgStrings(t, acquire.args, 0, owned.owner)
	assertArgStrings(t, acquire.args, 1, "1")
	assertArgStrings(t, acquire.args, 2, owned.generation)
	assertArgStrings(t, acquire.args, 3, "60001")
	if !strings.Contains(acquire.script, "return requestedTTL") {
		t.Fatal("lease Acquire script did not return the granted TTL")
	}

	next := testSession(item.ID, clock.Now())
	next.Version = 2
	next.Tokens.AccessToken = "next-access-secret"
	if err := backend.CompareAndSwapWithLease(ctx, leaseValue, item.ID, 1, next); err != nil {
		t.Fatal(err)
	}
	commit := client.lastEval(t, scriptMarkerFencedCAS)
	assertStringSliceEqual(t, commit.keys, []string{backend.sessionKey(item.ID), backend.leaseKey(item.ID)})
	wantCommitArgs := []string{
		owned.owner,
		"1",
		owned.generation,
		"1",
		"2",
	}
	for index, want := range wantCommitArgs {
		assertArgStrings(t, commit.args, index, want)
	}
	if payload, ok := commit.args[5].([]byte); !ok || bytes.Contains(payload, []byte(next.Tokens.AccessToken)) {
		t.Fatal("fenced commit exposed token plaintext")
	}
	assertArgStrings(t, commit.args, 6, strconv.FormatInt(time.Hour.Milliseconds(), 10))
	if leaseValue.Valid(ctx) {
		t.Fatal("successful fenced CAS left the Redis lease valid")
	}
	if err := leaseValue.Release(ctx); err != nil {
		t.Fatal("release did not acknowledge the successfully consumed lease")
	}
}

func TestFencesAreGlobalAndMonotonicAcrossSessions(t *testing.T) {
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	backendValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{2}, 256))))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	first := testSession("fence-first", clock.Now())
	second := testSession("fence-second", clock.Now())
	if err := backend.Create(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := backend.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	firstLease, err := backend.AcquireRefreshLease(ctx, first.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secondLease, err := backend.AcquireRefreshLease(ctx, second.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if firstLease.(*refreshLease).fence != 1 || secondLease.(*refreshLease).fence != 2 {
		t.Fatal("fencing sequence was not globally monotonic")
	}
}

func TestCreateReplacesExpiredStateAndMutationsRejectExpiredCurrentSession(t *testing.T) {
	t.Run("create replaces expired state", func(t *testing.T) {
		clock, _, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{5}, 128)))
		ctx := context.Background()
		current := testSession("replace-expired", clock.Now())
		if err := backend.Create(ctx, current); err != nil {
			t.Fatal(err)
		}
		clock.Set(current.IdleExpiresAt)
		replacement := testSession(current.ID, clock.Now())
		if err := backend.Create(ctx, replacement); err != nil {
			t.Fatal("expired state prevented replacement")
		}
	})

	t.Run("plain CAS rejects expired current state", func(t *testing.T) {
		clock, _, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{6}, 128)))
		ctx := context.Background()
		current := testSession("cas-expired", clock.Now())
		if err := backend.Create(ctx, current); err != nil {
			t.Fatal(err)
		}
		clock.Set(current.IdleExpiresAt)
		next := testSession(current.ID, clock.Now())
		next.Version = 2
		if err := backend.CompareAndSwap(ctx, current.ID, 1, next); !errors.Is(err, session.ErrExpired) {
			t.Fatal("CAS did not reject an expired current Session")
		}
	})

	for _, operation := range []string{"CAS", "delete"} {
		t.Run("leased "+operation+" rejects expired current state", func(t *testing.T) {
			clock, _, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{7}, 128)))
			ctx := context.Background()
			current := testSession("leased-expired-"+strings.ToLower(operation), clock.Now())
			if err := backend.Create(ctx, current); err != nil {
				t.Fatal(err)
			}
			leaseValue, err := backend.AcquireRefreshLease(ctx, current.ID, 2*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			clock.Set(current.IdleExpiresAt)
			if operation == "CAS" {
				next := testSession(current.ID, clock.Now())
				next.Version = 2
				err = backend.CompareAndSwapWithLease(ctx, leaseValue, current.ID, 1, next)
			} else {
				err = backend.DeleteWithLease(ctx, leaseValue, current.ID, 1)
			}
			if !errors.Is(err, session.ErrExpired) {
				t.Fatal("leased mutation did not reject an expired current Session")
			}
			if leaseValue.Valid(ctx) {
				t.Fatal("expired Session cleanup left its lease valid")
			}
		})
	}
}

func TestExpiredGetCannotDeleteConcurrentReplacement(t *testing.T) {
	clock := newSessionClock()
	baseClient := newFakeRedisClient(clock.Now)
	client := &cleanupRaceClient{fakeRedisClient: baseClient}
	backendValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{13}, 128))))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	current := testSession("expired-cleanup-race", clock.Now())
	if err := backend.Create(ctx, current); err != nil {
		t.Fatal(err)
	}
	clock.Set(current.IdleExpiresAt)
	replacement := testSession(current.ID, clock.Now())
	replacement.Version = 2
	replacement.Tokens.AccessToken = "concurrent-replacement"
	replacementPayload, err := encodeModel(backend.codec, replacement)
	if err != nil {
		t.Fatal(err)
	}
	client.beforeExpiredCleanup = func() {
		baseClient.mu.Lock()
		defer baseClient.mu.Unlock()
		baseClient.values[backend.sessionKey(current.ID)] = &fakeValue{
			fields: map[string]string{
				"version":    "2",
				"payload":    string(replacementPayload),
				"generation": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{31}, generationByteLength)),
				"last_fence": "0",
			},
			expiresAt: baseClient.serverTimeLocked().Add(time.Hour),
		}
	}

	got, err := backend.Get(ctx, current.ID)
	if err != nil {
		t.Fatal("Get did not retry after concurrent replacement")
	}
	if got.Version != 2 || got.Tokens.AccessToken != "concurrent-replacement" {
		t.Fatal("Get did not return the concurrent replacement")
	}
	if baseClient.values[backend.sessionKey(current.ID)] == nil {
		t.Fatal("expired cleanup deleted the concurrent replacement")
	}
}

func TestCreateAtomicallyInvalidatesOrphanLeaseAndProtectsSameVersionReplacement(t *testing.T) {
	for _, operation := range []string{"CAS", "delete"} {
		t.Run(operation, func(t *testing.T) {
			clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{21}, 512)))
			ctx := context.Background()
			original := testSession("orphan-"+strings.ToLower(operation), clock.Now())
			if err := backend.Create(ctx, original); err != nil {
				t.Fatal(err)
			}
			oldLease, err := backend.AcquireRefreshLease(ctx, original.ID, 2*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			client.advanceServer(time.Hour)

			oldNext := testSession(original.ID, clock.Now())
			oldNext.Version = 2
			oldNext.Tokens.AccessToken = "old-owner-write"
			if operation == "CAS" {
				err = backend.CompareAndSwapWithLease(ctx, oldLease, original.ID, 1, oldNext)
			} else {
				err = backend.DeleteWithLease(ctx, oldLease, original.ID, 1)
			}
			if !errors.Is(err, session.ErrNotFound) {
				t.Fatal("old operation before recreation had the wrong classification")
			}

			replacement := testSession(original.ID, clock.Now())
			replacement.Tokens.AccessToken = "replacement-value"
			if err := backend.Create(ctx, replacement); err != nil {
				t.Fatal("same-ID Session recreation failed")
			}
			if oldLease.Valid(ctx) {
				t.Fatal("recreation left the orphan lease valid")
			}
			if operation == "CAS" {
				err = backend.CompareAndSwapWithLease(ctx, oldLease, original.ID, 1, oldNext)
			} else {
				err = backend.DeleteWithLease(ctx, oldLease, original.ID, 1)
			}
			if !errors.Is(err, session.ErrLeaseLost) {
				t.Fatal("old operation after same-version recreation was not fenced")
			}
			stored, err := backend.Get(ctx, original.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Version != 1 || stored.Tokens.AccessToken != "replacement-value" {
				t.Fatal("old owner changed the same-version replacement")
			}
		})
	}
}

func TestLeasePhysicalTTLIsCappedToRemainingSessionPTTL(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{22}, 256)))
	item := testSession("lease-ttl-cap", clock.Now())
	if err := backend.Create(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	client.advanceServer(30 * time.Minute)
	leaseValue, err := backend.AcquireRefreshLease(context.Background(), item.ID, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	owned := leaseValue.(*refreshLease)
	client.mu.Lock()
	serverNow := client.serverTimeLocked()
	leaseRemaining := client.values[backend.leaseKey(item.ID)].expiresAt.Sub(serverNow)
	sessionRemaining := client.values[backend.sessionKey(item.ID)].expiresAt.Sub(serverNow)
	client.mu.Unlock()
	if leaseRemaining <= 0 || leaseRemaining > sessionRemaining || leaseRemaining > 30*time.Minute {
		t.Fatalf("lease TTL %s exceeded remaining Session PTTL %s", leaseRemaining, sessionRemaining)
	}
	if localRemaining := owned.expiresAt.Sub(clock.Now()); localRemaining != leaseRemaining {
		t.Fatalf("local lease TTL %s differs from Redis grant %s", localRemaining, leaseRemaining)
	}
}

func TestStalledAcquireCannotBindToRecreatedSessionGeneration(t *testing.T) {
	clock := newSessionClock()
	baseClient := newFakeRedisClient(clock.Now)
	owner := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{23}, ownerByteLength))
	client := newAcquireGateClient(baseClient, owner)
	random := bytes.NewReader(bytes.Join([][]byte{
		bytes.Repeat([]byte{22}, generationByteLength),
		bytes.Repeat([]byte{23}, ownerByteLength),
		bytes.Repeat([]byte{24}, generationByteLength),
	}, nil))
	backendValue, err := New(client, validOptions(clock, random))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	item := testSession("generation-stall", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	result := make(chan leaseResult, 1)
	go func() {
		leaseValue, acquireErr := backend.AcquireRefreshLease(ctx, item.ID, 2*time.Hour)
		result <- leaseResult{lease: leaseValue, err: acquireErr}
	}()
	client.waitUntilBlocked(t)
	baseClient.advanceServer(time.Hour)
	replacement := testSession(item.ID, clock.Now())
	replacement.Tokens.AccessToken = "new-generation"
	if err := backend.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	client.resume()
	stalled := <-result
	if stalled.err == nil || stalled.lease != nil {
		t.Fatal("pre-recreation Acquire bound its lease to the new Session generation")
	}
	stored, err := backend.Get(ctx, item.ID)
	if err != nil || stored.Tokens.AccessToken != "new-generation" || stored.Version != 1 {
		t.Fatal("stalled old-generation Acquire changed the replacement")
	}
}

func TestFenceGrantOrderingRejectsDelayedLowerReservation(t *testing.T) {
	clock := newSessionClock()
	baseClient := newFakeRedisClient(clock.Now)
	ownerA := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{24}, ownerByteLength))
	client := newAcquireGateClient(baseClient, ownerA)
	backendAValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{24}, 512))))
	if err != nil {
		t.Fatal(err)
	}
	backendBValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{25}, 512))))
	if err != nil {
		t.Fatal(err)
	}
	backendA := backendAValue.(*Backend)
	backendB := backendBValue.(*Backend)
	ctx := context.Background()
	item := testSession("grant-order", clock.Now())
	if err := backendA.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	resultA := make(chan leaseResult, 1)
	go func() {
		leaseValue, acquireErr := backendA.AcquireRefreshLease(ctx, item.ID, time.Minute)
		resultA <- leaseResult{lease: leaseValue, err: acquireErr}
	}()
	client.waitUntilBlocked(t)
	leaseB, err := backendB.AcquireRefreshLease(ctx, item.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if leaseB.(*refreshLease).fence != 2 {
		t.Fatal("higher reservation did not receive fence 2")
	}
	if err := leaseB.Release(ctx); err != nil {
		t.Fatal(err)
	}
	client.resume()
	acquiredA := <-resultA
	if acquiredA.err != nil || acquiredA.lease == nil {
		t.Fatal("delayed contender did not retry its stale reservation")
	}
	if acquiredA.lease.(*refreshLease).fence <= 2 {
		t.Fatal("lower reserved fence was granted after the higher fence")
	}
}

func TestAcquireLocalDeadlineStartsAtSuccessfulGrant(t *testing.T) {
	clock := newSessionClock()
	baseClient := newFakeRedisClient(clock.Now)
	client := newScriptGateClient(baseClient, scriptMarkerFenceNext)
	backendValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{34}, 512))))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	item := testSession("grant-deadline", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}

	const requested = time.Minute
	result := make(chan leaseResult, 1)
	go func() {
		leaseValue, acquireErr := backend.AcquireRefreshLease(ctx, item.ID, requested)
		result <- leaseResult{lease: leaseValue, err: acquireErr}
	}()
	client.waitUntilBlocked(t)
	clock.Advance(2 * requested)
	baseClient.advanceServer(2 * requested)
	client.resume()
	acquired := <-result
	if acquired.err != nil || acquired.lease == nil {
		t.Fatal("delayed Acquire did not receive the Redis grant")
	}
	if !acquired.lease.Valid(ctx) {
		t.Error("newly granted lease was already locally expired")
	}
	if successor, err := backend.AcquireRefreshLease(ctx, item.ID, requested); successor != nil || !errors.Is(err, session.ErrConflict) {
		t.Error("newly granted Redis lease did not block a concurrent successor")
	}

	clock.Advance(requested)
	baseClient.advanceServer(requested)
	if acquired.lease.Valid(ctx) {
		t.Error("lease remained valid at the granted TTL boundary")
	}
	successor, err := backend.AcquireRefreshLease(ctx, item.ID, requested)
	if err != nil || successor == nil {
		t.Fatal("new Acquire was unavailable after the granted TTL elapsed")
	}
	if err := successor.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRedisRemainsAuthoritativeAfterAcquireResponseDelay(t *testing.T) {
	clock := newSessionClock()
	baseClient := newFakeRedisClient(clock.Now)
	client := newAfterAcquireGateClient(baseClient)
	backendValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{35}, 512))))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	item := testSession("grant-response-delay", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}

	const requested = time.Minute
	result := make(chan leaseResult, 1)
	go func() {
		leaseValue, acquireErr := backend.AcquireRefreshLease(ctx, item.ID, requested)
		result <- leaseResult{lease: leaseValue, err: acquireErr}
	}()
	client.waitUntilBlocked(t)
	clock.Advance(requested)
	baseClient.advanceServer(requested)
	client.resume()
	acquired := <-result
	if acquired.err != nil || acquired.lease == nil {
		t.Fatal("delayed response lost the completed Redis grant")
	}
	if acquired.lease.Valid(ctx) {
		t.Fatal("optimistic local deadline bypassed authoritative Redis expiry")
	}
	successor, err := backend.AcquireRefreshLease(ctx, item.ID, requested)
	if err != nil || successor == nil {
		t.Fatal("expired Redis lease blocked a successor after response delay")
	}
	if err := successor.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseGrantStatusAndDeadlineBoundaries(t *testing.T) {
	t.Run("one millisecond is success", func(t *testing.T) {
		clock, _, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{36}, 256)))
		item := testSession("one-millisecond-grant", clock.Now())
		if err := backend.Create(context.Background(), item); err != nil {
			t.Fatal(err)
		}
		leaseValue, err := backend.AcquireRefreshLease(context.Background(), item.ID, time.Nanosecond)
		if err != nil || leaseValue == nil {
			t.Fatal("one-millisecond positive status was not treated as success")
		}
		owned := leaseValue.(*refreshLease)
		if got := owned.expiresAt.Sub(clock.Now()); got != time.Millisecond {
			t.Fatalf("local deadline offset = %s, want 1ms", got)
		}
		if err := leaseValue.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	const maxDurationMilliseconds = int64(math.MaxInt64) / int64(time.Millisecond)
	// time.Time stores wall seconds from year 1; subtracting the Unix epoch
	// offset constructs its largest representable wall second without overflow.
	const secondsFromYearOneToUnixEpoch = int64(62135596800)
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	maximumTime := time.Unix(math.MaxInt64-secondsFromYearOneToUnixEpoch, 999999999).UTC()
	for _, test := range []struct {
		name         string
		observedAt   time.Time
		milliseconds int64
		wantOK       bool
	}{
		{name: "zero", observedAt: now, milliseconds: 0},
		{name: "negative", observedAt: now, milliseconds: -1},
		{name: "one", observedAt: now, milliseconds: 1, wantOK: true},
		{name: "maximum duration", observedAt: now, milliseconds: maxDurationMilliseconds, wantOK: true},
		{name: "duration overflow", observedAt: now, milliseconds: maxDurationMilliseconds + 1},
		{name: "time add saturation", observedAt: maximumTime, milliseconds: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			deadline, ok := leaseDeadline(test.observedAt, test.milliseconds)
			if ok != test.wantOK {
				t.Fatalf("leaseDeadline(%s) = %s, ok %t, want %t", test.observedAt, deadline, ok, test.wantOK)
			}
			if ok && !deadline.After(test.observedAt) {
				t.Fatal("accepted deadline did not advance time")
			}
		})
	}
}

func TestStaleFenceRetriesAreBoundedAndContextAware(t *testing.T) {
	t.Run("bounded", func(t *testing.T) {
		clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{32}, 512)))
		item := testSession("stale-fence-bounded", clock.Now())
		if err := backend.Create(context.Background(), item); err != nil {
			t.Fatal(err)
		}
		client.mu.Lock()
		client.values[backend.sessionKey(item.ID)].fields["last_fence"] = "100"
		client.mu.Unlock()
		leaseValue, err := backend.AcquireRefreshLease(context.Background(), item.ID, time.Minute)
		if leaseValue != nil || !errors.Is(err, session.ErrConflict) {
			t.Fatal("stale-fence retry exhaustion returned the wrong result")
		}
		client.mu.Lock()
		fence := client.fences[backend.fenceKey()]
		client.mu.Unlock()
		if fence != maxFenceGrantAttempts {
			t.Fatalf("reserved %d fences, want retry bound %d", fence, maxFenceGrantAttempts)
		}
	})

	t.Run("context", func(t *testing.T) {
		clock := newSessionClock()
		baseClient := newFakeRedisClient(clock.Now)
		ctx, cancel := context.WithCancel(context.Background())
		client := &cancelAfterAcquireClient{fakeRedisClient: baseClient, cancel: cancel}
		backendValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{33}, 512))))
		if err != nil {
			t.Fatal(err)
		}
		backend := backendValue.(*Backend)
		item := testSession("stale-fence-context", clock.Now())
		if err := backend.Create(context.Background(), item); err != nil {
			t.Fatal(err)
		}
		baseClient.mu.Lock()
		baseClient.values[backend.sessionKey(item.ID)].fields["last_fence"] = "100"
		baseClient.mu.Unlock()
		leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
		if leaseValue != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("canceled stale-fence retry returned the wrong result")
		}
		baseClient.mu.Lock()
		fence := baseClient.fences[backend.fenceKey()]
		baseClient.mu.Unlock()
		if fence != 1 {
			t.Fatal("Acquire reserved another fence after cancellation")
		}
	})
}

func TestAuthoritativeServerExpiryRejectsOperationsWithStaleApplicationClock(t *testing.T) {
	for _, operation := range []string{"CAS", "delete", "valid", "release"} {
		t.Run(operation, func(t *testing.T) {
			clock := newSessionClock()
			baseClient := newFakeRedisClient(clock.Now)
			client := newScriptGateClient(baseClient, markerForLeaseOperation(operation))
			backendValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{26}, 512))))
			if err != nil {
				t.Fatal(err)
			}
			backend := backendValue.(*Backend)
			ctx := context.Background()
			item := testSession("server-expiry-"+operation, clock.Now())
			if err := backend.Create(ctx, item); err != nil {
				t.Fatal(err)
			}
			leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			baseClient.mu.Lock()
			baseClient.values[backend.leaseKey(item.ID)].expiresAt = baseClient.serverTimeLocked().Add(2 * time.Minute)
			baseClient.mu.Unlock()
			result := make(chan error, 1)
			go func() {
				switch operation {
				case "CAS":
					next := testSession(item.ID, clock.Now())
					next.Version = 2
					result <- backend.CompareAndSwapWithLease(ctx, leaseValue, item.ID, 1, next)
				case "delete":
					result <- backend.DeleteWithLease(ctx, leaseValue, item.ID, 1)
				case "valid":
					if leaseValue.Valid(ctx) {
						result <- nil
					} else {
						result <- session.ErrLeaseLost
					}
				case "release":
					result <- leaseValue.Release(ctx)
				}
			}()
			client.waitUntilBlocked(t)
			baseClient.advanceServer(time.Minute)
			client.resume()
			err = <-result
			if operation == "valid" {
				if err == nil {
					t.Fatal("Valid authorized after authoritative server expiry")
				}
			} else if !errors.Is(err, session.ErrLeaseLost) {
				t.Fatal("operation did not reject authoritative server expiry as lease loss")
			}
			stored, getErr := backend.Get(ctx, item.ID)
			if getErr != nil || stored.Version != 1 {
				t.Fatal("expired lease operation changed the Session")
			}
		})
	}
}

func TestAcquireRechecksServerAfterEntropyDelay(t *testing.T) {
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	random := newGatedReader(27)
	backendValue, err := New(client, validOptions(clock, random))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	item := testSession("entropy-delay", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	random.arm()
	result := make(chan leaseResult, 1)
	go func() {
		leaseValue, acquireErr := backend.AcquireRefreshLease(ctx, item.ID, 2*time.Hour)
		result <- leaseResult{lease: leaseValue, err: acquireErr}
	}()
	random.waitUntilBlocked(t)
	client.advanceServer(time.Hour)
	random.resume()
	acquired := <-result
	if acquired.err == nil || acquired.lease != nil {
		t.Fatal("Acquire succeeded after Session expired during entropy delay")
	}
}

func TestLeaseMutationRechecksServerAfterCodecAndGetDelays(t *testing.T) {
	for _, stage := range []string{"codec", "Get"} {
		t.Run(stage, func(t *testing.T) {
			clock := newSessionClock()
			baseClient := newFakeRedisClient(clock.Now)
			options := validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{29}, 512)))
			var client goredis.UniversalClient = baseClient
			var arm, wait, resume func()
			if stage == "codec" {
				codec := newGatedCodec(options.Codec)
				options.Codec = codec
				arm = codec.arm
				wait = func() { codec.waitUntilBlocked(t) }
				resume = codec.resume
			} else {
				gate := newHMGetGateClient(baseClient)
				client = gate
				arm = gate.arm
				wait = func() { gate.waitUntilBlocked(t) }
				resume = gate.resume
			}
			backendValue, err := New(client, options)
			if err != nil {
				t.Fatal(err)
			}
			backend := backendValue.(*Backend)
			ctx := context.Background()
			item := testSession("mutation-delay-"+strings.ToLower(stage), clock.Now())
			if err := backend.Create(ctx, item); err != nil {
				t.Fatal(err)
			}
			leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			next := testSession(item.ID, clock.Now())
			next.Version = 2
			arm()
			result := make(chan error, 1)
			go func() { result <- backend.CompareAndSwapWithLease(ctx, leaseValue, item.ID, 1, next) }()
			wait()
			baseClient.advanceServer(time.Minute)
			resume()
			if err := <-result; !errors.Is(err, session.ErrLeaseLost) {
				t.Fatal("mutation delay did not recheck authoritative server expiry")
			}
			stored, err := backend.Get(ctx, item.ID)
			if err != nil || stored.Version != 1 {
				t.Fatal("expired delayed mutation changed the Session")
			}
		})
	}
}

func TestLuaServerTimeExactIntegerBoundary(t *testing.T) {
	const maxExactMilliseconds int64 = 1<<53 - 1
	for _, test := range []struct {
		name      string
		duration  time.Duration
		wantError bool
	}{
		{name: "exact maximum", duration: 10 * time.Millisecond},
		{name: "addition overflow", duration: 11 * time.Millisecond, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{28}, 512)))
			client.setServer(time.UnixMilli(maxExactMilliseconds - 10))
			item := testSession("lua-time-"+strings.ReplaceAll(test.name, " ", "-"), clock.Now())
			if err := backend.Create(context.Background(), item); err != nil {
				t.Fatal(err)
			}
			leaseValue, err := backend.AcquireRefreshLease(context.Background(), item.ID, test.duration)
			if test.wantError {
				if !errors.Is(err, ErrBackendUnavailable) || leaseValue != nil {
					t.Fatal("inexact Lua timestamp addition was accepted")
				}
			} else if err != nil || leaseValue == nil {
				t.Fatal("exact Lua timestamp boundary was rejected")
			}
		})
	}
}

func TestFenceExhaustionAndRandomFailureInstallNoLease(t *testing.T) {
	t.Run("random failure does not consume fence", func(t *testing.T) {
		clock, client, backend := newBackendFixture(t, io.LimitReader(strings.NewReader(strings.Repeat("x", generationByteLength+5)), generationByteLength+5))
		item := testSession("random-no-fence", clock.Now())
		if err := backend.Create(context.Background(), item); err != nil {
			t.Fatal(err)
		}
		if _, err := backend.AcquireRefreshLease(context.Background(), item.ID, time.Minute); !errors.Is(err, ErrRandomSource) {
			t.Fatal("random failure returned the wrong classification")
		}
		if client.fences[backend.fenceKey()] != 0 || client.values[backend.leaseKey(item.ID)] != nil {
			t.Fatal("random failure consumed a fence or installed a lease")
		}
	})

	t.Run("maximum fence cannot wrap", func(t *testing.T) {
		clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{8}, 64)))
		item := testSession("fence-exhausted", clock.Now())
		if err := backend.Create(context.Background(), item); err != nil {
			t.Fatal(err)
		}
		client.fences[backend.fenceKey()] = math.MaxUint64
		if _, err := backend.AcquireRefreshLease(context.Background(), item.ID, time.Minute); !errors.Is(err, ErrFenceExhausted) {
			t.Fatal("fence exhaustion returned the wrong classification")
		}
		if client.fences[backend.fenceKey()] != math.MaxUint64 || client.values[backend.leaseKey(item.ID)] != nil {
			t.Fatal("fence exhaustion wrapped or installed a lease")
		}
	})
}

func TestForeignOrConsumedLeasesAreRejectedBeforeRedis(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{10}, 256)))
	_, _, foreign := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{11}, 256)))
	ctx := context.Background()
	item := testSession("lease-origin", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	next := testSession(item.ID, clock.Now())
	next.Version = 2
	before := client.callCount()
	foreignLease := &refreshLease{backend: foreign, sessionID: item.ID, key: foreign.leaseKey(item.ID)}
	if err := backend.CompareAndSwapWithLease(ctx, foreignLease, item.ID, 1, next); !errors.Is(err, session.ErrLeaseLost) {
		t.Fatal("foreign lease returned the wrong classification")
	}
	if client.callCount() != before {
		t.Fatal("foreign lease reached Redis")
	}
	if err := backend.CompareAndSwapWithLease(ctx, leaseValue, item.ID, 1, next); err != nil {
		t.Fatal(err)
	}
	before = client.callCount()
	if err := backend.CompareAndSwapWithLease(ctx, leaseValue, item.ID, 1, next); !errors.Is(err, session.ErrLeaseLost) {
		t.Fatal("consumed lease returned the wrong classification")
	}
	if client.callCount() != before {
		t.Fatal("consumed lease reached Redis")
	}
}

func TestFencedScriptsValidateBeforeMutationAndDeleteLease(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{12}, 256)))
	ctx := context.Background()
	item := testSession("script-order", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	next := testSession(item.ID, clock.Now())
	next.Version = 2
	if err := backend.CompareAndSwapWithLease(ctx, leaseValue, item.ID, 1, next); err != nil {
		t.Fatal(err)
	}
	script := client.lastEval(t, scriptMarkerFencedCAS).script
	mutation := strings.Index(script, `redis.call("HSET", KEYS[1], "version", ARGV[5]`)
	leaseDelete := strings.Index(script, `redis.pcall("DEL", KEYS[2])`)
	for name, validation := range map[string]string{
		"server Session TTL": `redis.call("PTTL", KEYS[1]) <= 0`,
		"server lease TTL":   `redis.call("PTTL", KEYS[2]) <= 0`,
		"owner":              `owner ~= ARGV[1]`,
		"fence":              `fence ~= ARGV[2]`,
		"generation":         `generation ~= ARGV[3]`,
		"server time":        `redis.call("TIME")`,
		"lease expiry":       `tonumber(leaseExpiry) <= now`,
		"version":            `current ~= ARGV[4]`,
	} {
		position := strings.Index(script, validation)
		if position < 0 || position > mutation {
			t.Fatalf("%s was not validated before mutation", name)
		}
	}
	if mutation < 0 || leaseDelete < mutation {
		t.Fatal("fenced CAS script does not validate, mutate, and consume lease in order")
	}
}

func TestDeleteWithLeaseUsesAtomicFencedScriptAndConsumesLease(t *testing.T) {
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	backendValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{3}, 64))))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	item := testSession("delete-fenced", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	owned := leaseValue.(*refreshLease)
	if err := backend.DeleteWithLease(ctx, leaseValue, item.ID, 1); err != nil {
		t.Fatal(err)
	}
	call := client.lastEval(t, scriptMarkerFencedDelete)
	assertStringSliceEqual(t, call.keys, []string{backend.sessionKey(item.ID), backend.leaseKey(item.ID)})
	wants := []string{owned.owner, "1", owned.generation, "1"}
	for index, want := range wants {
		assertArgStrings(t, call.args, index, want)
	}
	if leaseValue.Valid(ctx) {
		t.Fatal("successful fenced delete left lease valid")
	}
}

func TestInvalidInputsAndCanceledContextsDoNotReachRedis(t *testing.T) {
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	backendValue, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{4}, 64))))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	next := testSession("valid", clock.Now())
	next.Version = 2
	invalidCalls := []func() error{
		func() error { return backend.PutFlow(ctx, nil) },
		func() error { _, err := backend.ConsumeFlow(ctx, " "); return err },
		func() error { return backend.Create(ctx, nil) },
		func() error { return backend.Create(ctx, &session.Session{ID: "id", Version: 0}) },
		func() error { _, err := backend.Get(ctx, " "); return err },
		func() error { return backend.CompareAndSwap(ctx, "other", 1, next) },
		func() error { return backend.CompareAndSwap(ctx, next.ID, math.MaxUint64, next) },
		func() error { return backend.Delete(ctx, " ") },
		func() error { _, err := backend.AcquireRefreshLease(ctx, " ", time.Minute); return err },
		func() error { _, err := backend.AcquireRefreshLease(ctx, "valid", 0); return err },
		func() error { return backend.CompareAndSwapWithLease(ctx, nil, next.ID, 1, next) },
		func() error { return backend.DeleteWithLease(ctx, nil, next.ID, 0) },
	}
	for index, call := range invalidCalls {
		before := client.callCount()
		if err := call(); err == nil {
			t.Fatalf("invalid call %d returned nil", index)
		}
		if client.callCount() != before {
			t.Fatalf("invalid call %d reached Redis", index)
		}
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	before := client.callCount()
	if err := backend.PutFlow(canceled, &session.Flow{ID: "flow", ExpiresAt: clock.Now().Add(time.Minute)}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context returned the wrong error")
	}
	if client.callCount() != before {
		t.Fatal("canceled call reached Redis")
	}
}

func TestTTLBoundariesAndOverflowAreSafe(t *testing.T) {
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if ttl, err := deadlineTTL(now.Add(time.Nanosecond), now); err != nil || ttl != time.Millisecond {
		t.Fatalf("sub-millisecond ttl = %s, err=%v", ttl, err)
	}
	if ttl, err := sessionTTL(&session.Session{ExpiresAt: now.Add(2 * time.Hour), IdleExpiresAt: now.Add(time.Hour)}, now); err != nil || ttl != time.Hour {
		t.Fatalf("session ttl = %s, err=%v", ttl, err)
	}
	if _, err := deadlineTTL(now, now); !errors.Is(err, session.ErrExpired) {
		t.Fatal("expiry equality returned the wrong error")
	}
	if got := ceilMillisecond(time.Duration(math.MaxInt64)); got <= 0 || got%time.Millisecond != 0 {
		t.Fatalf("maximum duration rounded unsafely: %s", got)
	}
}

func TestFailuresAreTypedAndSanitized(t *testing.T) {
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	backendValue, err := New(client, validOptions(clock, io.LimitReader(
		strings.NewReader(strings.Repeat("x", generationByteLength)+"random-source-sensitive"),
		generationByteLength+5,
	)))
	if err != nil {
		t.Fatal(err)
	}
	backend := backendValue.(*Backend)
	ctx := context.Background()
	item := testSession("session-sensitive", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute); !errors.Is(err, ErrRandomSource) || strings.Contains(err.Error(), item.ID) {
		t.Fatal("random failure was not typed and sanitized")
	}

	client.err = errors.New("redis://user:password@host payload-sensitive session-sensitive")
	_, err = backend.Get(ctx, item.ID)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatal("Redis failure returned the wrong classification")
	}
	for _, secret := range []string{"user", "password", "host", "payload-sensitive", item.ID} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("Redis failure exposed sensitive detail")
		}
	}
	client.err = context.DeadlineExceeded
	if _, err := backend.Get(ctx, item.ID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline was not preserved")
	}
}

func newBackendFixture(t testing.TB, random io.Reader) (*sessiontest.Clock, *fakeRedisClient, *Backend) {
	t.Helper()
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	backendValue, err := New(client, validOptions(clock, random))
	if err != nil {
		t.Fatal("construct test backend")
	}
	return clock, client, backendValue.(*Backend)
}

func validOptions(clock *sessiontest.Clock, random io.Reader) Options {
	codec, err := NewAESGCMCodec(Key{ID: "test", Bytes: bytes.Repeat([]byte{42}, 32)}, nil)
	if err != nil {
		panic("static test codec is invalid")
	}
	return Options{Prefix: "tenant:iam", Codec: codec, Clock: clock, Random: random}
}

func newSessionClock() *sessiontest.Clock {
	clock := &sessiontest.Clock{}
	clock.Set(time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC))
	return clock
}

func testSession(id string, now time.Time) *session.Session {
	return &session.Session{
		ID:      id,
		Version: 1,
		Tokens: session.TokenSet{
			AccessToken:   "access-secret",
			RefreshToken:  "refresh-secret",
			GrantedScopes: []string{"openid"},
		},
		CreatedAt:     now,
		UpdatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(2 * time.Hour),
		IdleExpiresAt: now.Add(time.Hour),
	}
}

func withPrefix(options Options, prefix string) Options { options.Prefix = prefix; return options }
func withCodec(options Options, codec Codec) Options    { options.Codec = codec; return options }
func withClock(options Options, clock interface{ Now() time.Time }) Options {
	options.Clock = clock
	return options
}
func withRandom(options Options, random io.Reader) Options { options.Random = random; return options }

type identityCodec struct{}

func (*identityCodec) Seal(plaintext []byte) ([]byte, error) {
	return append([]byte("sealed:"), plaintext...), nil
}
func (*identityCodec) Open(encoded []byte) ([]byte, error) {
	if !bytes.HasPrefix(encoded, []byte("sealed:")) {
		return nil, errors.New("codec-sensitive-detail")
	}
	return append([]byte(nil), encoded[len("sealed:"):]...), nil
}

type recordedEval struct {
	script string
	keys   []string
	args   []interface{}
}

type fakeValue struct {
	text      string
	fields    map[string]string
	expiresAt time.Time
}

// fakeRedisClient keeps application and Redis server clocks separate and models
// only the commands and script effects used by Backend, including TIME/PTTL.
// It deliberately does not interpret arbitrary Lua; real Redis execution belongs to Task 4.
type fakeRedisClient struct {
	goredis.UniversalClient

	mu                           sync.Mutex
	appNow                       func() time.Time
	serverNow                    time.Time
	serverOffset                 time.Duration
	serverFixed                  bool
	logicalClassificationHarness bool
	values                       map[string]*fakeValue
	fences                       map[string]uint64
	evals                        []recordedEval
	calls                        int
	err                          error
}

type cleanupRaceClient struct {
	*fakeRedisClient
	once                 sync.Once
	beforeExpiredCleanup func()
}

type leaseResult struct {
	lease session.Lease
	err   error
}

type acquireGateClient struct {
	*fakeRedisClient
	owner   string
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func newAcquireGateClient(client *fakeRedisClient, owner string) *acquireGateClient {
	return &acquireGateClient{
		fakeRedisClient: client,
		owner:           owner,
		entered:         make(chan struct{}),
		proceed:         make(chan struct{}),
	}
}

func (c *acquireGateClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *goredis.Cmd {
	if strings.Contains(script, scriptMarkerLeaseAcquire) && len(args) > 0 && argString(args[0]) == c.owner {
		c.once.Do(func() {
			close(c.entered)
			select {
			case <-c.proceed:
			case <-ctx.Done():
			}
		})
	}
	return c.fakeRedisClient.Eval(ctx, script, keys, args...)
}

func (c *acquireGateClient) waitUntilBlocked(t testing.TB) {
	t.Helper()
	waitForSignal(t, c.entered, "Acquire did not reach its Redis script")
}

func (c *acquireGateClient) resume() { close(c.proceed) }

type afterAcquireGateClient struct {
	*fakeRedisClient
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func newAfterAcquireGateClient(client *fakeRedisClient) *afterAcquireGateClient {
	return &afterAcquireGateClient{
		fakeRedisClient: client,
		entered:         make(chan struct{}),
		proceed:         make(chan struct{}),
	}
}

func (c *afterAcquireGateClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *goredis.Cmd {
	result := c.fakeRedisClient.Eval(ctx, script, keys, args...)
	if strings.Contains(script, scriptMarkerLeaseAcquire) {
		c.once.Do(func() {
			close(c.entered)
			select {
			case <-c.proceed:
			case <-ctx.Done():
			}
		})
	}
	return result
}

func (c *afterAcquireGateClient) waitUntilBlocked(t testing.TB) {
	t.Helper()
	waitForSignal(t, c.entered, "Acquire response was not delayed after its Redis grant")
}

func (c *afterAcquireGateClient) resume() { close(c.proceed) }

type cancelAfterAcquireClient struct {
	*fakeRedisClient
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelAfterAcquireClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *goredis.Cmd {
	result := c.fakeRedisClient.Eval(ctx, script, keys, args...)
	if strings.Contains(script, scriptMarkerLeaseAcquire) {
		c.once.Do(c.cancel)
	}
	return result
}

type scriptGateClient struct {
	*fakeRedisClient
	marker  string
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func newScriptGateClient(client *fakeRedisClient, marker string) *scriptGateClient {
	return &scriptGateClient{
		fakeRedisClient: client,
		marker:          marker,
		entered:         make(chan struct{}),
		proceed:         make(chan struct{}),
	}
}

func (c *scriptGateClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *goredis.Cmd {
	if strings.Contains(script, c.marker) {
		c.once.Do(func() {
			close(c.entered)
			select {
			case <-c.proceed:
			case <-ctx.Done():
			}
		})
	}
	return c.fakeRedisClient.Eval(ctx, script, keys, args...)
}

func (c *scriptGateClient) waitUntilBlocked(t testing.TB) {
	t.Helper()
	waitForSignal(t, c.entered, "operation did not reach its Redis script")
}

func (c *scriptGateClient) resume() { close(c.proceed) }

type hmGetGateClient struct {
	*fakeRedisClient
	mu      sync.Mutex
	armed   bool
	entered chan struct{}
	proceed chan struct{}
}

func newHMGetGateClient(client *fakeRedisClient) *hmGetGateClient {
	return &hmGetGateClient{fakeRedisClient: client}
}

func (c *hmGetGateClient) arm() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = true
	c.entered = make(chan struct{})
	c.proceed = make(chan struct{})
}

func (c *hmGetGateClient) HMGet(ctx context.Context, key string, fields ...string) *goredis.SliceCmd {
	c.mu.Lock()
	if !c.armed {
		c.mu.Unlock()
		return c.fakeRedisClient.HMGet(ctx, key, fields...)
	}
	c.armed = false
	entered := c.entered
	proceed := c.proceed
	c.mu.Unlock()
	close(entered)
	select {
	case <-proceed:
	case <-ctx.Done():
	}
	return c.fakeRedisClient.HMGet(ctx, key, fields...)
}

func (c *hmGetGateClient) waitUntilBlocked(t testing.TB) {
	t.Helper()
	c.mu.Lock()
	entered := c.entered
	c.mu.Unlock()
	waitForSignal(t, entered, "Get did not reach HMGET")
}

func (c *hmGetGateClient) resume() {
	c.mu.Lock()
	proceed := c.proceed
	c.mu.Unlock()
	close(proceed)
}

type gatedCodec struct {
	delegate Codec
	mu       sync.Mutex
	armed    bool
	entered  chan struct{}
	proceed  chan struct{}
}

func newGatedCodec(delegate Codec) *gatedCodec { return &gatedCodec{delegate: delegate} }

func (c *gatedCodec) arm() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = true
	c.entered = make(chan struct{})
	c.proceed = make(chan struct{})
}

func (c *gatedCodec) Seal(plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	if !c.armed {
		c.mu.Unlock()
		return c.delegate.Seal(plaintext)
	}
	c.armed = false
	entered := c.entered
	proceed := c.proceed
	c.mu.Unlock()
	close(entered)
	<-proceed
	return c.delegate.Seal(plaintext)
}

func (c *gatedCodec) Open(encoded []byte) ([]byte, error) { return c.delegate.Open(encoded) }

func (c *gatedCodec) waitUntilBlocked(t testing.TB) {
	t.Helper()
	c.mu.Lock()
	entered := c.entered
	c.mu.Unlock()
	waitForSignal(t, entered, "codec did not reach Seal")
}

func (c *gatedCodec) resume() {
	c.mu.Lock()
	proceed := c.proceed
	c.mu.Unlock()
	close(proceed)
}

func markerForLeaseOperation(operation string) string {
	switch operation {
	case "CAS":
		return scriptMarkerFencedCAS
	case "delete":
		return scriptMarkerFencedDelete
	case "valid":
		return scriptMarkerLeaseValid
	case "release":
		return scriptMarkerLeaseRelease
	default:
		panic("unknown lease operation")
	}
}

type gatedReader struct {
	mu      sync.Mutex
	value   byte
	armed   bool
	entered chan struct{}
	proceed chan struct{}
}

func newGatedReader(value byte) *gatedReader { return &gatedReader{value: value} }

func (r *gatedReader) arm() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.armed = true
	r.entered = make(chan struct{})
	r.proceed = make(chan struct{})
}

func (r *gatedReader) Read(destination []byte) (int, error) {
	r.mu.Lock()
	for index := range destination {
		destination[index] = r.value
	}
	if !r.armed {
		r.mu.Unlock()
		return len(destination), nil
	}
	r.armed = false
	entered := r.entered
	proceed := r.proceed
	r.mu.Unlock()
	close(entered)
	<-proceed
	return len(destination), nil
}

func (r *gatedReader) waitUntilBlocked(t testing.TB) {
	t.Helper()
	r.mu.Lock()
	entered := r.entered
	r.mu.Unlock()
	waitForSignal(t, entered, "random reader was not reached")
}

func (r *gatedReader) resume() {
	r.mu.Lock()
	proceed := r.proceed
	r.mu.Unlock()
	close(proceed)
}

func waitForSignal(t testing.TB, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal(failure)
	}
}

func (c *cleanupRaceClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *goredis.Cmd {
	if strings.Contains(script, scriptMarkerDeleteExpired) {
		c.once.Do(c.beforeExpiredCleanup)
	}
	return c.fakeRedisClient.Eval(ctx, script, keys, args...)
}

func newFakeRedisClient(now func() time.Time) *fakeRedisClient {
	return &fakeRedisClient{
		appNow:      now,
		serverNow:   now(),
		serverFixed: true,
		values:      make(map[string]*fakeValue),
		fences:      make(map[string]uint64),
	}
}

// enableLogicalClassificationHarness couples server time to the contract test
// clock and retains just-expired values for the Backend's one-shot logical
// ErrExpired classification. It is not a faithful Redis physical-expiry mode.
func (c *fakeRedisClient) enableLogicalClassificationHarness() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serverFixed = false
	c.serverOffset = 0
	c.logicalClassificationHarness = true
}

func (c *fakeRedisClient) advanceServer(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.serverFixed {
		c.serverNow = c.serverNow.Add(delta)
	} else {
		c.serverOffset += delta
	}
}

func (c *fakeRedisClient) setServer(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serverNow = now
	c.serverFixed = true
}

func (c *fakeRedisClient) serverTimeLocked() time.Time {
	if c.serverFixed {
		return c.serverNow
	}
	return c.appNow().Add(c.serverOffset)
}

func (c *fakeRedisClient) expiresBeforeLogicalReadLocked() bool {
	return !c.logicalClassificationHarness
}

func (c *fakeRedisClient) HMGet(ctx context.Context, key string, fields ...string) *goredis.SliceCmd {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if err := c.commandError(ctx); err != nil {
		return goredis.NewSliceResult(nil, err)
	}
	// The conformance-only coupled-clock mode retains a just-expired value long
	// enough for Backend to classify and atomically remove it. Normal fake use
	// applies the independently controlled Redis server's physical expiration.
	if c.expiresBeforeLogicalReadLocked() {
		c.expireLocked(key)
	}
	value := c.values[key]
	result := make([]interface{}, len(fields))
	if value != nil {
		for index, field := range fields {
			if text, exists := value.fields[field]; exists {
				result[index] = text
			}
		}
	}
	return goredis.NewSliceResult(result, nil)
}

func (c *fakeRedisClient) Del(ctx context.Context, keys ...string) *goredis.IntCmd {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if err := c.commandError(ctx); err != nil {
		return goredis.NewIntResult(0, err)
	}
	var deleted int64
	for _, key := range keys {
		c.expireLocked(key)
		if _, exists := c.values[key]; exists {
			delete(c.values, key)
			deleted++
		}
	}
	return goredis.NewIntResult(deleted, nil)
}

func (c *fakeRedisClient) EvalSha(ctx context.Context, _ string, _ []string, _ ...interface{}) *goredis.Cmd {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if err := c.commandError(ctx); err != nil {
		return goredis.NewCmdResult(nil, err)
	}
	return goredis.NewCmdResult(nil, goredis.ErrNoScript)
}

func (c *fakeRedisClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *goredis.Cmd {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if err := c.commandError(ctx); err != nil {
		return goredis.NewCmdResult(nil, err)
	}
	copiedArgs := make([]interface{}, len(args))
	for index, arg := range args {
		if payload, ok := arg.([]byte); ok {
			copiedArgs[index] = append([]byte(nil), payload...)
		} else {
			copiedArgs[index] = arg
		}
	}
	c.evals = append(c.evals, recordedEval{script: script, keys: append([]string(nil), keys...), args: copiedArgs})
	result := c.runScriptLocked(script, keys, args)
	return goredis.NewCmdResult(result, nil)
}

func (c *fakeRedisClient) runScriptLocked(script string, keys []string, args []interface{}) interface{} {
	switch {
	case strings.Contains(script, scriptMarkerFenceNext):
		if c.fences[keys[0]] == math.MaxUint64 {
			return ""
		}
		c.fences[keys[0]]++
		return strconv.FormatUint(c.fences[keys[0]], 10)
	case strings.Contains(script, scriptMarkerCreate):
		if c.expiresBeforeLogicalReadLocked() {
			c.expireLocked(keys[0])
			c.expireLocked(keys[1])
		}
		if c.values[keys[0]] != nil {
			return int64(0)
		}
		delete(c.values, keys[1])
		c.values[keys[0]] = &fakeValue{fields: map[string]string{
			"version": argString(args[0]), "payload": argString(args[1]),
			"generation": argString(args[2]), "last_fence": "0",
		}, expiresAt: c.serverTimeLocked().Add(argDuration(args[3]))}
		return int64(1)
	case strings.Contains(script, scriptMarkerCAS):
		if c.expiresBeforeLogicalReadLocked() {
			c.expireLocked(keys[0])
		}
		current := c.values[keys[0]]
		if current == nil {
			return int64(-1)
		}
		if current.fields["version"] != argString(args[0]) {
			return int64(0)
		}
		current.fields["version"] = argString(args[1])
		current.fields["payload"] = argString(args[2])
		current.expiresAt = c.serverTimeLocked().Add(argDuration(args[3]))
		return int64(1)
	case strings.Contains(script, scriptMarkerDeleteExpired):
		current := c.values[keys[0]]
		if current == nil || current.fields["version"] != argString(args[0]) ||
			current.fields["payload"] != argString(args[1]) ||
			current.fields["generation"] != argString(args[2]) {
			return int64(0)
		}
		delete(c.values, keys[0])
		delete(c.values, keys[1])
		return int64(1)
	case strings.Contains(script, scriptMarkerFlowPut):
		if c.expiresBeforeLogicalReadLocked() {
			c.expireLocked(keys[0])
		}
		if c.values[keys[0]] != nil {
			return int64(0)
		}
		c.values[keys[0]] = &fakeValue{text: argString(args[0]), expiresAt: c.serverTimeLocked().Add(argDuration(args[1]))}
		return int64(1)
	case strings.Contains(script, scriptMarkerFlowConsume):
		if c.expiresBeforeLogicalReadLocked() {
			c.expireLocked(keys[0])
		}
		current := c.values[keys[0]]
		if current == nil {
			return nil
		}
		delete(c.values, keys[0])
		return current.text
	case strings.Contains(script, scriptMarkerLeaseAcquire):
		sessionTTL := c.pttlLocked(keys[0])
		if sessionTTL == -2 || sessionTTL == 0 {
			return int64(-1)
		}
		if sessionTTL < 0 {
			return int64(-2)
		}
		currentSession := c.values[keys[0]]
		if currentSession.fields["generation"] != argString(args[2]) {
			return int64(-5)
		}
		leaseTTL := c.pttlLocked(keys[1])
		if leaseTTL >= 0 {
			return int64(0)
		}
		if leaseTTL != -2 {
			return int64(-2)
		}
		candidate := argString(args[1])
		last := currentSession.fields["last_fence"]
		if !canonicalUint64(candidate) || !canonicalUint64(last) {
			return int64(-2)
		}
		if decimalLessOrEqual(candidate, last) {
			return int64(-4)
		}
		requestedTTL, ok := parseLuaPositiveInteger(argString(args[3]))
		if !ok {
			return int64(-2)
		}
		if sessionTTL < requestedTTL {
			requestedTTL = sessionTTL
		}
		now, ok := c.luaServerMillisecondsLocked()
		if !ok || requestedTTL > maxLuaExactInteger-now {
			return int64(-2)
		}
		c.values[keys[1]] = &fakeValue{fields: map[string]string{
			"owner": argString(args[0]), "fence": candidate,
			"generation": argString(args[2]), "expires_at": strconv.FormatInt(now+requestedTTL, 10),
		}, expiresAt: c.serverTimeLocked().Add(time.Duration(requestedTTL) * time.Millisecond)}
		currentSession.fields["last_fence"] = candidate
		return requestedTTL
	case strings.Contains(script, scriptMarkerLeaseValid):
		if c.validLeaseLocked(keys[0], keys[1], args) {
			return int64(1)
		}
		return int64(0)
	case strings.Contains(script, scriptMarkerLeaseRelease):
		if !c.validLeaseLocked(keys[0], keys[1], args) {
			return int64(0)
		}
		delete(c.values, keys[1])
		return int64(1)
	case strings.Contains(script, scriptMarkerFencedCAS):
		if c.pttlLocked(keys[0]) <= 0 {
			return int64(-1)
		}
		if !c.validLeaseLocked(keys[0], keys[1], args[:3]) {
			return int64(-3)
		}
		current := c.values[keys[0]]
		if current.fields["version"] != argString(args[3]) {
			return int64(0)
		}
		if _, ok := parseLuaPositiveInteger(argString(args[6])); !ok {
			return int64(-2)
		}
		current.fields["version"] = argString(args[4])
		current.fields["payload"] = argString(args[5])
		current.expiresAt = c.serverTimeLocked().Add(argDuration(args[6]))
		delete(c.values, keys[1])
		return int64(1)
	case strings.Contains(script, scriptMarkerFencedDelete):
		if c.pttlLocked(keys[0]) <= 0 {
			return int64(-1)
		}
		if !c.validLeaseLocked(keys[0], keys[1], args[:3]) {
			return int64(-3)
		}
		current := c.values[keys[0]]
		if current.fields["version"] != argString(args[3]) {
			return int64(0)
		}
		delete(c.values, keys[0])
		delete(c.values, keys[1])
		return int64(1)
	default:
		panic("fake received unknown script")
	}
}

func (c *fakeRedisClient) validLeaseLocked(sessionKey, leaseKey string, args []interface{}) bool {
	if len(args) < 3 || c.pttlLocked(sessionKey) <= 0 || c.pttlLocked(leaseKey) <= 0 {
		return false
	}
	sessionValue := c.values[sessionKey]
	value := c.values[leaseKey]
	expiresAt, expiryErr := strconv.ParseInt(value.fields["expires_at"], 10, 64)
	now, nowOK := c.luaServerMillisecondsLocked()
	return expiryErr == nil && expiresAt > 0 && expiresAt <= maxLuaExactInteger && nowOK &&
		sessionValue.fields["generation"] == argString(args[2]) &&
		value.fields["owner"] == argString(args[0]) &&
		value.fields["fence"] == argString(args[1]) &&
		value.fields["generation"] == argString(args[2]) &&
		expiresAt > now
}

func (c *fakeRedisClient) pttlLocked(key string) int64 {
	c.expireLocked(key)
	value := c.values[key]
	if value == nil {
		return -2
	}
	if value.expiresAt.IsZero() {
		return -1
	}
	return value.expiresAt.Sub(c.serverTimeLocked()).Milliseconds()
}

func (c *fakeRedisClient) luaServerMillisecondsLocked() (int64, bool) {
	now := c.serverTimeLocked().UnixMilli()
	return now, now >= 0 && now <= maxLuaExactInteger
}

func (c *fakeRedisClient) expireLocked(key string) {
	value := c.values[key]
	if value != nil && !value.expiresAt.IsZero() && !value.expiresAt.After(c.serverTimeLocked()) {
		delete(c.values, key)
	}
}

func (c *fakeRedisClient) commandError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.err
}

func (c *fakeRedisClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *fakeRedisClient) lastEval(t testing.TB, marker string) recordedEval {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for index := len(c.evals) - 1; index >= 0; index-- {
		if strings.Contains(c.evals[index].script, marker) {
			return c.evals[index]
		}
	}
	t.Fatalf("no EVAL recorded for %s", marker)
	return recordedEval{}
}

func argString(value interface{}) string {
	switch value := value.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	default:
		panic("unexpected fake argument type " + reflect.TypeOf(value).String())
	}
}

func argDuration(value interface{}) time.Duration {
	milliseconds, err := strconv.ParseInt(argString(value), 10, 64)
	if err != nil {
		panic(err)
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func parseLuaPositiveInteger(value string) (int64, bool) {
	if value == "" || value[0] == '0' {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed > 0 && parsed <= maxLuaExactInteger && strconv.FormatInt(parsed, 10) == value
}

func canonicalUint64(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && strconv.FormatUint(parsed, 10) == value
}

func decimalLessOrEqual(left, right string) bool {
	if len(left) != len(right) {
		return len(left) < len(right)
	}
	return left <= right
}

func assertStringSliceEqual(t testing.TB, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %#v, want %#v", got, want)
	}
}

func assertArgStrings(t testing.TB, args []interface{}, index int, want string) {
	t.Helper()
	if index >= len(args) || argString(args[index]) != want {
		t.Fatalf("arg %d = %#v, want %q", index, args, want)
	}
}

var _ goredis.UniversalClient = (*fakeRedisClient)(nil)
