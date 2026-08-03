package redis

import (
	"bytes"
	"context"
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
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session/sessiontest"
)

func TestBackendConformanceAgainstFaithfulStateFake(t *testing.T) {
	sessiontest.Run(t, func(t testing.TB, clock *sessiontest.Clock) session.Backend {
		t.Helper()
		client := newFakeRedisClient(clock.Now)
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
	assertStringSliceEqual(t, create.keys, []string{backend.sessionKey(item.ID)})
	assertArgStrings(t, create.args, 0, "1")
	assertArgStrings(t, create.args, 2, strconv.FormatInt(time.Hour.Milliseconds(), 10))
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
	assertArgStrings(t, acquire.args, 2, strconv.FormatInt(owned.expiresAt.UnixMilli(), 10))
	assertArgStrings(t, acquire.args, 3, "60001")
	assertArgStrings(t, acquire.args, 4, strconv.FormatInt(clock.Now().UnixMilli(), 10))

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
		strconv.FormatInt(owned.expiresAt.UnixMilli(), 10),
		strconv.FormatInt(clock.Now().UnixMilli(), 10),
		"1",
		"2",
	}
	for index, want := range wantCommitArgs {
		assertArgStrings(t, commit.args, index, want)
	}
	if payload, ok := commit.args[6].([]byte); !ok || bytes.Contains(payload, []byte(next.Tokens.AccessToken)) {
		t.Fatal("fenced commit exposed token plaintext")
	}
	assertArgStrings(t, commit.args, 7, strconv.FormatInt(time.Hour.Milliseconds(), 10))
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
				"version": "2",
				"payload": string(replacementPayload),
			},
			expiresAt: time.Now().Add(time.Hour),
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

func TestFenceExhaustionAndRandomFailureInstallNoLease(t *testing.T) {
	t.Run("random failure does not consume fence", func(t *testing.T) {
		clock, client, backend := newBackendFixture(t, io.LimitReader(strings.NewReader("short"), 5))
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
	validationEnd := strings.Index(script, `if redis.call("EXISTS", KEYS[1])`)
	mutation := strings.Index(script, `redis.call("HSET", KEYS[1], "version", ARGV[6]`)
	leaseDelete := strings.Index(script, `redis.pcall("DEL", KEYS[2])`)
	for name, validation := range map[string]string{
		"owner":        `owner ~= ARGV[1]`,
		"fence":        `fence ~= ARGV[2]`,
		"lease expiry": `leaseExpiry ~= ARGV[3]`,
		"version":      `current ~= ARGV[5]`,
	} {
		position := strings.Index(script, validation)
		if position < 0 || position > mutation {
			t.Fatalf("%s was not validated before mutation", name)
		}
	}
	if validationEnd < 0 || mutation < 0 || leaseDelete < mutation {
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
	wants := []string{owned.owner, "1", strconv.FormatInt(owned.expiresAt.UnixMilli(), 10), strconv.FormatInt(clock.Now().UnixMilli(), 10), "1"}
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
	backendValue, err := New(client, validOptions(clock, io.LimitReader(strings.NewReader("random-source-sensitive"), 5)))
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

// fakeRedisClient faithfully models only the commands and script effects used by Backend.
// It deliberately does not interpret arbitrary Lua; real Redis execution belongs to Task 4.
type fakeRedisClient struct {
	goredis.UniversalClient

	mu     sync.Mutex
	now    func() time.Time
	values map[string]*fakeValue
	fences map[string]uint64
	evals  []recordedEval
	calls  int
	err    error
}

type cleanupRaceClient struct {
	*fakeRedisClient
	once                 sync.Once
	beforeExpiredCleanup func()
}

func (c *cleanupRaceClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *goredis.Cmd {
	if strings.Contains(script, scriptMarkerDeleteExpired) {
		c.once.Do(c.beforeExpiredCleanup)
	}
	return c.fakeRedisClient.Eval(ctx, script, keys, args...)
}

func newFakeRedisClient(now func() time.Time) *fakeRedisClient {
	return &fakeRedisClient{now: now, values: make(map[string]*fakeValue), fences: make(map[string]uint64)}
}

func (c *fakeRedisClient) HMGet(ctx context.Context, key string, fields ...string) *goredis.SliceCmd {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if err := c.commandError(ctx); err != nil {
		return goredis.NewSliceResult(nil, err)
	}
	c.expireLocked(key)
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
	for _, key := range keys {
		c.expireLocked(key)
	}
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
		if c.values[keys[0]] != nil {
			return int64(0)
		}
		c.values[keys[0]] = &fakeValue{fields: map[string]string{"version": argString(args[0]), "payload": argString(args[1])}, expiresAt: time.Now().Add(argDuration(args[2]))}
		return int64(1)
	case strings.Contains(script, scriptMarkerCAS):
		current := c.values[keys[0]]
		if current == nil {
			return int64(-1)
		}
		if current.fields["version"] != argString(args[0]) {
			return int64(0)
		}
		current.fields["version"] = argString(args[1])
		current.fields["payload"] = argString(args[2])
		current.expiresAt = time.Now().Add(argDuration(args[3]))
		return int64(1)
	case strings.Contains(script, scriptMarkerDeleteExpired):
		current := c.values[keys[0]]
		if current == nil || current.fields["version"] != argString(args[0]) ||
			current.fields["payload"] != argString(args[1]) {
			return int64(0)
		}
		delete(c.values, keys[0])
		delete(c.values, keys[1])
		return int64(1)
	case strings.Contains(script, scriptMarkerFlowPut):
		if c.values[keys[0]] != nil {
			return int64(0)
		}
		c.values[keys[0]] = &fakeValue{text: argString(args[0]), expiresAt: time.Now().Add(argDuration(args[1]))}
		return int64(1)
	case strings.Contains(script, scriptMarkerFlowConsume):
		current := c.values[keys[0]]
		if current == nil {
			return nil
		}
		delete(c.values, keys[0])
		return current.text
	case strings.Contains(script, scriptMarkerLeaseAcquire):
		if c.values[keys[0]] == nil {
			return int64(-1)
		}
		if current := c.values[keys[1]]; current != nil {
			currentExpiry, expiryErr := strconv.ParseInt(current.fields["expires_at"], 10, 64)
			now, nowErr := strconv.ParseInt(args[4].(string), 10, 64)
			if expiryErr != nil || nowErr != nil {
				return int64(-2)
			}
			if currentExpiry > now {
				return int64(0)
			}
			delete(c.values, keys[1])
		}
		c.values[keys[1]] = &fakeValue{fields: map[string]string{
			"owner": args[0].(string), "fence": args[1].(string), "expires_at": args[2].(string),
		}, expiresAt: time.Now().Add(argDuration(args[3]))}
		return int64(1)
	case strings.Contains(script, scriptMarkerLeaseValid):
		if c.validLeaseLocked(keys[0], args) {
			return int64(1)
		}
		return int64(0)
	case strings.Contains(script, scriptMarkerLeaseRelease):
		if !c.validLeaseLocked(keys[0], args) {
			return int64(0)
		}
		delete(c.values, keys[0])
		return int64(1)
	case strings.Contains(script, scriptMarkerFencedCAS):
		if !c.validLeaseLocked(keys[1], args[:4]) {
			return int64(-3)
		}
		current := c.values[keys[0]]
		if current == nil {
			return int64(-1)
		}
		if current.fields["version"] != args[4].(string) {
			return int64(0)
		}
		current.fields["version"] = args[5].(string)
		current.fields["payload"] = argString(args[6])
		current.expiresAt = time.Now().Add(argDuration(args[7]))
		delete(c.values, keys[1])
		return int64(1)
	case strings.Contains(script, scriptMarkerFencedDelete):
		if !c.validLeaseLocked(keys[1], args[:4]) {
			return int64(-3)
		}
		current := c.values[keys[0]]
		if current == nil {
			return int64(-1)
		}
		if current.fields["version"] != args[4].(string) {
			return int64(0)
		}
		delete(c.values, keys[0])
		delete(c.values, keys[1])
		return int64(1)
	default:
		panic("fake received unknown script")
	}
}

func (c *fakeRedisClient) validLeaseLocked(key string, args []interface{}) bool {
	value := c.values[key]
	if value == nil || len(args) < 4 {
		return false
	}
	expiresAt, expiryErr := strconv.ParseInt(value.fields["expires_at"], 10, 64)
	now, nowErr := strconv.ParseInt(args[3].(string), 10, 64)
	return expiryErr == nil && nowErr == nil &&
		value.fields["owner"] == args[0].(string) &&
		value.fields["fence"] == args[1].(string) &&
		value.fields["expires_at"] == args[2].(string) &&
		expiresAt > now
}

func (c *fakeRedisClient) expireLocked(key string) {
	value := c.values[key]
	if value != nil && !value.expiresAt.IsZero() && !value.expiresAt.After(time.Now()) {
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
