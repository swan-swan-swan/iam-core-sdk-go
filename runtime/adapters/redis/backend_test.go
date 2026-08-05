package redis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
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
		backend, err := New(client, validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{1}, 8192))))
		if err != nil {
			t.Fatal(err)
		}
		return backend
	})
}

func TestBackendUsesNoLuaCommands(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{41}, 512)))
	ctx := context.Background()
	item := testSession("no-lua-session", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	flow := &session.Flow{ID: "no-lua-flow", ExpiresAt: clock.Now().Add(time.Minute)}
	if err := backend.PutFlow(ctx, flow); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.ConsumeFlow(ctx, flow.ID); err != nil {
		t.Fatal(err)
	}
	leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaseValue.Release(ctx); err != nil {
		t.Fatal(err)
	}
	for _, command := range client.recordedCommands() {
		switch command.name {
		case "eval", "evalsha", "script":
			t.Fatalf("backend issued forbidden command %q", command.name)
		}
	}
}

func TestNativeFlowUsesSetNXAndOneGetDel(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{42}, 128)))
	ctx := context.Background()
	flow := &session.Flow{ID: "native-flow", State: "state", ExpiresAt: clock.Now().Add(1500*time.Millisecond + time.Nanosecond)}
	if err := backend.PutFlow(ctx, flow); err != nil {
		t.Fatal(err)
	}
	if err := backend.PutFlow(ctx, flow); !errors.Is(err, session.ErrConflict) {
		t.Fatalf("duplicate PutFlow error = %v", err)
	}
	if _, err := backend.ConsumeFlow(ctx, flow.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.ConsumeFlow(ctx, flow.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("second consume error = %v", err)
	}
	commands := client.recordedCommands()
	var sets, getdels int
	for _, command := range commands {
		switch command.name {
		case "set":
			sets++
			if len(command.args) != 6 || commandText(command.args[1]) != backend.flowKey(flow.ID) ||
				strings.ToLower(commandText(command.args[3])) != "px" || commandText(command.args[4]) != "1501" ||
				strings.ToLower(commandText(command.args[5])) != "nx" {
				t.Fatalf("SET args = %#v", command.args)
			}
		case "getdel":
			getdels++
		}
	}
	if sets != 2 || getdels != 2 {
		t.Fatalf("SET count = %d, GETDEL count = %d", sets, getdels)
	}
}

func TestNativeSessionCreateCASExpiryAndWatchAbort(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{43}, 512)))
	ctx := context.Background()
	current := testSession("native-session", clock.Now())
	if err := backend.Create(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := backend.Create(ctx, current); !errors.Is(err, session.ErrConflict) {
		t.Fatalf("duplicate Create error = %v", err)
	}

	replacement := testSession(current.ID, clock.Now())
	replacement.Version = 2
	replacement.Tokens.AccessToken = "replacement"
	client.setBeforeExec(func(values map[string]*fakeValue) {
		values[backend.sessionKey(current.ID)].fields["last_fence"] = "1"
	})
	if err := backend.CompareAndSwap(ctx, current.ID, 1, replacement); !errors.Is(err, session.ErrConflict) {
		t.Fatalf("watch abort error = %v", err)
	}
	stored, err := backend.Get(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != 1 || stored.Tokens.AccessToken != current.Tokens.AccessToken {
		t.Fatal("WATCH abort partially updated the Session")
	}
	if err := backend.CompareAndSwap(ctx, current.ID, 1, replacement); err != nil {
		t.Fatal(err)
	}
	stored, err = backend.Get(ctx, current.ID)
	if err != nil || stored.Version != 2 || stored.Tokens.AccessToken != "replacement" {
		t.Fatal("normal CAS did not install the replacement")
	}

	clock.Set(replacement.IdleExpiresAt)
	if _, err := backend.Get(ctx, current.ID); !errors.Is(err, session.ErrExpired) {
		t.Fatalf("expired Get error = %v", err)
	}
	if _, err := backend.Get(ctx, current.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("post-cleanup Get error = %v", err)
	}
}

func TestNativeLeaseAcquisitionFencingAndServerPTTL(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{44}, 2048)))
	ctx := context.Background()
	item := testSession("native-lease", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	owned := leaseValue.(*refreshLease)
	if owned.fence != 1 {
		t.Fatalf("first fence = %d", owned.fence)
	}
	if contender, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute); contender != nil || !errors.Is(err, session.ErrConflict) {
		t.Fatalf("contending acquire = %v, %v", contender, err)
	}
	client.advanceServer(30 * time.Minute)
	clock.Advance(2 * time.Hour)
	if !leaseValue.Valid(ctx) {
		t.Fatal("lease validity did not use server PTTL")
	}
	client.mu.Lock()
	leaseTTL := client.pttlLocked(backend.leaseKey(item.ID))
	sessionTTL := client.pttlLocked(backend.sessionKey(item.ID))
	client.mu.Unlock()
	if leaseTTL <= 0 || leaseTTL > sessionTTL {
		t.Fatalf("lease PTTL = %s, session PTTL = %s", leaseTTL, sessionTTL)
	}
	clock.Set(item.CreatedAt)
	if err := leaseValue.Release(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if second.(*refreshLease).fence != 2 {
		t.Fatalf("second fence = %d", second.(*refreshLease).fence)
	}
	if err := leaseValue.Release(ctx); !errors.Is(err, session.ErrLeaseLost) {
		t.Fatalf("stale release error = %v", err)
	}
	if !second.Valid(ctx) {
		t.Fatal("stale release invalidated current lease")
	}
	if err := second.Release(ctx); err != nil {
		t.Fatal(err)
	}
	other := testSession("native-lease-other", clock.Now())
	if err := backend.Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	otherLease, err := backend.AcquireRefreshLease(ctx, other.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if otherLease.(*refreshLease).fence != 1 {
		t.Fatalf("first per-Session fence = %d", otherLease.(*refreshLease).fence)
	}
	client.advanceServer(time.Minute)
	if otherLease.Valid(ctx) {
		t.Fatal("lease remained valid after its server PTTL elapsed")
	}
}

func TestNativeLeaseRejectsStaleCredentialsAndFencesMutations(t *testing.T) {
	for _, operation := range []string{"cas", "delete"} {
		t.Run(operation, func(t *testing.T) {
			clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{45}, 1024)))
			ctx := context.Background()
			item := testSession("fenced-"+operation, clock.Now())
			if err := backend.Create(ctx, item); err != nil {
				t.Fatal(err)
			}
			leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			owned := leaseValue.(*refreshLease)
			client.mu.Lock()
			client.values[backend.leaseKey(item.ID)].fields["owner"] = "different-owner"
			client.mu.Unlock()
			next := testSession(item.ID, clock.Now())
			next.Version = 2
			if operation == "cas" {
				err = backend.CompareAndSwapWithLease(ctx, leaseValue, item.ID, 1, next)
			} else {
				err = backend.DeleteWithLease(ctx, leaseValue, item.ID, 1)
			}
			if !errors.Is(err, session.ErrLeaseLost) {
				t.Fatalf("stale credential error = %v", err)
			}
			stored, getErr := backend.Get(ctx, item.ID)
			if getErr != nil || stored.Version != 1 {
				t.Fatal("stale lease changed the Session")
			}

			client.mu.Lock()
			client.values[backend.leaseKey(item.ID)].fields["owner"] = owned.owner
			client.mu.Unlock()
			if operation == "cas" {
				err = backend.CompareAndSwapWithLease(ctx, leaseValue, item.ID, 1, next)
			} else {
				err = backend.DeleteWithLease(ctx, leaseValue, item.ID, 1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if leaseValue.Valid(ctx) {
				t.Fatal("successful fenced mutation left lease valid")
			}
			if err := leaseValue.Release(ctx); err != nil {
				t.Fatal("first acknowledgement failed")
			}
		})
	}
}

func TestNativeLeaseRejectsStaleOwnerGenerationAndFence(t *testing.T) {
	for _, field := range []string{"owner", "generation", "fence"} {
		t.Run(field, func(t *testing.T) {
			clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{48}, 512)))
			ctx := context.Background()
			item := testSession("stale-"+field, clock.Now())
			if err := backend.Create(ctx, item); err != nil {
				t.Fatal(err)
			}
			leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			client.mu.Lock()
			client.values[backend.leaseKey(item.ID)].fields[field] = "stale"
			client.mu.Unlock()
			if leaseValue.Valid(ctx) {
				t.Fatalf("lease with stale %s remained valid", field)
			}
			if err := leaseValue.Release(ctx); !errors.Is(err, session.ErrLeaseLost) {
				t.Fatalf("stale %s release error = %v", field, err)
			}
		})
	}
}

func TestNativeLeaseFenceExhaustionInstallsNoLease(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{46}, 512)))
	ctx := context.Background()
	item := testSession("fence-exhaustion", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	client.values[backend.sessionKey(item.ID)].fields["last_fence"] = strconv.FormatUint(math.MaxUint64, 10)
	client.mu.Unlock()
	if leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute); leaseValue != nil || !errors.Is(err, ErrFenceExhausted) {
		t.Fatalf("exhausted acquire = %v, %v", leaseValue, err)
	}
	client.mu.Lock()
	_, installed := client.values[backend.leaseKey(item.ID)]
	client.mu.Unlock()
	if installed {
		t.Fatal("fence exhaustion installed a lease")
	}
}

func TestNativeLeaseAcquireAcceptsGoRedisMissingPTTLSentinel(t *testing.T) {
	clock, _, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{49}, 512)))
	ctx := context.Background()
	item := testSession("missing-pttl-sentinel", clock.Now())
	if err := backend.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	leaseValue, err := backend.AcquireRefreshLease(ctx, item.ID, time.Minute)
	if err != nil {
		t.Fatalf("first acquire with go-redis PTTL -2ns sentinel: %v", err)
	}
	if leaseValue == nil || !leaseValue.Valid(ctx) {
		t.Fatal("first acquire did not install a valid lease")
	}
}

func TestKeysAreNamespacedDigestsAndClusterCompatible(t *testing.T) {
	backend := &Backend{prefix: "tenant:iam"}
	raw := "raw-session-secret"
	sessionKey := backend.sessionKey(raw)
	flowKey := backend.flowKey(raw)
	leaseKey := backend.leaseKey(raw)
	for kind, key := range map[string]string{"session": sessionKey, "flow": flowKey, "lease": leaseKey} {
		if strings.Contains(key, raw) {
			t.Fatalf("%s key exposed raw identifier", kind)
		}
	}
	if sessionKey == flowKey || sessionKey == leaseKey || flowKey == leaseKey {
		t.Fatal("Redis namespaces collided")
	}
	sessionTag := sessionKey[strings.IndexByte(sessionKey, '{'):]
	leaseTag := leaseKey[strings.IndexByte(leaseKey, '{'):]
	if sessionTag != leaseTag {
		t.Fatal("Session and Lease keys do not share a Cluster hash tag")
	}
}

func TestNewRejectsInvalidDependenciesAndPrefixes(t *testing.T) {
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	valid := validOptions(clock, bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	var typedNilClient *fakeRedisClient
	tests := []struct {
		client goredis.UniversalClient
		opts   Options
	}{
		{nil, valid}, {typedNilClient, valid}, {client, withPrefix(valid, "")},
		{client, withPrefix(valid, "bad{prefix")}, {client, withCodec(valid, nil)},
		{client, withClock(valid, nil)}, {client, withRandom(valid, nil)},
	}
	for _, test := range tests {
		if backend, err := New(test.client, test.opts); backend != nil || !errors.Is(err, ErrInvalidOptions) {
			t.Fatal("invalid options returned the wrong result")
		}
	}
}

func TestNativeBackendErrorsAreTypedAndSanitized(t *testing.T) {
	clock, client, backend := newBackendFixture(t, bytes.NewReader(bytes.Repeat([]byte{47}, 128)))
	client.setError(errors.New("redis-sensitive-detail"))
	if _, err := backend.Get(context.Background(), "id"); !errors.Is(err, ErrBackendUnavailable) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("Get error = %v", err)
	}
	client.setError(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := backend.Create(ctx, testSession("canceled", clock.Now())); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Create error = %v", err)
	}
}

func newBackendFixture(t testing.TB, random io.Reader) (*sessiontest.Clock, *fakeRedisClient, *Backend) {
	t.Helper()
	clock := newSessionClock()
	client := newFakeRedisClient(clock.Now)
	backendValue, err := New(client, validOptions(clock, random))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return clock, client, backendValue.(*Backend)
}

func validOptions(clock *sessiontest.Clock, random io.Reader) Options {
	codec, err := NewAESGCMCodec(Key{ID: "test", Bytes: bytes.Repeat([]byte{42}, 32)}, nil)
	if err != nil {
		panic(err)
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
		ID: id, Version: 1,
		Tokens:        session.TokenSet{AccessToken: "access-secret", RefreshToken: "refresh-secret", GrantedScopes: []string{"openid"}},
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

type fakeValue struct {
	text      string
	fields    map[string]string
	expiresAt time.Time
}

type recordedCommand struct {
	name string
	args []interface{}
}

type fakeRedisClient struct {
	*goredis.Client

	mu                           sync.Mutex
	watchMu                      sync.Mutex
	appNow                       func() time.Time
	serverNow                    time.Time
	serverOffset                 time.Duration
	serverFixed                  bool
	logicalClassificationHarness bool
	values                       map[string]*fakeValue
	commands                     []recordedCommand
	err                          error
	beforeExec                   func(map[string]*fakeValue)
}

func newFakeRedisClient(now func() time.Time) *fakeRedisClient {
	c := &fakeRedisClient{
		appNow: now, serverNow: now(), serverFixed: true,
		values: make(map[string]*fakeValue),
	}
	client := goredis.NewClient(&goredis.Options{
		Addr:       "fake.invalid:6379",
		MaxRetries: -1,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("fake Redis hook unexpectedly dialed")
		},
	})
	c.Client = client
	client.AddHook((*fakeRedisHook)(c))
	return c
}

func (c *fakeRedisClient) Watch(ctx context.Context, fn func(*goredis.Tx) error, keys ...string) error {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()
	return c.Client.Watch(ctx, fn, keys...)
}

func (c *fakeRedisClient) enableLogicalClassificationHarness() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serverFixed = false
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

func (c *fakeRedisClient) serverTimeLocked() time.Time {
	if c.serverFixed {
		return c.serverNow
	}
	return c.appNow().Add(c.serverOffset)
}

func (c *fakeRedisClient) setBeforeExec(fn func(map[string]*fakeValue)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beforeExec = fn
}

func (c *fakeRedisClient) setError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *fakeRedisClient) recordedCommands() []recordedCommand {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]recordedCommand, len(c.commands))
	copy(result, c.commands)
	return result
}

type fakeRedisHook fakeRedisClient

func (c *fakeRedisHook) DialHook(next goredis.DialHook) goredis.DialHook { return next }

func (c *fakeRedisHook) ProcessHook(_ goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		client := (*fakeRedisClient)(c)
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.executeLocked(ctx, cmd)
	}
}

func (c *fakeRedisHook) ProcessPipelineHook(_ goredis.ProcessPipelineHook) goredis.ProcessPipelineHook {
	return func(ctx context.Context, commands []goredis.Cmder) error {
		client := (*fakeRedisClient)(c)
		client.mu.Lock()
		defer client.mu.Unlock()
		for _, command := range commands {
			client.recordLocked(command)
		}
		if client.err != nil {
			return client.err
		}
		if client.beforeExec != nil && len(commands) >= 2 && commands[0].Name() == "multi" {
			before := client.beforeExec
			client.beforeExec = nil
			before(client.values)
			return goredis.TxFailedErr
		}
		for _, command := range commands {
			if command.Name() == "multi" {
				command.(*goredis.StatusCmd).SetVal("OK")
				continue
			}
			if command.Name() == "exec" {
				command.(*goredis.SliceCmd).SetVal([]interface{}{})
				continue
			}
			if err := client.applyLocked(ctx, command); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *fakeRedisClient) executeLocked(ctx context.Context, cmd goredis.Cmder) error {
	c.recordLocked(cmd)
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.err != nil {
		return c.err
	}
	return c.applyLocked(ctx, cmd)
}

func (c *fakeRedisClient) recordLocked(cmd goredis.Cmder) {
	args := cmd.Args()
	copied := make([]interface{}, len(args))
	for index, arg := range args {
		if value, ok := arg.([]byte); ok {
			copied[index] = append([]byte(nil), value...)
		} else {
			copied[index] = arg
		}
	}
	c.commands = append(c.commands, recordedCommand{name: strings.ToLower(cmd.Name()), args: copied})
}

func (c *fakeRedisClient) applyLocked(_ context.Context, cmd goredis.Cmder) error {
	name := strings.ToLower(cmd.Name())
	args := cmd.Args()
	if name == "eval" || name == "evalsha" || name == "script" {
		return fmt.Errorf("forbidden scripting command: %s", name)
	}
	switch name {
	case "watch", "unwatch":
		cmd.(*goredis.StatusCmd).SetVal("OK")
		return nil
	case "set":
		key := commandText(args[1])
		c.expireLocked(key)
		nx := false
		ttl := time.Duration(0)
		for index := 3; index < len(args); index++ {
			switch strings.ToLower(commandText(args[index])) {
			case "nx":
				nx = true
			case "px":
				index++
				ttl = parseCommandInt(args[index]) * time.Millisecond
			case "ex":
				index++
				ttl = parseCommandInt(args[index]) * time.Second
			}
		}
		if nx && c.values[key] != nil {
			return goredis.Nil
		}
		c.values[key] = &fakeValue{text: commandText(args[2]), expiresAt: c.serverTimeLocked().Add(ttl)}
		cmd.(*goredis.StatusCmd).SetVal("OK")
		return nil
	case "getdel":
		key := commandText(args[1])
		if !c.logicalClassificationHarness {
			c.expireLocked(key)
		}
		value := c.values[key]
		if value == nil {
			return goredis.Nil
		}
		delete(c.values, key)
		cmd.(*goredis.StringCmd).SetVal(value.text)
		return nil
	case "hmget":
		key := commandText(args[1])
		if !c.logicalClassificationHarness {
			c.expireLocked(key)
		}
		value := c.values[key]
		result := make([]interface{}, len(args)-2)
		if value != nil {
			for index := 2; index < len(args); index++ {
				if field, ok := value.fields[commandText(args[index])]; ok {
					result[index-2] = field
				}
			}
		}
		cmd.(*goredis.SliceCmd).SetVal(result)
		return nil
	case "pttl":
		cmd.(*goredis.DurationCmd).SetVal(c.pttlLocked(commandText(args[1])))
		return nil
	case "hset":
		key := commandText(args[1])
		c.expireLocked(key)
		value := c.values[key]
		if value == nil {
			value = &fakeValue{fields: make(map[string]string)}
			c.values[key] = value
		}
		if value.fields == nil {
			value.fields = make(map[string]string)
		}
		var added int64
		for index := 2; index+1 < len(args); index += 2 {
			field := commandText(args[index])
			if _, exists := value.fields[field]; !exists {
				added++
			}
			value.fields[field] = commandText(args[index+1])
		}
		cmd.(*goredis.IntCmd).SetVal(added)
		return nil
	case "pexpire":
		key := commandText(args[1])
		c.expireLocked(key)
		value := c.values[key]
		if value == nil {
			cmd.(*goredis.BoolCmd).SetVal(false)
			return nil
		}
		value.expiresAt = c.serverTimeLocked().Add(parseCommandInt(args[2]) * time.Millisecond)
		cmd.(*goredis.BoolCmd).SetVal(true)
		return nil
	case "del":
		var deleted int64
		for _, arg := range args[1:] {
			key := commandText(arg)
			c.expireLocked(key)
			if _, exists := c.values[key]; exists {
				delete(c.values, key)
				deleted++
			}
		}
		cmd.(*goredis.IntCmd).SetVal(deleted)
		return nil
	default:
		return fmt.Errorf("fake Redis received unsupported command %q", name)
	}
}

func (c *fakeRedisClient) pttlLocked(key string) time.Duration {
	c.expireLocked(key)
	value := c.values[key]
	if value == nil {
		return time.Duration(-2)
	}
	if value.expiresAt.IsZero() {
		return time.Duration(-1)
	}
	remaining := value.expiresAt.Sub(c.serverTimeLocked())
	return time.Duration(remaining.Milliseconds()) * time.Millisecond
}

func (c *fakeRedisClient) expireLocked(key string) {
	value := c.values[key]
	if value != nil && !value.expiresAt.IsZero() && !value.expiresAt.After(c.serverTimeLocked()) {
		delete(c.values, key)
	}
}

func commandText(value interface{}) string {
	switch value := value.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return fmt.Sprint(value)
	}
}

func parseCommandInt(value interface{}) time.Duration {
	parsed, err := strconv.ParseInt(commandText(value), 10, 64)
	if err != nil {
		panic(err)
	}
	return time.Duration(parsed)
}

var _ goredis.UniversalClient = (*fakeRedisClient)(nil)
var _ goredis.Hook = (*fakeRedisHook)(nil)
