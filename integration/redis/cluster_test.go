package redis_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
	redisadapter "github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session/sessiontest"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestRedisClusterConformance(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	client := newRedisCluster(t)
	sessiontest.Run(t, func(t testing.TB, clock *sessiontest.Clock) session.Backend {
		t.Helper()
		prefix := integrationPrefix(t.Name())
		codec, err := redisadapter.NewAESGCMCodec(redisadapter.Key{
			ID:    "cluster-integration",
			Bytes: bytes.Repeat([]byte{3}, 32),
		}, nil)
		if err != nil {
			t.Fatal("create Redis Cluster codec:", err)
		}
		backend, err := redisadapter.New(client, redisadapter.Options{
			Prefix: prefix,
			Codec:  codec,
			Clock:  clock,
			Random: rand.Reader,
		})
		if err != nil {
			t.Fatal("create Redis Cluster backend:", err)
		}
		return &logicalLeaseBackend{
			Backend: backend,
			prefix:  prefix,
			clock:   clock,
			records: make(map[string]logicalLeaseRecord),
			readIdentity: func(ctx context.Context, key string) (leaseIdentity, error) {
				return readRedisLeaseIdentity(ctx, client, key)
			},
			expireIdentity: func(
				ctx context.Context,
				key string,
				identity leaseIdentity,
			) (bool, error) {
				return expireRedisLeaseIdentity(ctx, client, key, identity)
			},
		}
	})

	t.Run("lease CAS uses one Cluster slot", func(t *testing.T) {
		testClusterLeaseCAS(t, client)
	})
}

func newRedisCluster(t *testing.T) *goredis.ClusterClient {
	t.Helper()
	ctx := t.Context()
	network, err := tcnetwork.New(ctx)
	if err != nil {
		t.Fatal("create Redis Cluster network:", err)
	}
	testcontainers.CleanupNetwork(t, network)

	aliases := []string{"redis-0", "redis-1", "redis-2"}
	containers := make([]testcontainers.Container, 0, len(aliases))
	mappedAddresses := make(map[string]string, len(aliases))
	for _, alias := range aliases {
		container, err := testcontainers.Run(
			ctx,
			"redis:7.4-alpine",
			tcnetwork.WithNetwork([]string{alias}, network),
			testcontainers.WithExposedPorts("6379/tcp"),
			testcontainers.WithCmd(
				"redis-server",
				"--cluster-enabled", "yes",
				"--cluster-config-file", "nodes.conf",
				"--cluster-node-timeout", "5000",
				"--cluster-announce-hostname", alias,
				"--cluster-preferred-endpoint-type", "hostname",
				"--appendonly", "no",
			),
			testcontainers.WithWaitStrategy(
				wait.ForLog("Ready to accept connections").WithStartupTimeout(30*time.Second),
			),
		)
		testcontainers.CleanupContainer(t, container)
		if err != nil {
			t.Fatalf("start Redis Cluster node %s: %v", alias, err)
		}
		host, err := container.Host(ctx)
		if err != nil {
			t.Fatalf("get Redis Cluster node %s host: %v", alias, err)
		}
		port, err := container.MappedPort(ctx, "6379/tcp")
		if err != nil {
			t.Fatalf("get Redis Cluster node %s mapped port: %v", alias, err)
		}
		containers = append(containers, container)
		mappedAddresses[alias+":6379"] = net.JoinHostPort(host, port.Port())
	}

	create := []string{
		"redis-cli", "--cluster", "create",
		"redis-0:6379", "redis-1:6379", "redis-2:6379",
		"--cluster-replicas", "0", "--cluster-yes",
	}
	exitCode, output, err := containers[0].Exec(ctx, create)
	rawOutput, readErr := io.ReadAll(output)
	if err != nil || readErr != nil || exitCode != 0 {
		t.Fatalf(
			"initialize Redis Cluster: exit=%d exec=%v read=%v output=%s",
			exitCode,
			err,
			readErr,
			strings.TrimSpace(string(rawOutput)),
		)
	}
	waitForRedisCluster(t, containers)

	seedAddresses := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		seedAddresses = append(seedAddresses, alias+":6379")
	}
	client := goredis.NewClusterClient(&goredis.ClusterOptions{
		Addrs: seedAddresses,
		MaintNotificationsConfig: &maintnotifications.Config{
			Mode: maintnotifications.ModeDisabled,
		},
		NewClient: func(options *goredis.Options) *goredis.Client {
			translated := *options
			if mapped, ok := mappedAddresses[translated.Addr]; ok {
				translated.Addr = mapped
			}
			node := goredis.NewClient(&translated)
			node.AddHook(rejectLuaHook{})
			return node
		},
	})
	client.AddHook(rejectLuaHook{})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error("close Redis Cluster client:", err)
		}
	})
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("ping Redis Cluster:", err)
	}
	return client
}

func waitForRedisCluster(t *testing.T, containers []testcontainers.Container) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	lastStatus := ""
	for time.Now().Before(deadline) {
		ready := true
		for index, container := range containers {
			exitCode, output, err := container.Exec(t.Context(), []string{"redis-cli", "cluster", "info"})
			rawOutput, readErr := io.ReadAll(output)
			lastStatus = fmt.Sprintf(
				"node=%d exit=%d exec=%v read=%v output=%s",
				index,
				exitCode,
				err,
				readErr,
				strings.TrimSpace(string(rawOutput)),
			)
			if err != nil || readErr != nil || exitCode != 0 ||
				!strings.Contains(string(rawOutput), "cluster_state:ok") ||
				!strings.Contains(string(rawOutput), "cluster_known_nodes:3") {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Redis Cluster did not become ready:", lastStatus)
}

func testClusterLeaseCAS(t *testing.T, client goredis.UniversalClient) {
	t.Helper()
	clock := new(sessiontest.Clock)
	now := time.Now().UTC().Truncate(time.Millisecond)
	clock.Set(now)
	codec, err := redisadapter.NewAESGCMCodec(redisadapter.Key{
		ID:    "cluster-lease-cas",
		Bytes: bytes.Repeat([]byte{4}, 32),
	}, nil)
	if err != nil {
		t.Fatal("create Cluster lease CAS codec:", err)
	}
	backend, err := redisadapter.New(client, redisadapter.Options{
		Prefix: integrationPrefix(t.Name()),
		Codec:  codec,
		Clock:  clock,
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatal("create Cluster lease CAS backend:", err)
	}
	item := &session.Session{
		ID:            "cluster-lease-cas",
		Version:       1,
		CreatedAt:     now,
		UpdatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(time.Minute),
		IdleExpiresAt: now.Add(time.Minute),
	}
	if err := backend.Create(t.Context(), item); err != nil {
		t.Fatal("create Cluster Session:", err)
	}
	lease, err := backend.AcquireRefreshLease(t.Context(), item.ID, 10*time.Second)
	if err != nil {
		t.Fatal("acquire Cluster refresh lease:", err)
	}
	next := *item
	next.Version = 2
	next.UpdatedAt = now.Add(time.Second)
	if err := backend.CompareAndSwapWithLease(t.Context(), lease, item.ID, 1, &next); err != nil {
		t.Fatal("Cluster lease CAS:", err)
	}
	stored, err := backend.Get(t.Context(), item.ID)
	if err != nil {
		t.Fatal("get Cluster Session after lease CAS:", err)
	}
	if stored.Version != 2 {
		t.Fatalf("Cluster Session version = %d, want 2", stored.Version)
	}
	if lease.Valid(t.Context()) {
		t.Fatal("successful Cluster lease CAS left the lease valid")
	}
}

func TestRejectLuaHook(t *testing.T) {
	for _, name := range []string{"eval", "evalsha", "script"} {
		t.Run(name, func(t *testing.T) {
			cmd := goredis.NewCmd(t.Context(), name)
			err := rejectLuaHook{}.ProcessHook(func(context.Context, goredis.Cmder) error {
				return fmt.Errorf("next hook unexpectedly called")
			})(t.Context(), cmd)
			if err == nil || !strings.Contains(err.Error(), "forbidden Redis command") {
				t.Fatalf("%s rejection error = %v", name, err)
			}
		})
	}
}
