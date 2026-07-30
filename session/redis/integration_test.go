package redisstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/sessiontest"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

var integrationSequence atomic.Uint64

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

type integrationFixture struct {
	admin   *goredis.Client
	backend *Backend
}

func TestBackendConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("real Redis integration test")
	}
	for _, image := range integrationImages() {
		t.Run(image, func(t *testing.T) {
			sessiontest.Run(t, func(t *testing.T) session.Backend {
				t.Helper()
				return newIntegrationBackend(t, image)
			})
		})
	}
}

func TestBackendAtomicCreateAndStorageDetails(t *testing.T) {
	if testing.Short() {
		t.Skip("real Redis integration test")
	}
	for _, image := range integrationImages() {
		t.Run(image, func(t *testing.T) {
			t.Run("concurrent create", func(t *testing.T) {
				fixture := newIntegrationFixture(t, image)
				ctx := context.Background()
				item := integrationSession("concurrent-session-secret", time.Now().Add(time.Minute))

				const contenders = 24
				var group sync.WaitGroup
				results := make(chan error, contenders)
				for range contenders {
					group.Add(1)
					go func() {
						defer group.Done()
						results <- fixture.backend.Create(ctx, item)
					}()
				}
				group.Wait()
				close(results)

				var successes, conflicts int
				for err := range results {
					switch {
					case err == nil:
						successes++
					case errors.Is(err, session.ErrVersionConflict):
						conflicts++
					default:
						t.Fatalf("unexpected create result: %v", err)
					}
				}
				if successes != 1 || conflicts != contenders-1 {
					t.Fatalf("successes/conflicts = %d/%d", successes, conflicts)
				}
				stored, err := fixture.backend.Get(ctx, item.ID)
				if err != nil {
					t.Fatal(err)
				}
				if stored.Version != 1 || stored.TokenSet.AccessToken != item.TokenSet.AccessToken {
					t.Fatal("winning session payload or version is invalid")
				}
				assertPositiveTTL(
					t,
					fixture.admin,
					expectedRedisKey(fixture.backend.prefix, "session", item.ID),
				)
			})

			t.Run("direct storage assertions", func(t *testing.T) {
				fixture := newIntegrationFixture(t, image)
				assertDirectRedisStorage(t, fixture)
			})
		})
	}
}

func TestLuaExpiryFailureRollsBackWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("real Redis integration test")
	}
	for _, image := range integrationImages() {
		t.Run(image, func(t *testing.T) {
			fixture := newIntegrationFixture(t, image)
			ctx := context.Background()

			t.Run("create removes new hash", func(t *testing.T) {
				key := fixture.backend.sessionKey("create-expiry-fault")
				payload, err := encodeModel(
					fixture.backend.codec,
					integrationSession("create-expiry-fault", time.Now().Add(time.Minute)),
				)
				if err != nil {
					t.Fatal(err)
				}
				status, err := sessionCreateScript.Run(
					ctx,
					fixture.admin,
					[]string{key},
					"1",
					payload,
					"invalid-milliseconds",
				).Int64()
				if err != nil {
					t.Fatalf("script leaked expiry failure instead of status: %v", err)
				}
				if status != -2 {
					t.Fatalf("status = %d", status)
				}
				if exists, err := fixture.admin.Exists(ctx, key).Result(); err != nil {
					t.Fatal(err)
				} else if exists != 0 {
					t.Fatal("failed create left a persistent Redis key")
				}
			})

			t.Run("cas restores old fields and ttl", func(t *testing.T) {
				key := fixture.backend.sessionKey("cas-expiry-fault")
				oldPayload := []byte("old-encrypted-payload")
				nextPayload := []byte("next-encrypted-payload")
				if err := fixture.admin.HSet(
					ctx,
					key,
					"version",
					"1",
					"payload",
					oldPayload,
				).Err(); err != nil {
					t.Fatal(err)
				}
				if err := fixture.admin.PExpire(ctx, key, time.Minute).Err(); err != nil {
					t.Fatal(err)
				}
				ttlBefore, err := fixture.admin.PTTL(ctx, key).Result()
				if err != nil {
					t.Fatal(err)
				}

				status, err := sessionCompareAndSwapScript.Run(
					ctx,
					fixture.admin,
					[]string{key},
					"1",
					"2",
					nextPayload,
					"invalid-milliseconds",
				).Int64()
				if err != nil {
					t.Fatalf("script leaked expiry failure instead of status: %v", err)
				}
				if status != -2 {
					t.Fatalf("status = %d", status)
				}
				fields, err := fixture.admin.HGetAll(ctx, key).Result()
				if err != nil {
					t.Fatal(err)
				}
				if len(fields) != 2 || fields["version"] != "1" ||
					fields["payload"] != string(oldPayload) {
					t.Fatal("failed CAS exposed updated fields")
				}
				ttlAfter, err := fixture.admin.PTTL(ctx, key).Result()
				if err != nil {
					t.Fatal(err)
				}
				if ttlAfter <= 0 || ttlAfter > ttlBefore {
					t.Fatalf("rollback changed ttl: before=%s after=%s", ttlBefore, ttlAfter)
				}
			})

			t.Run("fenced cas restores old fields and ttl", func(t *testing.T) {
				item := integrationSession("fenced-cas-expiry-fault", time.Now().Add(time.Minute))
				if err := fixture.backend.Create(ctx, item); err != nil {
					t.Fatal(err)
				}
				lock, err := fixture.backend.Lock(ctx, item.ID, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				owned, ok := lock.(*ownedLock)
				if !ok {
					t.Fatalf("lock type = %T", lock)
				}
				key := fixture.backend.sessionKey(item.ID)
				before, err := fixture.admin.HGetAll(ctx, key).Result()
				if err != nil {
					t.Fatal(err)
				}
				ttlBefore, err := fixture.admin.PTTL(ctx, key).Result()
				if err != nil {
					t.Fatal(err)
				}
				next := *item
				next.Version = 2
				next.TokenSet.AccessToken = "next-plaintext-access-token"
				nextPayload, err := encodeModel(fixture.backend.codec, &next)
				if err != nil {
					t.Fatal(err)
				}

				status, err := sessionCompareAndSwapWithLockScript.Run(
					ctx,
					fixture.admin,
					[]string{key, fixture.backend.lockKey(item.ID)},
					owned.token,
					"1",
					"2",
					nextPayload,
					"invalid-milliseconds",
				).Int64()
				if err != nil {
					t.Fatalf("script leaked expiry failure instead of status: %v", err)
				}
				if status != -2 {
					t.Fatalf("status = %d", status)
				}
				after, err := fixture.admin.HGetAll(ctx, key).Result()
				if err != nil {
					t.Fatal(err)
				}
				if before["version"] != after["version"] || before["payload"] != after["payload"] {
					t.Fatal("failed fenced CAS exposed updated fields")
				}
				ttlAfter, err := fixture.admin.PTTL(ctx, key).Result()
				if err != nil {
					t.Fatal(err)
				}
				if ttlAfter <= 0 || ttlAfter > ttlBefore {
					t.Fatalf("rollback changed ttl: before=%s after=%s", ttlBefore, ttlAfter)
				}
				if err := lock.Unlock(ctx); err != nil {
					t.Fatal(err)
				}
			})

			t.Run("acl denial is sanitized and leaves state safe", func(t *testing.T) {
				assertACLDeniedExpiryIsSafe(t, fixture)
			})
		})
	}
}

func integrationImages() []string {
	if image := os.Getenv("IAMCORE_TEST_REDIS_IMAGE"); image != "" {
		return []string{image}
	}
	return []string{"redis:6.2-alpine", "redis:7.4-alpine"}
}

func newIntegrationBackend(t *testing.T, image string) session.Backend {
	t.Helper()
	return newIntegrationFixture(t, image).backend
}

func newIntegrationFixture(t *testing.T, image string) *integrationFixture {
	t.Helper()
	ctx := context.Background()
	container, err := tcredis.Run(ctx, image)
	if err != nil {
		t.Fatalf("start exact Redis image %q: %v", image, err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Errorf("terminate Redis image %q: %v", image, err)
		}
	})

	connectionString, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("resolve Redis test connection for image %q: %v", image, err)
	}
	clientOptions, err := goredis.ParseURL(connectionString)
	if err != nil {
		t.Fatalf("parse Redis test connection for image %q", image)
	}
	client := goredis.NewClient(clientOptions)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close Redis test client: %v", err)
		}
	})
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping Redis image %q: %v", image, err)
	}

	codec, err := session.NewAESGCMCodec(
		session.Key{ID: "integration-primary", Bytes: []byte("0123456789abcdef0123456789abcdef")},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("iamcore-integration-%d", integrationSequence.Add(1))
	backend, err := New(client, Options{
		Prefix: prefix,
		Codec:  codec,
		Clock:  wallClock{},
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &integrationFixture{admin: client, backend: backend}
}

func integrationSession(id string, expiry time.Time) *session.Session {
	return &session.Session{
		ID:      id,
		Version: 1,
		TokenSet: oidc.TokenSet{
			AccessToken:  "plaintext-access-token",
			RefreshToken: "plaintext-refresh-token",
		},
		Identity: oidc.Identity{
			Subject: "plaintext-subject",
		},
		ExpiresAt: expiry,
	}
}

func assertPositiveTTL(t *testing.T, client *goredis.Client, key string) {
	t.Helper()
	ttl, err := client.PTTL(context.Background(), key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 {
		t.Fatalf("key does not have a positive TTL: %s", ttl)
	}
}

func assertDirectRedisStorage(t *testing.T, fixture *integrationFixture) {
	t.Helper()
	ctx := context.Background()
	sessionItem := integrationSession("storage-session-secret", time.Now().Add(time.Minute))
	if err := fixture.backend.Create(ctx, sessionItem); err != nil {
		t.Fatal(err)
	}
	sessionKey := expectedRedisKey(fixture.backend.prefix, "session", sessionItem.ID)
	assertHashedKeysOnly(t, fixture, sessionItem.ID, sessionKey)
	assertPositiveTTL(t, fixture.admin, sessionKey)
	fields, err := fixture.admin.HGetAll(ctx, sessionKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields["version"] != "1" || fields["payload"] == "" {
		t.Fatal("session hash fields are not version plus payload")
	}
	for _, plaintext := range []string{
		sessionItem.ID,
		sessionItem.TokenSet.AccessToken,
		sessionItem.TokenSet.RefreshToken,
		sessionItem.Identity.Subject,
	} {
		if strings.Contains(fields["payload"], plaintext) {
			t.Fatal("session payload exposed plaintext")
		}
	}
	decoded, err := fixture.backend.codec.Decode([]byte(fields["payload"]))
	if err != nil {
		t.Fatal("stored session payload did not decode")
	}
	var roundTrip session.Session
	if err := json.Unmarshal(decoded, &roundTrip); err != nil {
		t.Fatal("decoded session payload was not JSON")
	}
	if roundTrip.ID != sessionItem.ID ||
		roundTrip.TokenSet.AccessToken != sessionItem.TokenSet.AccessToken ||
		roundTrip.Identity.Subject != sessionItem.Identity.Subject {
		t.Fatal("stored session payload did not round-trip")
	}

	flow := &session.Flow{
		ID:        "storage-flow-secret",
		State:     "plaintext-flow-state",
		Nonce:     "plaintext-flow-nonce",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := fixture.backend.PutFlow(ctx, flow); err != nil {
		t.Fatal(err)
	}
	flowKey := expectedRedisKey(fixture.backend.prefix, "flow", flow.ID)
	assertHashedKeysOnly(t, fixture, flow.ID, flowKey)
	assertPositiveTTL(t, fixture.admin, flowKey)
	flowPayload, err := fixture.admin.Get(ctx, flowKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{flow.ID, flow.State, flow.Nonce} {
		if strings.Contains(flowPayload, plaintext) {
			t.Fatal("flow payload exposed plaintext")
		}
	}
	decoded, err = fixture.backend.codec.Decode([]byte(flowPayload))
	if err != nil {
		t.Fatal("stored flow payload did not decode")
	}
	var roundTripFlow session.Flow
	if err := json.Unmarshal(decoded, &roundTripFlow); err != nil ||
		roundTripFlow.ID != flow.ID || roundTripFlow.State != flow.State {
		t.Fatal("stored flow payload did not round-trip")
	}

	lockID := "storage-lock-secret"
	lock, err := fixture.backend.Lock(ctx, lockID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lockKey := expectedRedisKey(fixture.backend.prefix, "lock", lockID)
	assertHashedKeysOnly(t, fixture, lockID, lockKey)
	assertPositiveTTL(t, fixture.admin, lockKey)
	ownership, err := fixture.admin.Get(ctx, lockKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ownership == "" || strings.Contains(ownership, lockID) {
		t.Fatal("lock ownership value is absent or exposes the identifier")
	}
	if !lock.Valid(ctx) {
		t.Fatal("stored lock is not valid")
	}
	if err := lock.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertHashedKeysOnly(
	t *testing.T,
	fixture *integrationFixture,
	rawIdentifier string,
	expectedKey string,
) {
	t.Helper()
	ctx := context.Background()
	exists, err := fixture.admin.Exists(ctx, expectedKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if exists != 1 {
		t.Fatal("expected SHA-256 key does not exist")
	}
	keys, err := fixture.admin.Keys(ctx, fixture.backend.prefix+":*").Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if strings.Contains(key, rawIdentifier) {
			t.Fatal("Redis key exposed a raw identifier")
		}
	}
}

func expectedRedisKey(prefix, kind, rawIdentifier string) string {
	sum := sha256.Sum256([]byte(rawIdentifier))
	digest := hex.EncodeToString(sum[:])
	if kind == "session" || kind == "lock" {
		digest = "{" + digest + "}"
	}
	return prefix + ":" + kind + ":" + digest
}

func assertACLDeniedExpiryIsSafe(t *testing.T, fixture *integrationFixture) {
	t.Helper()
	ctx := context.Background()
	sequence := integrationSequence.Add(1)
	username := fmt.Sprintf("iamcore-fault-%d", sequence)
	password := fmt.Sprintf("integration-password-%d", sequence)
	prefix := fmt.Sprintf("iamcore-acl-%d", sequence)
	if err := fixture.admin.Do(
		ctx,
		"ACL",
		"SETUSER",
		username,
		"on",
		">"+password,
		"~"+prefix+":*",
		"+eval",
		"+evalsha",
		"+exists",
		"+hset",
		"+hget",
		"+del",
		"-pexpire",
	).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.admin.Do(context.Background(), "ACL", "DELUSER", username).Err(); err != nil {
			t.Errorf("delete integration ACL user: %v", err)
		}
	})
	restricted := goredis.NewClient(&goredis.Options{
		Addr:     fixture.admin.Options().Addr,
		Username: username,
		Password: password,
	})
	t.Cleanup(func() { _ = restricted.Close() })
	backend, err := New(restricted, Options{
		Prefix: prefix,
		Codec:  fixture.backend.codec,
		Clock:  wallClock{},
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}

	item := integrationSession("acl-create-secret", time.Now().Add(time.Minute))
	err = backend.Create(ctx, item)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("create ACL failure was not sanitized: %v", err)
	}
	if exists, err := fixture.admin.Exists(ctx, backend.sessionKey(item.ID)).Result(); err != nil {
		t.Fatal(err)
	} else if exists != 0 {
		t.Fatal("ACL-denied create left a persistent key")
	}

	casItem := integrationSession("acl-cas-secret", time.Now().Add(time.Minute))
	adminBackend, err := New(fixture.admin, Options{
		Prefix: prefix,
		Codec:  fixture.backend.codec,
		Clock:  wallClock{},
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adminBackend.Create(ctx, casItem); err != nil {
		t.Fatal(err)
	}
	key := adminBackend.sessionKey(casItem.ID)
	before, err := fixture.admin.HGetAll(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	ttlBefore, err := fixture.admin.PTTL(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	next := *casItem
	next.Version = 2
	next.TokenSet.AccessToken = "next-plaintext-access-token"
	err = backend.CompareAndSwap(ctx, casItem.ID, 1, &next)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("CAS ACL failure was not sanitized: %v", err)
	}
	after, err := fixture.admin.HGetAll(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if before["version"] != after["version"] || before["payload"] != after["payload"] {
		t.Fatal("ACL-denied CAS exposed updated fields")
	}
	ttlAfter, err := fixture.admin.PTTL(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttlAfter <= 0 || ttlAfter > ttlBefore {
		t.Fatalf("ACL-denied CAS changed ttl: before=%s after=%s", ttlBefore, ttlAfter)
	}
}
