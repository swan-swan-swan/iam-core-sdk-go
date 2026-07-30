package redisstore

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/sessiontest"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

var integrationSequence atomic.Uint64

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

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

func integrationImages() []string {
	if image := os.Getenv("IAMCORE_TEST_REDIS_IMAGE"); image != "" {
		return []string{image}
	}
	return []string{"redis:6.2-alpine", "redis:7.4-alpine"}
}

func newIntegrationBackend(t *testing.T, image string) session.Backend {
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
	return backend
}
