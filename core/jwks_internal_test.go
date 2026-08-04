package core

import (
	"context"
	"errors"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestRemoteKeysReturnsInstalledCacheWhenRefreshIsThrottled(t *testing.T) {
	installed := []jose.JSONWebKey{{KeyID: "rotated"}}
	set := &keySet{
		keys:            installed,
		clock:           fixedJWKSClock{now: time.Unix(100, 0)},
		refreshInterval: time.Hour,
		lastRefresh:     time.Unix(100, 0),
		hasRefreshed:    true,
	}

	got, err := set.remoteKeys(context.Background())
	if err != nil {
		t.Fatalf("remoteKeys() error = %v", err)
	}
	if len(got) != 1 || got[0].KeyID != "rotated" {
		t.Fatalf("remoteKeys() = %#v", got)
	}
	got[0].KeyID = "mutated"
	if set.keys[0].KeyID != "rotated" {
		t.Fatal("remoteKeys() returned aliased cache")
	}
}

type fixedJWKSClock struct{ now time.Time }

func (clock fixedJWKSClock) Now() time.Time { return clock.now }

func TestRemoteKeysPrioritizesCallerCancellationOverCompletedFetch(t *testing.T) {
	for range 100 {
		completed := &jwksInflight{done: make(chan struct{}), keys: []jose.JSONWebKey{{KeyID: "test-key"}}}
		close(completed.done)
		set := &keySet{inflight: completed}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := set.remoteKeys(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("remoteKeys() error = %v, want context.Canceled", err)
		}
	}
}
