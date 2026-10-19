package httpcatalog_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpcatalog"
)

const heartbeatHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRegistryHeartbeatUsesCurrentHashAndFreshToken(t *testing.T) {
	var calls atomic.Int32
	var tokens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/http-resource-catalog/registration" {
			_, _ = w.Write([]byte(`{"code":0,"data":{"application":"beacon","catalog_hash":"` + heartbeatHash + `"}}`))
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/http-resource-catalog/registration/heartbeat" || r.Header.Get("Authorization") != "Bearer token-2" {
			t.Errorf("unexpected heartbeat request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body["catalog_hash"] != heartbeatHash {
			t.Errorf("heartbeat body = %#v error=%v", body, err)
		}
		calls.Add(1)
		_, _ = w.Write([]byte(`{"code":0,"data":{"application":"beacon","catalog_hash":"` + heartbeatHash + `"}}`))
	}))
	defer server.Close()
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify", Release: "test", Tokens: core.TokenSourceFunc(func(context.Context) (string, error) {
		return "token-" + string(rune('0'+tokens.Add(1))), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notify", "notify.item.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := registry.HeartbeatOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || tokens.Load() != 2 {
		t.Fatalf("calls=%d tokens=%d", calls.Load(), tokens.Load())
	}
}

func TestRegistrySyncRejectsManifestChangedDuringRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseResponse
		_, _ = w.Write([]byte(`{"code":0,"data":{"application":"beacon","catalog_hash":"` + heartbeatHash + `"}}`))
	}))
	defer server.Close()
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify", Release: "test", Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notify", "notify.item.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, syncErr := registry.Sync(t.Context()); done <- syncErr }()
	<-requestStarted
	if err := registry.Register(catalogSpec(t, "/api/v1/new", "notify.item.create", "beacon:notify:create")); err != nil {
		t.Fatal(err)
	}
	close(releaseResponse)
	if err := <-done; err == nil || registry.Check(t.Context()) == nil {
		t.Fatalf("stale Sync result must fail and keep registry unhealthy: err=%v health=%v", err, registry.Check(t.Context()))
	}
}

func TestRegistryHeartbeatConflictResyncsCompleteManifest(t *testing.T) {
	var syncs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			syncs.Add(1)
			var body httpcatalog.Manifest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Routes) != 1 {
				t.Errorf("manifest = %#v err=%v", body, err)
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"application":"beacon","catalog_hash":"` + heartbeatHash + `"}}`))
			return
		}
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify", Release: "test", Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notify", "notify.item.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := registry.HeartbeatOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if syncs.Load() != 2 {
		t.Fatalf("syncs=%d want 2", syncs.Load())
	}
}

func TestRegistryRunHeartbeatStopsWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{"application":"beacon","catalog_hash":"` + heartbeatHash + `"}}`))
	}))
	defer server.Close()
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify", Release: "test", HeartbeatInterval: time.Millisecond, Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notify", "notify.item.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := registry.RunHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryRunHeartbeatRetriesTransientFailureAndRestoresHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var heartbeats atomic.Int32
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if heartbeats.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			defer close(done)
		}
		_, _ = w.Write([]byte(`{"code":0,"data":{"application":"beacon","catalog_hash":"` + heartbeatHash + `"}}`))
	}))
	defer server.Close()
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify", Release: "test", HeartbeatInterval: 50 * time.Millisecond, HeartbeatRetryDelay: time.Millisecond, Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notify", "notify.item.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { <-done; time.Sleep(5 * time.Millisecond); cancel() }()
	if err := registry.RunHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if heartbeats.Load() != 2 || registry.Check(t.Context()) != nil {
		t.Fatalf("heartbeats=%d health=%v", heartbeats.Load(), registry.Check(t.Context()))
	}
}
