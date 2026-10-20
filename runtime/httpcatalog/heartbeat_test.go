package httpcatalog_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpcatalog"
)

const heartbeatHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func serverManifestHash(t *testing.T, manifest httpcatalog.Manifest) string {
	t.Helper()
	routes := append([]httpcatalog.Route(nil), manifest.Routes...)
	sort.Slice(routes, func(i, j int) bool { return routes[i].Name < routes[j].Name })
	input := struct {
		SchemaVersion string              `json:"schema_version"`
		Application   string              `json:"application"`
		Service       string              `json:"service"`
		Routes        []httpcatalog.Route `json:"routes"`
	}{manifest.SchemaVersion, manifest.Application, manifest.Service, routes}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func writeSyncSuccess(t *testing.T, w http.ResponseWriter, r *http.Request, catalogHash string) {
	t.Helper()
	var manifest httpcatalog.Manifest
	if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
		t.Error(err)
		return
	}
	_, _ = fmt.Fprintf(w, `{"code":0,"data":{"application":%q,"catalog_hash":%q,"deployment_generation":0,"manifest_hash":%q,"changed":true}}`, manifest.Application, catalogHash, serverManifestHash(t, manifest))
}

func writeHeartbeatSuccess(t *testing.T, w http.ResponseWriter, body map[string]any, catalogHash string) {
	t.Helper()
	_, _ = fmt.Fprintf(w, `{"code":0,"data":{"application":"beacon","catalog_hash":%q,"deployment_generation":0,"manifest_hash":%q,"changed":false,"heartbeat_at":"2026-10-20T00:00:00Z"}}`, catalogHash, body["manifest_hash"])
}

func TestRegistryHeartbeatUsesCurrentHashAndFreshToken(t *testing.T) {
	var calls atomic.Int32
	var tokens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/http-resource-catalog/registration" {
			writeSyncSuccess(t, w, r, heartbeatHash)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/http-resource-catalog/registration/heartbeat" || r.Header.Get("Authorization") != "Bearer token-2" {
			t.Errorf("unexpected heartbeat request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 3 || body["catalog_hash"] != heartbeatHash || body["deployment_generation"] != float64(0) || body["manifest_hash"] == "" {
			t.Errorf("heartbeat body = %#v error=%v", body, err)
		}
		calls.Add(1)
		writeHeartbeatSuccess(t, w, body, heartbeatHash)
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
		writeSyncSuccess(t, w, r, heartbeatHash)
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

func TestRegistryHeartbeatConflictDoesNotResyncCompleteManifest(t *testing.T) {
	var syncs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			syncs.Add(1)
			writeSyncSuccess(t, w, r, heartbeatHash)
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":40901,"message":"catalog_generation_conflict","data":{"reason_code":"catalog_generation_conflict"}}`))
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
	if err := registry.HeartbeatOnce(t.Context()); err == nil || registry.Check(t.Context()) == nil {
		t.Fatalf("old replica must be unhealthy: err=%v health=%v", err, registry.Check(t.Context()))
	}
	if syncs.Load() != 1 {
		t.Fatalf("syncs=%d want 1", syncs.Load())
	}
}

func TestRegistryHeartbeatConflictNeverAcceptsNewCatalogHash(t *testing.T) {
	const newerHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	var syncs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			hash := heartbeatHash
			if syncs.Add(1) == 2 {
				hash = newerHash
			}
			writeSyncSuccess(t, w, r, hash)
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":40901,"data":{"reason_code":"catalog_generation_conflict"}}`))
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
	if err := registry.HeartbeatOnce(t.Context()); err == nil {
		t.Fatal("conflicting heartbeat accepted")
	}
	if err := registry.Check(t.Context()); err == nil || syncs.Load() != 1 {
		t.Fatalf("conflict retained health or resynced: health=%v syncs=%d", err, syncs.Load())
	}
}

func TestRegistryRunHeartbeatStopsWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSyncSuccess(t, w, r, heartbeatHash)
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
		if r.Method == http.MethodPut {
			writeSyncSuccess(t, w, r, heartbeatHash)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		writeHeartbeatSuccess(t, w, body, heartbeatHash)
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

func TestRegistryHeartbeatManifestChangedStopsWithoutRequest(t *testing.T) {
	var syncs, heartbeats atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			syncs.Add(1)
			writeSyncSuccess(t, w, r, heartbeatHash)
			return
		}
		heartbeats.Add(1)
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
	if err := registry.Register(catalogSpec(t, "/api/v1/new", "notify.item.create", "beacon:notify:create")); err != nil {
		t.Fatal(err)
	}
	if err := registry.HeartbeatOnce(t.Context()); !errors.Is(err, httpcatalog.ErrManifestChanged) {
		t.Fatalf("HeartbeatOnce = %v", err)
	}
	if _, err := registry.Sync(t.Context()); !errors.Is(err, httpcatalog.ErrManifestChanged) {
		t.Fatalf("same-generation Sync = %v", err)
	}
	if registry.Check(t.Context()) == nil || syncs.Load() != 1 || heartbeats.Load() != 0 {
		t.Fatalf("health=%v syncs=%d heartbeats=%d", registry.Check(t.Context()), syncs.Load(), heartbeats.Load())
	}
}

func TestRegistryRunHeartbeatWithoutSyncNeverRegisters(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify", Release: "test", HeartbeatInterval: time.Millisecond, Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notify", "notify.item.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	if err := registry.RunHeartbeat(t.Context()); err == nil {
		t.Fatal("unsynchronized heartbeat accepted")
	}
	if requests.Load() != 0 {
		t.Fatalf("unexpected requests=%d", requests.Load())
	}
}

func TestRegistryHeartbeatManifestChangedDuringRequestStaysUnhealthy(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writeSyncSuccess(t, w, r, heartbeatHash)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		close(started)
		<-release
		writeHeartbeatSuccess(t, w, body, heartbeatHash)
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
	done := make(chan error, 1)
	go func() { done <- registry.HeartbeatOnce(t.Context()) }()
	<-started
	if err := registry.Register(catalogSpec(t, "/api/v1/new", "notify.item.create", "beacon:notify:create")); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil || registry.Check(t.Context()) == nil {
		t.Fatalf("stale heartbeat accepted: err=%v health=%v", err, registry.Check(t.Context()))
	}
}

func TestRegistryRunHeartbeatBoundsTransientRetries(t *testing.T) {
	var syncs, heartbeats atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			syncs.Add(1)
			writeSyncSuccess(t, w, r, heartbeatHash)
			return
		}
		heartbeats.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: server.URL, Application: "beacon", Service: "notify", Release: "test", HeartbeatInterval: time.Millisecond, HeartbeatRetryDelay: time.Millisecond, Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notify", "notify.item.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := registry.RunHeartbeat(t.Context()); err == nil {
		t.Fatal("transient failures were accepted")
	}
	if syncs.Load() != 1 || heartbeats.Load() != 3 || registry.Check(t.Context()) == nil {
		t.Fatalf("syncs=%d heartbeats=%d health=%v", syncs.Load(), heartbeats.Load(), registry.Check(t.Context()))
	}
}
