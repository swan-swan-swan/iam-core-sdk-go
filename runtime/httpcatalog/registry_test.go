package httpcatalog_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpcatalog"
)

// TestRegistrySyncSendsDeterministicActionAlignedManifest 验证启动同步发送完整且确定性的代码路由清单。
func TestRegistrySyncSendsDeterministicActionAlignedManifest(t *testing.T) {
	var got httpcatalog.Manifest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		if !ok || clientID != "ops-gateway-catalog-registrar" || secret != "secret" {
			t.Fatalf("BasicAuth() = (%q, %q, %v)", clientID, secret, ok)
		}
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/http-resource-catalog/registration" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode manifest: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"success","data":{"application":"opsgw","catalog_hash":"sha256:abc","changed":true}}`))
	}))
	defer server.Close()

	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{
		BaseURL: server.URL, Application: "opsgw", Service: "ops-gateway", Release: "20260819-001",
		ClientID: "ops-gateway-catalog-registrar", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Register(httpauthz.RouteSpec{Name: "portal.catalog", Method: "GET", ResourceServer: "opsws", Resource: "portal_discover", Action: "opsws:portal:discover"}); err != nil {
		t.Fatalf("Register(portal) error = %v", err)
	}
	if err := registry.Register(httpauthz.RouteSpec{Name: "admin.list", Method: "GET", ResourceServer: "opsws", Resource: "admin_list", Action: "opsws:admin:list"}); err != nil {
		t.Fatalf("Register(admin) error = %v", err)
	}
	if err := registry.Check(context.Background()); err == nil {
		t.Fatal("Check(before sync) error = nil")
	}
	result, err := registry.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.CatalogHash != "sha256:abc" || !result.Changed || len(got.Routes) != 2 || got.Routes[0].Name != "admin.list" || got.Routes[1].Name != "portal.catalog" {
		t.Fatalf("Sync() = %#v, manifest = %#v", result, got)
	}
	if err := registry.Check(context.Background()); err != nil {
		t.Fatalf("Check(after sync) error = %v", err)
	}
}

// TestRegistryRejectsActionCoordinateMismatch 验证 SDK 在发起网络请求前拒绝不一致目录坐标。
func TestRegistryRejectsActionCoordinateMismatch(t *testing.T) {
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{
		BaseURL: "http://127.0.0.1:8080", Application: "opsgw", Service: "ops-gateway", Release: "dev",
		ClientID: "ops-gateway-catalog-registrar", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if err := registry.Register(httpauthz.RouteSpec{Name: "admin.list", Method: "GET", ResourceServer: "opsws", Resource: "admin", Action: "opsws:admin:list"}); err == nil {
		t.Fatal("Register(mismatch) error = nil")
	}
}

// TestRegistryRegisterIsIdempotent 验证动态路由包装器重复登记同一路由不会破坏同步健康状态。
func TestRegistryRegisterIsIdempotent(t *testing.T) {
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{
		BaseURL: "http://127.0.0.1:8080", Application: "opsgw", Service: "ops-gateway", Release: "dev",
		ClientID: "ops-gateway-catalog-registrar", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	spec := httpauthz.RouteSpec{Name: "admin.list", Method: "GET", ResourceServer: "opsws", Resource: "admin_list", Action: "opsws:admin:list"}
	if err := registry.Register(spec); err != nil {
		t.Fatalf("Register(first) error = %v", err)
	}
	if err := registry.Register(spec); err != nil {
		t.Fatalf("Register(second) error = %v", err)
	}
	spec.Action = "opsws:admin:update"
	spec.Resource = "admin_update"
	if err := registry.Register(spec); err == nil {
		t.Fatal("Register(conflicting name) error = nil")
	}
}
