package httpcatalog_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/httpauthz"
	"github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/httpcatalog"
)

// TestRegistrySyncSendsDeterministicV2Manifest 验证启动同步发送完整且确定性的代码路由清单。
func TestRegistrySyncSendsDeterministicV2Manifest(t *testing.T) {
	var got httpcatalog.Manifest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		if !ok || clientID != "ops-gateway-catalog-registrar" || secret != "secret" {
			t.Fatal("BasicAuth credentials did not match the registrar")
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
	if err := registry.Register(catalogSpec(t, "/api/v1/apps", "portal.application.list", "opsws:portal:discover")); err != nil {
		t.Fatalf("Register(portal) error = %v", err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/admin", "admin.application.list", "opsws:admin:select")); err != nil {
		t.Fatalf("Register(admin) error = %v", err)
	}
	if err := registry.Check(context.Background()); err == nil {
		t.Fatal("Check(before sync) error = nil")
	}
	result, err := registry.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.CatalogHash != "sha256:abc" || !result.Changed || len(got.Routes) != 2 || got.Routes[0].Name != "admin.application.list" || got.Routes[1].Name != "portal.application.list" {
		t.Fatalf("Sync() = %#v, manifest = %#v", result, got)
	}
	if got.SchemaVersion != "2" || got.Routes[1].RouteTemplate != "/api/v1/apps" || got.Routes[1].Resource != "portal_application_list" || got.Routes[1].Action != "opsws:portal:discover" {
		t.Fatalf("Manifest v2 coordinates = %#v", got)
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
	spec := catalogSpec(t, "/api/v1/admin", "admin.application.list", "opsws:admin:select")
	spec.Resource = "admin"
	if err := registry.Register(spec); err == nil {
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
	spec := catalogSpec(t, "/api/v1/admin", "admin.application.list", "opsws:admin:select")
	if err := registry.Register(spec); err != nil {
		t.Fatalf("Register(first) error = %v", err)
	}
	if err := registry.Register(spec); err != nil {
		t.Fatalf("Register(second) error = %v", err)
	}
	spec.Action = "opsws:admin:update"
	if err := registry.Register(spec); err == nil {
		t.Fatal("Register(conflicting name) error = nil")
	}
}

func catalogSpec(t *testing.T, path, name, action string) httpauthz.RouteSpec {
	t.Helper()
	spec, err := httpauthz.NewRouteSpec("GET", path, name, action)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestRegistryAllowsSharedActionAndDynamicTemplates(t *testing.T) {
	for _, path := range []string{"/api/v1/apps/:id", "/api/v1/apps"} {
		registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: "http://127.0.0.1:8080", Application: "opsgw", Service: "ops-gateway", Release: "dev", ClientID: "ops-gateway-catalog-registrar", ClientSecret: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		list := catalogSpec(t, "/api/v1/apps", "portal.application.list", "opsws:portal:discover")
		detail := catalogSpec(t, path, "portal.application.detail", "opsws:portal:discover")
		for _, spec := range []httpauthz.RouteSpec{list, detail} {
			if err := registry.Register(spec); err != nil {
				t.Fatal(err)
			}
		}
		detail.Resource = list.Resource
		if err := registry.Register(detail); err == nil {
			t.Fatal("accepted resource override")
		}
	}
}

func TestRegistryRejectsMalformedDeclarationsWithoutNormalization(t *testing.T) {
	base := catalogSpec(t, "/api/v1/apps", "portal.application.list", "opsws:portal:discover")
	for _, mutate := range []func(*httpauthz.RouteSpec){
		func(s *httpauthz.RouteSpec) { s.Name = " " + s.Name },
		func(s *httpauthz.RouteSpec) { s.Action += " " },
		func(s *httpauthz.RouteSpec) { s.ResourceServer = "iam" },
		func(s *httpauthz.RouteSpec) { s.Method = "get" },
		func(s *httpauthz.RouteSpec) { s.RouteTemplate = "/apps?token=secret" },
		func(s *httpauthz.RouteSpec) { s.Action = "opsws:portal:list" },
	} {
		registry, err := httpcatalog.NewRegistry(httpcatalog.Config{BaseURL: "http://127.0.0.1:8080", Application: "opsgw", Service: "ops-gateway", Release: "dev", ClientID: "ops-gateway-catalog-registrar", ClientSecret: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		spec := base
		mutate(&spec)
		if err := registry.Register(spec); err == nil {
			t.Fatal("accepted malformed declaration")
		}
	}
}
