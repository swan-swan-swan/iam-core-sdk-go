package httpauthz_test

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz"
)

func TestNewRouteSpecDerivesCoordinates(t *testing.T) {
	spec, err := httpauthz.NewRouteSpec("GET", "/api/v1/apps", "portal.application.list", "opsws:portal:discover")
	if err != nil || spec.Name != "portal.application.list" || spec.Method != "GET" || spec.RouteTemplate != "/api/v1/apps" || spec.ResourceServer != "opsws" || spec.Resource != "portal_application_list" || spec.Action != "opsws:portal:discover" {
		t.Fatalf("NewRouteSpec() = %#v, %v", spec, err)
	}
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{spec})
	if err != nil {
		t.Fatal(err)
	}
	route, err := manifest.NewBinder().Bind(spec.Name)
	if err != nil || route.Name() != spec.Name || route.RouteTemplate() != spec.RouteTemplate || route.Action() != spec.Action {
		t.Fatalf("compiled route lost declaration: %#v, %v", route, err)
	}
}

func TestCompileManifestAllowsOneActionOnManyRoutes(t *testing.T) {
	for _, detailPath := range []string{"/api/v1/apps/:id", "/api/v1/apps"} {
		list, err := httpauthz.NewRouteSpec("GET", "/api/v1/apps", "portal.application.list", "opsws:portal:discover")
		if err != nil {
			t.Fatal(err)
		}
		detail, err := httpauthz.NewRouteSpec("GET", detailPath, "portal.application.detail", "opsws:portal:discover")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{list, detail}); err != nil {
			t.Fatal(err)
		}
		if _, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{list, list}); err == nil {
			t.Fatal("duplicate route accepted")
		}
		detail.Resource = list.Resource
		if _, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{list, detail}); err == nil {
			t.Fatal("overridden resource accepted")
		}
	}
}

func TestCompileManifestRevalidatesEveryCoordinate(t *testing.T) {
	base, err := httpauthz.NewRouteSpec("GET", "/api/v1/apps", "portal.application.list", "opsws:portal:discover")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*httpauthz.RouteSpec)
	}{
		{"name", func(s *httpauthz.RouteSpec) { s.Name = "portal.list" }},
		{"resource", func(s *httpauthz.RouteSpec) { s.Resource = "portal_discover" }},
		{"server", func(s *httpauthz.RouteSpec) { s.ResourceServer = "iam" }},
		{"method", func(s *httpauthz.RouteSpec) { s.Method = "get" }},
		{"template", func(s *httpauthz.RouteSpec) { s.RouteTemplate = "/apps?token=secret" }},
		{"missing template", func(s *httpauthz.RouteSpec) { s.RouteTemplate = "" }},
		{"action", func(s *httpauthz.RouteSpec) { s.Action = "opsws:portal:list" }},
		{"missing action", func(s *httpauthz.RouteSpec) { s.Action = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := base
			tc.mutate(&spec)
			_, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{spec})
			assertSanitizedInvalidConfig(t, err, "secret")
		})
	}
}

func TestManifestAcceptsEveryStandardMethod(t *testing.T) {
	methods := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{
				Name:           "orders.item." + strings.ToLower(method),
				Method:         method,
				ResourceServer: "orders_api",
				Resource:       "orders_item_" + strings.ToLower(method),
				RouteTemplate:  "/orders", Action: "orders_api:orders:select",
			}})
			if err != nil {
				t.Fatalf("CompileManifest() error = %v", err)
			}
			route, err := manifest.NewBinder().Bind("orders.item." + strings.ToLower(method))
			if err != nil {
				t.Fatalf("Bind() error = %v", err)
			}
			if route.Method() != method || route.ResourceServer() != "orders_api" || route.Resource() != "orders_item_"+strings.ToLower(method) {
				t.Fatalf("route = %q/%q/%q", route.Method(), route.ResourceServer(), route.Resource())
			}
		})
	}
}

func TestManifestPreservesCanonicalAction(t *testing.T) {
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{
		Name:           "orders.item.list",
		Method:         "GET",
		ResourceServer: "orders_api",
		Resource:       "orders_item_list", RouteTemplate: "/orders",
		Action: "orders_api:orders:select",
	}})
	if err != nil {
		t.Fatal(err)
	}
	route, err := manifest.NewBinder().Bind("orders.item.list")
	if err != nil {
		t.Fatal(err)
	}
	if got := route.Action(); got != "orders_api:orders:select" {
		t.Fatalf("route Action() = %q", got)
	}
}

func TestManifestRejectsInvalidOrDuplicateRoutes(t *testing.T) {
	base, err := httpauthz.NewRouteSpec("GET", "/orders", "orders.item.list", "orders_api:orders:select")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*httpauthz.RouteSpec)
	}{
		{"empty name", func(s *httpauthz.RouteSpec) { s.Name = "" }},
		{"trimmed name", func(s *httpauthz.RouteSpec) { s.Name = " orders.item.list" }},
		{"control name", func(s *httpauthz.RouteSpec) { s.Name = "orders.item.list\x00" }},
		{"invalid utf8 name", func(s *httpauthz.RouteSpec) { s.Name = string([]byte{0xff}) }},
		{"empty method", func(s *httpauthz.RouteSpec) { s.Method = "" }},
		{"mixed method", func(s *httpauthz.RouteSpec) { s.Method = "Get" }},
		{"padded method", func(s *httpauthz.RouteSpec) { s.Method = " GET" }},
		{"control method", func(s *httpauthz.RouteSpec) { s.Method = "GET\x00" }},
		{"unknown method", func(s *httpauthz.RouteSpec) { s.Method = "PROPFIND" }},
		{"empty server", func(s *httpauthz.RouteSpec) { s.ResourceServer = "" }},
		{"padded server", func(s *httpauthz.RouteSpec) { s.ResourceServer = "orders_api " }},
		{"empty resource", func(s *httpauthz.RouteSpec) { s.Resource = "" }},
		{"padded resource", func(s *httpauthz.RouteSpec) { s.Resource = " orders_item_list" }},
		{"two-level action", func(s *httpauthz.RouteSpec) { s.Action = "orders_api:select" }},
		{"four-level action", func(s *httpauthz.RouteSpec) { s.Action = "orders_api:orders:select:all" }},
		{"uppercase action", func(s *httpauthz.RouteSpec) { s.Action = "orders_api:orders:Select" }},
		{"hyphen action", func(s *httpauthz.RouteSpec) { s.Action = "orders-api:orders:select" }},
		{"blank action", func(s *httpauthz.RouteSpec) { s.Action = " " }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := base
			tc.mutate(&spec)
			_, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{spec})
			assertSanitizedInvalidConfig(t, err, spec.Name)
		})
	}
}

func TestManifestAllowsNilAndEmptySpecifications(t *testing.T) {
	for _, specs := range [][]httpauthz.RouteSpec{nil, {}} {
		manifest, err := httpauthz.CompileManifest(specs)
		if err != nil {
			t.Fatalf("CompileManifest(%#v) error = %v", specs, err)
		}
		if err := manifest.NewBinder().Validate(); err != nil {
			t.Fatalf("empty manifest Validate() error = %v", err)
		}
	}
}

func TestManifestCopiesSpecifications(t *testing.T) {
	specs := []httpauthz.RouteSpec{{Name: "orders.item.list", Method: "GET", RouteTemplate: "/orders", ResourceServer: "orders_api", Resource: "orders_item_list", Action: "orders_api:orders:select"}}
	manifest, err := httpauthz.CompileManifest(specs)
	if err != nil {
		t.Fatal(err)
	}
	specs[0] = httpauthz.RouteSpec{Name: "changed", Method: "POST", ResourceServer: "changed_api", Resource: "changed"}

	route, err := manifest.NewBinder().Bind("orders.item.list")
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if route.Method() != "GET" || route.ResourceServer() != "orders_api" || route.Resource() != "orders_item_list" {
		t.Fatalf("route changed with input = %q/%q/%q", route.Method(), route.ResourceServer(), route.Resource())
	}
}

func TestBinderRequiresEveryManifestRouteExactlyOnce(t *testing.T) {
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{
		{Name: "orders.item.list", Method: "GET", RouteTemplate: "/orders", ResourceServer: "orders_api", Resource: "orders_item_list", Action: "orders_api:orders:select"},
		{Name: "orders.item.create", Method: "POST", RouteTemplate: "/orders", ResourceServer: "orders_api", Resource: "orders_item_create", Action: "orders_api:orders:create"},
	})
	if err != nil {
		t.Fatal(err)
	}
	binder := manifest.NewBinder()
	assertSanitizedInvalidConfig(t, binder.Validate(), "orders.item.list")
	assertSanitizedInvalidConfig(t, bindError(binder, "unknown-route"), "unknown-route")
	if _, err := binder.Bind("orders.item.list"); err != nil {
		t.Fatalf("Bind(list_orders) error = %v", err)
	}
	assertSanitizedInvalidConfig(t, bindError(binder, "orders.item.list"), "orders.item.list")
	assertSanitizedInvalidConfig(t, binder.Validate(), "orders.item.create")
	if _, err := binder.Bind("orders.item.create"); err != nil {
		t.Fatalf("Bind(create_orders) error = %v", err)
	}
	if err := binder.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestManifestBindersAreIndependent(t *testing.T) {
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{Name: "orders.item.list", Method: "GET", RouteTemplate: "/orders", ResourceServer: "orders_api", Resource: "orders_item_list", Action: "orders_api:orders:select"}})
	if err != nil {
		t.Fatal(err)
	}
	first, second := manifest.NewBinder(), manifest.NewBinder()
	if _, err := first.Bind("orders.item.list"); err != nil {
		t.Fatalf("first Bind() error = %v", err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("first Validate() error = %v", err)
	}
	assertSanitizedInvalidConfig(t, second.Validate(), "list")
	if _, err := second.Bind("orders.item.list"); err != nil {
		t.Fatalf("second Bind() error = %v", err)
	}
}

func TestBinderConcurrentBindingIsExactlyOnce(t *testing.T) {
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{Name: "orders.item.list", Method: "GET", RouteTemplate: "/orders", ResourceServer: "orders_api", Resource: "orders_item_list", Action: "orders_api:orders:select"}})
	if err != nil {
		t.Fatal(err)
	}
	binder := manifest.NewBinder()
	const workers = 32
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := binder.Bind("orders.item.list")
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)

	successes := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		assertSanitizedInvalidConfig(t, err, "list")
	}
	if successes != 1 {
		t.Fatalf("successful Bind calls = %d, want 1", successes)
	}
	if err := binder.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func bindError(binder *httpauthz.Binder, name string) error {
	_, err := binder.Bind(name)
	return err
}

func assertSanitizedInvalidConfig(t *testing.T, err error, sensitive string) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil")
	}
	var typed *core.Error
	if !errors.As(err, &typed) || typed == nil || typed.Kind != core.KindInvalidConfig {
		t.Fatalf("error = %#v, want sanitized invalid config", err)
	}
	if sensitive != "" && strings.Contains(err.Error(), sensitive) {
		t.Fatalf("error leaks sensitive route data: %q", err)
	}
}
