package httpauthz_test

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz"
)

func TestManifestAcceptsEveryStandardMethod(t *testing.T) {
	methods := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{
				Name:           "orders_" + strings.ToLower(method),
				Method:         method,
				ResourceServer: "orders_api",
				Resource:       "orders",
			}})
			if err != nil {
				t.Fatalf("CompileManifest() error = %v", err)
			}
			route, err := manifest.NewBinder().Bind("orders_" + strings.ToLower(method))
			if err != nil {
				t.Fatalf("Bind() error = %v", err)
			}
			if route.Method() != method || route.ResourceServer() != "orders_api" || route.Resource() != "orders" {
				t.Fatalf("route = %q/%q/%q", route.Method(), route.ResourceServer(), route.Resource())
			}
		})
	}
}

func TestManifestRejectsInvalidOrDuplicateRoutes(t *testing.T) {
	tests := []struct {
		name      string
		specs     []httpauthz.RouteSpec
		sensitive string
	}{
		{"empty name", []httpauthz.RouteSpec{{Method: "GET", ResourceServer: "orders_api", Resource: "orders"}}, ""},
		{"trimmed name", []httpauthz.RouteSpec{{Name: " orders", Method: "GET", ResourceServer: "orders_api", Resource: "orders"}}, " orders"},
		{"control name", []httpauthz.RouteSpec{{Name: "orders\x00", Method: "GET", ResourceServer: "orders_api", Resource: "orders"}}, "orders\x00"},
		{"invalid utf8 name", []httpauthz.RouteSpec{{Name: string([]byte{0xff}), Method: "GET", ResourceServer: "orders_api", Resource: "orders"}}, string([]byte{0xff})},
		{"empty method", []httpauthz.RouteSpec{{Name: "list", ResourceServer: "orders_api", Resource: "orders"}}, ""},
		{"lower method", []httpauthz.RouteSpec{{Name: "list", Method: "get", ResourceServer: "orders_api", Resource: "orders"}}, "get"},
		{"mixed method", []httpauthz.RouteSpec{{Name: "list", Method: "Get", ResourceServer: "orders_api", Resource: "orders"}}, "Get"},
		{"trimmed method", []httpauthz.RouteSpec{{Name: "list", Method: " GET", ResourceServer: "orders_api", Resource: "orders"}}, " GET"},
		{"control method", []httpauthz.RouteSpec{{Name: "list", Method: "GET\x00", ResourceServer: "orders_api", Resource: "orders"}}, "GET\x00"},
		{"nonstandard method", []httpauthz.RouteSpec{{Name: "list", Method: "PROPFIND", ResourceServer: "orders_api", Resource: "orders"}}, "PROPFIND"},
		{"empty resource server", []httpauthz.RouteSpec{{Name: "list", Method: "GET", Resource: "orders"}}, ""},
		{"trimmed resource server", []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api ", Resource: "orders"}}, "orders_api "},
		{"control resource server", []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders\napi", Resource: "orders"}}, "orders\napi"},
		{"invalid utf8 resource server", []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: string([]byte{0xff}), Resource: "orders"}}, string([]byte{0xff})},
		{"empty resource", []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api"}}, ""},
		{"trimmed resource", []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api", Resource: " orders"}}, " orders"},
		{"control resource", []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api", Resource: "orders\t"}}, "orders\t"},
		{"invalid utf8 resource", []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api", Resource: string([]byte{0xff})}}, string([]byte{0xff})},
		{"duplicate name", []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api", Resource: "orders"}, {Name: "list", Method: "POST", ResourceServer: "orders_api", Resource: "orders"}}, "list"},
		{"duplicate canonical binding", []httpauthz.RouteSpec{{Name: "one", Method: "GET", ResourceServer: "orders_api", Resource: "orders"}, {Name: "two", Method: "GET", ResourceServer: "orders_api", Resource: "orders"}}, "orders_api"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := httpauthz.CompileManifest(test.specs)
			assertSanitizedInvalidConfig(t, err, test.sensitive)
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
	specs := []httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api", Resource: "orders"}}
	manifest, err := httpauthz.CompileManifest(specs)
	if err != nil {
		t.Fatal(err)
	}
	specs[0] = httpauthz.RouteSpec{Name: "changed", Method: "POST", ResourceServer: "changed_api", Resource: "changed"}

	route, err := manifest.NewBinder().Bind("list")
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if route.Method() != "GET" || route.ResourceServer() != "orders_api" || route.Resource() != "orders" {
		t.Fatalf("route changed with input = %q/%q/%q", route.Method(), route.ResourceServer(), route.Resource())
	}
}

func TestBinderRequiresEveryManifestRouteExactlyOnce(t *testing.T) {
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{
		{Name: "list_orders", Method: "GET", ResourceServer: "orders_api", Resource: "orders"},
		{Name: "create_orders", Method: "POST", ResourceServer: "orders_api", Resource: "orders"},
	})
	if err != nil {
		t.Fatal(err)
	}
	binder := manifest.NewBinder()
	assertSanitizedInvalidConfig(t, binder.Validate(), "list_orders")
	assertSanitizedInvalidConfig(t, bindError(binder, "unknown-route"), "unknown-route")
	if _, err := binder.Bind("list_orders"); err != nil {
		t.Fatalf("Bind(list_orders) error = %v", err)
	}
	assertSanitizedInvalidConfig(t, bindError(binder, "list_orders"), "list_orders")
	assertSanitizedInvalidConfig(t, binder.Validate(), "create_orders")
	if _, err := binder.Bind("create_orders"); err != nil {
		t.Fatalf("Bind(create_orders) error = %v", err)
	}
	if err := binder.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestManifestBindersAreIndependent(t *testing.T) {
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api", Resource: "orders"}})
	if err != nil {
		t.Fatal(err)
	}
	first, second := manifest.NewBinder(), manifest.NewBinder()
	if _, err := first.Bind("list"); err != nil {
		t.Fatalf("first Bind() error = %v", err)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("first Validate() error = %v", err)
	}
	assertSanitizedInvalidConfig(t, second.Validate(), "list")
	if _, err := second.Bind("list"); err != nil {
		t.Fatalf("second Bind() error = %v", err)
	}
}

func TestBinderConcurrentBindingIsExactlyOnce(t *testing.T) {
	manifest, err := httpauthz.CompileManifest([]httpauthz.RouteSpec{{Name: "list", Method: "GET", ResourceServer: "orders_api", Resource: "orders"}})
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
			_, err := binder.Bind("list")
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
