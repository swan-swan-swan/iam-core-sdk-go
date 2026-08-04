package httpauthz

import (
	"sync"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

const manifestOperation = "httpauthz.manifest"

type RouteSpec struct {
	Name           string
	Method         string
	ResourceServer string
	Resource       string
}

type Manifest struct {
	routes map[string]Route
}

type Binder struct {
	manifest *Manifest
	mu       sync.Mutex
	bound    map[string]struct{}
}

type routeTuple struct {
	method         string
	resourceServer string
	resource       string
}

func CompileManifest(specs []RouteSpec) (*Manifest, error) {
	routes := make(map[string]Route, len(specs))
	tuples := make(map[routeTuple]struct{}, len(specs))
	for _, spec := range specs {
		if !validRouteValue(spec.Name) || !validRouteMethod(spec.Method) ||
			!validRouteValue(spec.ResourceServer) || !validRouteValue(spec.Resource) {
			return nil, invalidManifestError()
		}
		if _, exists := routes[spec.Name]; exists {
			return nil, invalidManifestError()
		}
		tuple := routeTuple{method: spec.Method, resourceServer: spec.ResourceServer, resource: spec.Resource}
		if _, exists := tuples[tuple]; exists {
			return nil, invalidManifestError()
		}
		routes[spec.Name] = Route{
			method:         spec.Method,
			resourceServer: spec.ResourceServer,
			resource:       spec.Resource,
			compiled:       true,
		}
		tuples[tuple] = struct{}{}
	}
	return &Manifest{routes: routes}, nil
}

func (m *Manifest) NewBinder() *Binder {
	return &Binder{manifest: m, bound: make(map[string]struct{})}
}

func (b *Binder) Bind(name string) (Route, error) {
	if b == nil {
		return Route{}, invalidManifestError()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.manifest == nil || b.manifest.routes == nil {
		return Route{}, invalidManifestError()
	}
	route, exists := b.manifest.routes[name]
	if !exists {
		return Route{}, invalidManifestError()
	}
	if _, exists := b.bound[name]; exists {
		return Route{}, invalidManifestError()
	}
	b.bound[name] = struct{}{}
	return route, nil
}

func (b *Binder) Validate() error {
	if b == nil {
		return invalidManifestError()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.manifest == nil || b.manifest.routes == nil || len(b.bound) != len(b.manifest.routes) {
		return invalidManifestError()
	}
	return nil
}

func invalidManifestError() *core.Error {
	return core.NewError(core.KindInvalidConfig, manifestOperation, 0, false, nil)
}
