package httpauthz

import (
	"sync"

	"github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/authzcontract"
	"github.com/swan-swan-swan/iam-core-sdk-go/v2/runtime/core"
)

const manifestOperation = "httpauthz.manifest"

// RouteSpec 是路由注册、PDP 保护与 Catalog 同步共享的完整逻辑路由声明。
// 调用方应使用 NewRouteSpec 派生坐标，不得手写 Resource。
type RouteSpec struct {
	Name   string
	Method string
	// RouteTemplate 是 HTTP 框架注册使用的绝对路径模板。
	RouteTemplate  string
	ResourceServer string
	Resource       string
	Action         string
}

// Manifest 保存经过严格验证的不可变逻辑路由集合。
type Manifest struct {
	routes map[string]Route
}

// Binder 保证清单内每条路由恰好绑定一次。
type Binder struct {
	manifest *Manifest
	mu       sync.Mutex
	bound    map[string]struct{}
}

// NewRouteSpec 校验名称、动词及模板，并确定性派生授权坐标。
func NewRouteSpec(method, routeTemplate, routeName, action string) (RouteSpec, error) {
	parsedAction, err := authzcontract.ParseAction(action)
	if err != nil {
		return RouteSpec{}, invalidManifestError()
	}
	parsedRoute, err := authzcontract.ParseRouteName(routeName)
	if err != nil || authzcontract.ValidateRouteTemplate(routeTemplate) != nil || !validRouteMethod(method) {
		return RouteSpec{}, invalidManifestError()
	}
	return RouteSpec{Name: routeName, Method: method, RouteTemplate: routeTemplate,
		ResourceServer: parsedAction.Server, Resource: parsedRoute.ResourceCode(), Action: action}, nil
}

// CompileManifest 重新校验全部声明字段，拒绝重复名称及派生资源。
func CompileManifest(specs []RouteSpec) (*Manifest, error) {
	routes := make(map[string]Route, len(specs))
	resources := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		expected, err := NewRouteSpec(spec.Method, spec.RouteTemplate, spec.Name, spec.Action)
		if err != nil || expected != spec {
			return nil, invalidManifestError()
		}
		if _, exists := routes[spec.Name]; exists {
			return nil, invalidManifestError()
		}
		if _, exists := resources[spec.Resource]; exists {
			return nil, invalidManifestError()
		}
		routes[spec.Name] = Route{
			name:           spec.Name,
			routeTemplate:  spec.RouteTemplate,
			method:         spec.Method,
			resourceServer: spec.ResourceServer,
			resource:       spec.Resource,
			action:         spec.Action,
			compiled:       true,
		}
		resources[spec.Resource] = struct{}{}
	}
	return &Manifest{routes: routes}, nil
}

func validRouteAction(action string) bool {
	_, err := authzcontract.ParseAction(action)
	return err == nil
}

// NewBinder 为当前清单创建独立绑定器。
func (m *Manifest) NewBinder() *Binder {
	return &Binder{manifest: m, bound: make(map[string]struct{})}
}

// Bind 按逻辑路由名称返回一次绑定的授权路由。
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

// Validate 校验清单中所有路由均已绑定。
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
