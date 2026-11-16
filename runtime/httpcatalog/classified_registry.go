package httpcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/authzcontract"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpauthz"
)

// ClassifiedManifestSchemaVersion 是显式分类完整清单的协议版本，与Go module主版本无关。
const ClassifiedManifestSchemaVersion = "4"

// ClassifiedRoute 是Manifest v4的五字段路由事实，字段顺序也是摘要合同。
type ClassifiedRoute struct {
	// Name 是稳定逻辑路由名称。
	Name string `json:"name"`
	// Method 是真实HTTP方法。
	Method string `json:"method"`
	// RouteTemplate 是框架注册使用的绝对路径模板。
	RouteTemplate string `json:"route_template"`
	// Action 是原有三级业务能力。
	Action string `json:"action"`
	// PolicyClass 是显式策略类别。
	PolicyClass authzcontract.PolicyClass `json:"policy_class"`
}

// ClassifiedManifest 是Manifest v4完整清单，不改变原Manifest的形状。
type ClassifiedManifest struct {
	// SchemaVersion 必须等于ClassifiedManifestSchemaVersion。
	SchemaVersion string `json:"schema_version"`
	// Application 是目录所属应用。
	Application string `json:"application"`
	// Service 是目录贡献服务。
	Service string `json:"service"`
	// Release 是部署发布标识，不进入摘要。
	Release string `json:"release"`
	// DeploymentGeneration 是宿主分配的部署代次，不进入摘要。
	DeploymentGeneration uint64 `json:"deployment_generation"`
	// Routes 是带有显式分类的完整路由集合。
	Routes []ClassifiedRoute `json:"routes"`
}

// ManifestDigest 按固定字段顺序和name、method排序计算v4摘要，包含分类。
func (manifest ClassifiedManifest) ManifestDigest() (string, error) {
	routes := append(make([]ClassifiedRoute, 0, len(manifest.Routes)), manifest.Routes...)
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Name != routes[j].Name {
			return routes[i].Name < routes[j].Name
		}
		return routes[i].Method < routes[j].Method
	})
	input := struct {
		SchemaVersion string            `json:"schema_version"`
		Application   string            `json:"application"`
		Service       string            `json:"service"`
		Routes        []ClassifiedRoute `json:"routes"`
	}{manifest.SchemaVersion, manifest.Application, manifest.Service, routes}
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// NewClassifiedRegistry 创建仅接受显式分类声明并发送v4的Registry，不自动降级。
func NewClassifiedRegistry(config Config) (*Registry, error) {
	r, err := NewRegistry(config)
	if err != nil {
		return nil, err
	}
	r.routes = nil
	r.classifiedRoutes = make(map[string]ClassifiedRoute)
	return r, nil
}

// RegisterClassified 校验并登记v4事实；同名或同Action不同分类时拒绝候选。
func (r *Registry) RegisterClassified(spec httpauthz.ClassifiedRouteSpec) error {
	if r == nil {
		return errCatalogRegistration
	}
	expected, err := httpauthz.NewClassifiedRouteSpec(spec.Spec.Method, spec.Spec.RouteTemplate, spec.Spec.Name, spec.Spec.Action, spec.PolicyClass)
	if err != nil {
		return fmt.Errorf("%w: %w", errCatalogRegistration, err)
	}
	if expected != spec {
		return errCatalogRegistration
	}
	route := ClassifiedRoute{Name: spec.Spec.Name, Method: spec.Spec.Method, RouteTemplate: spec.Spec.RouteTemplate, Action: spec.Spec.Action, PolicyClass: spec.PolicyClass}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.classifiedRoutes == nil {
		return errCatalogRegistration
	}
	if existing, exists := r.classifiedRoutes[route.Name]; exists {
		if existing == route {
			return nil
		}
		if existing.PolicyClass != route.PolicyClass {
			return fmt.Errorf("%w: %w", errCatalogRegistration, authzcontract.ErrInvalidPolicyClass)
		}
		return errCatalogRegistration
	}
	for _, existing := range r.classifiedRoutes {
		if existing.Action == route.Action && existing.PolicyClass != route.PolicyClass {
			return fmt.Errorf("%w: %w", errCatalogRegistration, authzcontract.ErrInvalidPolicyClass)
		}
	}
	r.classifiedRoutes[route.Name] = route
	r.routesVersion++
	r.synced = false
	r.lastErr = errCatalogRegistration
	return nil
}

// ExportClassifiedManifest 返回无网络及持久化副作用的独立v4完整清单副本。
func (r *Registry) ExportClassifiedManifest() (ClassifiedManifest, error) {
	if r == nil {
		return ClassifiedManifest{}, errCatalogRegistration
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.classifiedManifestLocked()
}

// classifiedManifestLocked 由已持有读锁的调用方构建独立排序副本。
func (r *Registry) classifiedManifestLocked() (ClassifiedManifest, error) {
	if len(r.classifiedRoutes) == 0 {
		return ClassifiedManifest{}, errCatalogRegistration
	}
	routes := make([]ClassifiedRoute, 0, len(r.classifiedRoutes))
	for _, route := range r.classifiedRoutes {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Name != routes[j].Name {
			return routes[i].Name < routes[j].Name
		}
		return routes[i].Method < routes[j].Method
	})
	return ClassifiedManifest{SchemaVersion: ClassifiedManifestSchemaVersion, Application: r.config.Application, Service: r.config.Service, Release: r.config.Release, DeploymentGeneration: r.config.DeploymentGeneration, Routes: routes}, nil
}
