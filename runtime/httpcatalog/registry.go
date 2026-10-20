package httpcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpauthz"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/internal/nilcheck"
)

const (
	// ManifestSchemaVersion 是完整逻辑路由清单的显式协议版本。
	ManifestSchemaVersion = "3"

	registrationPath      = "/api/v1/http-resource-catalog/registration"
	heartbeatPath         = registrationPath + "/heartbeat"
	registrationOperation = "httpcatalog.sync"
)

var errCatalogRegistration = errors.New("http catalog registration failed")

var (
	// ErrGenerationConflict 表示服务端拒绝当前部署代次，实例必须停止续约。
	ErrGenerationConflict = errors.New("http catalog generation conflict")
	// ErrManifestChanged 表示已发布的当前代次与本地路由清单不再一致。
	ErrManifestChanged = errors.New("http catalog manifest changed")
)

// Config 定义启动目录 Registry 与注册客户端配置。
type Config struct {
	BaseURL     string
	Application string
	Service     string
	Release     string
	// DeploymentGeneration 由宿主部署流程为每个 application/service 分配，零值也是显式代次。
	DeploymentGeneration uint64
	// Tokens 为每次 Catalog 同步提供当前机器 Access Token；Registry 不缓存令牌。
	Tokens     core.TokenSource
	HTTPClient *http.Client
	Observer   core.Observer
	// HeartbeatInterval 控制续约周期；零值为 24 小时。
	HeartbeatInterval time.Duration
	// HeartbeatRetryDelay 是心跳失败后的有界退避基础间隔，零值为一分钟。
	HeartbeatRetryDelay time.Duration
}

// Route 定义注册协议中的单条路由。
type Route struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	// RouteTemplate 是代码声明的真实 HTTP 路径模板。
	RouteTemplate string `json:"route_template"`
	Action        string `json:"action"`
}

// Manifest 定义发送给 IAM Core 的完整代码路由清单。
type Manifest struct {
	// SchemaVersion 必须等于 ManifestSchemaVersion。
	SchemaVersion        string  `json:"schema_version"`
	Application          string  `json:"application"`
	Service              string  `json:"service"`
	Release              string  `json:"release"`
	DeploymentGeneration uint64  `json:"deployment_generation"`
	Routes               []Route `json:"routes"`
}

// ManifestDigest 按服务端固定字段顺序计算完整路由清单摘要，不包含 release 或部署代次。
func (manifest Manifest) ManifestDigest() (string, error) {
	routes := append(make([]Route, 0, len(manifest.Routes)), manifest.Routes...)
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Name != routes[j].Name {
			return routes[i].Name < routes[j].Name
		}
		return routes[i].Method < routes[j].Method
	})
	input := struct {
		SchemaVersion string  `json:"schema_version"`
		Application   string  `json:"application"`
		Service       string  `json:"service"`
		Routes        []Route `json:"routes"`
	}{manifest.SchemaVersion, manifest.Application, manifest.Service, routes}
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// Result 定义一次启动同步的非敏感结果。
type Result struct {
	Application          string `json:"application"`
	CatalogHash          string `json:"catalog_hash"`
	DeploymentGeneration uint64 `json:"deployment_generation"`
	ManifestHash         string `json:"manifest_hash"`
	Changed              bool   `json:"changed"`
}

// Registry 收集代码路由并维护最近一次同步健康状态。
type Registry struct {
	mu            sync.RWMutex
	config        Config
	endpoint      string
	client        *http.Client
	routes        map[string]Route
	routesVersion uint64
	synced        bool
	lastErr       error
	catalogHash   string
	manifestHash  string
	fenced        bool
}

// NewRegistry 创建启动目录 Registry。
func NewRegistry(config Config) (*Registry, error) {
	config.BaseURL = strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	config.Application = strings.TrimSpace(config.Application)
	config.Service = strings.TrimSpace(config.Service)
	config.Release = strings.TrimSpace(config.Release)
	if config.BaseURL == "" || config.Application == "" || config.Service == "" || config.Release == "" || nilcheck.IsNil(config.Tokens) || (config.Observer != nil && nilcheck.IsNil(config.Observer)) {
		return nil, errCatalogRegistration
	}
	if config.HeartbeatInterval < 0 || config.HeartbeatRetryDelay < 0 {
		return nil, errCatalogRegistration
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 24 * time.Hour
	}
	if config.HeartbeatRetryDelay == 0 {
		config.HeartbeatRetryDelay = time.Minute
	}
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !isLoopbackHTTP(parsed)) {
		return nil, errCatalogRegistration
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	cloned := *client
	if cloned.Timeout <= 0 {
		cloned.Timeout = 10 * time.Second
	}
	cloned.Jar = nil
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Registry{
		config: config, endpoint: config.BaseURL + registrationPath, client: &cloned,
		routes: make(map[string]Route), lastErr: errCatalogRegistration,
	}, nil
}

// Register 校验并登记一条代码拥有的授权路由。
func (r *Registry) Register(spec httpauthz.RouteSpec) error {
	if r == nil {
		return errCatalogRegistration
	}
	expected, err := httpauthz.NewRouteSpec(spec.Method, spec.RouteTemplate, spec.Name, spec.Action)
	if err != nil || expected != spec {
		return errCatalogRegistration
	}
	route := Route{
		Name: spec.Name, Method: spec.Method, RouteTemplate: spec.RouteTemplate,
		Action: spec.Action,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, exists := r.routes[route.Name]; exists {
		if existing == route {
			return nil
		}
		return errCatalogRegistration
	}
	r.routes[route.Name] = route
	r.routesVersion++
	r.synced = false
	r.lastErr = errCatalogRegistration
	return nil
}

// Check 返回最近一次完整 Manifest 是否已成功同步。
func (r *Registry) Check(context.Context) error {
	if r == nil {
		return errCatalogRegistration
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.synced || r.lastErr != nil || r.catalogHash == "" || r.manifestHash == "" || r.fenced {
		return errCatalogRegistration
	}
	return nil
}

// manifestSnapshot 返回按路由名稳定排序的不可变 Manifest。
func (r *Registry) manifestSnapshot() (Manifest, uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.routes) == 0 {
		return Manifest{}, 0, errCatalogRegistration
	}
	routes := make([]Route, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Name < routes[j].Name })
	return Manifest{SchemaVersion: ManifestSchemaVersion, Application: r.config.Application, Service: r.config.Service, Release: r.config.Release, DeploymentGeneration: r.config.DeploymentGeneration, Routes: routes}, r.routesVersion, nil
}

// recordSync 保存不包含远端正文或凭据的同步终态。
func (r *Registry) recordSync(version uint64, catalogHash, manifestHash string, err error) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if version != r.routesVersion {
		return false
	}
	r.lastErr = err
	r.synced = err == nil
	if err == nil {
		r.catalogHash = catalogHash
		r.manifestHash = manifestHash
	} else {
		r.catalogHash = ""
	}
	return true
}

func (r *Registry) recordHeartbeat(version uint64, catalogHash, manifestHash string, err error) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if version != r.routesVersion || catalogHash != r.catalogHash || manifestHash != r.manifestHash {
		return false
	}
	r.lastErr = err
	r.synced = err == nil
	return true
}

func (r *Registry) fence() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fenced = true
	r.synced = false
	r.lastErr = ErrGenerationConflict
}

// isLoopbackHTTP 判断测试与本地开发 HTTP 地址是否仅绑定回环主机。
func isLoopbackHTTP(parsed *url.URL) bool {
	if parsed == nil || parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	return strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}
