// Package httpcatalog 提供业务服务启动时的 HTTP Resource Catalog 注册能力。
package httpcatalog

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/httpauthz"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/internal/nilcheck"
)

const (
	registrationPath      = "/api/v1/http-resource-catalog/registration"
	registrationOperation = "httpcatalog.sync"
)

var errCatalogRegistration = errors.New("http catalog registration failed")

// Config 定义启动目录 Registry 与注册客户端配置。
type Config struct {
	BaseURL      string
	Application  string
	Service      string
	Release      string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	Observer     core.Observer
}

// Route 定义注册协议中的单条路由。
type Route struct {
	Name           string `json:"name"`
	Method         string `json:"method"`
	ResourceServer string `json:"resource_server"`
	Resource       string `json:"resource"`
	Action         string `json:"action"`
}

// Manifest 定义发送给 IAM Core 的完整代码路由清单。
type Manifest struct {
	Application string  `json:"application"`
	Service     string  `json:"service"`
	Release     string  `json:"release"`
	Routes      []Route `json:"routes"`
}

// Result 定义一次启动同步的非敏感结果。
type Result struct {
	Application string `json:"application"`
	CatalogHash string `json:"catalog_hash"`
	Changed     bool   `json:"changed"`
}

// Registry 收集代码路由并维护最近一次同步健康状态。
type Registry struct {
	mu       sync.RWMutex
	config   Config
	endpoint string
	client   *http.Client
	routes   map[string]Route
	tuples   map[string]struct{}
	synced   bool
	lastErr  error
}

// NewRegistry 创建启动目录 Registry。
func NewRegistry(config Config) (*Registry, error) {
	config.BaseURL = strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	config.Application = strings.TrimSpace(config.Application)
	config.Service = strings.TrimSpace(config.Service)
	config.Release = strings.TrimSpace(config.Release)
	config.ClientID = strings.TrimSpace(config.ClientID)
	if config.BaseURL == "" || config.Application == "" || config.Service == "" || config.Release == "" || !strings.HasSuffix(config.ClientID, "-catalog-registrar") || strings.TrimSpace(config.ClientSecret) == "" || (config.Observer != nil && nilcheck.IsNil(config.Observer)) {
		return nil, errCatalogRegistration
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
		routes: make(map[string]Route), tuples: make(map[string]struct{}), lastErr: errCatalogRegistration,
	}, nil
}

// Register 校验并登记一条代码拥有的授权路由。
func (r *Registry) Register(spec httpauthz.RouteSpec) error {
	if r == nil {
		return errCatalogRegistration
	}
	route := Route{
		Name: strings.TrimSpace(spec.Name), Method: strings.TrimSpace(spec.Method),
		ResourceServer: strings.TrimSpace(spec.ResourceServer), Resource: strings.TrimSpace(spec.Resource), Action: strings.TrimSpace(spec.Action),
	}
	if !validActionAlignedRoute(route) {
		return errCatalogRegistration
	}
	tuple := route.Method + "\x00" + route.ResourceServer + "\x00" + route.Resource
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, exists := r.routes[route.Name]; exists {
		if existing == route {
			return nil
		}
		return errCatalogRegistration
	}
	if _, exists := r.tuples[tuple]; exists {
		return errCatalogRegistration
	}
	r.routes[route.Name] = route
	r.tuples[tuple] = struct{}{}
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
	if !r.synced || r.lastErr != nil {
		return errCatalogRegistration
	}
	return nil
}

// manifestSnapshot 返回按路由名稳定排序的不可变 Manifest。
func (r *Registry) manifestSnapshot() (Manifest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.routes) == 0 {
		return Manifest{}, errCatalogRegistration
	}
	routes := make([]Route, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Name < routes[j].Name })
	return Manifest{Application: r.config.Application, Service: r.config.Service, Release: r.config.Release, Routes: routes}, nil
}

// recordSync 保存不包含远端正文或凭据的同步终态。
func (r *Registry) recordSync(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastErr = err
	r.synced = err == nil
}

// validActionAlignedRoute 校验 ResourceServer 与 Resource 均由三级 Action 确定。
func validActionAlignedRoute(route Route) bool {
	parts := strings.Split(route.Action, ":")
	if route.Name == "" || route.Method == "" || len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || part[0] < 'a' || part[0] > 'z' {
			return false
		}
		for _, character := range part[1:] {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return route.ResourceServer == parts[0] && route.Resource == parts[1]+"_"+parts[2]
}

// isLoopbackHTTP 判断测试与本地开发 HTTP 地址是否仅绑定回环主机。
func isLoopbackHTTP(parsed *url.URL) bool {
	if parsed == nil || parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	return strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}
