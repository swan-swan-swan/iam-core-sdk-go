package client

import (
	"net"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"
)

const (
	defaultTimeout   = 10 * time.Second
	maxResponseBytes = 1 << 20
)

// Config configures a strict management API transport.
type Config struct {
	BaseURL     string
	TokenSource TokenSource
	HTTPClient  *http.Client
	Timeout     time.Duration
	Observer    Observer
}

// Client executes authenticated management API requests.
type Client struct {
	baseURL    *url.URL
	tokens     TokenSource
	httpClient *http.Client
	timeout    time.Duration
	observer   Observer
}

// New validates cfg and returns a client that never follows redirects or
// stores cookies.
func New(cfg Config) (*Client, error) {
	baseURL, ok := validBaseURL(cfg.BaseURL)
	if !ok || isNilInterface(cfg.TokenSource) || cfg.Timeout < 0 {
		return nil, &Error{Kind: KindInvalidConfig}
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	source := cfg.HTTPClient
	if source == nil {
		source = http.DefaultClient
	}
	httpClient := *source
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Client{
		baseURL:    baseURL,
		tokens:     cfg.TokenSource,
		httpClient: &httpClient,
		timeout:    timeout,
		observer:   cfg.Observer,
	}, nil
}

func validBaseURL(raw string) (*url.URL, bool) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return nil, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Hostname() == "" || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(raw, "#") {
		return nil, false
	}
	basePath := strings.TrimSuffix(parsed.Path, "/")
	if parsed.RawPath != "" || strings.Contains(parsed.Path, "\\") || parsed.Path != "" && parsed.Path != "/" && path.Clean(parsed.Path) != basePath {
		return nil, false
	}
	parsed.Path = basePath

	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return nil, false
		}
	default:
		return nil, false
	}
	return parsed, true
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
