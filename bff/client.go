package bff

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/nilcheck"
)

const (
	defaultFlowTTL             = 10 * time.Minute
	defaultSessionAbsoluteTTL  = 7 * 24 * time.Hour
	defaultSessionIdleTTL      = 8 * time.Hour
	defaultRefreshBeforeExpiry = time.Minute
	defaultRefreshLeaseTTL     = 15 * time.Second
)

var defaultScopes = []string{"openid", "profile", "email", "groups"}

type SecretProvider interface {
	Secret(context.Context) (string, error)
}

type SecretProviderFunc func(context.Context) (string, error)

func (f SecretProviderFunc) Secret(ctx context.Context) (string, error) { return f(ctx) }

type Config struct {
	Core                         *core.Runtime
	ClientID                     string
	ClientSecret                 SecretProvider
	RedirectURL                  string
	Scopes                       []string
	Backend                      session.Backend
	SessionCookie                http.Cookie
	FlowCookie                   http.Cookie
	FlowTTL                      time.Duration
	SessionAbsoluteTTL           time.Duration
	SessionIdleTTL               time.Duration
	RefreshBeforeExpiry          time.Duration
	RefreshLeaseTTL              time.Duration
	AllowedReturnToURLs          []string
	AllowInsecureLoopbackCookies bool
	HTTPClient                   *http.Client
	Clock                        core.Clock
	Random                       io.Reader
	Observer                     core.Observer
	Logger                       *slog.Logger
}

type Client struct {
	core                *core.Runtime
	clientID            string
	clientSecret        SecretProvider
	redirectURL         string
	scopes              []string
	backend             session.Backend
	sessionCookie       http.Cookie
	flowCookie          http.Cookie
	flowTTL             time.Duration
	sessionAbsoluteTTL  time.Duration
	sessionIdleTTL      time.Duration
	refreshBeforeExpiry time.Duration
	refreshLeaseTTL     time.Duration
	allowedReturnTo     map[string]struct{}
	httpClient          *http.Client
	clock               core.Clock
	random              io.Reader
	randomMu            sync.Mutex
	observer            core.Observer
	logger              *slog.Logger
}

func DefaultScopes() []string { return append([]string(nil), defaultScopes...) }

func New(cfg Config) (*Client, error) {
	if cfg.Core == nil || cfg.ClientID == "" || cfg.ClientID != strings.TrimSpace(cfg.ClientID) ||
		!cfg.Core.AcceptsAudience(cfg.ClientID) || nilcheck.IsNil(cfg.ClientSecret) || nilcheck.IsNil(cfg.Backend) {
		return nil, configureError()
	}
	metadata := cfg.Core.Metadata()
	if !slices.Contains(metadata.CodeChallengeMethodsSupported, "S256") {
		return nil, configureError()
	}
	redirect, err := validateRedirectURL(cfg.RedirectURL)
	if err != nil {
		return nil, configureError()
	}
	loopback := isLoopbackHTTPURL(redirect)
	if redirect.Scheme == "http" && (!loopback || !cfg.AllowInsecureLoopbackCookies) {
		return nil, configureError()
	}
	scopes, err := validateScopes(cfg.Scopes)
	if err != nil {
		return nil, configureError()
	}
	flowTTL, ok := positiveDurationOrDefault(cfg.FlowTTL, defaultFlowTTL)
	if !ok {
		return nil, configureError()
	}
	absoluteTTL, ok := positiveDurationOrDefault(cfg.SessionAbsoluteTTL, defaultSessionAbsoluteTTL)
	if !ok {
		return nil, configureError()
	}
	idleTTL, ok := positiveDurationOrDefault(cfg.SessionIdleTTL, defaultSessionIdleTTL)
	if !ok {
		return nil, configureError()
	}
	refreshBefore, ok := positiveDurationOrDefault(cfg.RefreshBeforeExpiry, defaultRefreshBeforeExpiry)
	if !ok {
		return nil, configureError()
	}
	refreshLease, ok := positiveDurationOrDefault(cfg.RefreshLeaseTTL, defaultRefreshLeaseTTL)
	if !ok {
		return nil, configureError()
	}
	production := redirect.Scheme == "https"
	sessionCookie, err := validateCookieTemplate(cfg.SessionCookie, production)
	if err != nil {
		return nil, configureError()
	}
	flowCookie, err := validateCookieTemplate(cfg.FlowCookie, production)
	if err != nil || sessionCookie.Name == flowCookie.Name {
		return nil, configureError()
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedReturnToURLs))
	for _, candidate := range cfg.AllowedReturnToURLs {
		if validateAllowedAbsoluteReturnTo(candidate) != nil {
			return nil, configureError()
		}
		if _, duplicate := allowed[candidate]; duplicate {
			return nil, configureError()
		}
		allowed[candidate] = struct{}{}
	}
	clock := cfg.Clock
	if nilcheck.IsNil(clock) {
		clock = core.RealClock{}
	}
	randomSource := cfg.Random
	if nilcheck.IsNil(randomSource) {
		randomSource = rand.Reader
	}
	observer := cfg.Observer
	if nilcheck.IsNil(observer) {
		observer = core.NopObserver{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Client{
		core: cfg.Core, clientID: cfg.ClientID, clientSecret: cfg.ClientSecret,
		redirectURL: cfg.RedirectURL, scopes: scopes, backend: cfg.Backend,
		sessionCookie: sessionCookie, flowCookie: flowCookie,
		flowTTL: flowTTL, sessionAbsoluteTTL: absoluteTTL, sessionIdleTTL: idleTTL,
		refreshBeforeExpiry: refreshBefore, refreshLeaseTTL: refreshLease,
		allowedReturnTo: allowed, httpClient: cloneHTTPClient(cfg.HTTPClient), clock: clock,
		random: randomSource, observer: observer, logger: logger,
	}, nil
}

func validateScopes(configured []string) ([]string, error) {
	if len(configured) == 0 {
		return DefaultScopes(), nil
	}
	seen := make(map[string]struct{}, len(configured))
	hasOpenID := false
	result := make([]string, len(configured))
	for index, scope := range configured {
		if scope == "" || scope != strings.TrimSpace(scope) || strings.ContainsAny(scope, " \t\r\n") || scope == "roles" {
			return nil, configureError()
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, configureError()
		}
		seen[scope] = struct{}{}
		hasOpenID = hasOpenID || scope == "openid"
		result[index] = scope
	}
	if !hasOpenID {
		return nil, configureError()
	}
	return result, nil
}

func positiveDurationOrDefault(value, fallback time.Duration) (time.Duration, bool) {
	if value < 0 {
		return 0, false
	}
	if value == 0 {
		return fallback, true
	}
	return value, true
}

func cloneHTTPClient(injected *http.Client) *http.Client {
	if injected == nil {
		injected = &http.Client{}
	}
	cloned := *injected
	cloned.Jar = nil
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cloned
}

func configureError() *core.Error {
	return core.NewError(core.KindInvalidConfig, "bff.configure", 0, false, nil)
}

func bffError(kind core.Kind, operation string, status int, retryable bool) *core.Error {
	return core.NewError(kind, operation, status, retryable, nil)
}

func (c *Client) record(ctx context.Context, operation string, err error, started time.Time) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	duration := c.clock.Now().Sub(started)
	if ctx == nil {
		ctx = context.Background()
	}
	c.observer.Observe(ctx, core.Event{Operation: operation, Outcome: outcome, Duration: duration})
	c.logger.Info("iamcore operation", slog.String("operation", operation), slog.String("outcome", outcome), slog.Duration("duration", duration))
}
