package core

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/nilcheck"
)

const (
	defaultDiscoveryTimeout = 5 * time.Second
	defaultJWKSTimeout      = 5 * time.Second
	defaultUnknownKIDDelay  = 30 * time.Second
)

type Metadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	ScopesSupported                  []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

type Config struct {
	IssuerURL                 string
	Audiences                 []string
	HTTPClient                *http.Client
	DiscoveryTimeout          time.Duration
	JWKSTimeout               time.Duration
	UnknownKIDRefreshInterval time.Duration
	Clock                     Clock
	Observer                  Observer
	Logger                    *slog.Logger
}

type Runtime struct {
	metadata  Metadata
	audiences map[string]struct{}
	transport transportClient
	keys      *keySet
	clock     Clock
	observer  Observer
	logger    *slog.Logger
}

type AccessTokenVerifier interface {
	VerifyAccessToken(context.Context, string) (AuthContext, error)
}

func New(ctx context.Context, cfg Config) (runtime *Runtime, resultErr error) {
	const operation = "core.discovery"
	if ctx == nil || ctx.Err() != nil {
		return nil, coreError(KindInvalidConfig, operation, 0, false)
	}
	issuerURL, audiences, err := validateRuntimeConfig(cfg)
	if err != nil {
		return nil, err
	}
	clock := cfg.Clock
	if nilcheck.IsNil(clock) {
		clock = RealClock{}
	}
	observer := cfg.Observer
	if nilcheck.IsNil(observer) {
		observer = NopObserver{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	discoveryTimeout := cfg.DiscoveryTimeout
	if discoveryTimeout == 0 {
		discoveryTimeout = defaultDiscoveryTimeout
	}
	jwksTimeout := cfg.JWKSTimeout
	if jwksTimeout == 0 {
		jwksTimeout = defaultJWKSTimeout
	}
	unknownKIDInterval := cfg.UnknownKIDRefreshInterval
	if unknownKIDInterval == 0 {
		unknownKIDInterval = defaultUnknownKIDDelay
	}
	runtime = &Runtime{
		audiences: audiences,
		transport: newTransportClient(cfg.HTTPClient),
		clock:     clock,
		observer:  observer,
		logger:    logger,
	}
	started := clock.Now()
	recorder := runtime
	defer func() { recorder.record(ctx, operation, resultErr, started) }()
	requestCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	request, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet,
		strings.TrimRight(issuerURL, "/")+"/.well-known/openid-configuration", nil)
	if requestErr != nil {
		return nil, coreError(KindInvalidConfig, operation, 0, false)
	}
	response, requestErr := runtime.transport.getJSON(request)
	if requestErr != nil {
		if errors.Is(requestErr, errTransportProtocol) {
			return nil, coreError(KindProtocol, operation, response.status, false)
		}
		return nil, coreError(KindIAMUnavailable, operation, 0, true)
	}
	if response.status != http.StatusOK {
		return nil, statusCoreError(operation, response.status)
	}
	var metadata Metadata
	if decodeJSON(response.body, &metadata) != nil {
		return nil, coreError(KindProtocol, operation, response.status, false)
	}
	if normalizeIssuer(metadata.Issuer) != normalizeIssuer(issuerURL) {
		return nil, coreError(KindInvalidConfig, operation, response.status, false)
	}
	allowLocalHTTP := isLoopbackHTTPURL(issuerURL)
	if err := validateMetadata(metadata, allowLocalHTTP); err != nil {
		return nil, err
	}
	runtime.metadata = cloneMetadata(metadata)
	runtime.keys = newKeySet(metadata.JWKSURI, runtime.transport, jwksTimeout, unknownKIDInterval, clock)
	return runtime, nil
}

func (r *Runtime) Metadata() Metadata {
	if r == nil {
		return Metadata{}
	}
	return cloneMetadata(r.metadata)
}

func (r *Runtime) AcceptsAudience(audience string) bool {
	if r == nil {
		return false
	}
	_, ok := r.audiences[strings.TrimSpace(audience)]
	return ok
}

func validateRuntimeConfig(cfg Config) (string, map[string]struct{}, *Error) {
	issuer := cfg.IssuerURL
	if issuer == "" || issuer != strings.TrimSpace(issuer) ||
		cfg.DiscoveryTimeout < 0 || cfg.JWKSTimeout < 0 || cfg.UnknownKIDRefreshInterval < 0 {
		return "", nil, coreError(KindInvalidConfig, "core.configure", 0, false)
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && !isLoopbackHTTP(parsed)) {
		return "", nil, coreError(KindInvalidConfig, "core.configure", 0, false)
	}
	audiences := make(map[string]struct{}, len(cfg.Audiences))
	for _, raw := range cfg.Audiences {
		audience := strings.TrimSpace(raw)
		if audience == "" {
			return "", nil, coreError(KindInvalidConfig, "core.configure", 0, false)
		}
		audiences[audience] = struct{}{}
	}
	if len(audiences) == 0 {
		return "", nil, coreError(KindInvalidConfig, "core.configure", 0, false)
	}
	return issuer, audiences, nil
}

func validateMetadata(metadata Metadata, allowLocalHTTP bool) *Error {
	if metadata.Issuer == "" || !slices.Contains(metadata.CodeChallengeMethodsSupported, "S256") ||
		!slices.Contains(metadata.IDTokenSigningAlgValuesSupported, "RS256") {
		return coreError(KindProtocol, "core.discovery", http.StatusOK, false)
	}
	for _, endpoint := range []string{
		metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.UserInfoEndpoint,
		metadata.JWKSURI, metadata.EndSessionEndpoint,
	} {
		if !validEndpoint(endpoint, allowLocalHTTP) {
			return coreError(KindProtocol, "core.discovery", http.StatusOK, false)
		}
	}
	return nil
}

func validEndpoint(raw string, allowLocalHTTP bool) bool {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	return parsed.Scheme == "https" || (allowLocalHTTP && isLoopbackHTTP(parsed))
}

func isLoopbackHTTPURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && isLoopbackHTTP(parsed)
}

func isLoopbackHTTP(parsed *url.URL) bool {
	if parsed.Scheme != "http" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeIssuer(raw string) string { return strings.TrimRight(raw, "/") }

func cloneMetadata(metadata Metadata) Metadata {
	metadata.ScopesSupported = append([]string(nil), metadata.ScopesSupported...)
	metadata.CodeChallengeMethodsSupported = append([]string(nil), metadata.CodeChallengeMethodsSupported...)
	metadata.IDTokenSigningAlgValuesSupported = append([]string(nil), metadata.IDTokenSigningAlgValuesSupported...)
	return metadata
}

func coreError(kind Kind, operation string, status int, retryable bool) *Error {
	return NewError(kind, operation, status, retryable, nil)
}

func statusCoreError(operation string, status int) *Error {
	if status == http.StatusUnauthorized {
		return coreError(KindUnauthenticated, operation, status, false)
	}
	if status == http.StatusForbidden {
		return coreError(KindForbidden, operation, status, false)
	}
	if status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
		return coreError(KindIAMUnavailable, operation, status, true)
	}
	return coreError(KindProtocol, operation, status, false)
}

func (r *Runtime) record(ctx context.Context, operation string, err error, started time.Time) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	duration := r.clock.Now().Sub(started)
	r.observer.Observe(ctx, Event{Operation: operation, Outcome: outcome, Duration: duration})
	r.logger.Info("iamcore operation", slog.String("operation", operation), slog.String("outcome", outcome), slog.Duration("duration", duration))
}
