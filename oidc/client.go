package oidc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
	"golang.org/x/oauth2"
)

const defaultTimeout = 5 * time.Second

type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

type SecretProvider interface {
	Secret(context.Context) (string, error)
}

type SecretProviderFunc func(context.Context) (string, error)

func (f SecretProviderFunc) Secret(ctx context.Context) (string, error) {
	return f(ctx)
}

func StaticSecret(value string) SecretProvider {
	return SecretProviderFunc(func(context.Context) (string, error) {
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("client secret is empty")
		}
		return value, nil
	})
}

type Config struct {
	IssuerURL      string
	ClientID       string
	SecretProvider SecretProvider
	RedirectURL    string
	Scopes         []string
	HTTPClient     *http.Client
	Timeout        time.Duration
	Hooks          observability.Hooks
	Logger         *slog.Logger
}

type Client struct {
	metadata       Metadata
	secretProvider SecretProvider
	oauthConfig    oauth2.Config
	transport      transport.Client
	timeout        time.Duration
	hooks          observability.Hooks
	logger         *slog.Logger
	keySet         *coreosoidc.RemoteKeySet
	verifier       *coreosoidc.IDTokenVerifier
}

func New(ctx context.Context, config Config) (result *Client, resultErr error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	hooks := config.Hooks
	if hooks == nil {
		hooks = observability.Nop{}
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	client := &Client{
		secretProvider: config.SecretProvider,
		transport:      transport.Client{HTTP: config.HTTPClient},
		timeout:        timeout,
		hooks:          hooks,
		logger:         logger,
	}

	started := time.Now()
	defer func() {
		duration := time.Since(started)
		client.observe(ctx, "oidc.discovery", outcome(resultErr), duration)
		client.log("oidc.discovery", outcome(resultErr), duration)
	}()
	metadata, correlation, err := client.discover(ctx, config.IssuerURL)
	if err != nil {
		return nil, withCorrelation(sanitizeError("oidc.discovery", err), correlation)
	}
	if normalizeIssuer(metadata.Issuer) != normalizeIssuer(config.IssuerURL) {
		err := sdkerr.New(sdkerr.KindInvalidConfig, "oidc.discovery", 0, false, nil)
		return nil, withCorrelation(err, correlation)
	}
	issuerURL, _ := url.Parse(config.IssuerURL)
	if err := validateMetadata(metadata, isLocalHTTP(issuerURL)); err != nil {
		return nil, withCorrelation(err, correlation)
	}

	client.metadata = metadata
	client.oauthConfig = oauth2.Config{
		ClientID:    config.ClientID,
		RedirectURL: config.RedirectURL,
		Scopes:      append([]string(nil), config.Scopes...),
		Endpoint: oauth2.Endpoint{
			AuthURL:   metadata.AuthorizationEndpoint,
			TokenURL:  metadata.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	jwksHTTPClient := &http.Client{
		Transport: boundedRoundTripper{client: client.transport},
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	keySetContext := coreosoidc.ClientContext(context.WithoutCancel(ctx), jwksHTTPClient)
	client.keySet = coreosoidc.NewRemoteKeySet(keySetContext, metadata.JWKSURI)
	client.verifier = coreosoidc.NewVerifier(metadata.Issuer, client.keySet, &coreosoidc.Config{
		ClientID: config.ClientID,
	})
	return client, nil
}

func (c *Client) Metadata() Metadata {
	metadata := c.metadata
	metadata.ScopesSupported = append([]string(nil), metadata.ScopesSupported...)
	return metadata
}

func (c *Client) discover(ctx context.Context, issuer string) (Metadata, transport.Correlation, error) {
	requestContext, cancel := c.withTimeout(ctx)
	defer cancel()
	discoveryURL := normalizeIssuer(issuer) + "/.well-known/openid-configuration"
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return Metadata{}, transport.Correlation{}, sdkerr.New(
			sdkerr.KindInvalidConfig,
			"oidc.discovery",
			0,
			false,
			nil,
		)
	}
	response, err := c.transport.Do(request)
	if err != nil {
		return Metadata{}, transport.Correlation{}, sanitizeError("oidc.discovery", err)
	}
	if response.StatusCode != http.StatusOK {
		return Metadata{}, response.Correlation, statusError("oidc.discovery", response.StatusCode)
	}
	var metadata Metadata
	if err := transport.DecodeJSON(response.Body, &metadata); err != nil {
		return Metadata{}, response.Correlation, sdkerr.New(
			sdkerr.KindProtocol,
			"oidc.discovery",
			response.StatusCode,
			false,
			nil,
		)
	}
	return metadata, response.Correlation, nil
}

func validateConfig(config Config) error {
	issuer := config.IssuerURL
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(config.ClientID) == "" || config.SecretProvider == nil ||
		strings.TrimSpace(config.RedirectURL) == "" {
		return sdkerr.New(sdkerr.KindInvalidConfig, "oidc.configure", 0, false, nil)
	}
	if config.Timeout < 0 {
		return sdkerr.New(sdkerr.KindInvalidConfig, "oidc.configure", 0, false, nil)
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Host == "" || (parsed.Scheme != "https" && !isLocalHTTP(parsed)) {
		return sdkerr.New(sdkerr.KindInvalidConfig, "oidc.configure", 0, false, nil)
	}
	hasOpenID := false
	for _, scope := range config.Scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return sdkerr.New(sdkerr.KindInvalidConfig, "oidc.configure", 0, false, nil)
	}
	return nil
}

func validateMetadata(metadata Metadata, allowLocalHTTP bool) *sdkerr.Error {
	endpoints := []string{
		metadata.AuthorizationEndpoint,
		metadata.TokenEndpoint,
		metadata.UserInfoEndpoint,
		metadata.JWKSURI,
		metadata.EndSessionEndpoint,
	}
	if strings.TrimSpace(metadata.Issuer) == "" {
		return sdkerr.New(sdkerr.KindProtocol, "oidc.discovery", http.StatusOK, false, nil)
	}
	for _, endpoint := range endpoints {
		if !validEndpoint(endpoint, allowLocalHTTP) {
			return sdkerr.New(sdkerr.KindProtocol, "oidc.discovery", http.StatusOK, false, nil)
		}
	}
	return nil
}

func validEndpoint(value string, allowLocalHTTP bool) bool {
	if value != strings.TrimSpace(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return false
	}
	return parsed.Scheme == "https" || (allowLocalHTTP && isLocalHTTP(parsed))
}

func isLocalHTTP(parsed *url.URL) bool {
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

func normalizeIssuer(value string) string {
	return strings.TrimSuffix(value, "/")
}

func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.timeout)
}

func (c *Client) observe(ctx context.Context, operation, result string, duration time.Duration) {
	c.hooks.Observe(ctx, observability.Event{
		Operation: operation,
		Outcome:   result,
		Duration:  duration,
	})
}

func (c *Client) log(operation, result string, duration time.Duration) {
	c.logger.Info("iamcore operation",
		slog.String("operation", operation),
		slog.String("outcome", result),
		slog.Duration("duration", duration),
	)
}

func outcome(err error) string {
	if err != nil {
		return "error"
	}
	return "success"
}

func statusError(operation string, status int) *sdkerr.Error {
	switch {
	case status == http.StatusUnauthorized:
		return sdkerr.New(sdkerr.KindUnauthenticated, operation, status, false, nil)
	case status == http.StatusForbidden:
		return sdkerr.New(sdkerr.KindForbidden, operation, status, false, nil)
	case status == http.StatusTooManyRequests || status >= http.StatusInternalServerError:
		return sdkerr.New(sdkerr.KindIAMUnavailable, operation, status, true, nil)
	default:
		return sdkerr.New(sdkerr.KindProtocol, operation, status, false, nil)
	}
}

func sanitizeError(operation string, err error) *sdkerr.Error {
	if typed, ok := err.(*sdkerr.Error); ok {
		return &sdkerr.Error{
			Kind:       typed.Kind,
			Operation:  operation,
			HTTPStatus: typed.HTTPStatus,
			RequestID:  safeCorrelationID(typed.RequestID),
			TraceID:    safeCorrelationID(typed.TraceID),
			DecisionID: safeCorrelationID(typed.DecisionID),
			Retryable:  typed.Retryable,
		}
	}
	return sdkerr.New(sdkerr.KindIAMUnavailable, operation, 0, true, nil)
}

func withCorrelation(err *sdkerr.Error, correlation transport.Correlation) *sdkerr.Error {
	err.RequestID = safeCorrelationID(correlation.RequestID)
	err.TraceID = safeCorrelationID(correlation.TraceID)
	return err
}

func safeCorrelationID(value string) string {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
		return ""
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("-_.:/", character):
		default:
			return ""
		}
	}
	return value
}

type boundedRoundTripper struct {
	client transport.Client
}

func (roundTripper boundedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := roundTripper.client.Do(request)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode:    response.StatusCode,
		Status:        fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode)),
		Header:        response.Header,
		Body:          io.NopCloser(bytes.NewReader(response.Body)),
		ContentLength: int64(len(response.Body)),
		Request:       request,
	}, nil
}
