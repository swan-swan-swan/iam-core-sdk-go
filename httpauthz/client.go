package httpauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/nilcheck"
)

const (
	defaultPDPTimeout  = 5 * time.Second
	decideOperation    = "httpauthz.decide"
	configureOperation = "httpauthz.configure"
)

type PDPConfig struct {
	IssuerURL  string
	HTTPClient *http.Client
	Timeout    time.Duration
	Observer   core.Observer
	Logger     *slog.Logger
}

type PDPClient struct {
	endpoint   string
	httpClient *http.Client
	timeout    time.Duration
	observer   core.Observer
	logger     *slog.Logger
}

func NewPDPClient(cfg PDPConfig) (*PDPClient, error) {
	endpoint, err := decisionEndpoint(cfg.IssuerURL)
	if err != nil || cfg.Timeout < 0 {
		return nil, newPDPError(core.KindInvalidConfig, configureOperation, 0, false)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultPDPTimeout
	}
	observer := cfg.Observer
	if nilcheck.IsNil(observer) {
		observer = core.NopObserver{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &PDPClient{
		endpoint:   endpoint,
		httpClient: cloneHTTPClient(cfg.HTTPClient),
		timeout:    timeout,
		observer:   observer,
		logger:     logger,
	}, nil
}

func (c *PDPClient) Decide(ctx context.Context, tokens core.TokenSource, route Route) (decision Decision, resultErr error) {
	if c == nil {
		return Decision{}, newPDPError(core.KindInvalidConfig, decideOperation, 0, false)
	}
	started := time.Now()
	defer func() { c.record(ctx, resultErr, started) }()
	if ctx == nil || c.httpClient == nil || c.endpoint == "" || c.timeout <= 0 || nilcheck.IsNil(tokens) || !validRoute(route) {
		return Decision{}, newPDPError(core.KindInvalidConfig, decideOperation, 0, false)
	}
	if ctx.Err() != nil {
		return Decision{}, ctx.Err()
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	accessToken, err := tokens.AccessToken(requestCtx)
	if contextErr := decideContextError(ctx, requestCtx, 0); contextErr != nil {
		return Decision{}, contextErr
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return Decision{}, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return Decision{}, context.DeadlineExceeded
		}
		return Decision{}, sanitizeTokenSourceError(err)
	}
	if !validAccessToken(accessToken) {
		return Decision{}, newPDPError(core.KindUnauthenticated, decideOperation, 0, false)
	}

	payload, err := json.Marshal(decisionRequest{
		ResourceServer: route.resourceServer,
		Resource:       route.resource,
		HTTPMethod:     route.method,
	})
	if err != nil {
		return Decision{}, newPDPError(core.KindProtocol, decideOperation, 0, false)
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Decision{}, newPDPError(core.KindInvalidConfig, decideOperation, 0, false)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := c.httpClient.Do(request)
	if err != nil {
		if contextErr := decideContextError(ctx, requestCtx, 0); contextErr != nil {
			return Decision{}, contextErr
		}
		return Decision{}, newPDPError(core.KindIAMUnavailable, decideOperation, 0, true)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Decision{}, decisionStatusError(response.StatusCode)
	}
	if contextErr := decideContextError(ctx, requestCtx, response.StatusCode); contextErr != nil {
		return Decision{}, contextErr
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxDecisionResponseBytes+1))
	if readErr != nil {
		if contextErr := decideContextError(ctx, requestCtx, response.StatusCode); contextErr != nil {
			return Decision{}, contextErr
		}
		return Decision{}, newPDPError(core.KindIAMUnavailable, decideOperation, response.StatusCode, true)
	}
	if contextErr := decideContextError(ctx, requestCtx, response.StatusCode); contextErr != nil {
		return Decision{}, contextErr
	}
	if int64(len(body)) > maxDecisionResponseBytes {
		return Decision{}, newPDPError(core.KindProtocol, decideOperation, response.StatusCode, false)
	}
	if !isJSONMediaType(response.Header.Get("Content-Type")) {
		return Decision{}, newPDPError(core.KindProtocol, decideOperation, response.StatusCode, false)
	}
	decision, err = decodeDecision(body)
	if err != nil {
		return Decision{}, newPDPError(core.KindProtocol, decideOperation, response.StatusCode, false)
	}
	return decision, nil
}

func decideContextError(callerCtx, operationCtx context.Context, status int) error {
	if err := callerCtx.Err(); err != nil {
		return err
	}
	if operationCtx.Err() != nil {
		return newPDPError(core.KindIAMUnavailable, decideOperation, status, true)
	}
	return nil
}

func decisionEndpoint(issuer string) (string, error) {
	if issuer == "" || issuer != strings.TrimSpace(issuer) || !utf8.ValidString(issuer) || strings.ContainsFunc(issuer, unicode.IsControl) {
		return "", errors.New("invalid issuer")
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(issuer, "#") {
		return "", errors.New("invalid issuer")
	}
	if parsed.Scheme != "https" && !isLoopbackHTTP(parsed) {
		return "", errors.New("invalid issuer")
	}
	return strings.TrimRight(issuer, "/") + "/authorization/v1/decisions", nil
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

func cloneHTTPClient(injected *http.Client) *http.Client {
	if injected == nil {
		injected = &http.Client{}
	}
	cloned := *injected
	cloned.Jar = nil
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cloned
}

func validRoute(route Route) bool {
	if !route.compiled || !validRouteMethod(route.method) {
		return false
	}
	return validRouteValue(route.resourceServer) && validRouteValue(route.resource)
}

func validRouteMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func validRouteValue(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func validAccessToken(token string) bool {
	return token != "" && token == strings.TrimSpace(token) && utf8.ValidString(token) &&
		!strings.ContainsFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

func isJSONMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"))
}

func decisionStatusError(status int) *core.Error {
	switch status {
	case http.StatusUnauthorized:
		return newPDPError(core.KindUnauthenticated, decideOperation, status, false)
	case http.StatusServiceUnavailable:
		return newPDPError(core.KindIAMUnavailable, decideOperation, status, true)
	default:
		return newPDPError(core.KindProtocol, decideOperation, status, false)
	}
}

func sanitizeTokenSourceError(err error) *core.Error {
	var typed *core.Error
	if !errors.As(err, &typed) || typed == nil {
		return newPDPError(core.KindUnauthenticated, decideOperation, 0, false)
	}
	status := typed.HTTPStatus
	if status < 0 || status > 999 {
		status = 0
	}
	switch typed.Kind {
	case core.KindIAMUnavailable, core.KindSessionUnavailable:
		return newPDPError(typed.Kind, decideOperation, status, true)
	case core.KindUnauthenticated:
		return newPDPError(core.KindUnauthenticated, decideOperation, status, false)
	default:
		return newPDPError(core.KindUnauthenticated, decideOperation, 0, false)
	}
}

func newPDPError(kind core.Kind, operation string, status int, retryable bool) *core.Error {
	return core.NewError(kind, operation, status, retryable, nil)
}

func (c *PDPClient) record(ctx context.Context, err error, started time.Time) {
	if c.observer == nil || c.logger == nil {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	duration := time.Since(started)
	if ctx == nil {
		ctx = context.Background()
	}
	c.observer.Observe(ctx, core.Event{Operation: decideOperation, Outcome: outcome, Duration: duration})
	c.logger.Info("iamcore operation", slog.String("operation", decideOperation), slog.String("outcome", outcome), slog.Duration("duration", duration))
}
