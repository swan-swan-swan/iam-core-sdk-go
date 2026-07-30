// Package authz provides fail-closed, per-request authorization decisions.
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
)

const (
	decisionPath   = "/authorization/v1/decisions"
	defaultTimeout = 5 * time.Second
	operation      = "authz.decide"
)

// Permission identifies the resource and HTTP action to authorize.
type Permission struct {
	ResourceServer string
	Resource       string
	HTTPMethod     string
}

// Decision is the IAM policy decision. A denied decision has nil error.
type Decision struct {
	ID         string
	Allowed    bool
	ReasonCode string
	RequestID  string
	TraceID    string
}

// Config configures a decision client. Endpoint, when empty, is derived from
// IssuerURL using the fixed IAM decision path.
type Config struct {
	IssuerURL  string
	Endpoint   string
	HTTPClient *http.Client
	Timeout    time.Duration
	Hooks      observability.Hooks
	Logger     *slog.Logger
}

// Client makes one independent PDP decision request for every Decide call.
type Client struct {
	endpoint  string
	transport transport.Client
	timeout   time.Duration
	hooks     observability.Hooks
	logger    *slog.Logger
}

// New validates the configured issuer and endpoint and constructs a decision
// client. HTTP is permitted only for explicit localhost or loopback endpoints.
func New(config Config) (*Client, error) {
	issuer, validIssuer := parseIssuer(config.IssuerURL)
	if config.Timeout < 0 || !validIssuer {
		return nil, decisionError(sdkerr.KindInvalidConfig, "authz.configure", 0, false, transport.Correlation{}, nil)
	}
	endpoint := config.Endpoint
	if endpoint == "" {
		issuer.Path = strings.TrimSuffix(issuer.Path, "/") + decisionPath
		issuer.RawPath = ""
		endpoint = issuer.String()
	}
	if !validEndpoint(endpoint) {
		return nil, decisionError(sdkerr.KindInvalidConfig, "authz.configure", 0, false, transport.Correlation{}, nil)
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
	return &Client{
		endpoint:  endpoint,
		transport: transport.Client{HTTP: config.HTTPClient},
		timeout:   timeout,
		hooks:     hooks,
		logger:    logger,
	}, nil
}

// Decide asks IAM for one fresh decision. It neither caches nor retries; any
// transport or protocol failure returns an error and never becomes an allow.
func (c *Client) Decide(ctx context.Context, accessToken string, permission Permission) (decision Decision, resultErr error) {
	started := time.Now()
	var correlation transport.Correlation
	defer func() {
		duration := time.Since(started)
		outcome := decisionOutcome(resultErr, decision)
		c.hooks.Observe(ctx, observability.Event{Operation: operation, Outcome: outcome, Duration: duration})
		c.log(outcome, duration, correlation)
	}()

	if !validInput(accessToken) || !validInput(permission.ResourceServer) || !validInput(permission.Resource) || !validMethod(permission.HTTPMethod) {
		return Decision{}, decisionError(sdkerr.KindInvalidConfig, operation, 0, false, transport.Correlation{}, nil)
	}
	payload, err := json.Marshal(decisionRequest{
		ResourceServer: permission.ResourceServer,
		Resource:       permission.Resource,
		HTTPMethod:     permission.HTTPMethod,
	})
	if err != nil {
		return Decision{}, decisionError(sdkerr.KindProtocol, operation, 0, false, transport.Correlation{}, nil)
	}
	requestContext, cancel := c.withTimeout(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Decision{}, decisionError(sdkerr.KindInvalidConfig, operation, 0, false, transport.Correlation{}, nil)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := c.transport.Do(request)
	correlation = sanitizeCorrelation(response.Correlation, accessToken, permission, c.endpoint)
	if response.StatusCode != 0 && (response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices) {
		return Decision{}, statusError(response.StatusCode, correlation)
	}
	if err != nil {
		return Decision{}, transportError(err, response.StatusCode, correlation)
	}
	parsed, err := decodeDecision(response.Body)
	if err != nil {
		return Decision{}, decisionError(sdkerr.KindProtocol, operation, response.StatusCode, false, correlation, nil)
	}
	correlation = mergeCorrelation(correlation, parsed.correlation, accessToken, permission, c.endpoint)
	if strings.TrimSpace(parsed.id) == "" || strings.TrimSpace(parsed.reasonCode) == "" {
		return Decision{}, decisionError(sdkerr.KindProtocol, operation, response.StatusCode, false, correlation, nil)
	}
	decision = Decision{
		ID:         parsed.id,
		Allowed:    parsed.allowed,
		ReasonCode: parsed.reasonCode,
		RequestID:  correlation.RequestID,
		TraceID:    correlation.TraceID,
	}
	return decision, nil
}

type decisionRequest struct {
	ResourceServer string `json:"resource_server"`
	Resource       string `json:"resource"`
	HTTPMethod     string `json:"http_method"`
}

type decodedDecision struct {
	id          string
	allowed     bool
	reasonCode  string
	correlation transport.Correlation
}

func decodeDecision(body []byte) (decodedDecision, error) {
	if err := rejectDuplicateJSON(body); err != nil {
		return decodedDecision{}, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return decodedDecision{}, err
	}
	if rawCode, isEnvelope := root["code"]; isEnvelope {
		var code int
		if err := json.Unmarshal(rawCode, &code); err != nil || code != 0 {
			return decodedDecision{}, errors.New("invalid envelope")
		}
		data, present := root["data"]
		if !present {
			return decodedDecision{}, errors.New("missing envelope data")
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(data, &nested); err != nil {
			return decodedDecision{}, err
		}
		result, err := decodeDecisionFields(nested)
		if err != nil {
			return decodedDecision{}, err
		}
		correlation, err := correlationFromMap(root)
		if err != nil {
			return decodedDecision{}, err
		}
		result.correlation = correlation
		return result, nil
	}
	return decodeDecisionFields(root)
}

func decodeDecisionFields(values map[string]json.RawMessage) (decodedDecision, error) {
	var result decodedDecision
	if err := requiredString(values, "decision_id", &result.id); err != nil ||
		requiredBoolean(values, "allowed", &result.allowed) != nil ||
		requiredString(values, "reason_code", &result.reasonCode) != nil {
		return decodedDecision{}, errors.New("invalid decision")
	}
	correlation, err := correlationFromMap(values)
	if err != nil {
		return decodedDecision{}, err
	}
	result.correlation = correlation
	return result, nil
}

func requiredString(values map[string]json.RawMessage, name string, target *string) error {
	raw, present := values[name]
	if !present || json.Unmarshal(raw, target) != nil || strings.TrimSpace(*target) == "" {
		return errors.New("missing required string")
	}
	return nil
}

func requiredBoolean(values map[string]json.RawMessage, name string, target *bool) error {
	raw, present := values[name]
	if !present || json.Unmarshal(raw, target) != nil || (!bytes.Equal(raw, []byte("true")) && !bytes.Equal(raw, []byte("false"))) {
		return errors.New("missing required boolean")
	}
	return nil
}

func correlationFromMap(values map[string]json.RawMessage) (transport.Correlation, error) {
	var correlation transport.Correlation
	if err := optionalString(values, "request_id", &correlation.RequestID); err != nil {
		return transport.Correlation{}, err
	}
	if err := optionalString(values, "trace_id", &correlation.TraceID); err != nil {
		return transport.Correlation{}, err
	}
	return correlation, nil
}

func optionalString(values map[string]json.RawMessage, name string, target *string) error {
	raw, present := values[name]
	if !present {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("invalid optional string")
	}
	return json.Unmarshal(raw, target)
}

func statusError(status int, correlation transport.Correlation) *sdkerr.Error {
	if status == http.StatusUnauthorized {
		return decisionError(sdkerr.KindUnauthenticated, operation, status, false, correlation, nil)
	}
	if status >= http.StatusInternalServerError && status <= 599 {
		return decisionError(sdkerr.KindIAMUnavailable, operation, status, true, correlation, nil)
	}
	return decisionError(sdkerr.KindProtocol, operation, status, false, correlation, nil)
}

func transportError(err error, status int, correlation transport.Correlation) *sdkerr.Error {
	var typed *sdkerr.Error
	if errors.As(err, &typed) {
		return decisionError(typed.Kind, operation, typed.HTTPStatus, typed.Retryable, correlation, nil)
	}
	return decisionError(sdkerr.KindIAMUnavailable, operation, status, true, correlation, nil)
}

func decisionError(kind sdkerr.Kind, operation string, status int, retryable bool, correlation transport.Correlation, cause error) *sdkerr.Error {
	return &sdkerr.Error{
		Kind:       kind,
		Operation:  operation,
		HTTPStatus: status,
		Retryable:  retryable,
		RequestID:  safeCorrelationID(correlation.RequestID),
		TraceID:    safeCorrelationID(correlation.TraceID),
		DecisionID: "",
		Cause:      cause,
	}
}

func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

func (c *Client) log(outcome string, duration time.Duration, correlation transport.Correlation) {
	c.logger.Info("iamcore authorization decision",
		slog.String("operation", operation),
		slog.String("outcome", outcome),
		slog.Duration("duration", duration),
		slog.String("request_id", safeCorrelationID(correlation.RequestID)),
		slog.String("trace_id", safeCorrelationID(correlation.TraceID)),
	)
}

func decisionOutcome(err error, decision Decision) string {
	if err != nil {
		return "error"
	}
	if decision.Allowed {
		return "allow"
	}
	return "deny"
}

func validEndpoint(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || containsControl(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return false
	}
	return parsed.Scheme == "https" || isLocalHTTP(parsed)
}

func parseIssuer(value string) (url.URL, bool) {
	if !validEndpoint(value) {
		return url.URL{}, false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil {
		return url.URL{}, false
	}
	return *parsed, true
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

func validInput(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && !containsControlOrWhitespace(value)
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func containsControlOrWhitespace(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func validMethod(method string) bool {
	switch method {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions,
		http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace:
		return true
	default:
		return false
	}
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

func sanitizeCorrelation(correlation transport.Correlation, token string, permission Permission, endpoint string) transport.Correlation {
	return mergeCorrelation(transport.Correlation{}, correlation, token, permission, endpoint)
}

func mergeCorrelation(first, second transport.Correlation, token string, permission Permission, endpoint string) transport.Correlation {
	result := first
	if result.RequestID == "" {
		result.RequestID = second.RequestID
	}
	if result.TraceID == "" {
		result.TraceID = second.TraceID
	}
	for _, value := range []string{token, permission.ResourceServer, permission.Resource, permission.HTTPMethod} {
		if value != "" && strings.Contains(result.RequestID, value) {
			result.RequestID = ""
		}
		if value != "" && strings.Contains(result.TraceID, value) {
			result.TraceID = ""
		}
	}
	if parsed, err := url.Parse(endpoint); err == nil {
		for _, values := range parsed.Query() {
			for _, value := range values {
				if value != "" && strings.Contains(result.RequestID, value) {
					result.RequestID = ""
				}
				if value != "" && strings.Contains(result.TraceID, value) {
					result.TraceID = ""
				}
			}
		}
	}
	result.RequestID = safeCorrelationID(result.RequestID)
	result.TraceID = safeCorrelationID(result.TraceID)
	return result
}

// rejectDuplicateJSON validates exactly one JSON document and rejects duplicate
// object member names at every nesting level before permissive field decoding.
func rejectDuplicateJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter, ok := token.(json.Delim); {
	case ok && delimiter == '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := seen[name]; exists {
				return errors.New("duplicate object key")
			}
			seen[name] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case ok && delimiter == '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case ok:
		return errors.New("unexpected delimiter")
	default:
		return nil
	}
}
