package applicationhandoff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/internal/nilcheck"
)

const (
	defaultTimeout       = 5 * time.Second
	maxResponseBodyBytes = 1 << 20
	createOperation      = "applicationhandoff.create"
	configureOperation   = "applicationhandoff.configure"
)

var (
	decisionIDPattern    = regexp.MustCompile(`^dec_[A-Za-z0-9_-]{1,60}$`)
	correlationIDPattern = regexp.MustCompile(`^op_cor_[A-Za-z0-9_-]{1,52}$`)
)

// Config 定义 Application Handoff Client 的不可变运行配置。
type Config struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
	Observer   core.Observer
}

// Client 调用 IAM Core 的单用途 Application Handoff Runtime API。
type Client struct {
	endpoint   string
	httpClient *http.Client
	timeout    time.Duration
	observer   core.Observer
}

// New 校验端点并克隆调用方 HTTP Client；克隆实例不使用 Cookie Jar，也不跟随重定向。
func New(config Config) (*Client, error) {
	endpoint, err := handoffEndpoint(config.BaseURL)
	if err != nil || config.Timeout < 0 {
		return nil, handoffError(core.KindInvalidConfig, configureOperation, 0, false)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	cloned := *client
	cloned.Jar = nil
	cloned.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	observer := config.Observer
	if nilcheck.IsNil(observer) {
		observer = core.NopObserver{}
	}
	return &Client{endpoint: endpoint, httpClient: &cloned, timeout: timeout, observer: observer}, nil
}

// Create 使用当前请求的用户 Access Token 创建短时一次性 Handoff。
func (client *Client) Create(ctx context.Context, tokens core.TokenSource, input CreateInput) (output CreateOutput, resultErr error) {
	started := time.Now()
	defer func() { client.observe(ctx, resultErr, started) }()
	if client == nil || client.httpClient == nil || client.endpoint == "" || client.timeout <= 0 || ctx == nil || nilcheck.IsNil(tokens) || !validInput(input) {
		return CreateOutput{}, handoffError(core.KindInvalidConfig, createOperation, 0, false)
	}
	if err := ctx.Err(); err != nil {
		return CreateOutput{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	token, err := tokens.AccessToken(requestContext)
	if contextErr := operationContextError(ctx, requestContext, 0); contextErr != nil {
		return CreateOutput{}, contextErr
	}
	if err != nil || !validBearerToken(token) {
		return CreateOutput{}, handoffError(core.KindUnauthenticated, createOperation, 0, false)
	}
	payload, err := json.Marshal(createRequest(input))
	if err != nil {
		return CreateOutput{}, handoffError(core.KindProtocol, createOperation, 0, false)
	}
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, client.endpoint, bytes.NewReader(payload))
	if err != nil {
		return CreateOutput{}, handoffError(core.KindInvalidConfig, createOperation, 0, false)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.httpClient.Do(request)
	if err != nil {
		if contextErr := operationContextError(ctx, requestContext, 0); contextErr != nil {
			return CreateOutput{}, contextErr
		}
		return CreateOutput{}, handoffError(core.KindIAMUnavailable, createOperation, 0, true)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return CreateOutput{}, statusError(response.StatusCode)
	}
	if contextErr := operationContextError(ctx, requestContext, response.StatusCode); contextErr != nil {
		return CreateOutput{}, contextErr
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes+1))
	if err != nil {
		return CreateOutput{}, handoffError(core.KindIAMUnavailable, createOperation, response.StatusCode, true)
	}
	if len(body) > maxResponseBodyBytes || !jsonMediaType(response.Header.Get("Content-Type")) {
		return CreateOutput{}, handoffError(core.KindProtocol, createOperation, response.StatusCode, false)
	}
	var envelope struct {
		Code int            `json:"code"`
		Data createResponse `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&envelope); err != nil || envelope.Code != 0 || decoder.Decode(&struct{}{}) != io.EOF || !validCreateResponse(envelope.Data) {
		return CreateOutput{}, handoffError(core.KindProtocol, createOperation, response.StatusCode, false)
	}
	return CreateOutput{HandoffID: envelope.Data.HandoffID, LaunchURL: envelope.Data.LaunchURL, ExpiresIn: time.Duration(envelope.Data.ExpiresIn) * time.Second}, nil
}

func validInput(input CreateInput) bool {
	return validOpenID(input.ApplicationOpenID, "op_app_") && decisionIDPattern.MatchString(input.DecisionID) && correlationIDPattern.MatchString(input.CorrelationID)
}

func validCreateResponse(response createResponse) bool {
	if !validOpenID(response.HandoffID, "op_hnd_") || response.ExpiresIn <= 0 || response.ExpiresIn > 300 {
		return false
	}
	parsed, err := url.Parse(response.LaunchURL)
	return err == nil && parsed.IsAbs() && parsed.Host != "" && parsed.User == nil && parsed.Fragment == "" && (parsed.Scheme == "https" || isLoopbackHTTP(parsed))
}

func validOpenID(value, prefix string) bool {
	if len(value) != 26 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func handoffEndpoint(baseURL string) (string, error) {
	if baseURL == "" || baseURL != strings.TrimSpace(baseURL) {
		return "", errors.New("invalid base url")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Scheme != "https" && !isLoopbackHTTP(parsed)) {
		return "", errors.New("invalid base url")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/v1/application-handoffs"
	parsed.RawPath = ""
	return parsed.String(), nil
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

func validBearerToken(token string) bool {
	if token == "" {
		return false
	}
	body := false
	padding := false
	for index := 0; index < len(token); index++ {
		character := token[index]
		if character == '=' {
			if !body {
				return false
			}
			padding = true
			continue
		}
		if padding || !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("-._~+/", rune(character))) {
			return false
		}
		body = true
	}
	return body
}

func jsonMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"))
}

func statusError(status int) *core.Error {
	switch {
	case status == http.StatusUnauthorized:
		return handoffError(core.KindUnauthenticated, createOperation, status, false)
	case status == http.StatusForbidden:
		return handoffError(core.KindForbidden, createOperation, status, false)
	case status >= 500:
		return handoffError(core.KindIAMUnavailable, createOperation, status, true)
	default:
		return handoffError(core.KindProtocol, createOperation, status, false)
	}
}

func operationContextError(caller, operation context.Context, status int) error {
	if err := caller.Err(); err != nil {
		return err
	}
	if operation.Err() != nil {
		return handoffError(core.KindIAMUnavailable, createOperation, status, true)
	}
	return nil
}

func handoffError(kind core.Kind, operation string, status int, retryable bool) *core.Error {
	return core.NewError(kind, operation, status, retryable, nil)
}

func (client *Client) observe(ctx context.Context, err error, started time.Time) {
	if client == nil || client.observer == nil {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() { _ = recover() }()
	client.observer.Observe(ctx, core.Event{Operation: createOperation, Outcome: outcome, CredentialSource: string(core.CredentialBearer), Duration: time.Since(started)})
}
