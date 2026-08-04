package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

// Do validates and executes exactly one authenticated management API request.
func (c *Client) Do(ctx context.Context, request Request, out any) (metadata Metadata, resultErr error) {
	started := time.Now()
	statusCode := 0
	operation := ""
	observeContext := ctx
	if observeContext == nil {
		observeContext = context.Background()
	}
	defer func() {
		outcome := "success"
		if resultErr != nil {
			outcome = string(errorKind(resultErr))
		}
		c.observe(observeContext, Event{
			Operation:  operation,
			Outcome:    outcome,
			StatusCode: statusCode,
			Duration:   time.Since(started),
		})
	}()

	if ctx == nil || !validOperation(request.Operation) {
		return Metadata{}, invalidArgumentError("")
	}
	operation = request.Operation
	if !validMethod(request.Method) || !validCanonicalPath(request.Path) || !validQuery(request.Query) || !validIdempotencyKey(request.IdempotencyKey) {
		return Metadata{}, invalidArgumentError(operation)
	}

	callContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	token, err := c.tokens.AccessToken(callContext)
	if err != nil || !validAccessToken(token) {
		return Metadata{}, &Error{Kind: KindUnauthenticated, Operation: operation}
	}

	var body []byte
	if request.Body != nil {
		body, err = json.Marshal(request.Body)
		if err != nil {
			return Metadata{}, invalidArgumentError(operation)
		}
	}

	target := c.requestURL(request.Path, request.Query)
	httpRequest, err := http.NewRequestWithContext(callContext, request.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return Metadata{}, invalidArgumentError(operation)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("Accept", "application/json")
	if request.Body != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	if request.IdempotencyKey != "" {
		httpRequest.Header.Set("Idempotency-Key", request.IdempotencyKey)
	}
	httpRequest.Header.Del("Cookie")

	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return Metadata{}, unavailableError(operation, statusCode)
	}
	if response == nil || response.Body == nil {
		return Metadata{}, unavailableError(operation, statusCode)
	}
	statusCode = response.StatusCode
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return Metadata{}, unavailableError(operation, statusCode)
	}
	if len(responseBody) > maxResponseBytes {
		return Metadata{}, protocolError(operation, statusCode)
	}
	return decodeEnvelope(responseBody, statusCode, operation, out)
}

func (c *Client) requestURL(requestPath string, query url.Values) *url.URL {
	target := *c.baseURL
	target.Path = strings.TrimSuffix(target.Path, "/") + requestPath
	target.RawPath = ""
	target.RawQuery = query.Encode()
	target.ForceQuery = false
	target.Fragment = ""
	return &target
}

func (c *Client) observe(ctx context.Context, event Event) {
	if c == nil || isNilInterface(c.observer) {
		return
	}
	defer func() {
		_ = recover()
	}()
	c.observer.Observe(ctx, event)
}

func validOperation(operation string) bool {
	if len(operation) > 128 || strings.TrimSpace(operation) != operation {
		return false
	}
	segments := strings.Split(operation, ".")
	if len(segments) < 2 || segments[0] != "management" {
		return false
	}
	for _, segment := range segments[1:] {
		if segment == "" {
			return false
		}
		for _, character := range segment {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func validMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func validCanonicalPath(requestPath string) bool {
	if !strings.HasPrefix(requestPath, "/api/v1/") || strings.Contains(requestPath, "\\") || strings.Contains(requestPath, "%") || path.Clean(requestPath) != requestPath {
		return false
	}
	parsed, err := url.ParseRequestURI(requestPath)
	return err == nil && parsed.Path == requestPath && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validQuery(query url.Values) bool {
	for key, values := range query {
		if key == "" || strings.TrimSpace(key) != key || containsControlCharacter(key) || len(values) == 0 {
			return false
		}
		for _, value := range values {
			if containsControlCharacter(value) {
				return false
			}
		}
	}
	return true
}

func validIdempotencyKey(key string) bool {
	if key == "" {
		return true
	}
	if len(key) > 255 || strings.TrimSpace(key) != key {
		return false
	}
	for _, character := range key {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validAccessToken(token string) bool {
	if token == "" || strings.TrimSpace(token) != token {
		return false
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func containsControlCharacter(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func invalidArgumentError(operation string) *Error {
	return &Error{Kind: KindInvalidArgument, Operation: operation}
}

func unavailableError(operation string, statusCode int) *Error {
	return &Error{Kind: KindIAMUnavailable, Operation: operation, StatusCode: statusCode, Retryable: true}
}

func errorKind(err error) Kind {
	var managementError *Error
	if errors.As(err, &managementError) && managementError != nil {
		return managementError.Kind
	}
	return KindProtocol
}
