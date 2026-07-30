package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
)

func (c *Client) Logout(
	ctx context.Context,
	accessToken string,
	idTokenHint string,
) (resultErr error) {
	const operation = "oidc.logout"
	started := time.Now()
	defer func() {
		duration := time.Since(started)
		c.observe(ctx, operation, outcome(resultErr), duration)
		c.log(operation, outcome(resultErr), duration)
	}()

	if strings.TrimSpace(idTokenHint) == "" {
		return sdkerr.New(sdkerr.KindInvalidConfig, operation, 0, false, nil)
	}
	endpoint, err := url.Parse(c.metadata.EndSessionEndpoint)
	if err != nil {
		return sdkerr.New(sdkerr.KindProtocol, operation, 0, false, nil)
	}
	query := endpoint.Query()
	query.Set("id_token_hint", idTokenHint)
	endpoint.RawQuery = query.Encode()

	requestContext, cancel := c.withTimeout(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return sdkerr.New(sdkerr.KindProtocol, operation, 0, false, nil)
	}
	request.Header.Set("Accept", "application/json")
	if strings.TrimSpace(accessToken) != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	response, err := c.transport.Do(request)
	if err != nil {
		return sanitizeError(operation, err)
	}
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return nil
	}

	var envelope iamErrorEnvelope
	if err := transport.DecodeJSON(response.Body, &envelope); err != nil {
		protocolErr := sdkerr.New(sdkerr.KindProtocol, operation, response.StatusCode, false, nil)
		sensitiveValues := append([]string{accessToken}, endpointQueryValues(endpoint.String())...)
		return withSubmittedSafeCorrelation(protocolErr, response.Correlation, sensitiveValues...)
	}
	statusErr := statusError(operation, response.StatusCode)
	sensitiveValues := append([]string{accessToken}, endpointQueryValues(endpoint.String())...)
	return withSubmittedSafeCorrelation(statusErr, response.Correlation, sensitiveValues...)
}

type iamErrorEnvelope struct {
	Code      json.RawMessage `json:"code"`
	Message   json.RawMessage `json:"message"`
	Data      json.RawMessage `json:"data"`
	RequestID string          `json:"request_id"`
	TraceID   string          `json:"trace_id"`
}
