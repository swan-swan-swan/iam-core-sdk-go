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

	requestContext, cancel := withTimeout(ctx, c.tokenUserInfoTimeout)
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
	sensitiveValues := append([]string{accessToken}, endpointQueryValues(endpoint.String())...)
	if response.StatusCode != 0 &&
		(response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices) {
		if err == nil {
			var envelope iamErrorEnvelope
			_ = transport.DecodeJSON(response.Body, &envelope)
		}
		statusErr := statusError(operation, response.StatusCode)
		return withSubmittedSafeCorrelation(statusErr, response.Correlation, sensitiveValues...)
	}
	if err != nil {
		transportErr := sanitizeError(operation, err)
		return withSubmittedSafeCorrelation(transportErr, response.Correlation, sensitiveValues...)
	}
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		if len(response.Body) != 0 {
			var successBody any
			if err := transport.DecodeJSON(response.Body, &successBody); err != nil {
				protocolErr := sdkerr.New(sdkerr.KindProtocol, operation, response.StatusCode, false, nil)
				return withSubmittedSafeCorrelation(protocolErr, response.Correlation, sensitiveValues...)
			}
		}
		return nil
	}
	protocolErr := sdkerr.New(sdkerr.KindProtocol, operation, response.StatusCode, false, nil)
	return withSubmittedSafeCorrelation(protocolErr, response.Correlation, sensitiveValues...)
}

type iamErrorEnvelope struct {
	Code      json.RawMessage `json:"code"`
	Message   json.RawMessage `json:"message"`
	Data      json.RawMessage `json:"data"`
	RequestID string          `json:"request_id"`
	TraceID   string          `json:"trace_id"`
}
