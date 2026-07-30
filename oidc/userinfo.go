package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
)

func (c *Client) UserInfo(
	ctx context.Context,
	accessToken string,
) (identity Identity, resultErr error) {
	const operation = "oidc.userinfo"
	started := time.Now()
	defer func() {
		duration := time.Since(started)
		c.observe(ctx, operation, outcome(resultErr), duration)
		c.log(operation, outcome(resultErr), duration)
	}()

	if strings.TrimSpace(accessToken) == "" {
		return Identity{}, sdkerr.New(sdkerr.KindInvalidConfig, operation, 0, false, nil)
	}
	requestContext, cancel := withTimeout(ctx, c.tokenUserInfoTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, c.metadata.UserInfoEndpoint, nil)
	if err != nil {
		return Identity{}, sdkerr.New(sdkerr.KindProtocol, operation, 0, false, nil)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := c.transport.Do(request)
	sensitiveValues := append([]string{accessToken}, endpointQueryValues(c.metadata.UserInfoEndpoint)...)
	if response.StatusCode != 0 &&
		(response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices) {
		statusErr := statusError(operation, response.StatusCode)
		return Identity{}, withSubmittedSafeCorrelation(statusErr, response.Correlation, sensitiveValues...)
	}
	if err != nil {
		transportErr := sanitizeError(operation, err)
		return Identity{}, withSubmittedSafeCorrelation(transportErr, response.Correlation, sensitiveValues...)
	}
	var raw map[string]json.RawMessage
	if err := transport.DecodeJSON(response.Body, &raw); err != nil {
		protocolErr := sdkerr.New(sdkerr.KindProtocol, operation, response.StatusCode, false, nil)
		return Identity{}, withSubmittedSafeCorrelation(
			protocolErr,
			headerCorrelation(response.Header),
			sensitiveValues...,
		)
	}

	extraClaims := cloneRawClaims(raw)
	if err := decodeKnownClaim(raw, "sub", &identity.Subject); err != nil ||
		decodeKnownClaim(raw, "username", &identity.Username) != nil ||
		decodeKnownClaim(raw, "email", &identity.Email) != nil ||
		decodeKnownClaim(raw, "display_name", &identity.DisplayName) != nil ||
		decodeKnownClaim(raw, "roles", &identity.Roles) != nil ||
		strings.TrimSpace(identity.Subject) == "" {
		protocolErr := sdkerr.New(sdkerr.KindProtocol, operation, response.StatusCode, false, nil)
		return Identity{}, withSubmittedSafeCorrelation(
			protocolErr,
			headerCorrelation(response.Header),
			sensitiveValues...,
		)
	}
	for _, known := range []string{"sub", "username", "email", "display_name", "roles"} {
		delete(extraClaims, known)
	}
	identity.Roles = append([]string(nil), identity.Roles...)
	identity.Scopes = append([]string(nil), c.oauthConfig.Scopes...)
	identity.ExtraClaims = extraClaims
	return identity, nil
}

func decodeKnownClaim(claims map[string]json.RawMessage, name string, target any) error {
	raw, ok := claims[name]
	if !ok {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errInvalidKnownClaim
	}
	return json.Unmarshal(raw, target)
}

func cloneRawClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	cloned := make(map[string]json.RawMessage, len(claims))
	for name, raw := range claims {
		cloned[name] = append(json.RawMessage(nil), raw...)
	}
	return cloned
}

func withSubmittedSafeCorrelation(
	err *sdkerr.Error,
	correlation transport.Correlation,
	submitted ...string,
) *sdkerr.Error {
	err = withCorrelation(err, correlation)
	for _, value := range submitted {
		if value == "" {
			continue
		}
		if strings.Contains(err.RequestID, value) {
			err.RequestID = ""
		}
		if strings.Contains(err.TraceID, value) {
			err.TraceID = ""
		}
	}
	return err
}

func endpointQueryValues(endpoint string) []string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil
	}
	var values []string
	for _, entries := range parsed.Query() {
		values = append(values, entries...)
	}
	return values
}

func headerCorrelation(header http.Header) transport.Correlation {
	return transport.Correlation{RequestID: header.Get("X-Request-ID")}
}

var errInvalidKnownClaim = &knownClaimError{}

type knownClaimError struct{}

func (*knownClaimError) Error() string {
	return "invalid known claim"
}
