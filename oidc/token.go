package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
	"golang.org/x/oauth2"
)

type TokenSet struct {
	AccessToken       string
	TokenType         string
	RefreshToken      string
	IDToken           string
	AccessTokenExpiry time.Time
}

func (c *Client) AuthCodeURL(state string, nonce string) string {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(nonce) == "" {
		return ""
	}
	return c.oauthConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
}

func (c *Client) Exchange(ctx context.Context, code string) (TokenSet, error) {
	if strings.TrimSpace(code) == "" {
		return TokenSet{}, sdkerr.New(sdkerr.KindInvalidConfig, "oidc.exchange", 0, false, nil)
	}
	return c.requestToken(ctx, "oidc.exchange", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {c.oauthConfig.RedirectURL},
	}, "")
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (TokenSet, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return TokenSet{}, sdkerr.New(sdkerr.KindInvalidConfig, "oidc.refresh", 0, false, nil)
	}
	return c.requestToken(ctx, "oidc.refresh", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, refreshToken)
}

type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken json.RawMessage `json:"refresh_token"`
	IDToken      string          `json:"id_token"`
	ExpiresIn    int64           `json:"expires_in"`
	Error        string          `json:"error"`
	IAMCode      int             `json:"code"`
}

func (c *Client) requestToken(
	ctx context.Context,
	operation string,
	form url.Values,
	previousRefreshToken string,
) (tokens TokenSet, resultErr error) {
	started := time.Now()
	defer func() {
		duration := time.Since(started)
		c.observe(ctx, operation, outcome(resultErr), duration)
		c.log(operation, outcome(resultErr), duration)
	}()

	secret, err := c.secretProvider.Secret(ctx)
	if err != nil || strings.TrimSpace(secret) == "" {
		return TokenSet{}, sdkerr.New(sdkerr.KindInvalidConfig, operation, 0, false, nil)
	}
	form.Set("client_id", c.oauthConfig.ClientID)
	form.Set("client_secret", secret)

	requestContext, cancel := c.withTimeout(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		c.metadata.TokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return TokenSet{}, sdkerr.New(sdkerr.KindInvalidConfig, operation, 0, false, nil)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := c.transport.Do(request)
	if err != nil {
		return TokenSet{}, sanitizeError(operation, err)
	}
	var body tokenResponse
	if err := transport.DecodeJSON(response.Body, &body); err != nil {
		protocolErr := sdkerr.New(sdkerr.KindProtocol, operation, response.StatusCode, false, nil)
		return TokenSet{}, withFormSafeCorrelation(protocolErr, response.Correlation, form)
	}
	if response.StatusCode != http.StatusOK {
		endpointErr := tokenEndpointError(operation, response.StatusCode, body)
		return TokenSet{}, withFormSafeCorrelation(endpointErr, response.Correlation, form)
	}
	refreshToken, refreshTokenPresent, refreshTokenValid := decodeRefreshToken(body.RefreshToken)
	if body.Error != "" || body.IAMCode != 0 || strings.TrimSpace(body.AccessToken) == "" ||
		strings.TrimSpace(body.TokenType) == "" || body.ExpiresIn < 0 ||
		body.ExpiresIn > math.MaxInt64/int64(time.Second) || !refreshTokenValid {
		protocolErr := sdkerr.New(sdkerr.KindProtocol, operation, response.StatusCode, false, nil)
		return TokenSet{}, withFormSafeCorrelation(protocolErr, response.Correlation, form)
	}

	if !refreshTokenPresent {
		refreshToken = previousRefreshToken
	}
	tokens = TokenSet{
		AccessToken:  body.AccessToken,
		TokenType:    body.TokenType,
		RefreshToken: refreshToken,
		IDToken:      body.IDToken,
	}
	if body.ExpiresIn > 0 {
		tokens.AccessTokenExpiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	return tokens, nil
}

func decodeRefreshToken(raw json.RawMessage) (string, bool, bool) {
	if len(raw) == 0 {
		return "", false, true
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", true, false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", true, false
	}
	return value, true, true
}

func tokenEndpointError(
	operation string,
	status int,
	body tokenResponse,
) *sdkerr.Error {
	var err *sdkerr.Error
	switch body.Error {
	case "invalid_grant":
		err = sdkerr.New(sdkerr.KindUnauthenticated, operation, status, false, nil)
		err.Reason = sdkerr.ReasonInvalidGrant
	case "invalid_client":
		err = sdkerr.New(sdkerr.KindUnauthenticated, operation, status, false, nil)
	case "access_denied":
		err = sdkerr.New(sdkerr.KindForbidden, operation, status, false, nil)
	case "server_error", "temporarily_unavailable":
		err = sdkerr.New(sdkerr.KindIAMUnavailable, operation, status, true, nil)
	default:
		err = statusError(operation, status)
	}
	return err
}

func withFormSafeCorrelation(
	err *sdkerr.Error,
	correlation transport.Correlation,
	form url.Values,
) *sdkerr.Error {
	err = withCorrelation(err, correlation)
	for _, values := range form {
		for _, submitted := range values {
			if submitted == "" {
				continue
			}
			if strings.Contains(err.RequestID, submitted) {
				err.RequestID = ""
			}
			if strings.Contains(err.TraceID, submitted) {
				err.TraceID = ""
			}
		}
	}
	return err
}
