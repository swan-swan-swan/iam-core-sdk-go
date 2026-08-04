package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

const maxOAuthResponseBytes = 1 << 20

type exchangedTokens struct {
	accessToken  string
	tokenType    string
	refreshToken string
	idToken      string
	expiresIn    int64
	expiresAt    time.Time
	scope        string
}

type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken json.RawMessage `json:"refresh_token"`
	IDToken      string          `json:"id_token"`
	ExpiresIn    int64           `json:"expires_in"`
	Scope        json.RawMessage `json:"scope"`
	Error        json.RawMessage `json:"error"`
}

type userInfo struct {
	subject       string
	username      string
	usernameSet   bool
	displayName   string
	displaySet    bool
	email         string
	emailSet      bool
	groups        []string
	groupsPresent bool
}

func (c *Client) exchange(ctx context.Context, code, verifier string) (tokens exchangedTokens, resultErr error) {
	const operation = "bff.exchange"
	started := c.clock.Now()
	defer func() { c.record(ctx, operation, resultErr, started) }()
	if ctx == nil || code == "" || code != strings.TrimSpace(code) || !validPKCEVerifier(verifier) {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, 0, false)
	}
	if err := ctx.Err(); err != nil {
		return exchangedTokens{}, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, c.tokenTimeout)
	defer cancel()
	secret, err := c.clientSecret.Secret(operationCtx)
	if contextErr := operationContextError(ctx, operationCtx, operation, 0); contextErr != nil {
		return exchangedTokens{}, contextErr
	}
	if err != nil {
		if contextErr := normalizedContextError(err); contextErr != nil {
			return exchangedTokens{}, contextErr
		}
		return exchangedTokens{}, bffError(core.KindInvalidConfig, operation, 0, false)
	}
	if secret == "" || secret != strings.TrimSpace(secret) {
		return exchangedTokens{}, bffError(core.KindInvalidConfig, operation, 0, false)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.redirectURL},
		"client_id":     {c.clientID},
		"client_secret": {secret},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(operationCtx, http.MethodPost, c.core.Metadata().TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, 0, false)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if contextErr := operationContextError(ctx, operationCtx, operation, 0); contextErr != nil {
			return exchangedTokens{}, contextErr
		}
		return exchangedTokens{}, bffError(core.KindIAMUnavailable, operation, 0, true)
	}
	receivedAt := c.clock.Now()
	defer response.Body.Close()
	body, err := readOAuthJSON(response)
	if err != nil {
		if contextErr := operationContextError(ctx, operationCtx, operation, response.StatusCode); contextErr != nil {
			return exchangedTokens{}, contextErr
		}
	}
	if response.StatusCode != http.StatusOK {
		var endpoint tokenResponse
		if err == nil && decodeUniqueJSON(body, &endpoint) == nil {
			oauthError, present, fieldErr := decodeOAuthError(endpoint.Error)
			if fieldErr != nil {
				return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
			}
			if present {
				return exchangedTokens{}, oauthEndpointError(operation, response.StatusCode, oauthError)
			}
		}
		return exchangedTokens{}, statusOAuthError(operation, response.StatusCode)
	}
	if err != nil {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	var decoded tokenResponse
	if decodeUniqueJSON(body, &decoded) != nil ||
		decoded.AccessToken == "" || decoded.AccessToken != strings.TrimSpace(decoded.AccessToken) ||
		decoded.TokenType != "Bearer" || decoded.IDToken == "" || decoded.IDToken != strings.TrimSpace(decoded.IDToken) ||
		decoded.ExpiresIn <= 0 || decoded.ExpiresIn > math.MaxInt64/int64(time.Second) {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	_, errorPresent, err := decodeOAuthError(decoded.Error)
	if err != nil || errorPresent {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	refreshToken, err := optionalNonemptyString(decoded.RefreshToken)
	if err != nil {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	scope, err := optionalString(decoded.Scope)
	if err != nil || (len(decoded.Scope) != 0 && !validScopeString(scope)) {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	return exchangedTokens{
		accessToken: decoded.AccessToken, tokenType: decoded.TokenType, refreshToken: refreshToken,
		idToken: decoded.IDToken, expiresIn: decoded.ExpiresIn,
		expiresAt: receivedAt.Add(time.Duration(decoded.ExpiresIn) * time.Second), scope: scope,
	}, nil
}

func decodeOAuthError(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, nil
	}
	var value string
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil || value == "" {
		return "", true, errors.New("invalid OAuth error")
	}
	return value, true, nil
}

func (c *Client) loadUserInfo(ctx context.Context, accessToken string) (identity userInfo, resultErr error) {
	const operation = "bff.userinfo"
	started := c.clock.Now()
	defer func() { c.record(ctx, operation, resultErr, started) }()
	if ctx == nil || accessToken == "" || accessToken != strings.TrimSpace(accessToken) {
		return userInfo{}, bffError(core.KindProtocol, operation, 0, false)
	}
	if err := ctx.Err(); err != nil {
		return userInfo{}, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, c.userInfoTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(operationCtx, http.MethodGet, c.core.Metadata().UserInfoEndpoint, nil)
	if err != nil {
		return userInfo{}, bffError(core.KindProtocol, operation, 0, false)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := c.httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if contextErr := operationContextError(ctx, operationCtx, operation, 0); contextErr != nil {
			return userInfo{}, contextErr
		}
		return userInfo{}, bffError(core.KindIAMUnavailable, operation, 0, true)
	}
	defer response.Body.Close()
	body, err := readOAuthJSON(response)
	if err != nil {
		if contextErr := operationContextError(ctx, operationCtx, operation, response.StatusCode); contextErr != nil {
			return userInfo{}, contextErr
		}
	}
	if response.StatusCode != http.StatusOK {
		return userInfo{}, statusOAuthError(operation, response.StatusCode)
	}
	if err != nil {
		return userInfo{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	var claims map[string]json.RawMessage
	if decodeUniqueJSON(body, &claims) != nil {
		return userInfo{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	if err := requiredStringClaim(claims, "sub", &identity.subject); err != nil {
		return userInfo{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	identity.usernameSet, err = optionalStringClaim(claims, "username", &identity.username)
	if err != nil {
		return userInfo{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	identity.displaySet, err = optionalStringClaim(claims, "display_name", &identity.displayName)
	if err != nil {
		return userInfo{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	identity.emailSet, err = optionalStringClaim(claims, "email", &identity.email)
	if err != nil {
		return userInfo{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	if raw, present := claims["groups"]; present {
		if json.Unmarshal(raw, &identity.groups) != nil || identity.groups == nil {
			return userInfo{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
		}
		identity.groups = normalizeGroups(identity.groups)
		identity.groupsPresent = true
	}
	return identity, nil
}

func readOAuthJSON(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("missing response")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return nil, errors.New("invalid content type")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxOAuthResponseBytes+1))
	if err != nil || len(body) > maxOAuthResponseBytes {
		return nil, errors.New("invalid body")
	}
	return body, nil
}

func optionalNonemptyString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || value == "" || value != strings.TrimSpace(value) {
		return "", errors.New("invalid string")
	}
	return value, nil
}

func optionalString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var value string
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
		return "", errors.New("invalid string")
	}
	return value, nil
}

func requiredStringClaim(claims map[string]json.RawMessage, name string, target *string) error {
	raw, present := claims[name]
	if !present || json.Unmarshal(raw, target) != nil || *target == "" || *target != strings.TrimSpace(*target) {
		return errors.New("invalid required claim")
	}
	return nil
}

func optionalStringClaim(claims map[string]json.RawMessage, name string, target *string) (bool, error) {
	raw, present := claims[name]
	if !present {
		return false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, target) != nil {
		return false, errors.New("invalid optional claim")
	}
	return true, nil
}

func statusOAuthError(operation string, status int) *core.Error {
	switch {
	case status == http.StatusUnauthorized:
		return bffError(core.KindUnauthenticated, operation, status, false)
	case status == http.StatusForbidden:
		return bffError(core.KindForbidden, operation, status, false)
	case status == http.StatusTooManyRequests || status >= http.StatusInternalServerError:
		return bffError(core.KindIAMUnavailable, operation, status, true)
	default:
		return bffError(core.KindProtocol, operation, status, false)
	}
}

func oauthEndpointError(operation string, status int, oauthError string) *core.Error {
	var result *core.Error
	switch oauthError {
	case "invalid_grant":
		result = bffError(core.KindUnauthenticated, operation, status, false)
		result.Reason = core.ReasonInvalidGrant
	case "invalid_client":
		result = bffError(core.KindUnauthenticated, operation, status, false)
	case "access_denied":
		result = bffError(core.KindForbidden, operation, status, false)
		result.Reason = core.ReasonAccessDenied
	case "temporarily_unavailable":
		result = bffError(core.KindIAMUnavailable, operation, status, true)
		result.Reason = core.ReasonTemporarilyUnavailable
	case "server_error":
		result = bffError(core.KindIAMUnavailable, operation, status, true)
	default:
		result = statusOAuthError(operation, status)
	}
	return result
}

func decodeUniqueJSON(body []byte, target any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("empty json")
	}
	validator := json.NewDecoder(bytes.NewReader(body))
	if err := consumeUniqueJSONValue(validator); err != nil {
		return err
	}
	var trailing any
	if validator.Decode(&trailing) != io.EOF {
		return errors.New("trailing json")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid json")
	}
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return errors.New("invalid object")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate key")
			}
			seen[name] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("invalid delimiter")
	}
	return nil
}
