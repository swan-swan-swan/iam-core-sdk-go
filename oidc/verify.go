package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
)

type Identity struct {
	Subject     string
	Username    string
	Email       string
	DisplayName string
	Roles       []string
	Scopes      []string
	ExtraClaims map[string]json.RawMessage
}

type IDTokenClaims struct {
	Subject     string   `json:"sub"`
	Nonce       string   `json:"nonce"`
	SessionID   string   `json:"sid"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Scope       string   `json:"scope"`
}

type AccessTokenClaims struct {
	Subject  string   `json:"sub"`
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	TokenID  string   `json:"jti"`
	Scope    string   `json:"scope"`
	Expiry   int64    `json:"exp"`
}

func (c *Client) VerifyIDToken(
	ctx context.Context,
	rawIDToken string,
	expectedNonce string,
) (claims IDTokenClaims, resultErr error) {
	const operation = "oidc.verify_id_token"
	started := time.Now()
	defer func() {
		duration := time.Since(started)
		c.observe(ctx, operation, outcome(resultErr), duration)
		c.log(operation, outcome(resultErr), duration)
	}()

	token, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return IDTokenClaims{}, verificationError(operation)
	}
	if err := token.Claims(&claims); err != nil {
		return IDTokenClaims{}, verificationError(operation)
	}
	if strings.TrimSpace(claims.Subject) == "" ||
		subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return IDTokenClaims{}, verificationError(operation)
	}
	claims.Roles = append([]string(nil), claims.Roles...)
	return claims, nil
}

// VerifyAccessTokenJWT verifies the JWT signature and registered token claims.
// Signature validity does not prove revocation status or authorization; callers
// that authenticate requests must use the online UserInfo endpoint.
func (c *Client) VerifyAccessTokenJWT(
	ctx context.Context,
	rawAccessToken string,
) (claims AccessTokenClaims, resultErr error) {
	const operation = "oidc.verify_access_token"
	started := time.Now()
	defer func() {
		duration := time.Since(started)
		c.observe(ctx, operation, outcome(resultErr), duration)
		c.log(operation, outcome(resultErr), duration)
	}()

	if !usesRS256(rawAccessToken) {
		return AccessTokenClaims{}, verificationError(operation)
	}
	payload, err := c.keySet.VerifySignature(ctx, rawAccessToken)
	if err != nil {
		return AccessTokenClaims{}, verificationError(operation)
	}
	var wire accessTokenClaims
	if err := json.Unmarshal(payload, &wire); err != nil {
		return AccessTokenClaims{}, verificationError(operation)
	}
	audience, err := decodeAudience(wire.Audience)
	if err != nil {
		return AccessTokenClaims{}, verificationError(operation)
	}
	now := time.Now()
	if wire.Issuer != c.metadata.Issuer || !containsAudience(audience, c.oauthConfig.ClientID) ||
		wire.Expiry == 0 || !now.Before(time.Unix(wire.Expiry, 0)) ||
		(wire.NotBefore != nil && now.Before(time.Unix(*wire.NotBefore, 0))) {
		return AccessTokenClaims{}, verificationError(operation)
	}
	return AccessTokenClaims{
		Subject:  wire.Subject,
		Issuer:   wire.Issuer,
		Audience: append([]string(nil), audience...),
		TokenID:  wire.TokenID,
		Scope:    wire.Scope,
		Expiry:   wire.Expiry,
	}, nil
}

type accessTokenClaims struct {
	Subject   string          `json:"sub"`
	Issuer    string          `json:"iss"`
	Audience  json.RawMessage `json:"aud"`
	TokenID   string          `json:"jti"`
	Scope     string          `json:"scope"`
	Expiry    int64           `json:"exp"`
	NotBefore *int64          `json:"nbf"`
}

func usesRS256(rawToken string) bool {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var value struct {
		Algorithm string `json:"alg"`
	}
	return json.Unmarshal(header, &value) == nil && value.Algorithm == "RS256"
}

func decodeAudience(raw json.RawMessage) ([]string, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, errInvalidAudience
		}
		return []string{single}, nil
	}
	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err != nil || len(multiple) == 0 {
		return nil, errInvalidAudience
	}
	for _, audience := range multiple {
		if audience == "" {
			return nil, errInvalidAudience
		}
	}
	return multiple, nil
}

func containsAudience(audiences []string, expected string) bool {
	for _, audience := range audiences {
		if subtle.ConstantTimeCompare([]byte(audience), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

var errInvalidAudience = &audienceError{}

type audienceError struct{}

func (*audienceError) Error() string {
	return "invalid audience"
}

func verificationError(operation string) *sdkerr.Error {
	return sdkerr.New(sdkerr.KindProtocol, operation, 0, false, nil)
}
