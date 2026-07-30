package oidc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
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

	if strings.TrimSpace(expectedNonce) == "" {
		return IDTokenClaims{}, verificationError(operation)
	}
	token, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return IDTokenClaims{}, verificationError(operation)
	}
	if err := token.Claims(&claims); err != nil {
		return IDTokenClaims{}, verificationError(operation)
	}
	if strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.Nonce) == "" ||
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

	return c.verifyAccessTokenJWTAt(ctx, rawAccessToken, time.Now())
}

func (c *Client) verifyAccessTokenJWTAt(
	ctx context.Context,
	rawAccessToken string,
	now time.Time,
) (AccessTokenClaims, error) {
	const operation = "oidc.verify_access_token"
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
	expiry, err := decodeNumericDate(wire.Expiry, true)
	if err != nil {
		return AccessTokenClaims{}, verificationError(operation)
	}
	notBefore, err := decodeNumericDate(wire.NotBefore, false)
	if err != nil {
		return AccessTokenClaims{}, verificationError(operation)
	}
	nowValue := numericDateFromTime(now)
	if wire.Issuer != c.metadata.Issuer || !containsAudience(audience, c.oauthConfig.ClientID) ||
		expiry.value.Cmp(nowValue) <= 0 ||
		(notBefore != nil && notBefore.value.Cmp(nowValue) > 0) {
		return AccessTokenClaims{}, verificationError(operation)
	}
	return AccessTokenClaims{
		Subject:  wire.Subject,
		Issuer:   wire.Issuer,
		Audience: append([]string(nil), audience...),
		TokenID:  wire.TokenID,
		Scope:    wire.Scope,
		Expiry:   expiry.unixSeconds,
	}, nil
}

type accessTokenClaims struct {
	Subject   string          `json:"sub"`
	Issuer    string          `json:"iss"`
	Audience  json.RawMessage `json:"aud"`
	TokenID   string          `json:"jti"`
	Scope     string          `json:"scope"`
	Expiry    json.RawMessage `json:"exp"`
	NotBefore json.RawMessage `json:"nbf"`
}

type numericDate struct {
	value       *big.Rat
	unixSeconds int64
}

func decodeNumericDate(raw json.RawMessage, required bool) (*numericDate, error) {
	if len(raw) == 0 {
		if required {
			return nil, errInvalidNumericDate
		}
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errInvalidNumericDate
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, errInvalidNumericDate
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errInvalidNumericDate
	}
	number, ok := decoded.(json.Number)
	if !ok {
		return nil, errInvalidNumericDate
	}
	value, ok := new(big.Rat).SetString(number.String())
	if !ok ||
		value.Cmp(new(big.Rat).SetInt64(-1<<63)) < 0 ||
		value.Cmp(new(big.Rat).SetInt64(1<<63-1)) > 0 {
		return nil, errInvalidNumericDate
	}
	whole := new(big.Int).Quo(value.Num(), value.Denom())
	if !whole.IsInt64() {
		return nil, errInvalidNumericDate
	}
	return &numericDate{value: value, unixSeconds: whole.Int64()}, nil
}

func numericDateFromTime(value time.Time) *big.Rat {
	seconds := new(big.Rat).SetInt64(value.Unix())
	fraction := new(big.Rat).SetFrac64(int64(value.Nanosecond()), int64(time.Second))
	return seconds.Add(seconds, fraction)
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
var errInvalidNumericDate = &numericDateError{}

type audienceError struct{}

func (*audienceError) Error() string {
	return "invalid audience"
}

type numericDateError struct{}

func (*numericDateError) Error() string {
	return "invalid numeric date"
}

func verificationError(operation string) *sdkerr.Error {
	return sdkerr.New(sdkerr.KindProtocol, operation, 0, false, nil)
}
