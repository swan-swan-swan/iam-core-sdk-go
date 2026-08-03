package core

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"slices"
	"strings"
	"time"
)

type tokenClaims struct {
	Subject     string          `json:"sub"`
	Issuer      string          `json:"iss"`
	Audience    json.RawMessage `json:"aud"`
	TokenID     string          `json:"jti"`
	IssuedAt    json.RawMessage `json:"iat"`
	NotBefore   json.RawMessage `json:"nbf"`
	ExpiresAt   json.RawMessage `json:"exp"`
	Nonce       string          `json:"nonce"`
	Scope       string          `json:"scope"`
	Groups      []string        `json:"groups"`
	Username    string          `json:"username"`
	DisplayName string          `json:"display_name"`
	Email       string          `json:"email"`
}

func (r *Runtime) VerifyAccessToken(ctx context.Context, raw string) (auth AuthContext, resultErr error) {
	return r.verifyToken(ctx, raw, "core.verify_access_token", "", false)
}

func (r *Runtime) VerifyIDToken(ctx context.Context, raw, expectedNonce string) (auth AuthContext, resultErr error) {
	return r.verifyToken(ctx, raw, "core.verify_id_token", expectedNonce, true)
}

func (r *Runtime) VerifyRefreshedIDToken(ctx context.Context, raw string) (auth AuthContext, resultErr error) {
	return r.verifyToken(ctx, raw, "core.verify_refreshed_id_token", "", false)
}

func (r *Runtime) verifyToken(ctx context.Context, raw, operation, expectedNonce string, requireNonce bool) (auth AuthContext, resultErr error) {
	if r == nil {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	started := r.clock.Now()
	defer func() { r.record(ctx, operation, resultErr, started) }()
	if ctx != nil && ctx.Err() != nil {
		return AuthContext{}, ctx.Err()
	}
	if ctx == nil || strings.TrimSpace(raw) == "" ||
		(requireNonce && strings.TrimSpace(expectedNonce) == "") {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	payload, err := r.keys.verifySignature(ctx, raw)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return AuthContext{}, err
		}
		if errors.Is(err, errJWKSUnavailable) {
			return AuthContext{}, coreError(KindIAMUnavailable, operation, 0, true)
		}
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	var claims tokenClaims
	if json.Unmarshal(payload, &claims) != nil {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	audience, err := decodeAudience(claims.Audience)
	if err != nil {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	issuedAt, err := decodeNumericDate(claims.IssuedAt, true)
	if err != nil {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	notBefore, err := decodeNumericDate(claims.NotBefore, false)
	if err != nil {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	expiresAt, err := decodeNumericDate(claims.ExpiresAt, true)
	if err != nil {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	now := numericDateFromTime(r.clock.Now())
	if strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.Issuer) == "" ||
		strings.TrimSpace(claims.TokenID) == "" || normalizeIssuer(claims.Issuer) != normalizeIssuer(r.metadata.Issuer) ||
		!r.acceptsAnyAudience(audience) || expiresAt.value.Cmp(now) <= 0 ||
		(notBefore != nil && notBefore.value.Cmp(now) > 0) {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	if requireNonce && (strings.TrimSpace(claims.Nonce) == "" ||
		subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1) {
		return AuthContext{}, coreError(KindUnauthenticated, operation, 0, false)
	}
	scopes := strings.Fields(claims.Scope)
	auth = AuthContext{
		Subject: claims.Subject, Issuer: claims.Issuer, Audience: append([]string(nil), audience...),
		TokenID: claims.TokenID, IssuedAt: issuedAt.asTime(), ExpiresAt: expiresAt.asTime(),
		Scopes: append([]string(nil), scopes...),
	}
	if notBefore != nil {
		auth.NotBefore = notBefore.asTime()
	}
	if slices.Contains(scopes, "profile") {
		auth.Username, auth.DisplayName = claims.Username, claims.DisplayName
	}
	if slices.Contains(scopes, "email") {
		auth.Email = claims.Email
	}
	if slices.Contains(scopes, "groups") {
		auth.Groups = normalizeGroups(claims.Groups)
	}
	return auth, nil
}

func (r *Runtime) acceptsAnyAudience(audiences []string) bool {
	for _, audience := range audiences {
		if _, ok := r.audiences[audience]; ok {
			return true
		}
	}
	return false
}

func normalizeGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	unique := make(map[string]struct{}, len(groups))
	for _, raw := range groups {
		if group := strings.TrimSpace(raw); group != "" {
			unique[group] = struct{}{}
		}
	}
	normalized := make([]string, 0, len(unique))
	for group := range unique {
		normalized = append(normalized, group)
	}
	slices.Sort(normalized)
	return normalized
}

type numericDate struct {
	value       *big.Rat
	unixSeconds int64
	nanoseconds int64
}

func decodeNumericDate(raw json.RawMessage, required bool) (*numericDate, error) {
	if len(raw) == 0 {
		if required {
			return nil, errors.New("missing numeric date")
		}
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("invalid numeric date")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if decoder.Decode(&decoded) != nil {
		return nil, errors.New("invalid numeric date")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("invalid numeric date")
	}
	number, ok := decoded.(json.Number)
	if !ok {
		return nil, errors.New("invalid numeric date")
	}
	value, ok := new(big.Rat).SetString(number.String())
	if !ok || value.Cmp(new(big.Rat).SetInt64(-1<<63)) < 0 || value.Cmp(new(big.Rat).SetInt64(1<<63-1)) > 0 {
		return nil, errors.New("invalid numeric date")
	}
	whole := new(big.Int).Quo(value.Num(), value.Denom())
	if !whole.IsInt64() {
		return nil, errors.New("invalid numeric date")
	}
	wholeValue := new(big.Rat).SetInt(whole)
	fraction := new(big.Rat).Sub(value, wholeValue)
	scaledNanos := new(big.Rat).Mul(fraction, new(big.Rat).SetInt64(int64(time.Second)))
	nanos := new(big.Int).Quo(scaledNanos.Num(), scaledNanos.Denom())
	if !nanos.IsInt64() {
		return nil, errors.New("invalid numeric date")
	}
	return &numericDate{value: value, unixSeconds: whole.Int64(), nanoseconds: nanos.Int64()}, nil
}

func (date *numericDate) asTime() time.Time {
	return time.Unix(date.unixSeconds, date.nanoseconds)
}

func numericDateFromTime(value time.Time) *big.Rat {
	seconds := new(big.Rat).SetInt64(value.Unix())
	fraction := new(big.Rat).SetFrac64(int64(value.Nanosecond()), int64(time.Second))
	return seconds.Add(seconds, fraction)
}

func decodeAudience(raw json.RawMessage) ([]string, error) {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		if single == "" {
			return nil, errors.New("invalid audience")
		}
		return []string{single}, nil
	}
	var multiple []string
	if json.Unmarshal(raw, &multiple) != nil || len(multiple) == 0 {
		return nil, errors.New("invalid audience")
	}
	for _, audience := range multiple {
		if audience == "" {
			return nil, errors.New("invalid audience")
		}
	}
	return multiple, nil
}

type protectedHeader struct{ keyID string }

func parseProtectedHeader(raw string) (protectedHeader, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return protectedHeader{}, errors.New("invalid header")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || rejectDuplicateJSON(header) != nil {
		return protectedHeader{}, errors.New("invalid header")
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(header, &values) != nil {
		return protectedHeader{}, errors.New("invalid header")
	}
	var algorithm, keyID string
	if rawAlgorithm, ok := values["alg"]; !ok || json.Unmarshal(rawAlgorithm, &algorithm) != nil || algorithm != "RS256" {
		return protectedHeader{}, errors.New("invalid header")
	}
	if rawKeyID, ok := values["kid"]; !ok || json.Unmarshal(rawKeyID, &keyID) != nil || strings.TrimSpace(keyID) == "" {
		return protectedHeader{}, errors.New("invalid header")
	}
	return protectedHeader{keyID: keyID}, nil
}

func rejectDuplicateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
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
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
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
