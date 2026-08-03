package testkit

import (
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuedAt = int64(1_600_000_000)
	testExpires  = int64(4_000_000_000)
)

// SignAccessToken returns a valid RS256 access token for audience using the
// current scope and groups fixture. The issuer's private key is never exposed.
func (i *Issuer) SignAccessToken(audience string) string {
	i.t.Helper()
	response, key, serial := i.tokenSigningSnapshot()
	raw, err := signTestToken(key, i.URL(), audience, response, "access", "", serial)
	if err != nil {
		i.t.Fatal("sign test access token")
	}
	return raw
}

// SignIDToken returns a valid RS256 ID token for audience and nonce using the
// current scope and groups fixture. The issuer's private key is never exposed.
func (i *Issuer) SignIDToken(audience, nonce string) string {
	i.t.Helper()
	response, key, serial := i.tokenSigningSnapshot()
	raw, err := signTestToken(key, i.URL(), audience, response, "id", nonce, serial)
	if err != nil {
		i.t.Fatal("sign test ID token")
	}
	return raw
}

func (i *Issuer) tokenSigningSnapshot() (TokenResponse, *rsa.PrivateKey, uint64) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.serial++
	return cloneTokenResponse(i.tokenResponse), i.key, i.serial
}

func signTestToken(
	key *rsa.PrivateKey,
	issuer, audience string,
	response TokenResponse,
	kind, nonce string,
	serial uint64,
) (string, error) {
	claims := jwt.MapClaims{
		"sub": testSubject, "iss": issuer, "aud": audience, "jti": fmt.Sprintf("test-%s-%d", kind, serial),
		"iat": testIssuedAt, "exp": testExpires, "scope": response.Scope,
		"username": "test-user", "display_name": "Test User", "email": "test@example.test",
	}
	if response.Groups != nil {
		claims["groups"] = cloneStrings(response.Groups)
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKeyID
	return token.SignedString(key)
}
