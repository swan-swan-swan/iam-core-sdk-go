package oidc

import (
	"context"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
)

const task4Subject = "op_usr_0123456789abcdefgjk"

type testTokenSigner struct {
	PrivateKey *rsa.PrivateKey
	Issuer     string
	ClientID   string
	KeyID      string
}

func newVerificationClient(t *testing.T) (*Client, *testTokenSigner) {
	t.Helper()
	client, fake := newTestClientAndServer(t)
	return client, &testTokenSigner{
		PrivateKey: fake.key,
		Issuer:     fake.Server.URL,
		ClientID:   "client-1",
		KeyID:      "test-key",
	}
}

func (s *testTokenSigner) IDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	return s.token(t, jwt.SigningMethodRS256, claims)
}

func (s *testTokenSigner) token(t *testing.T, method jwt.SigningMethod, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(method, jwt.MapClaims(claims))
	token.Header["kid"] = s.KeyID
	signed, err := token.SignedString(s.PrivateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func (s *testTokenSigner) validClaims() map[string]any {
	return map[string]any{
		"iss":   s.Issuer,
		"aud":   []string{s.ClientID},
		"sub":   task4Subject,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "nonce-1",
	}
}

func TestVerifyIDTokenReturnsClaims(t *testing.T) {
	client, signer := newVerificationClient(t)
	claims := signer.validClaims()
	claims["sid"] = "session-1"
	claims["username"] = "alice"
	claims["email"] = "alice@example.test"
	claims["display_name"] = "Alice"
	claims["roles"] = []string{"platform_dev"}
	claims["scope"] = "openid profile roles"

	got, err := client.VerifyIDToken(t.Context(), signer.IDToken(t, claims), "nonce-1")
	if err != nil {
		t.Fatalf("VerifyIDToken() error = %v", err)
	}
	if got.Subject != task4Subject || got.Nonce != "nonce-1" || got.SessionID != "session-1" ||
		got.Username != "alice" || got.Email != "alice@example.test" || got.DisplayName != "Alice" ||
		got.Scope != "openid profile roles" || len(got.Roles) != 1 || got.Roles[0] != "platform_dev" {
		t.Fatalf("claims = %#v", got)
	}
}

func TestVerifyIDTokenRejectsNonceMismatch(t *testing.T) {
	client, signer := newVerificationClient(t)
	raw := signer.IDToken(t, map[string]any{
		"iss":   client.Metadata().Issuer,
		"aud":   []string{"client-1"},
		"sub":   task4Subject,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "nonce-from-token",
	})
	_, err := client.VerifyIDToken(context.Background(), raw, "different-nonce")
	assertProtocolErrorIsRedacted(t, err, raw, "nonce-from-token", "different-nonce")
}

func TestVerifyIDTokenRejectsWrongIssuer(t *testing.T) {
	client, signer := newVerificationClient(t)
	claims := signer.validClaims()
	claims["iss"] = "https://wrong-issuer.example/token-secret"
	raw := signer.IDToken(t, claims)
	_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
	assertProtocolErrorIsRedacted(t, err, raw, "wrong-issuer", "token-secret")
}

func TestVerifyIDTokenRejectsWrongAudience(t *testing.T) {
	client, signer := newVerificationClient(t)
	claims := signer.validClaims()
	claims["aud"] = []string{"different-client-secret"}
	raw := signer.IDToken(t, claims)
	_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
	assertProtocolErrorIsRedacted(t, err, raw, "different-client-secret")
}

func TestVerifyIDTokenRejectsExpiredToken(t *testing.T) {
	client, signer := newVerificationClient(t)
	claims := signer.validClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	raw := signer.IDToken(t, claims)
	_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
	assertProtocolErrorIsRedacted(t, err, raw)
}

func TestVerifyIDTokenRejectsWrongAlgorithm(t *testing.T) {
	client, signer := newVerificationClient(t)
	raw := signer.token(t, jwt.SigningMethodRS384, signer.validClaims())
	_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
	assertProtocolErrorIsRedacted(t, err, raw)
}

func TestVerifyIDTokenRejectsMissingSubject(t *testing.T) {
	client, signer := newVerificationClient(t)
	claims := signer.validClaims()
	delete(claims, "sub")
	raw := signer.IDToken(t, claims)
	_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
	assertProtocolErrorIsRedacted(t, err, raw)
}

func TestVerifyAccessTokenJWTAcceptsStringAndArrayAudience(t *testing.T) {
	for _, audience := range []any{"client-1", []string{"other", "client-1"}} {
		t.Run("", func(t *testing.T) {
			client, signer := newVerificationClient(t)
			raw := signer.IDToken(t, map[string]any{
				"iss":   signer.Issuer,
				"aud":   audience,
				"sub":   task4Subject,
				"jti":   "token-1",
				"scope": "openid profile",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"nbf":   time.Now().Add(-time.Minute).Unix(),
			})
			got, err := client.VerifyAccessTokenJWT(t.Context(), raw)
			if err != nil {
				t.Fatalf("VerifyAccessTokenJWT() error = %v", err)
			}
			if got.Subject != task4Subject || got.Issuer != signer.Issuer || got.TokenID != "token-1" ||
				got.Scope != "openid profile" || got.Expiry == 0 || len(got.Audience) == 0 {
				t.Fatalf("claims = %#v", got)
			}
		})
	}
}

func TestVerifyAccessTokenJWTRejectsInvalidRegisteredClaims(t *testing.T) {
	tests := map[string]func(map[string]any){
		"issuer": func(claims map[string]any) {
			claims["iss"] = "https://wrong.example/access-secret"
		},
		"audience": func(claims map[string]any) {
			claims["aud"] = []string{"wrong-client-secret"}
		},
		"expired": func(claims map[string]any) {
			claims["exp"] = time.Now().Add(-time.Minute).Unix()
		},
		"missing expiry": func(claims map[string]any) {
			delete(claims, "exp")
		},
		"not before": func(claims map[string]any) {
			claims["nbf"] = time.Now().Add(time.Hour).Unix()
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, signer := newVerificationClient(t)
			claims := map[string]any{
				"iss": signer.Issuer,
				"aud": []string{signer.ClientID},
				"sub": task4Subject,
				"exp": time.Now().Add(time.Hour).Unix(),
			}
			mutate(claims)
			raw := signer.IDToken(t, claims)
			_, err := client.VerifyAccessTokenJWT(t.Context(), raw)
			assertProtocolErrorIsRedacted(t, err, raw, "access-secret", "wrong-client-secret")
		})
	}
}

func TestVerifyAccessTokenJWTRejectsWrongAlgorithm(t *testing.T) {
	client, signer := newVerificationClient(t)
	raw := signer.token(t, jwt.SigningMethodRS384, map[string]any{
		"iss": signer.Issuer,
		"aud": signer.ClientID,
		"sub": task4Subject,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err := client.VerifyAccessTokenJWT(t.Context(), raw)
	assertProtocolErrorIsRedacted(t, err, raw)
}

func TestVerifyAccessTokenJWTRejectsMalformedAudience(t *testing.T) {
	client, signer := newVerificationClient(t)
	raw := signer.IDToken(t, map[string]any{
		"iss": signer.Issuer,
		"aud": []any{"client-1", 7},
		"sub": task4Subject,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err := client.VerifyAccessTokenJWT(t.Context(), raw)
	assertProtocolErrorIsRedacted(t, err, raw)
}

func assertProtocolErrorIsRedacted(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected protocol error")
	}
	typed, ok := err.(*sdkerr.Error)
	if !ok || typed.Kind != sdkerr.KindProtocol || typed.Cause != nil {
		t.Fatalf("error = %#v", err)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("error exposed %q: %v", value, err)
		}
	}
}
