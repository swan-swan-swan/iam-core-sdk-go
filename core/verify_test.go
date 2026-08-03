package core_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/testkit"
)

func TestVerifyAccessTokenReturnsTypedGroupsAndActualScope(t *testing.T) {
	runtime, signer := newCoreRuntime(t)
	claims := signer.validClaims()
	claims["scope"] = "groups openid profile"
	claims["groups"] = []string{"ops", " ops ", "", "dev"}
	claims["username"] = "alice"
	claims["display_name"] = "Alice"
	claims["email"] = "hidden@example.test"
	raw := signer.AccessToken(t, claims)
	got, err := runtime.VerifyAccessToken(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Scopes, []string{"groups", "openid", "profile"}) || !slices.Equal(got.Groups, []string{"dev", "ops"}) {
		t.Fatalf("auth = %#v", got)
	}
	if got.Username != "alice" || got.DisplayName != "Alice" || got.Email != "" {
		t.Fatalf("scope-gated profile = %#v", got)
	}
}

func TestVerifyAccessTokenScopeGatesOptionalClaims(t *testing.T) {
	runtime, signer := newCoreRuntime(t)
	claims := signer.validClaims()
	claims["scope"] = "openid"
	claims["groups"] = []string{"ops"}
	claims["username"], claims["display_name"], claims["email"] = "alice", "Alice", "alice@example.test"
	got, err := runtime.VerifyAccessToken(t.Context(), signer.AccessToken(t, claims))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Groups) != 0 || got.Username != "" || got.DisplayName != "" || got.Email != "" {
		t.Fatalf("ungated claims leaked: %#v", got)
	}
}

func TestVerifyAccessTokenPreservesFractionalNumericDates(t *testing.T) {
	runtime, signer := newCoreRuntime(t)
	base := time.Now().Unix()
	claims := signer.validClaims()
	claims["iat"] = json.Number(strconv.FormatInt(base-60, 10) + ".125")
	claims["nbf"] = json.Number(strconv.FormatInt(base-30, 10) + ".25")
	claims["exp"] = json.Number(strconv.FormatInt(base+60, 10) + ".875")

	got, err := runtime.VerifyAccessToken(t.Context(), signer.AccessToken(t, claims))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(base-60, 125_000_000); !got.IssuedAt.Equal(want) {
		t.Fatalf("IssuedAt = %s, want %s", got.IssuedAt, want)
	}
	if want := time.Unix(base-30, 250_000_000); !got.NotBefore.Equal(want) {
		t.Fatalf("NotBefore = %s, want %s", got.NotBefore, want)
	}
	if want := time.Unix(base+60, 875_000_000); !got.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %s, want %s", got.ExpiresAt, want)
	}
}

func TestVerifyAccessTokenAcceptsStringAndArrayAudiences(t *testing.T) {
	for name, audience := range map[string]any{
		"string": "portal",
		"array":  []string{"another-audience", "portal"},
	} {
		t.Run(name, func(t *testing.T) {
			runtime, signer := newCoreRuntime(t)
			claims := signer.validClaims()
			claims["aud"] = audience
			got, err := runtime.VerifyAccessToken(t.Context(), signer.AccessToken(t, claims))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(got.Audience, "portal") {
				t.Fatalf("Audience = %v", got.Audience)
			}
		})
	}
}

func TestVerifyAccessTokenAcceptsExponentNumericDates(t *testing.T) {
	runtime, signer := newCoreRuntime(t)
	base := time.Now().Unix()
	claims := signer.validClaims()
	claims["iat"] = json.Number(strconv.FormatInt(base-60, 10) + "e0")
	claims["exp"] = json.Number(strconv.FormatInt(base+60, 10) + "e0")
	got, err := runtime.VerifyAccessToken(t.Context(), signer.AccessToken(t, claims))
	if err != nil {
		t.Fatal(err)
	}
	if !got.IssuedAt.Equal(time.Unix(base-60, 0)) || !got.ExpiresAt.Equal(time.Unix(base+60, 0)) {
		t.Fatalf("numeric dates = %s, %s", got.IssuedAt, got.ExpiresAt)
	}
}

func TestVerifyAccessTokenRejectsMalformedAudiencesAndMissingRegisteredClaims(t *testing.T) {
	tests := map[string]func(map[string]any){
		"missing issuer":   func(claims map[string]any) { delete(claims, "iss") },
		"missing audience": func(claims map[string]any) { delete(claims, "aud") },
		"empty array":      func(claims map[string]any) { claims["aud"] = []string{} },
		"empty member":     func(claims map[string]any) { claims["aud"] = []string{"portal", ""} },
		"mixed array":      func(claims map[string]any) { claims["aud"] = []any{"portal", 7} },
		"number":           func(claims map[string]any) { claims["aud"] = 7 },
		"null":             func(claims map[string]any) { claims["aud"] = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runtime, signer := newCoreRuntime(t)
			claims := signer.validClaims()
			mutate(claims)
			if _, err := runtime.VerifyAccessToken(t.Context(), signer.AccessToken(t, claims)); err == nil {
				t.Fatal("VerifyAccessToken() error = nil")
			}
		})
	}
}

func TestVerifyAccessTokenRejectsInvalidNumericDates(t *testing.T) {
	tests := map[string]func(map[string]any){
		"iat null":          func(claims map[string]any) { claims["iat"] = nil },
		"iat string":        func(claims map[string]any) { claims["iat"] = "1700000000" },
		"iat boolean":       func(claims map[string]any) { claims["iat"] = true },
		"iat array":         func(claims map[string]any) { claims["iat"] = []int64{1700000000} },
		"iat object":        func(claims map[string]any) { claims["iat"] = map[string]int64{"value": 1700000000} },
		"iat overflow":      func(claims map[string]any) { claims["iat"] = json.Number("9223372036854775808") },
		"iat underflow":     func(claims map[string]any) { claims["iat"] = json.Number("-9223372036854775809") },
		"iat huge exponent": func(claims map[string]any) { claims["iat"] = json.Number("1e100") },
		"exp null":          func(claims map[string]any) { claims["exp"] = nil },
		"nbf null":          func(claims map[string]any) { claims["nbf"] = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runtime, signer := newCoreRuntime(t)
			claims := signer.validClaims()
			mutate(claims)
			if _, err := runtime.VerifyAccessToken(t.Context(), signer.AccessToken(t, claims)); err == nil {
				t.Fatal("VerifyAccessToken() error = nil")
			}
		})
	}
}

func TestVerifyAccessTokenRejectsInvalidTokensWithoutLeakingValues(t *testing.T) {
	runtime, signer := newCoreRuntime(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func() string{
		"wrong issuer": func() string {
			c := signer.validClaims()
			c["iss"] = "https://token-secret.example"
			return signer.AccessToken(t, c)
		},
		"wrong audience": func() string {
			c := signer.validClaims()
			c["aud"] = "audience-secret"
			return signer.AccessToken(t, c)
		},
		"wrong kid": func() string {
			copy := *signer
			copy.KeyID = "kid-secret"
			return copy.AccessToken(t, copy.validClaims())
		},
		"wrong alg": func() string { return signer.token(t, jwt.SigningMethodRS384, signer.validClaims()) },
		"wrong signature": func() string {
			copy := *signer
			copy.PrivateKey = otherKey
			return copy.AccessToken(t, copy.validClaims())
		},
		"missing sub": func() string { c := signer.validClaims(); delete(c, "sub"); return signer.AccessToken(t, c) },
		"missing jti": func() string { c := signer.validClaims(); delete(c, "jti"); return signer.AccessToken(t, c) },
		"missing iat": func() string { c := signer.validClaims(); delete(c, "iat"); return signer.AccessToken(t, c) },
		"missing exp": func() string { c := signer.validClaims(); delete(c, "exp"); return signer.AccessToken(t, c) },
		"future nbf": func() string {
			c := signer.validClaims()
			c["nbf"] = time.Now().Add(time.Hour).Unix()
			return signer.AccessToken(t, c)
		},
		"expired": func() string {
			c := signer.validClaims()
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			return signer.AccessToken(t, c)
		},
		"duplicate header": func() string {
			return signer.rawToken(t, `{"alg":"RS256","kid":"test-key","kid":"header-secret"}`, signer.validClaims())
		},
		"nested duplicate header": func() string {
			return signer.rawToken(t, `{"alg":"RS256","kid":"test-key","future":{"x":1,"x":2}}`, signer.validClaims())
		},
	}
	for name, makeToken := range tests {
		t.Run(name, func(t *testing.T) {
			raw := makeToken()
			_, err := runtime.VerifyAccessToken(t.Context(), raw)
			if err == nil {
				t.Fatal("VerifyAccessToken() error = nil")
			}
			var typed *core.Error
			if !errors.As(err, &typed) || typed.Kind != core.KindUnauthenticated {
				t.Fatalf("error = %#v", err)
			}
			testkit.AssertNoLeak(t, err.Error(), raw, "token-secret", "audience-secret", "kid-secret", "header-secret")
		})
	}
}

func TestVerifyIDTokenNonceAndRefreshedSemantics(t *testing.T) {
	runtime, signer := newCoreRuntime(t)
	claims := signer.validClaims()
	claims["nonce"] = "nonce-1"
	claims["scope"] = "openid email"
	claims["email"] = "alice@example.test"
	raw := signer.AccessToken(t, claims)
	got, err := runtime.VerifyIDToken(t.Context(), raw, "nonce-1")
	if err != nil || got.Email != "alice@example.test" {
		t.Fatalf("VerifyIDToken() = %#v, %v", got, err)
	}
	if _, err := runtime.VerifyIDToken(t.Context(), raw, ""); err == nil {
		t.Fatal("empty expected nonce accepted")
	}
	if _, err := runtime.VerifyIDToken(t.Context(), raw, "different-secret"); err == nil {
		t.Fatal("nonce mismatch error = nil")
	} else {
		testkit.AssertNoLeak(t, err.Error(), "different-secret")
	}
	delete(claims, "nonce")
	if _, err := runtime.VerifyRefreshedIDToken(t.Context(), signer.AccessToken(t, claims)); err != nil {
		t.Fatalf("VerifyRefreshedIDToken() error = %v", err)
	}
}

func TestVerificationLogsDoNotContainTokenOrNonce(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	var output bytes.Buffer
	runtime, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client(),
		Logger: slog.New(slog.NewTextHandler(&output, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	signer := &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
	claims := signer.validClaims()
	claims["nonce"] = "nonce-from-token-secret"
	raw := signer.AccessToken(t, claims)
	_, err = runtime.VerifyIDToken(t.Context(), raw, "expected-nonce-secret")
	if err == nil {
		t.Fatal("VerifyIDToken() error = nil")
	}
	testkit.AssertNoLeak(t, output.String(), raw, "nonce-from-token-secret", "expected-nonce-secret")
}
