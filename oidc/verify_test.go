package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
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

func (s *testTokenSigner) rawToken(t *testing.T, payload string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"RS256","kid":"` + s.KeyID + `","typ":"JWT"}`),
	)
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign raw token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (s *testTokenSigner) rawTokenWithHeader(t *testing.T, header, payload string) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign raw token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
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

func TestVerifyIDTokenRejectsEmptyOrWhitespaceExpectedNonce(t *testing.T) {
	for name, nonce := range map[string]string{"empty": "", "whitespace": " \t"} {
		t.Run(name, func(t *testing.T) {
			client, signer := newVerificationClient(t)
			claims := signer.validClaims()
			claims["nonce"] = nonce
			raw := signer.IDToken(t, claims)
			_, err := client.VerifyIDToken(t.Context(), raw, nonce)
			assertProtocolErrorIsRedacted(t, err, raw, nonce)
		})
	}
}

func TestVerifyIDTokenRejectsAbsentOrEmptyTokenNonce(t *testing.T) {
	for name, nonce := range map[string]any{"absent": nil, "empty": ""} {
		t.Run(name, func(t *testing.T) {
			client, signer := newVerificationClient(t)
			claims := signer.validClaims()
			if nonce == nil {
				delete(claims, "nonce")
			} else {
				claims["nonce"] = nonce
			}
			raw := signer.IDToken(t, claims)
			_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
			assertProtocolErrorIsRedacted(t, err, raw)
		})
	}
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

func TestVerifyIDAndAccessTokensRequireStrictRS256KidHeader(t *testing.T) {
	headers := map[string]string{
		"missing kid":      `{"alg":"RS256"}`,
		"empty kid":        `{"alg":"RS256","kid":""}`,
		"non-string kid":   `{"alg":"RS256","kid":7}`,
		"duplicate kid":    `{"alg":"RS256","kid":"test-key","kid":"test-key"}`,
		"duplicate alg":    `{"alg":"RS256","alg":"RS256","kid":"test-key"}`,
		"nested duplicate": `{"alg":"RS256","kid":"test-key","future":{"x":1,"x":2}}`,
		"trailing":         `{"alg":"RS256","kid":"test-key"} true`,
	}
	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			client, signer := newVerificationClient(t)
			claims := signer.validClaims()
			raw := signer.rawTokenWithHeader(t, header, mustJSON(t, claims))
			_, idErr := client.VerifyIDToken(t.Context(), raw, "nonce-1")
			assertProtocolErrorIsRedacted(t, idErr, raw)
			_, accessErr := client.VerifyAccessTokenJWT(t.Context(), raw)
			assertProtocolErrorIsRedacted(t, accessErr, raw)
		})
	}
}

func TestJWKSFetchPropagatesOnlyAllowlistedCallerHeadersAndCachesKeys(t *testing.T) {
	fake := newFakeOIDCServer(t)
	recorder := &recordingRoundTripper{base: fake.Server.Client().Transport}
	client, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     &http.Client{Transport: recorder},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer := &testTokenSigner{
		PrivateKey: fake.key,
		Issuer:     fake.Server.URL,
		ClientID:   "client-1",
		KeyID:      "test-key",
	}
	headers := make(http.Header)
	headers.Set("Traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
	headers.Set("Tracestate", "vendor=value")
	headers.Set("X-Request-ID", "request-jwks-1")
	headers.Set("Authorization", "Bearer must-not-propagate")
	headers.Set("Cookie", "session=must-not-propagate")
	headers.Set("X-Untrusted", "must-not-propagate")
	ctx := transport.WithHeaders(t.Context(), headers)
	raw := signer.IDToken(t, signer.validClaims())

	if _, err := client.VerifyIDToken(ctx, raw, "nonce-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyIDToken(t.Context(), raw, "nonce-1"); err != nil {
		t.Fatal(err)
	}
	fakeHeaders := recorder.headers()
	if fakeHeaders.Get("Traceparent") != headers.Get("Traceparent") ||
		fakeHeaders.Get("Tracestate") != "vendor=value" ||
		fakeHeaders.Get("X-Request-ID") != "request-jwks-1" {
		t.Fatalf("propagated headers = %#v", fakeHeaders)
	}
	for _, name := range []string{"Authorization", "Cookie", "X-Untrusted"} {
		if fakeHeaders.Get(name) != "" {
			t.Fatalf("%s propagated to JWKS", name)
		}
	}
	if fake.JWKSCalls.Load() != 1 {
		t.Fatalf("JWKS calls = %d", fake.JWKSCalls.Load())
	}
}

type recordingRoundTripper struct {
	base http.RoundTripper
	mu   sync.Mutex
	last http.Header
}

func (r *recordingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.last = request.Header.Clone()
	r.mu.Unlock()
	return r.base.RoundTrip(request)
}

func (r *recordingRoundTripper) headers() http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last.Clone()
}

func TestJWKSCacheRotatesOnUnknownKid(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	firstSigner := &testTokenSigner{
		PrivateKey: fake.key,
		Issuer:     fake.Server.URL,
		ClientID:   "client-1",
		KeyID:      "test-key",
	}
	if _, err := client.VerifyIDToken(t.Context(), firstSigner.IDToken(t, firstSigner.validClaims()), "nonce-1"); err != nil {
		t.Fatal(err)
	}
	rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake.setJWKSKey(rotatedKey, "rotated-key")
	rotatedSigner := &testTokenSigner{
		PrivateKey: rotatedKey,
		Issuer:     fake.Server.URL,
		ClientID:   "client-1",
		KeyID:      "rotated-key",
	}
	if _, err := client.VerifyIDToken(t.Context(), rotatedSigner.IDToken(t, rotatedSigner.validClaims()), "nonce-1"); err != nil {
		t.Fatal(err)
	}
	if fake.JWKSCalls.Load() != 2 {
		t.Fatalf("JWKS calls = %d", fake.JWKSCalls.Load())
	}
}

func TestConcurrentJWKSCacheMissUsesSingleInflightFetch(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	fake.mu.Lock()
	fake.jwksStarted = started
	fake.jwksBlock = release
	fake.mu.Unlock()
	signer := &testTokenSigner{
		PrivateKey: fake.key,
		Issuer:     fake.Server.URL,
		ClientID:   "client-1",
		KeyID:      "test-key",
	}
	raw := signer.IDToken(t, signer.validClaims())
	const count = 6
	start := make(chan struct{})
	errs := make(chan error, count)
	for range count {
		go func() {
			<-start
			_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
			errs <- err
		}()
	}
	close(start)
	<-started
	deadline := time.After(time.Second)
	for {
		client.keySet.mu.RLock()
		waiters := 0
		if client.keySet.inflight != nil {
			waiters = client.keySet.inflight.waiters
		}
		client.keySet.mu.RUnlock()
		if waiters == count {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("inflight waiters = %d", waiters)
		default:
			runtime.Gosched()
		}
	}
	close(release)
	for range count {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if fake.JWKSCalls.Load() != 1 {
		t.Fatalf("JWKS calls = %d", fake.JWKSCalls.Load())
	}
}

func TestJWKSFetchHonorsCallerCancellationWhileSharedFetchContinues(t *testing.T) {
	client, fake := newTestClientAndServer(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	fake.mu.Lock()
	fake.jwksStarted = started
	fake.jwksBlock = release
	fake.mu.Unlock()
	signer := &testTokenSigner{
		PrivateKey: fake.key,
		Issuer:     fake.Server.URL,
		ClientID:   "client-1",
		KeyID:      "test-key",
	}
	raw := signer.IDToken(t, signer.validClaims())
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() {
		_, err := client.VerifyIDToken(ctx, raw, "nonce-1")
		first <- err
	}()
	<-started
	cancel()
	select {
	case err := <-first:
		assertProtocolErrorIsRedacted(t, err, raw)
	case <-time.After(time.Second):
		t.Fatal("verification did not honor caller cancellation")
	}

	second := make(chan error, 1)
	go func() {
		_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
		second <- err
	}()
	close(release)
	if err := <-second; err != nil {
		t.Fatalf("shared fetch did not complete: %v", err)
	}
	if fake.JWKSCalls.Load() != 1 {
		t.Fatalf("JWKS calls = %d", fake.JWKSCalls.Load())
	}
}

func TestJWKSFetchRejectsBadStatusContentTypeAndOversizedBody(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{"status", http.StatusServiceUnavailable, "application/json", `{"keys":[]}`},
		{"content type", http.StatusOK, "text/plain", `{"keys":[]}`},
		{"oversized", http.StatusOK, "application/json", strings.Repeat("x", (1<<20)+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, fake := newTestClientAndServer(t)
			fake.setRawJWKSResponse(test.status, test.contentType, test.body)
			_, signer := newVerificationClient(t)
			signer.Issuer = fake.Server.URL
			signer.PrivateKey = fake.key
			raw := signer.IDToken(t, signer.validClaims())
			_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
			assertProtocolErrorIsRedacted(t, err, raw, test.body)
			if fake.JWKSCalls.Load() != 1 {
				t.Fatalf("JWKS calls = %d", fake.JWKSCalls.Load())
			}
		})
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestVerifyIDTokenRejectsMissingSubject(t *testing.T) {
	client, signer := newVerificationClient(t)
	claims := signer.validClaims()
	delete(claims, "sub")
	raw := signer.IDToken(t, claims)
	_, err := client.VerifyIDToken(t.Context(), raw, "nonce-1")
	assertProtocolErrorIsRedacted(t, err, raw)
}

func TestVerifyRefreshedIDTokenAcceptsValidTokenWithoutNonce(t *testing.T) {
	client, signer := newVerificationClient(t)
	claims := signer.validClaims()
	delete(claims, "nonce")
	claims["username"] = "alice"

	got, err := client.VerifyRefreshedIDToken(t.Context(), signer.IDToken(t, claims))
	if err != nil {
		t.Fatalf("VerifyRefreshedIDToken() error = %v", err)
	}
	if got.Subject != task4Subject || got.Username != "alice" || got.Nonce != "" {
		t.Fatalf("claims = %#v", got)
	}
}

func TestVerifyRefreshedIDTokenRejectsInvalidRegisteredClaims(t *testing.T) {
	tests := map[string]func(*testTokenSigner, map[string]any){
		"wrong issuer": func(_ *testTokenSigner, claims map[string]any) {
			claims["iss"] = "https://wrong.example/token-secret"
		},
		"wrong audience": func(_ *testTokenSigner, claims map[string]any) {
			claims["aud"] = []string{"wrong-client-secret"}
		},
		"expired": func(_ *testTokenSigner, claims map[string]any) {
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
		},
		"missing subject": func(_ *testTokenSigner, claims map[string]any) {
			delete(claims, "sub")
		},
		"blank subject": func(_ *testTokenSigner, claims map[string]any) {
			claims["sub"] = " \t"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, signer := newVerificationClient(t)
			claims := signer.validClaims()
			mutate(signer, claims)
			raw := signer.IDToken(t, claims)
			_, err := client.VerifyRefreshedIDToken(t.Context(), raw)
			assertProtocolErrorIsRedacted(t, err, raw, "token-secret", "client-secret")
		})
	}
}

func TestVerifyRefreshedIDTokenRejectsWrongAlgorithm(t *testing.T) {
	client, signer := newVerificationClient(t)
	raw := signer.token(t, jwt.SigningMethodRS384, signer.validClaims())
	_, err := client.VerifyRefreshedIDToken(t.Context(), raw)
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

func TestVerifyAccessTokenJWTAcceptsFractionalNumericDates(t *testing.T) {
	client, signer := newVerificationClient(t)
	expiry := fmt.Sprintf("%d.25", time.Now().Add(time.Hour).Unix())
	notBefore := fmt.Sprintf("%d.5", time.Now().Add(-time.Hour).Unix())
	raw := signer.rawToken(t, fmt.Sprintf(`{
		"iss":%q,
		"aud":%q,
		"sub":%q,
		"exp":%s,
		"nbf":%s
	}`, signer.Issuer, signer.ClientID, task4Subject, expiry, notBefore))

	got, err := client.VerifyAccessTokenJWT(t.Context(), raw)

	if err != nil {
		t.Fatalf("VerifyAccessTokenJWT() error = %v", err)
	}
	if got.Expiry == 0 {
		t.Fatalf("expiry = %d", got.Expiry)
	}
}

func TestVerifyAccessTokenJWTAcceptsExponentNumericDates(t *testing.T) {
	client, signer := newVerificationClient(t)
	fixedNow := time.Unix(1_700_000_000, 500_000_000)
	raw := signer.rawToken(t, fmt.Sprintf(`{
		"iss":%q,
		"aud":%q,
		"sub":%q,
		"exp":1.70000000125e9,
		"nbf":1.7000000005e9
	}`, signer.Issuer, signer.ClientID, task4Subject))

	got, err := client.verifyAccessTokenJWTAt(t.Context(), raw, fixedNow)

	if err != nil {
		t.Fatalf("verifyAccessTokenJWTAt() error = %v", err)
	}
	if got.Expiry != 1_700_000_001 {
		t.Fatalf("expiry = %d", got.Expiry)
	}
}

func TestVerifyAccessTokenJWTRejectsExpiryAtExactBoundary(t *testing.T) {
	client, signer := newVerificationClient(t)
	fixedNow := time.Unix(1_700_000_000, 500_000_000)
	raw := signer.rawToken(t, fmt.Sprintf(`{
		"iss":%q,
		"aud":%q,
		"sub":%q,
		"exp":1700000000.5
	}`, signer.Issuer, signer.ClientID, task4Subject))

	_, err := client.verifyAccessTokenJWTAt(t.Context(), raw, fixedNow)

	assertProtocolErrorIsRedacted(t, err, raw)
}

func TestVerifyAccessTokenJWTAcceptsNBFAtExactBoundary(t *testing.T) {
	client, signer := newVerificationClient(t)
	fixedNow := time.Unix(1_700_000_000, 500_000_000)
	raw := signer.rawToken(t, fmt.Sprintf(`{
		"iss":%q,
		"aud":%q,
		"sub":%q,
		"exp":1700000001,
		"nbf":1700000000.5
	}`, signer.Issuer, signer.ClientID, task4Subject))

	if _, err := client.verifyAccessTokenJWTAt(t.Context(), raw, fixedNow); err != nil {
		t.Fatalf("verifyAccessTokenJWTAt() error = %v", err)
	}
}

func TestVerifyAccessTokenJWTRejectsNBFStrictlyAfterBoundary(t *testing.T) {
	client, signer := newVerificationClient(t)
	fixedNow := time.Unix(1_700_000_000, 500_000_000)
	raw := signer.rawToken(t, fmt.Sprintf(`{
		"iss":%q,
		"aud":%q,
		"sub":%q,
		"exp":1700000001,
		"nbf":1700000000.500000001
	}`, signer.Issuer, signer.ClientID, task4Subject))

	_, err := client.verifyAccessTokenJWTAt(t.Context(), raw, fixedNow)

	assertProtocolErrorIsRedacted(t, err, raw)
}

func TestVerifyAccessTokenJWTRejectsMissingOrNullNumericDates(t *testing.T) {
	client, signer := newVerificationClient(t)
	future := time.Now().Add(time.Hour).Unix()
	payloads := map[string]string{
		"missing expiry": fmt.Sprintf(`{
			"iss":%q,"aud":%q,"sub":%q
		}`, signer.Issuer, signer.ClientID, task4Subject),
		"null expiry": fmt.Sprintf(`{
			"iss":%q,"aud":%q,"sub":%q,"exp":null
		}`, signer.Issuer, signer.ClientID, task4Subject),
		"null not before": fmt.Sprintf(`{
			"iss":%q,"aud":%q,"sub":%q,"exp":%d,"nbf":null
		}`, signer.Issuer, signer.ClientID, task4Subject, future),
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			raw := signer.rawToken(t, payload)
			_, err := client.VerifyAccessTokenJWT(t.Context(), raw)
			assertProtocolErrorIsRedacted(t, err, raw)
		})
	}
}

func TestVerifyAccessTokenJWTRejectsInvalidOrUnrepresentableNumericDates(t *testing.T) {
	client, signer := newVerificationClient(t)
	future := time.Now().Add(time.Hour).Unix()
	for name, expiry := range map[string]string{
		"string":            fmt.Sprintf("%q", fmt.Sprintf("%d", future)),
		"NaN":               `NaN`,
		"positive infinity": `Infinity`,
		"unrepresentable":   `1e1000`,
	} {
		t.Run(name, func(t *testing.T) {
			payload := fmt.Sprintf(`{
				"iss":%q,"aud":%q,"sub":%q,"exp":%s
			}`, signer.Issuer, signer.ClientID, task4Subject, expiry)
			raw := signer.rawToken(t, payload)
			_, err := client.VerifyAccessTokenJWT(t.Context(), raw)
			assertProtocolErrorIsRedacted(t, err, raw, expiry)
		})
	}
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
