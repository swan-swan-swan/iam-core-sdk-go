package core_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

type coreIssuer struct {
	Server    *httptest.Server
	Key       *rsa.PrivateKey
	Metadata  core.Metadata
	JWKSCalls atomic.Int32

	mu            sync.RWMutex
	jwksKey       *rsa.PrivateKey
	jwksKeyID     string
	jwksStarted   chan<- struct{}
	jwksBlock     <-chan struct{}
	omitJWKSHints bool
}

func newCoreIssuer(t *testing.T, metadata core.Metadata) *coreIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	issuer := &coreIssuer{Key: key, Metadata: metadata, jwksKey: key, jwksKeyID: "test-key"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", issuer.handleDiscovery)
	mux.HandleFunc("/jwks", issuer.handleJWKS)
	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Server.Close)
	issuer.fillMetadata()
	return issuer
}

func (i *coreIssuer) fillMetadata() {
	if i.Metadata.Issuer == "" {
		i.Metadata.Issuer = i.Server.URL
	}
	if i.Metadata.AuthorizationEndpoint == "" {
		i.Metadata.AuthorizationEndpoint = i.Server.URL + "/authorize"
	}
	if i.Metadata.TokenEndpoint == "" {
		i.Metadata.TokenEndpoint = i.Server.URL + "/token"
	}
	if i.Metadata.UserInfoEndpoint == "" {
		i.Metadata.UserInfoEndpoint = i.Server.URL + "/userinfo"
	}
	if i.Metadata.JWKSURI == "" {
		i.Metadata.JWKSURI = i.Server.URL + "/jwks"
	}
	if i.Metadata.EndSessionEndpoint == "" {
		i.Metadata.EndSessionEndpoint = i.Server.URL + "/logout"
	}
}

func (i *coreIssuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(i.Metadata)
}

func (i *coreIssuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	i.JWKSCalls.Add(1)
	i.mu.RLock()
	key, keyID, started, block := i.jwksKey, i.jwksKeyID, i.jwksStarted, i.jwksBlock
	i.mu.RUnlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if block != nil {
		<-block
	}
	exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
	w.Header().Set("Content-Type", "application/json")
	jwk := map[string]string{
		"kty": "RSA", "kid": keyID,
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}
	i.mu.RLock()
	omitHints := i.omitJWKSHints
	i.mu.RUnlock()
	if !omitHints {
		jwk["use"], jwk["alg"] = "sig", "RS256"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{jwk}})
}

func (i *coreIssuer) setJWKS(key *rsa.PrivateKey, keyID string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.jwksKey, i.jwksKeyID = key, keyID
}

func (i *coreIssuer) blockJWKS(started chan<- struct{}, release <-chan struct{}) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.jwksStarted, i.jwksBlock = started, release
}

func (i *coreIssuer) omitOptionalJWKSHints() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.omitJWKSHints = true
}

type tokenSigner struct {
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Audience   string
	KeyID      string
}

func (s *tokenSigner) AccessToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	return s.token(t, jwt.SigningMethodRS256, claims)
}

func (s *tokenSigner) token(t *testing.T, method jwt.SigningMethod, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(method, jwt.MapClaims(claims))
	token.Header["kid"] = s.KeyID
	raw, err := token.SignedString(s.PrivateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return raw
}

func (s *tokenSigner) rawToken(t *testing.T, header string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (s *tokenSigner) validClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"sub": "op_usr_1", "iss": s.Issuer, "aud": s.Audience, "jti": "jti-1",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
	}
}

func newCoreRuntime(t *testing.T) (*core.Runtime, *tokenSigner) {
	t.Helper()
	issuer := newCoreIssuer(t, core.Metadata{
		ScopesSupported:                  []string{"openid", "profile", "email", "groups"},
		CodeChallengeMethodsSupported:    []string{"S256"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})
	runtime, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return runtime, &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
}
