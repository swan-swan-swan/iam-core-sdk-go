package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fakeOIDCServer struct {
	Server          *httptest.Server
	DiscoveryCalls  atomic.Int32
	TokenCalls      atomic.Int32
	JWKSCalls       atomic.Int32
	JWKSTargetCalls atomic.Int32
	LastTokenForm   url.Values

	mu                       sync.Mutex
	key                      *rsa.PrivateKey
	keyID                    string
	lastJWKSHeaders          http.Header
	jwksStarted              chan<- struct{}
	jwksBlock                <-chan struct{}
	jwksStatus               int
	jwksContentType          string
	jwksRawBody              *string
	discoveryIssuer          string
	discoveryOverrides       map[string]string
	tokenStatus              int
	tokenResponse            map[string]any
	tokenResponseRequestID   string
	tokenRawBody             *string
	tokenContentType         string
	rejectBasicAuthorization bool
	jwksRedirectTarget       string
}

func newFakeOIDCServer(t *testing.T) *fakeOIDCServer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate fake OIDC key: %v", err)
	}
	fake := &fakeOIDCServer{
		key:                key,
		keyID:              "test-key",
		discoveryOverrides: make(map[string]string),
		tokenStatus:        http.StatusOK,
		jwksStatus:         http.StatusOK,
		tokenResponse: map[string]any{
			"access_token":  "access-1",
			"token_type":    "Bearer",
			"refresh_token": "refresh-2",
			"expires_in":    3600,
		},
		rejectBasicAuthorization: true,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fake.handleDiscovery)
	mux.HandleFunc("/oidc/token", fake.handleToken)
	mux.HandleFunc("/oidc/jwks", fake.handleJWKS)
	mux.HandleFunc("/oidc/jwks-target", fake.handleJWKSTarget)
	fake.Server = httptest.NewServer(mux)
	t.Cleanup(fake.Server.Close)

	fake.tokenResponse["id_token"] = fake.signIDToken(t)
	return fake
}

func (f *fakeOIDCServer) OverrideDiscoveryIssuer(issuer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discoveryIssuer = issuer
}

func (f *fakeOIDCServer) overrideDiscoveryEndpoint(name, endpoint string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discoveryOverrides[name] = endpoint
}

func (f *fakeOIDCServer) setTokenResponse(status int, response map[string]any, requestID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenStatus = status
	f.tokenResponse = response
	f.tokenResponseRequestID = requestID
	f.tokenRawBody = nil
}

func (f *fakeOIDCServer) setRawTokenResponse(status int, contentType, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenStatus = status
	f.tokenContentType = contentType
	f.tokenRawBody = &body
}

func (f *fakeOIDCServer) setJWKSRedirect(target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksRedirectTarget = target
}

func (f *fakeOIDCServer) setJWKSKey(key *rsa.PrivateKey, keyID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = key
	f.keyID = keyID
}

func (f *fakeOIDCServer) jwksHeaders() http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastJWKSHeaders.Clone()
}

func (f *fakeOIDCServer) setRawJWKSResponse(status int, contentType, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksStatus = status
	f.jwksContentType = contentType
	f.jwksRawBody = &body
}

func (f *fakeOIDCServer) tokenForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneValues(f.LastTokenForm)
}

func (f *fakeOIDCServer) handleDiscovery(writer http.ResponseWriter, _ *http.Request) {
	f.DiscoveryCalls.Add(1)
	f.mu.Lock()
	issuer := f.discoveryIssuer
	overrides := make(map[string]string, len(f.discoveryOverrides))
	for name, value := range f.discoveryOverrides {
		overrides[name] = value
	}
	f.mu.Unlock()
	if issuer == "" {
		issuer = f.Server.URL
	}
	endpoint := func(name, fallback string) string {
		if value, ok := overrides[name]; ok {
			return value
		}
		return f.Server.URL + fallback
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": endpoint("authorization_endpoint", "/oidc/authorize"),
		"token_endpoint":         endpoint("token_endpoint", "/oidc/token"),
		"userinfo_endpoint":      endpoint("userinfo_endpoint", "/oidc/userinfo"),
		"jwks_uri":               endpoint("jwks_uri", "/oidc/jwks"),
		"end_session_endpoint":   endpoint("end_session_endpoint", "/oidc/logout"),
		"scopes_supported":       []string{"openid", "profile", "email", "roles"},
	})
}

func (f *fakeOIDCServer) handleToken(writer http.ResponseWriter, request *http.Request) {
	f.TokenCalls.Add(1)
	writer.Header().Set("Content-Type", "application/json")
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(writer).Encode(map[string]string{"error": "invalid_request"})
		return
	}

	f.mu.Lock()
	f.LastTokenForm = cloneValues(request.PostForm)
	status := f.tokenStatus
	response := cloneMap(f.tokenResponse)
	requestID := f.tokenResponseRequestID
	rawBody := f.tokenRawBody
	contentType := f.tokenContentType
	rejectBasic := f.rejectBasicAuthorization
	f.mu.Unlock()

	if rejectBasic && request.Header.Get("Authorization") != "" {
		writer.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(writer).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	if request.PostForm.Get("client_id") == "" || request.PostForm.Get("client_secret") == "" {
		writer.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(writer).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	switch request.PostForm.Get("grant_type") {
	case "authorization_code":
		if request.PostForm.Get("code") == "" {
			writer.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": "invalid_request"})
			return
		}
	case "refresh_token":
		if request.PostForm.Get("refresh_token") == "" {
			writer.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": "invalid_request"})
			return
		}
	default:
		writer.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(writer).Encode(map[string]string{"error": "unsupported_grant_type"})
		return
	}
	if requestID != "" {
		writer.Header().Set("X-Request-ID", requestID)
	}
	if rawBody != nil {
		writer.Header().Set("Content-Type", contentType)
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(*rawBody))
		return
	}
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(response)
}

func (f *fakeOIDCServer) handleJWKS(writer http.ResponseWriter, request *http.Request) {
	f.JWKSCalls.Add(1)
	f.mu.Lock()
	redirectTarget := f.jwksRedirectTarget
	f.lastJWKSHeaders = request.Header.Clone()
	started := f.jwksStarted
	block := f.jwksBlock
	status := f.jwksStatus
	contentType := f.jwksContentType
	rawBody := f.jwksRawBody
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if block != nil {
		<-block
	}
	if rawBody != nil {
		writer.Header().Set("Content-Type", contentType)
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(*rawBody))
		return
	}
	if redirectTarget != "" {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Location", redirectTarget)
		writer.WriteHeader(http.StatusFound)
		_, _ = writer.Write([]byte(`{}`))
		return
	}
	f.writeJWKS(writer)
}

func (f *fakeOIDCServer) handleJWKSTarget(writer http.ResponseWriter, _ *http.Request) {
	f.JWKSTargetCalls.Add(1)
	f.writeJWKS(writer)
}

func (f *fakeOIDCServer) writeJWKS(writer http.ResponseWriter) {
	f.mu.Lock()
	key := f.key
	keyID := f.keyID
	f.mu.Unlock()
	exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": keyID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(exponent),
		}},
	})
}

func (f *fakeOIDCServer) signIDToken(t *testing.T) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": f.Server.URL,
		"sub": "user-1",
		"aud": "client-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	f.mu.Lock()
	key := f.key
	keyID := f.keyID
	f.mu.Unlock()
	token.Header["kid"] = keyID
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign fake ID token: %v", err)
	}
	return signed
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	client, _ := newTestClientAndServer(t)
	return client
}

func newTestClientAndServer(t *testing.T) (*Client, *fakeOIDCServer) {
	t.Helper()
	fake := newFakeOIDCServer(t)
	client, err := New(t.Context(), Config{
		IssuerURL:      fake.Server.URL,
		ClientID:       "client-1",
		SecretProvider: StaticSecret("secret-1"),
		RedirectURL:    "https://app.example/callback",
		Scopes:         []string{"openid", "profile", "email", "roles"},
		HTTPClient:     fake.Server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client, fake
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func cloneMap(values map[string]any) map[string]any {
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
