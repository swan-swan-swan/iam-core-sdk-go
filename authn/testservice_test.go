package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/memory"
)

var fixedNow = time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type sequenceReader struct {
	mu       sync.Mutex
	next     byte
	failCall int
	calls    int
}

func (r *sequenceReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.failCall != 0 && r.calls == r.failCall {
		return 0, errors.New("secret random failure")
	}
	r.next++
	for index := range p {
		p[index] = r.next
	}
	return len(p), nil
}

type inspectableBackend struct {
	session.Backend
	flowCount    atomic.Int32
	createCount  atomic.Int32
	consumeCount atomic.Int32

	mu         sync.Mutex
	lastFlow   *session.Flow
	last       *session.Session
	putFlowErr error
	consumeErr error
	createErr  error
}

func (b *inspectableBackend) PutFlow(ctx context.Context, flow *session.Flow) error {
	if b.putFlowErr != nil {
		return b.putFlowErr
	}
	if err := b.Backend.PutFlow(ctx, flow); err != nil {
		return err
	}
	b.flowCount.Add(1)
	b.mu.Lock()
	copied := *flow
	b.lastFlow = &copied
	b.mu.Unlock()
	return nil
}

func (b *inspectableBackend) ConsumeFlow(ctx context.Context, id string) (*session.Flow, error) {
	b.consumeCount.Add(1)
	if b.consumeErr != nil {
		return nil, b.consumeErr
	}
	flow, err := b.Backend.ConsumeFlow(ctx, id)
	if err == nil {
		b.flowCount.Add(-1)
	}
	return flow, err
}

func (b *inspectableBackend) Create(ctx context.Context, item *session.Session) error {
	b.createCount.Add(1)
	if b.createErr != nil {
		return b.createErr
	}
	if err := b.Backend.Create(ctx, item); err != nil {
		return err
	}
	b.mu.Lock()
	copied := *item
	b.last = &copied
	b.mu.Unlock()
	return nil
}

func (b *inspectableBackend) FlowCount() int { return int(b.flowCount.Load()) }

func (b *inspectableBackend) LastFlow() *session.Flow {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lastFlow == nil {
		return nil
	}
	copied := *b.lastFlow
	return &copied
}

func (b *inspectableBackend) LastSession() *session.Session {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last == nil {
		return nil
	}
	copied := *b.last
	return &copied
}

type fakeBrowserOIDC struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	tokenCalls    atomic.Int32
	userInfoCalls atomic.Int32
	logoutCalls   atomic.Int32

	mu              sync.Mutex
	nonce           string
	tokenStatus     int
	userInfoStatus  int
	idSubject       string
	userInfoSubject string
	includeIDToken  bool

	refreshStatus         int
	refreshError          string
	refreshAccessToken    string
	refreshToken          string
	refreshIDSubject      string
	refreshRawIDToken     string
	includeRefreshToken   bool
	includeRefreshIDToken bool
	refreshStarted        chan<- struct{}
	refreshBlock          <-chan struct{}
	logoutStatus          int
	lastLogoutAccessToken string
	lastLogoutIDTokenHint string
	logoutCheck           func()
}

func newFakeBrowserOIDC(t *testing.T) *fakeBrowserOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeBrowserOIDC{
		key:             key,
		tokenStatus:     http.StatusOK,
		userInfoStatus:  http.StatusOK,
		idSubject:       "user-1",
		userInfoSubject: "user-1",
		includeIDToken:  true,

		refreshStatus:         http.StatusOK,
		refreshAccessToken:    "access-refreshed",
		refreshToken:          "refresh-rotated",
		refreshIDSubject:      "user-1",
		includeRefreshToken:   true,
		includeRefreshIDToken: true,
		logoutStatus:          http.StatusNoContent,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fake.discovery)
	mux.HandleFunc("/token", fake.token)
	mux.HandleFunc("/userinfo", fake.userInfo)
	mux.HandleFunc("/jwks", fake.jwks)
	mux.HandleFunc("/logout", fake.logout)
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeBrowserOIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                 f.server.URL,
		"authorization_endpoint": f.server.URL + "/authorize",
		"token_endpoint":         f.server.URL + "/token",
		"userinfo_endpoint":      f.server.URL + "/userinfo",
		"jwks_uri":               f.server.URL + "/jwks",
		"end_session_endpoint":   f.server.URL + "/logout",
		"scopes_supported":       []string{"openid", "profile"},
	})
}

func (f *fakeBrowserOIDC) token(w http.ResponseWriter, request *http.Request) {
	f.tokenCalls.Add(1)
	if err := request.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch request.PostForm.Get("grant_type") {
	case "authorization_code":
		f.exchangeToken(w, request)
	case "refresh_token":
		f.refresh(w, request)
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

func (f *fakeBrowserOIDC) exchangeToken(w http.ResponseWriter, request *http.Request) {
	if request.PostForm.Get("code") == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	status := f.tokenStatus
	includeIDToken := f.includeIDToken
	nonce := f.nonce
	subject := f.idSubject
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status != http.StatusOK {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "temporarily_unavailable"})
		return
	}
	body := map[string]any{
		"access_token": "access-secret",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	if includeIDToken {
		body["id_token"] = f.signIDToken(subject, nonce)
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeBrowserOIDC) refresh(w http.ResponseWriter, request *http.Request) {
	if request.PostForm.Get("refresh_token") == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	status := f.refreshStatus
	errorCode := f.refreshError
	accessToken := f.refreshAccessToken
	refreshToken := f.refreshToken
	idSubject := f.refreshIDSubject
	rawIDToken := f.refreshRawIDToken
	includeRefreshToken := f.includeRefreshToken
	includeIDToken := f.includeRefreshIDToken
	started := f.refreshStarted
	block := f.refreshBlock
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if block != nil {
		select {
		case <-block:
		case <-request.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status != http.StatusOK {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": errorCode})
		return
	}
	body := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   86400,
	}
	if includeRefreshToken {
		body["refresh_token"] = refreshToken
	}
	if includeIDToken {
		if rawIDToken == "" {
			rawIDToken = f.signIDToken(idSubject, "")
		}
		body["id_token"] = rawIDToken
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeBrowserOIDC) userInfo(w http.ResponseWriter, _ *http.Request) {
	f.userInfoCalls.Add(1)
	f.mu.Lock()
	status := f.userInfoStatus
	subject := f.userInfoSubject
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status == http.StatusOK {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":      subject,
			"username": "alice",
			"roles":    []string{"identity-attribute-only"},
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "unavailable"})
}

func (f *fakeBrowserOIDC) jwks(w http.ResponseWriter, _ *http.Request) {
	exponent := big.NewInt(int64(f.key.PublicKey.E)).Bytes()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "browser-key",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(f.key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}}})
}

func (f *fakeBrowserOIDC) logout(w http.ResponseWriter, request *http.Request) {
	f.logoutCalls.Add(1)
	f.mu.Lock()
	f.lastLogoutAccessToken = request.Header.Get("Authorization")
	f.lastLogoutIDTokenHint = request.URL.Query().Get("id_token_hint")
	status := f.logoutStatus
	check := f.logoutCheck
	f.mu.Unlock()
	if check != nil {
		check()
	}
	w.WriteHeader(status)
}

func (f *fakeBrowserOIDC) signIDToken(subject, nonce string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   f.server.URL,
		"sub":   subject,
		"aud":   "client-1",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": nonce,
	})
	token.Header["kid"] = "browser-key"
	signed, _ := token.SignedString(f.key)
	return signed
}

type testHarness struct {
	service *Service
	backend *inspectableBackend
	oidc    *fakeBrowserOIDC
	random  *sequenceReader
}

func newTestHarness(t *testing.T, mutate func(*Config, *testHarness)) *testHarness {
	t.Helper()
	fake := newFakeBrowserOIDC(t)
	client, err := oidc.New(t.Context(), oidc.Config{
		IssuerURL:      fake.server.URL,
		ClientID:       "client-1",
		SecretProvider: oidc.StaticSecret("client-secret"),
		RedirectURL:    "https://app.example/auth/callback",
		Scopes:         []string{"openid", "profile"},
		HTTPClient:     fake.server.Client(),
	})
	if err != nil {
		t.Fatalf("oidc.New() error = %v", err)
	}
	reader := &sequenceReader{}
	mem := memory.New(memory.Options{Clock: fixedClock{fixedNow}, Random: reader})
	backend := &inspectableBackend{Backend: mem}
	harness := &testHarness{backend: backend, oidc: fake, random: reader}
	config := Config{
		OIDC:        client,
		Backend:     backend,
		RedirectURL: "https://app.example/auth/callback",
		Clock:       fixedClock{fixedNow},
		Random:      reader,
	}
	if mutate != nil {
		mutate(&config, harness)
	}
	harness.service, err = New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return harness
}

func newTestService(t *testing.T) (*Service, *inspectableBackend) {
	t.Helper()
	harness := newTestHarness(t, nil)
	return harness.service, harness.backend
}

func newConcurrentRefreshService(t *testing.T) (*Service, *atomic.Int32) {
	t.Helper()
	harness := newTestHarness(t, nil)
	return harness.service, &harness.oidc.tokenCalls
}

func newCredentialService(t *testing.T, _ string) *Service {
	t.Helper()
	harness := newTestHarness(t, nil)
	return harness.service
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

var _ io.Reader = errorReader{}
