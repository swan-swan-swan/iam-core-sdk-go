package testkit

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

const (
	testKeyID   = "test-key"
	testSubject = "test-subject"
)

// TokenResponse configures successful token and UserInfo fixtures or one OAuth error.
type TokenResponse struct {
	Scope      string
	Groups     []string
	OAuthError string
	HTTPStatus int
}

// Calls is a snapshot of the issuer's OAuth endpoint calls. LastTokenForm can
// contain authorization codes, verifiers, refresh tokens, and client secrets;
// callers must not log it.
type Calls struct {
	Authorize     int
	Token         int
	Refresh       int
	UserInfo      int
	EndSession    int
	LastTokenForm url.Values
}

// Issuer is an in-process S256/RS256 OIDC issuer for tests.
type Issuer struct {
	t             testing.TB
	server        *httptest.Server
	key           *rsa.PrivateKey
	mu            sync.Mutex
	tokenResponse TokenResponse
	calls         Calls
	nonce         string
	serial        uint64
	closeOnce     sync.Once
}

// NewIssuer starts a complete fake OIDC issuer with an in-memory RSA key.
func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test issuer key: %v", err)
	}
	issuer := &Issuer{
		t:   t,
		key: key,
		tokenResponse: TokenResponse{
			Scope:  "openid profile email groups",
			Groups: []string{"test-group"},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", issuer.handleDiscovery)
	mux.HandleFunc("/jwks", issuer.handleJWKS)
	mux.HandleFunc("/authorize", issuer.handleAuthorize)
	mux.HandleFunc("/token", issuer.handleToken)
	mux.HandleFunc("/userinfo", issuer.handleUserInfo)
	mux.HandleFunc("/end-session", issuer.handleEndSession)
	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.Close)
	return issuer
}

// URL returns the fake issuer URL.
func (i *Issuer) URL() string {
	return i.server.URL
}

// HTTPClient returns a client configured for the issuer's test server.
func (i *Issuer) HTTPClient() *http.Client {
	return i.server.Client()
}

// SetTokenResponse replaces the token/UserInfo fixture using defensive copies.
func (i *Issuer) SetTokenResponse(response TokenResponse) {
	response.Groups = cloneStrings(response.Groups)
	i.mu.Lock()
	i.tokenResponse = response
	i.mu.Unlock()
}

// Calls returns a deep copy of the current call counters and last token form.
func (i *Issuer) Calls() Calls {
	i.mu.Lock()
	defer i.mu.Unlock()
	result := i.calls
	result.LastTokenForm = cloneURLValues(i.calls.LastTokenForm)
	return result
}

// Close stops the fake issuer. It is safe to call more than once.
func (i *Issuer) Close() {
	i.closeOnce.Do(i.server.Close)
}

func (i *Issuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	base := i.URL()
	writeJSON(w, http.StatusOK, core.Metadata{
		Issuer:                           base,
		AuthorizationEndpoint:            base + "/authorize",
		TokenEndpoint:                    base + "/token",
		UserInfoEndpoint:                 base + "/userinfo",
		JWKSURI:                          base + "/jwks",
		EndSessionEndpoint:               base + "/end-session",
		ScopesSupported:                  []string{"openid", "profile", "email", "groups"},
		CodeChallengeMethodsSupported:    []string{"S256"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})
}

func (i *Issuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	public := i.key.PublicKey
	i.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": testKeyID,
			"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		}},
	})
}

func (i *Issuer) handleAuthorize(w http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	i.mu.Lock()
	i.calls.Authorize++
	i.nonce = query.Get("nonce")
	i.mu.Unlock()
	redirect, err := url.Parse(query.Get("redirect_uri"))
	if err != nil || redirect.Scheme == "" || redirect.Host == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	values := redirect.Query()
	values.Set("code", "test-authorization-code")
	values.Set("state", query.Get("state"))
	redirect.RawQuery = values.Encode()
	http.Redirect(w, request, redirect.String(), http.StatusFound)
}

func (i *Issuer) handleToken(w http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	i.mu.Lock()
	if request.Form.Get("grant_type") == "refresh_token" {
		i.calls.Refresh++
	} else {
		i.calls.Token++
	}
	i.calls.LastTokenForm = cloneURLValues(request.Form)
	response := cloneTokenResponse(i.tokenResponse)
	nonce := i.nonce
	audience := request.Form.Get("client_id")
	if audience == "" {
		audience = "test-client"
	}
	i.serial++
	serial := i.serial
	key := i.key
	i.mu.Unlock()

	status := response.HTTPStatus
	if status == 0 {
		status = http.StatusOK
		if response.OAuthError != "" {
			status = http.StatusBadRequest
		}
	}
	if response.OAuthError != "" {
		writeJSON(w, status, map[string]string{"error": response.OAuthError})
		return
	}
	access, err := signTestToken(key, i.URL(), audience, response, "access", "", serial*2)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	idToken, err := signTestToken(key, i.URL(), audience, response, "id", nonce, serial*2+1)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(w, status, map[string]any{
		"access_token": access, "token_type": "Bearer", "refresh_token": fmt.Sprintf("test-refresh-%d", serial),
		"id_token": idToken, "expires_in": 3600, "scope": response.Scope,
	})
}

func (i *Issuer) handleUserInfo(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	i.calls.UserInfo++
	response := cloneTokenResponse(i.tokenResponse)
	i.mu.Unlock()
	body := map[string]any{
		"sub": testSubject, "username": "test-user", "display_name": "Test User", "email": "test@example.test",
	}
	if response.Groups != nil {
		body["groups"] = response.Groups
	}
	writeJSON(w, http.StatusOK, body)
}

func (i *Issuer) handleEndSession(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	i.calls.EndSession++
	i.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func cloneTokenResponse(response TokenResponse) TokenResponse {
	response.Groups = cloneStrings(response.Groups)
	return response
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func cloneURLValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	cloned := make(url.Values, len(values))
	for name, entries := range values {
		cloned[name] = append([]string(nil), entries...)
	}
	return cloned
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
