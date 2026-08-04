package testkit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

const (
	testKeyID            = "test-key"
	testSubject          = "test-subject"
	maxOAuthRequestBytes = int64(1 << 20)
)

type authorizationFlow struct {
	clientID      string
	redirectURI   string
	nonce         string
	codeChallenge string
}

type refreshBinding struct {
	clientID     string
	clientSecret string
}

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
	flows         map[string]authorizationFlow
	refreshTokens map[string]refreshBinding
	codeSerial    uint64
	tokenSerial   uint64
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
		flows:         make(map[string]authorizationFlow),
		refreshTokens: make(map[string]refreshBinding),
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
	if request.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	flow, redirect, state, err := validateAuthorizationRequest(query, err)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	i.mu.Lock()
	i.calls.Authorize++
	i.codeSerial++
	code := fmt.Sprintf("test-authorization-code-%d", i.codeSerial)
	i.flows[code] = flow
	i.mu.Unlock()
	values := redirect.Query()
	values.Set("code", code)
	values.Set("state", state)
	redirect.RawQuery = values.Encode()
	http.Redirect(w, request, redirect.String(), http.StatusFound)
}

func (i *Issuer) handleToken(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	form, err := parseTokenForm(request)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	accepted, err := i.acceptTokenForm(form)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	status := accepted.response.HTTPStatus
	if status == 0 {
		status = http.StatusOK
		if accepted.response.OAuthError != "" {
			status = http.StatusBadRequest
		}
	}
	if accepted.response.OAuthError != "" {
		writeJSON(w, status, map[string]string{"error": accepted.response.OAuthError})
		return
	}
	issuedAt := timeNow()
	access, err := signTestToken(accepted.key, i.URL(), accepted.clientID, accepted.response, "access", "", accepted.serial, issuedAt)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	idToken, err := signTestToken(accepted.key, i.URL(), accepted.clientID, accepted.response, "id", accepted.nonce, accepted.serial, issuedAt)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	refreshToken := fmt.Sprintf("test-refresh-%d", accepted.serial)
	i.mu.Lock()
	i.refreshTokens[refreshToken] = refreshBinding{clientID: accepted.clientID, clientSecret: accepted.clientSecret}
	i.mu.Unlock()
	writeJSON(w, status, map[string]any{
		"access_token": access, "token_type": "Bearer", "refresh_token": refreshToken,
		"id_token": idToken, "expires_in": testTokenExpiresIn, "scope": accepted.response.Scope,
	})
}

type acceptedTokenRequest struct {
	clientID     string
	clientSecret string
	nonce        string
	response     TokenResponse
	key          *rsa.PrivateKey
	serial       uint64
}

func validateAuthorizationRequest(
	query url.Values,
	parseErr error,
) (authorizationFlow, *url.URL, string, error) {
	expected := []string{
		"response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
		"code_challenge", "code_challenge_method",
	}
	if parseErr != nil || !hasExactSingleValues(query, expected) || query.Get("response_type") != "code" ||
		query.Get("code_challenge_method") != "S256" || !validPKCEChallenge(query.Get("code_challenge")) {
		return authorizationFlow{}, nil, "", errors.New("invalid authorization request")
	}
	for _, name := range []string{"client_id", "redirect_uri", "scope", "state", "nonce"} {
		if !validOAuthValue(query.Get(name)) {
			return authorizationFlow{}, nil, "", errors.New("invalid authorization request")
		}
	}
	redirect, err := url.Parse(query.Get("redirect_uri"))
	if err != nil || (redirect.Scheme != "http" && redirect.Scheme != "https") || redirect.Host == "" ||
		redirect.User != nil || redirect.Fragment != "" {
		return authorizationFlow{}, nil, "", errors.New("invalid redirect URI")
	}
	return authorizationFlow{
		clientID: query.Get("client_id"), redirectURI: query.Get("redirect_uri"), nonce: query.Get("nonce"),
		codeChallenge: query.Get("code_challenge"),
	}, redirect, query.Get("state"), nil
}

func parseTokenForm(request *http.Request) (url.Values, error) {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/x-www-form-urlencoded" || request.URL.RawQuery != "" {
		return nil, errors.New("invalid token request")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxOAuthRequestBytes+1))
	if err != nil || int64(len(body)) > maxOAuthRequestBytes {
		return nil, errors.New("invalid token request")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || len(form) == 0 {
		return nil, errors.New("invalid token request")
	}
	return form, nil
}

func (i *Issuer) acceptTokenForm(form url.Values) (acceptedTokenRequest, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	grantValues, present := form["grant_type"]
	if !present || len(grantValues) != 1 {
		return acceptedTokenRequest{}, errors.New("invalid grant")
	}
	accepted := acceptedTokenRequest{response: cloneTokenResponse(i.tokenResponse), key: i.key}
	if accepted.response.OAuthError == "" && i.tokenSerial == ^uint64(0) {
		return acceptedTokenRequest{}, errors.New("token serial exhausted")
	}
	switch grantValues[0] {
	case "authorization_code":
		expected := []string{"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"}
		if !hasExactSingleValues(form, expected) || !validOAuthValue(form.Get("code")) ||
			!validOAuthValue(form.Get("redirect_uri")) || !validOAuthValue(form.Get("client_id")) ||
			!validOAuthValue(form.Get("client_secret")) || !validPKCEVerifier(form.Get("code_verifier")) {
			return acceptedTokenRequest{}, errors.New("invalid authorization code request")
		}
		flow, ok := i.flows[form.Get("code")]
		if !ok || flow.clientID != form.Get("client_id") || flow.redirectURI != form.Get("redirect_uri") ||
			!matchesPKCE(flow.codeChallenge, form.Get("code_verifier")) {
			return acceptedTokenRequest{}, errors.New("invalid authorization code")
		}
		delete(i.flows, form.Get("code"))
		i.calls.Token++
		accepted.clientID, accepted.clientSecret, accepted.nonce = flow.clientID, form.Get("client_secret"), flow.nonce
	case "refresh_token":
		expected := []string{"grant_type", "refresh_token", "client_id", "client_secret"}
		if !hasExactSingleValues(form, expected) || !validOAuthValue(form.Get("refresh_token")) ||
			!validOAuthValue(form.Get("client_id")) || !validOAuthValue(form.Get("client_secret")) {
			return acceptedTokenRequest{}, errors.New("invalid refresh request")
		}
		binding, ok := i.refreshTokens[form.Get("refresh_token")]
		if !ok || binding.clientID != form.Get("client_id") || binding.clientSecret != form.Get("client_secret") {
			return acceptedTokenRequest{}, errors.New("invalid refresh token")
		}
		delete(i.refreshTokens, form.Get("refresh_token"))
		i.calls.Refresh++
		accepted.clientID, accepted.clientSecret = binding.clientID, binding.clientSecret
	default:
		return acceptedTokenRequest{}, errors.New("unsupported grant")
	}
	i.calls.LastTokenForm = cloneURLValues(form)
	if accepted.response.OAuthError == "" {
		i.tokenSerial++
		accepted.serial = i.tokenSerial
	}
	return accepted, nil
}

func hasExactSingleValues(values url.Values, expected []string) bool {
	if len(values) != len(expected) {
		return false
	}
	for _, name := range expected {
		entries, ok := values[name]
		if !ok || len(entries) != 1 {
			return false
		}
	}
	return true
}

func validOAuthValue(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func validPKCEChallenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-._~", character)) {
			return false
		}
	}
	return true
}

func matchesPKCE(challenge, verifier string) bool {
	digest := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(actual)) == 1
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
