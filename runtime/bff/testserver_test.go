package bff

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session/memory"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

const (
	testClientID     = "portal"
	testClientSecret = "client-secret-sensitive"
	testCode         = "authorization-code-sensitive"
	testAccessToken  = "access-token-sensitive"
	testRefreshToken = "refresh-token-sensitive"
	testSubject      = "op_usr_1"
)

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type optionalStrings struct {
	Present bool
	Values  []string
}

type bffIssuer struct {
	Server           *httptest.Server
	Key              *rsa.PrivateKey
	TokenScope       string
	AccessTokenScope string
	TokenCalls       atomic.Int32

	Clock *mutableClock

	mu                   sync.Mutex
	expectedChallenge    string
	expectedNonce        string
	IDTokenNonce         string
	IDTokenScope         string
	AccessTokenGroups    optionalStrings
	AccessAudience       string
	AccessUsername       string
	AccessDisplayName    string
	AccessEmail          string
	IDTokenGroups        optionalStrings
	IDAudience           string
	UserInfoGroups       optionalStrings
	IDTokenSubject       string
	UserInfoSubject      string
	TokenStatus          int
	TokenError           string
	TokenResponseError   any
	TokenErrorPresent    bool
	TokenType            string
	ExpiresIn            int64
	TokenContentType     string
	TokenBody            string
	TokenRedirect        bool
	UserInfoStatus       int
	UserInfoContentType  string
	UserInfoBody         string
	UserInfoClockAdvance time.Duration
	UserInfoRedirect     bool
	UserInfoTargetCalls  atomic.Int32
	lastTokenForm        url.Values
	lastTokenHeader      http.Header
	lastUserInfoHeader   http.Header
	issuedAccessToken    string
	issuedIDToken        string
	requestLog           []string
	userinfoCalls        int
}

func newBFFIssuer(t *testing.T, clock *mutableClock) *bffIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuer := &bffIssuer{
		Key: key, Clock: clock,
		TokenScope: "openid profile email groups", AccessTokenScope: "openid profile email groups",
		IDTokenScope:      "openid profile email groups",
		AccessTokenGroups: optionalStrings{Present: true, Values: []string{"ops", "dev"}},
		AccessAudience:    testClientID,
		IDTokenGroups:     optionalStrings{Present: true, Values: []string{"dev", "ops"}},
		IDAudience:        testClientID,
		UserInfoGroups:    optionalStrings{Present: true, Values: []string{"ops", "dev"}},
		IDTokenSubject:    testSubject, UserInfoSubject: testSubject,
		TokenStatus: http.StatusOK, TokenType: "Bearer", ExpiresIn: 300, TokenContentType: "application/json",
		UserInfoStatus: http.StatusOK, UserInfoContentType: "application/json",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", issuer.handleDiscovery)
	mux.HandleFunc("/jwks", issuer.handleJWKS)
	mux.HandleFunc("/token", issuer.handleToken)
	mux.HandleFunc("/token-final", issuer.handleTokenFinal)
	mux.HandleFunc("/userinfo", issuer.handleUserInfo)
	mux.HandleFunc("/userinfo-final", issuer.handleUserInfoFinal)
	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Server.Close)
	return issuer
}

func (i *bffIssuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(core.Metadata{
		Issuer: i.Server.URL, AuthorizationEndpoint: i.Server.URL + "/authorize",
		TokenEndpoint: i.Server.URL + "/token", UserInfoEndpoint: i.Server.URL + "/userinfo",
		JWKSURI: i.Server.URL + "/jwks", EndSessionEndpoint: i.Server.URL + "/logout",
		ScopesSupported:                  []string{"openid", "profile", "email", "groups"},
		CodeChallengeMethodsSupported:    []string{"S256"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})
}

func (i *bffIssuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	exponent := big.NewInt(int64(i.Key.PublicKey.E)).Bytes()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "bff-key", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(i.Key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}}})
}

func (i *bffIssuer) handleToken(w http.ResponseWriter, request *http.Request) {
	i.TokenCalls.Add(1)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.requestLog = append(i.requestLog, request.Method+" "+request.URL.Path)
	i.lastTokenHeader = request.Header.Clone()
	if err := request.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	i.lastTokenForm = cloneValues(request.PostForm)
	if i.TokenRedirect {
		http.Redirect(w, request, i.Server.URL+"/token-final", http.StatusFound)
		return
	}
	i.writeTokenResponse(w, request.PostForm)
}

func (i *bffIssuer) handleTokenFinal(w http.ResponseWriter, request *http.Request) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.requestLog = append(i.requestLog, request.Method+" "+request.URL.Path)
	i.writeTokenResponse(w, request.Form)
}

func (i *bffIssuer) writeTokenResponse(w http.ResponseWriter, form url.Values) {
	status := i.TokenStatus
	if status == 0 {
		status = http.StatusOK
	}
	contentType := i.TokenContentType
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if i.TokenBody != "" {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(i.TokenBody))
		return
	}
	if i.TokenError != "" {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": i.TokenError, "error_description": testCode})
		return
	}
	if form.Get("code_verifier") == "" || pkceChallenge(form.Get("code_verifier")) != i.expectedChallenge {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
		return
	}
	nonce := i.expectedNonce
	if i.IDTokenNonce != "" {
		nonce = i.IDTokenNonce
	}
	accessClaims := i.standardClaims(testSubject, i.AccessAudience)
	if i.AccessTokenScope != "<absent>" {
		accessClaims["scope"] = i.AccessTokenScope
	}
	putOptionalStrings(accessClaims, "groups", i.AccessTokenGroups)
	if i.AccessUsername != "" {
		accessClaims["username"] = i.AccessUsername
	}
	if i.AccessDisplayName != "" {
		accessClaims["display_name"] = i.AccessDisplayName
	}
	if i.AccessEmail != "" {
		accessClaims["email"] = i.AccessEmail
	}
	idClaims := i.standardClaims(i.IDTokenSubject, i.IDAudience)
	idClaims["nonce"] = nonce
	if i.IDTokenScope != "<absent>" {
		idClaims["scope"] = i.IDTokenScope
	}
	putOptionalStrings(idClaims, "groups", i.IDTokenGroups)
	i.issuedAccessToken = i.sign(accessClaims)
	i.issuedIDToken = i.sign(idClaims)
	response := map[string]any{
		"access_token": i.issuedAccessToken, "token_type": i.TokenType, "refresh_token": testRefreshToken,
		"id_token": i.issuedIDToken, "expires_in": i.ExpiresIn,
	}
	if i.TokenScope != "<absent>" {
		if i.TokenScope == "<null>" {
			response["scope"] = nil
		} else {
			response["scope"] = i.TokenScope
		}
	}
	if i.TokenErrorPresent {
		response["error"] = i.TokenResponseError
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func (i *bffIssuer) handleUserInfo(w http.ResponseWriter, request *http.Request) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.UserInfoClockAdvance != 0 {
		i.Clock.Advance(i.UserInfoClockAdvance)
	}
	i.userinfoCalls++
	i.requestLog = append(i.requestLog, request.Method+" "+request.URL.Path)
	i.lastUserInfoHeader = request.Header.Clone()
	if i.UserInfoRedirect {
		http.Redirect(w, request, i.Server.URL+"/userinfo-final", http.StatusFound)
		return
	}
	if i.UserInfoContentType != "" {
		w.Header().Set("Content-Type", i.UserInfoContentType)
	}
	status := i.UserInfoStatus
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if i.UserInfoBody != "" {
		_, _ = w.Write([]byte(i.UserInfoBody))
		return
	}
	response := map[string]any{
		"sub": i.UserInfoSubject, "username": "ada", "display_name": "Ada Lovelace", "email": "ada@example.test",
		"roles": []string{"role-must-never-fallback"},
	}
	putOptionalStrings(response, "groups", i.UserInfoGroups)
	_ = json.NewEncoder(w).Encode(response)
}

func (i *bffIssuer) handleUserInfoFinal(w http.ResponseWriter, _ *http.Request) {
	i.UserInfoTargetCalls.Add(1)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sub": testSubject})
}

func putOptionalStrings(target map[string]any, name string, values optionalStrings) {
	if values.Present {
		target[name] = append([]string{}, values.Values...)
	}
}

func (i *bffIssuer) standardClaims(subject, audience string) map[string]any {
	now := i.Clock.Now()
	return map[string]any{
		"sub": subject, "iss": i.Server.URL, "aud": audience, "jti": "token-id",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
}

func (i *bffIssuer) sign(claims map[string]any) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "bff-key"
	raw, err := token.SignedString(i.Key)
	if err != nil {
		panic(err)
	}
	return raw
}

func (i *bffIssuer) prepareAuthorization(location string) error {
	parsed, err := url.Parse(location)
	if err != nil {
		return errors.New("invalid authorization redirect")
	}
	query := parsed.Query()
	i.mu.Lock()
	i.expectedChallenge = query.Get("code_challenge")
	i.expectedNonce = query.Get("nonce")
	i.mu.Unlock()
	return nil
}

func (i *bffIssuer) LastTokenForm() url.Values {
	i.mu.Lock()
	defer i.mu.Unlock()
	return cloneValues(i.lastTokenForm)
}

func (i *bffIssuer) LastHeaders() (http.Header, http.Header) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastTokenHeader.Clone(), i.lastUserInfoHeader.Clone()
}

func (i *bffIssuer) IssuedAccessToken() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.issuedAccessToken
}

func (i *bffIssuer) IssuedIDToken() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.issuedIDToken
}

func (i *bffIssuer) UserInfoCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.userinfoCalls
}

func (i *bffIssuer) LogContains(value string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.ContainsFunc(i.requestLog, func(entry string) bool { return strings.Contains(entry, value) })
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for name, entries := range values {
		cloned[name] = append([]string(nil), entries...)
	}
	return cloned
}

type recordingBackend struct {
	*memory.Backend
	mu       sync.Mutex
	lastFlow *session.Flow
}

func (b *recordingBackend) PutFlow(ctx context.Context, flow *session.Flow) error {
	if err := b.Backend.PutFlow(ctx, flow); err != nil {
		return err
	}
	b.mu.Lock()
	cloned := *flow
	b.lastFlow = &cloned
	b.mu.Unlock()
	return nil
}

func (b *recordingBackend) LastFlow() *session.Flow {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lastFlow == nil {
		return nil
	}
	cloned := *b.lastFlow
	return &cloned
}

func (b *recordingBackend) mutateLastFlow(t *testing.T, mutate func(*session.Flow)) {
	t.Helper()
	flow := b.LastFlow()
	if flow == nil {
		t.Fatal("last flow is nil")
	}
	if _, err := b.Backend.ConsumeFlow(t.Context(), flow.ID); err != nil {
		t.Fatalf("consume flow for mutation: %v", err)
	}
	mutate(flow)
	if err := b.Backend.PutFlow(t.Context(), flow); err != nil {
		t.Fatalf("put mutated flow: %v", err)
	}
	b.mu.Lock()
	cloned := *flow
	b.lastFlow = &cloned
	b.mu.Unlock()
}

func newBFFTestClient(t *testing.T) (*Client, *recordingBackend, *bffIssuer) {
	t.Helper()
	config, backend, issuer := newBFFTestConfig(t)
	client, err := New(config)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return client, backend, issuer
}

func newBFFTestConfig(t *testing.T) (Config, *recordingBackend, *bffIssuer) {
	t.Helper()
	clock := &mutableClock{now: time.Unix(1_800_000_000, 0).UTC()}
	issuer := newBFFIssuer(t, clock)
	runtime, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.Server.URL, Audiences: []string{testClientID, "other-audience"}, HTTPClient: issuer.Server.Client(), Clock: clock,
	})
	if err != nil {
		t.Fatalf("core.New(): %v", err)
	}
	backend := &recordingBackend{Backend: memory.New(memory.Options{Clock: clock})}
	config := Config{
		Core: runtime, ClientID: testClientID,
		ClientSecret: SecretProviderFunc(func(context.Context) (string, error) { return testClientSecret, nil }),
		RedirectURL:  issuer.Server.URL + "/callback", Backend: backend,
		SessionCookie: insecureTestCookie("iam_session"), FlowCookie: insecureTestCookie("iam_flow"),
		AllowInsecureLoopbackCookies: true, HTTPClient: issuer.Server.Client(), Clock: clock,
	}
	return config, backend, issuer
}

func insecureTestCookie(name string) http.Cookie {
	return http.Cookie{Name: name, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

type loginAttempt struct {
	Location string
	State    string
	Flow     *http.Cookie
}

func beginLogin(t *testing.T, client *Client, issuer *bffIssuer, returnTo string) loginAttempt {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(returnTo), nil)
	client.LoginHandler().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("login status = %d", response.Code)
	}
	location := response.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal("authorization redirect was not a valid URL")
	}
	if err := issuer.prepareAuthorization(location); err != nil {
		t.Fatal("authorization redirect could not initialize the issuer fixture")
	}
	var flowCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == client.flowCookie.Name {
			copy := *cookie
			flowCookie = &copy
		}
	}
	if flowCookie == nil {
		t.Fatal("flow cookie was not set")
	}
	return loginAttempt{Location: location, State: parsed.Query().Get("state"), Flow: flowCookie}
}

func serveCallback(t *testing.T, client *Client, attempt loginAttempt, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/callback?"+rawQuery, nil)
	request.AddCookie(attempt.Flow)
	client.CallbackHandler().ServeHTTP(response, request)
	return response
}

func completeLogin(t *testing.T, client *Client, issuer *bffIssuer) *session.Session {
	t.Helper()
	attempt := beginLogin(t, client, issuer, "/profile")
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if response.Code != http.StatusFound {
		t.Fatalf("callback status = %d", response.Code)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == client.sessionCookie.Name && cookie.Value != "" {
			copy := *cookie
			sessionCookie = &copy
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie was not set")
	}
	created, err := client.backend.Get(t.Context(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("get created session: %v", err)
	}
	return created
}

var _ session.Backend = (*recordingBackend)(nil)
