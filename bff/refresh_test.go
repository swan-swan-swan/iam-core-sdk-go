package bff

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session/memory"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

var refreshTestNow = time.Unix(1_800_100_000, 0).UTC()

type refreshIssuer struct {
	Server *httptest.Server
	Key    *rsa.PrivateKey
	Clock  *mutableClock

	mu sync.Mutex

	RefreshGroups               []string
	RefreshIDGroups             []string
	RefreshUserInfoGroups       []string
	RefreshScope                string
	RefreshAccessScope          string
	RefreshIDScope              string
	RefreshAudience             string
	RefreshSubject              string
	RefreshUserInfoSubject      string
	RefreshOAuthError           string
	RefreshStatus               int
	RefreshExpiresIn            int64
	RefreshTokenBody            string
	RefreshTokenContentType     string
	RefreshUserInfoBody         string
	RefreshUserInfoStatus       int
	RefreshUserInfoContentType  string
	RefreshReplacementToken     string
	OmitRefreshToken            bool
	OmitIDToken                 bool
	AdvanceOnRefresh            time.Duration
	AdvanceOnUserInfo           time.Duration
	EndSessionStatus            int
	EndSessionBody              string
	EndSessionContentType       string
	EndSessionRedirect          bool
	EndSessionHook              func()
	refreshRelease              <-chan struct{}
	refreshStarted              chan struct{}
	refreshStartedOnce          sync.Once
	userInfoRelease             <-chan struct{}
	userInfoStarted             chan struct{}
	userInfoStartedOnce         sync.Once
	refreshCalls                int
	userinfoCalls               int
	endSessionCalls             int
	endSessionTargetCalls       int
	lastRefreshForm             url.Values
	lastRefreshHeader           http.Header
	lastEndSessionMethod        string
	lastEndSessionAuthorization string
	lastEndSessionIDTokenHint   string
	lastEndSessionRawQuery      string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type canceledResponseBody struct {
	ctx     context.Context
	started chan struct{}
	once    sync.Once
}

func (b *canceledResponseBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (*canceledResponseBody) Close() error { return nil }

func newRefreshTestClient(t *testing.T) (*Client, *memory.Backend, *refreshIssuer) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate refresh fixture key: %v", err)
	}
	clock := &mutableClock{now: refreshTestNow}
	issuer := &refreshIssuer{
		Key: key, Clock: clock,
		RefreshGroups:              []string{"ops"},
		RefreshScope:               "openid profile email groups",
		RefreshAudience:            testClientID,
		RefreshSubject:             testSubject,
		RefreshUserInfoSubject:     testSubject,
		RefreshStatus:              http.StatusOK,
		RefreshExpiresIn:           300,
		RefreshTokenContentType:    "application/json",
		RefreshUserInfoStatus:      http.StatusOK,
		RefreshUserInfoContentType: "application/json",
		RefreshReplacementToken:    "refresh-token-rotated-sensitive",
		EndSessionStatus:           http.StatusNoContent,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", issuer.handleDiscovery)
	mux.HandleFunc("/jwks", issuer.handleJWKS)
	mux.HandleFunc("/token", issuer.handleRefresh)
	mux.HandleFunc("/userinfo", issuer.handleUserInfo)
	mux.HandleFunc("/logout", issuer.handleEndSession)
	mux.HandleFunc("/logout-target", issuer.handleEndSessionTarget)
	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Server.Close)

	runtime, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.Server.URL, Audiences: []string{testClientID},
		HTTPClient: issuer.Server.Client(), Clock: clock,
	})
	if err != nil {
		t.Fatalf("core.New(): %v", err)
	}
	backend := memory.New(memory.Options{Clock: clock})
	client, err := New(Config{
		Core: runtime, ClientID: testClientID,
		ClientSecret: SecretProviderFunc(func(context.Context) (string, error) { return testClientSecret, nil }),
		RedirectURL:  issuer.Server.URL + "/callback", Backend: backend,
		SessionCookie:                productionCookie("__Host-portal_session"),
		FlowCookie:                   productionCookie("__Host-portal_flow"),
		AllowInsecureLoopbackCookies: true,
		HTTPClient:                   issuer.Server.Client(), Clock: clock,
		SessionAbsoluteTTL: 2 * time.Hour, SessionIdleTTL: 30 * time.Minute,
		RefreshBeforeExpiry: time.Minute, RefreshLeaseTTL: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return client, backend, issuer
}

func seedExpiringSession(
	t *testing.T,
	backend *memory.Backend,
	groups, scopes []string,
) *session.Session {
	t.Helper()
	item := refreshSessionFixture(groups, scopes)
	item.Tokens.AccessTokenExpiry = refreshTestNow.Add(30 * time.Second)
	if err := backend.Create(t.Context(), item); err != nil {
		t.Fatalf("create expiring session: %v", err)
	}
	return cloneSessionForTest(item)
}

func seedValidSession(t *testing.T, backend *memory.Backend) *session.Session {
	t.Helper()
	item := refreshSessionFixture([]string{"ops"}, []string{"email", "groups", "openid", "profile"})
	item.Tokens.AccessTokenExpiry = refreshTestNow.Add(10 * time.Minute)
	if err := backend.Create(t.Context(), item); err != nil {
		t.Fatalf("create valid session: %v", err)
	}
	return cloneSessionForTest(item)
}

func requestWithSessionCookie(id string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-portal_session", Value: id})
	return request
}

func serveWithCookie(t *testing.T, handler http.Handler, id string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-portal_session", Value: id})
	handler.ServeHTTP(response, request)
	return response
}

func refreshSessionFixture(groups, scopes []string) *session.Session {
	return &session.Session{
		ID: "session-refresh-test", Version: 1,
		Tokens: session.TokenSet{
			AccessToken: "access-token-old-sensitive", TokenType: "Bearer",
			RefreshToken: "refresh-token-old-sensitive", IDToken: "id-token-old-sensitive",
			GrantedScopes: append([]string(nil), scopes...),
		},
		Auth: core.AuthContext{
			Subject: testSubject, Issuer: "https://old-issuer.example.test", Audience: []string{testClientID},
			TokenID: "old-token-id", IssuedAt: refreshTestNow.Add(-time.Minute),
			ExpiresAt: refreshTestNow.Add(10 * time.Minute), Scopes: append([]string(nil), scopes...),
			Groups: append([]string(nil), groups...), Username: "old-user", DisplayName: "Old User",
			Email: "old@example.test",
		},
		CreatedAt: refreshTestNow.Add(-time.Minute), UpdatedAt: refreshTestNow.Add(-time.Minute),
		LastSeenAt: refreshTestNow.Add(-time.Minute), ExpiresAt: refreshTestNow.Add(2 * time.Hour),
		IdleExpiresAt: refreshTestNow.Add(30 * time.Minute),
	}
}

func cloneSessionForTest(item *session.Session) *session.Session {
	cloned := *item
	cloned.Tokens.GrantedScopes = append([]string(nil), item.Tokens.GrantedScopes...)
	cloned.Auth.Audience = append([]string(nil), item.Auth.Audience...)
	cloned.Auth.Scopes = append([]string(nil), item.Auth.Scopes...)
	cloned.Auth.Groups = append([]string(nil), item.Auth.Groups...)
	return &cloned
}

func (i *refreshIssuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(core.Metadata{
		Issuer: i.Server.URL, AuthorizationEndpoint: i.Server.URL + "/authorize",
		TokenEndpoint: i.Server.URL + "/token", UserInfoEndpoint: i.Server.URL + "/userinfo",
		JWKSURI: i.Server.URL + "/jwks", EndSessionEndpoint: i.Server.URL + "/logout",
		ScopesSupported:               []string{"openid", "profile", "email", "groups"},
		CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})
}

func (i *refreshIssuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	exponent := big.NewInt(int64(i.Key.PublicKey.E)).Bytes()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "refresh-key", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(i.Key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}}})
}

type refreshSnapshot struct {
	groups, idGroups, userInfoGroups []string
	scope, accessScope, idScope      string
	audience, subject, userSubject   string
	oauthError, tokenBody            string
	status                           int
	expiresIn                        int64
	contentType                      string
	replacement                      string
	omitRefresh, omitID              bool
	advance                          time.Duration
	release                          <-chan struct{}
	started                          chan struct{}
}

func (i *refreshIssuer) handleRefresh(w http.ResponseWriter, request *http.Request) {
	_ = request.ParseForm()
	i.mu.Lock()
	i.refreshCalls++
	i.lastRefreshForm = cloneValues(request.PostForm)
	i.lastRefreshHeader = request.Header.Clone()
	snapshot := refreshSnapshot{
		groups:         append([]string(nil), i.RefreshGroups...),
		idGroups:       append([]string(nil), i.RefreshIDGroups...),
		userInfoGroups: append([]string(nil), i.RefreshUserInfoGroups...),
		scope:          i.RefreshScope, accessScope: i.RefreshAccessScope, idScope: i.RefreshIDScope,
		audience: i.RefreshAudience, subject: i.RefreshSubject, userSubject: i.RefreshUserInfoSubject,
		oauthError: i.RefreshOAuthError, tokenBody: i.RefreshTokenBody,
		status: i.RefreshStatus, contentType: i.RefreshTokenContentType,
		expiresIn:   i.RefreshExpiresIn,
		replacement: i.RefreshReplacementToken, omitRefresh: i.OmitRefreshToken, omitID: i.OmitIDToken,
		advance: i.AdvanceOnRefresh, release: i.refreshRelease, started: i.refreshStarted,
	}
	i.mu.Unlock()
	if snapshot.started != nil {
		i.refreshStartedOnce.Do(func() { close(snapshot.started) })
	}
	if snapshot.release != nil {
		<-snapshot.release
	}
	if snapshot.advance != 0 {
		i.Clock.Advance(snapshot.advance)
	}
	if snapshot.contentType != "" {
		w.Header().Set("Content-Type", snapshot.contentType)
	}
	if snapshot.tokenBody != "" {
		w.WriteHeader(snapshot.status)
		_, _ = w.Write([]byte(snapshot.tokenBody))
		return
	}
	if snapshot.oauthError != "" {
		status := snapshot.status
		if status == http.StatusOK {
			status = http.StatusBadRequest
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": snapshot.oauthError, "error_description": "refresh-token-old-sensitive hostile detail",
		})
		return
	}
	accessScope := snapshot.accessScope
	if accessScope == "" {
		accessScope = snapshot.scope
	}
	idScope := snapshot.idScope
	if idScope == "" {
		idScope = snapshot.scope
	}
	idGroups := snapshot.idGroups
	if idGroups == nil {
		idGroups = snapshot.groups
	}
	accessClaims := i.standardClaims(snapshot.subject, snapshot.audience, "refresh-access-id")
	if accessScope != "<absent>" {
		accessClaims["scope"] = accessScope
	}
	accessClaims["groups"] = append([]string{}, snapshot.groups...)
	idClaims := i.standardClaims(snapshot.subject, snapshot.audience, "refresh-id-id")
	if idScope != "<absent>" {
		idClaims["scope"] = idScope
	}
	idClaims["groups"] = append([]string{}, idGroups...)
	response := map[string]any{
		"access_token": i.sign(accessClaims), "token_type": "Bearer", "expires_in": snapshot.expiresIn,
	}
	if snapshot.scope != "<absent>" {
		response["scope"] = snapshot.scope
	}
	if !snapshot.omitRefresh {
		response["refresh_token"] = snapshot.replacement
	}
	if !snapshot.omitID {
		response["id_token"] = i.sign(idClaims)
	}
	w.WriteHeader(snapshot.status)
	_ = json.NewEncoder(w).Encode(response)
}

func (i *refreshIssuer) handleUserInfo(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	i.userinfoCalls++
	groups := append([]string(nil), i.RefreshUserInfoGroups...)
	if groups == nil {
		groups = append([]string(nil), i.RefreshGroups...)
	}
	subject := i.RefreshUserInfoSubject
	body, status, contentType := i.RefreshUserInfoBody, i.RefreshUserInfoStatus, i.RefreshUserInfoContentType
	advance := i.AdvanceOnUserInfo
	started, release := i.userInfoStarted, i.userInfoRelease
	i.mu.Unlock()
	if started != nil {
		i.userInfoStartedOnce.Do(func() { close(started) })
	}
	if release != nil {
		<-release
	}
	if advance != 0 {
		i.Clock.Advance(advance)
	}
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	if body != "" {
		_, _ = w.Write([]byte(body))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub": subject, "username": "new-user", "display_name": "New User", "email": "new@example.test",
		"groups": groups, "roles": []string{"never-expose-role"},
	})
}

func (i *refreshIssuer) handleEndSession(w http.ResponseWriter, request *http.Request) {
	i.mu.Lock()
	i.endSessionCalls++
	i.lastEndSessionMethod = request.Method
	i.lastEndSessionAuthorization = request.Header.Get("Authorization")
	i.lastEndSessionIDTokenHint = request.URL.Query().Get("id_token_hint")
	i.lastEndSessionRawQuery = request.URL.RawQuery
	status, body, contentType, redirect := i.EndSessionStatus, i.EndSessionBody, i.EndSessionContentType, i.EndSessionRedirect
	hook := i.EndSessionHook
	i.mu.Unlock()
	if hook != nil {
		hook()
	}
	if redirect {
		http.Redirect(w, request, i.Server.URL+"/logout-target", http.StatusFound)
		return
	}
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (i *refreshIssuer) handleEndSessionTarget(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	i.endSessionTargetCalls++
	i.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (i *refreshIssuer) standardClaims(subject, audience, tokenID string) map[string]any {
	now := i.Clock.Now()
	return map[string]any{
		"sub": subject, "iss": i.Server.URL, "aud": audience, "jti": tokenID,
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
}

func (i *refreshIssuer) sign(claims map[string]any) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "refresh-key"
	raw, err := token.SignedString(i.Key)
	if err != nil {
		panic(err)
	}
	return raw
}

func (i *refreshIssuer) EndSessionCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.endSessionCalls
}

func (i *refreshIssuer) RefreshCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.refreshCalls
}

func (i *refreshIssuer) UserInfoCalls() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.userinfoCalls
}

func (i *refreshIssuer) blockRefresh() (<-chan struct{}, chan<- struct{}) {
	i.mu.Lock()
	defer i.mu.Unlock()
	started := make(chan struct{})
	release := make(chan struct{})
	i.refreshStarted = started
	i.refreshRelease = release
	return started, release
}

func (i *refreshIssuer) blockUserInfo() (<-chan struct{}, chan<- struct{}) {
	i.mu.Lock()
	defer i.mu.Unlock()
	started := make(chan struct{})
	release := make(chan struct{})
	i.userInfoStarted = started
	i.userInfoRelease = release
	return started, release
}

func closeTestBlock(release chan<- struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(release) }) }
}

func receiveTestValue[T any](t *testing.T, values <-chan T, description string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(2 * time.Second):
		var zero T
		t.Fatalf("timed out waiting for %s", description)
		return zero
	}
}

func (i *refreshIssuer) lastRefreshRequest() (url.Values, http.Header) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return cloneValues(i.lastRefreshForm), i.lastRefreshHeader.Clone()
}

func TestRefreshAtomicallyReplacesTokensIdentityGroupsAndScopes(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	old := seedExpiringSession(t, backend, []string{"old"}, []string{"openid", "groups"})
	issuer.RefreshGroups = []string{"new"}
	issuer.RefreshScope = "openid groups email"
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-portal_session", Value: old.ID})
	credential, present, err := client.ResolveSession(request)
	if err != nil || !present {
		t.Fatalf("ResolveSession() = %#v/%v/%v", credential, present, err)
	}
	stored, _ := backend.Get(t.Context(), old.ID)
	if !slices.Equal(stored.Auth.Groups, []string{"new"}) ||
		!slices.Equal(stored.Tokens.GrantedScopes, []string{"email", "groups", "openid"}) {
		t.Fatalf("session=%#v", stored)
	}
	if stored.Tokens.AccessToken == old.Tokens.AccessToken || stored.Tokens.IDToken == old.Tokens.IDToken ||
		stored.Tokens.RefreshToken != "refresh-token-rotated-sensitive" || stored.Auth.Subject != testSubject ||
		stored.Auth.Username != "" || stored.Auth.DisplayName != "" || stored.Auth.Email != "new@example.test" ||
		!slices.Equal(stored.Auth.Scopes, stored.Tokens.GrantedScopes) {
		t.Fatal("refresh did not atomically replace the full verified session state")
	}
	access, err := credential.Tokens.AccessToken(t.Context())
	if err != nil || access != stored.Tokens.AccessToken || issuer.RefreshCalls() != 1 || issuer.UserInfoCalls() != 1 {
		t.Fatalf("access/calls = redacted/%v/%d/%d", err, issuer.RefreshCalls(), issuer.UserInfoCalls())
	}
	form, headers := issuer.lastRefreshRequest()
	wantForm := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {"refresh-token-old-sensitive"},
		"client_id": {testClientID}, "client_secret": {testClientSecret},
	}
	if !reflect.DeepEqual(form, wantForm) || headers.Get("Accept") != "application/json" ||
		headers.Get("Content-Type") != "application/x-www-form-urlencoded" || headers.Get("Authorization") != "" {
		t.Fatal("refresh request did not match the frozen token endpoint contract")
	}
}

func TestRefreshValidationFailureCommitsNothing(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	before := seedExpiringSession(t, backend, []string{"old"}, []string{"openid", "groups"})
	issuer.RefreshAudience = "different-client"
	if _, _, err := client.ResolveSession(requestWithSessionCookie(before.ID)); err == nil {
		t.Fatal("ResolveSession() error=nil")
	}
	after, err := backend.Get(t.Context(), before.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("after=%#v err=%v want=%#v", after, err, before)
	}
}

func TestRefreshCannotSwitchExistingSessionSubject(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	before := seedExpiringSession(t, backend, []string{"old"}, []string{"openid", "groups"})
	issuer.RefreshSubject = "different-user"
	issuer.RefreshUserInfoSubject = "different-user"
	if _, _, err := client.ResolveSession(requestWithSessionCookie(before.ID)); !errors.Is(err, core.ErrUnauthenticated) {
		t.Fatalf("ResolveSession() error=%v", err)
	}
	after, err := backend.Get(t.Context(), before.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("subject-switching refresh committed session state")
	}
}

func TestInvalidGrantDeletesSessionWithLease(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"old"}, []string{"openid"})
	issuer.RefreshOAuthError = "invalid_grant"
	_, _, err := client.ResolveSession(requestWithSessionCookie(item.ID))
	if !errors.Is(err, core.ErrInvalidGrant) {
		t.Fatalf("error=%v", err)
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("Get() error=%v", err)
	}
}

type deleteLeaseFailingBackend struct {
	session.Backend
	deleteCalls atomic.Int32
}

type conflictOnceDeleteBackend struct {
	session.Backend
	once        sync.Once
	deleteCalls atomic.Int32
}

type blockingDeleteBackend struct {
	session.Backend
	unblock     <-chan struct{}
	deleteCalls atomic.Int32
}

func (b *blockingDeleteBackend) DeleteWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
) error {
	b.deleteCalls.Add(1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.unblock:
		return b.Backend.DeleteWithLease(ctx, lease, id, expectedVersion)
	}
}

func (b *conflictOnceDeleteBackend) DeleteWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
) error {
	b.deleteCalls.Add(1)
	b.once.Do(func() {
		current, err := b.Backend.Get(ctx, id)
		if err != nil {
			return
		}
		next := cloneSessionState(current)
		next.Version++
		next.LastSeenAt = next.LastSeenAt.Add(time.Millisecond)
		_ = b.Backend.CompareAndSwap(ctx, id, current.Version, next)
	})
	return b.Backend.DeleteWithLease(ctx, lease, id, expectedVersion)
}

func (b *deleteLeaseFailingBackend) DeleteWithLease(
	context.Context,
	session.Lease,
	string,
	uint64,
) error {
	b.deleteCalls.Add(1)
	return session.ErrLeaseLost
}

func TestInvalidGrantPreservesClassificationWhenFencedDeleteLosesLease(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"old"}, []string{"openid"})
	failing := &deleteLeaseFailingBackend{Backend: backend}
	client.backend = failing
	issuer.RefreshOAuthError = "invalid_grant"
	_, _, err := client.ResolveSession(requestWithSessionCookie(item.ID))
	if !errors.Is(err, core.ErrInvalidGrant) || failing.deleteCalls.Load() != 1 {
		t.Fatalf("error=%v delete calls=%d", err, failing.deleteCalls.Load())
	}
}

func TestInvalidGrantRetriesFencedDeleteAfterLastSeenConflict(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"old"}, []string{"openid"})
	conflicting := &conflictOnceDeleteBackend{Backend: backend}
	client.backend = conflicting
	issuer.RefreshOAuthError = "invalid_grant"
	_, _, err := client.ResolveSession(requestWithSessionCookie(item.ID))
	if !errors.Is(err, core.ErrInvalidGrant) {
		t.Fatalf("ResolveSession() error=%v", err)
	}
	if conflicting.deleteCalls.Load() != 2 {
		t.Fatalf("DeleteWithLease calls=%d", conflicting.deleteCalls.Load())
	}
	if _, err := backend.Get(t.Context(), item.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("invalid-grant session survived a LastSeen conflict: %v", err)
	}
}

func TestInvalidGrantBoundsDetachedFencedDelete(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"old"}, []string{"openid"})
	unblock := make(chan struct{})
	defer close(unblock)
	client.refreshLeaseTTL = 20 * time.Millisecond
	blocking := &blockingDeleteBackend{Backend: backend, unblock: unblock}
	client.backend = blocking
	issuer.RefreshOAuthError = "invalid_grant"
	result := make(chan error, 1)
	go func() {
		_, _, err := client.ResolveSession(requestWithSessionCookie(item.ID))
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, core.ErrInvalidGrant) || blocking.deleteCalls.Load() != 1 {
			t.Fatalf("ResolveSession() error=%v delete calls=%d", err, blocking.deleteCalls.Load())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("invalid-grant refresh hung in detached fenced delete")
	}
}

func TestRefreshTemporaryFailureReleasesLeaseWithoutMutation(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	before := seedExpiringSession(t, backend, []string{"old"}, []string{"openid"})
	issuer.RefreshOAuthError = "temporarily_unavailable"
	issuer.RefreshStatus = http.StatusServiceUnavailable
	_, _, err := client.ResolveSession(requestWithSessionCookie(before.ID))
	if !errors.Is(err, core.ErrUnavailable) {
		t.Fatalf("temporary refresh error=%v", err)
	}
	after, getErr := backend.Get(t.Context(), before.ID)
	if getErr != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("temporary failure mutated session: after=%#v err=%v", after, getErr)
	}
	issuer.RefreshOAuthError = ""
	issuer.RefreshStatus = http.StatusOK
	if _, present, err := client.ResolveSession(requestWithSessionCookie(before.ID)); err != nil || !present {
		t.Fatalf("second ResolveSession() present=%v err=%v", present, err)
	}
	if issuer.RefreshCalls() != 2 {
		t.Fatalf("refresh calls=%d", issuer.RefreshCalls())
	}
}

func TestResolveSessionNormalizesWrappedSecretProviderContextErrors(t *testing.T) {
	for name, providerErr := range map[string]error{
		"canceled": context.Canceled,
		"deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			client, backend, issuer := newRefreshTestClient(t)
			before := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
			secret := "refresh-provider-wrapper-sensitive-" + name
			wrapped := fmt.Errorf("%s: %w", secret, providerErr)
			client.clientSecret = SecretProviderFunc(func(context.Context) (string, error) { return "", wrapped })

			_, present, err := client.ResolveSession(requestWithSessionCookie(before.ID))
			if !present || err != providerErr || strings.Contains(err.Error(), secret) || issuer.RefreshCalls() != 0 {
				t.Fatalf("ResolveSession did not normalize provider context error: present=%v calls=%d", present, issuer.RefreshCalls())
			}
			after, getErr := backend.Get(t.Context(), before.ID)
			if getErr != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("provider context error mutated Session state")
			}
		})
	}
}

type observingBackend struct {
	session.Backend
	leaseConflict chan struct{}
	waitReload    chan struct{}
	conflictOnce  sync.Once
	waitOnce      sync.Once
	conflicted    atomic.Bool
}

type signalingGetBackend struct {
	session.Backend
	reloaded chan struct{}
	once     sync.Once
	getCalls atomic.Int32
}

func (b *signalingGetBackend) Get(ctx context.Context, id string) (*session.Session, error) {
	b.getCalls.Add(1)
	item, err := b.Backend.Get(ctx, id)
	b.once.Do(func() { close(b.reloaded) })
	return item, err
}

type countingLeasedCASBackend struct {
	session.Backend
	casCalls atomic.Int32
}

func (b *countingLeasedCASBackend) CompareAndSwapWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
	b.casCalls.Add(1)
	return b.Backend.CompareAndSwapWithLease(ctx, lease, id, expectedVersion, next)
}

type blockingReleaseLease struct {
	session.Lease
	unblock <-chan struct{}
}

func (l *blockingReleaseLease) Release(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.unblock:
		return l.Lease.Release(context.Background())
	}
}

type blockingReleaseBackend struct {
	session.Backend
	unblock <-chan struct{}
}

func (b *blockingReleaseBackend) AcquireRefreshLease(
	ctx context.Context,
	id string,
	duration time.Duration,
) (session.Lease, error) {
	lease, err := b.Backend.AcquireRefreshLease(ctx, id, duration)
	if err != nil {
		return nil, err
	}
	return &blockingReleaseLease{Lease: lease, unblock: b.unblock}, nil
}

func (b *blockingReleaseBackend) CompareAndSwapWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
	next *session.Session,
) error {
	return b.Backend.CompareAndSwapWithLease(ctx, unwrapBlockingReleaseLease(lease), id, expectedVersion, next)
}

func (b *blockingReleaseBackend) DeleteWithLease(
	ctx context.Context,
	lease session.Lease,
	id string,
	expectedVersion uint64,
) error {
	return b.Backend.DeleteWithLease(ctx, unwrapBlockingReleaseLease(lease), id, expectedVersion)
}

func unwrapBlockingReleaseLease(lease session.Lease) session.Lease {
	if wrapped, ok := lease.(*blockingReleaseLease); ok {
		return wrapped.Lease
	}
	return lease
}

func (b *observingBackend) AcquireRefreshLease(
	ctx context.Context,
	id string,
	duration time.Duration,
) (session.Lease, error) {
	lease, err := b.Backend.AcquireRefreshLease(ctx, id, duration)
	if errors.Is(err, session.ErrConflict) && b.leaseConflict != nil {
		b.conflicted.Store(true)
		b.conflictOnce.Do(func() { close(b.leaseConflict) })
	}
	return lease, err
}

func (b *observingBackend) Get(ctx context.Context, id string) (*session.Session, error) {
	if b.conflicted.Load() && b.waitReload != nil {
		b.waitOnce.Do(func() { close(b.waitReload) })
	}
	return b.Backend.Get(ctx, id)
}

func TestRefreshLeaseLoserReloadsWinnerAtDeadlineBoundary(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	baseline := seedExpiringSession(t, backend, []string{"old"}, []string{"openid", "groups"})
	reloaded := make(chan struct{})
	signaling := &signalingGetBackend{Backend: backend, reloaded: reloaded}
	client.backend = signaling
	deadline := make(chan time.Time, 1)
	ticks := make(chan time.Time)
	type result struct {
		item *session.Session
		err  error
	}
	resultChannel := make(chan result, 1)
	go func() {
		item, err := client.waitForRefreshWinnerUntil(t.Context(), baseline, deadline, ticks)
		resultChannel <- result{item: item, err: err}
	}()
	receiveTestValue(t, reloaded, "lease loser initial reload")
	winner := cloneSessionForTest(baseline)
	winner.Version++
	winner.Tokens.AccessToken = "winner-access-token-sensitive"
	winner.Tokens.RefreshToken = "winner-refresh-token-sensitive"
	winner.Tokens.AccessTokenExpiry = refreshTestNow.Add(5 * time.Minute)
	if err := backend.CompareAndSwap(t.Context(), baseline.ID, baseline.Version, winner); err != nil {
		t.Fatal(err)
	}
	deadline <- time.Now()
	outcome := receiveTestValue(t, resultChannel, "deadline-boundary lease winner")
	if outcome.err != nil || outcome.item == nil ||
		outcome.item.Tokens.AccessToken != winner.Tokens.AccessToken || issuer.RefreshCalls() != 0 ||
		signaling.getCalls.Load() != 2 {
		t.Fatalf(
			"deadline winner error=%v refresh calls=%d reloads=%d",
			outcome.err,
			issuer.RefreshCalls(),
			signaling.getCalls.Load(),
		)
	}
}

func TestConcurrentRefreshLeaseLoserReloadsWinnerWithoutSecondExchange(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"old"}, []string{"openid", "groups"})
	started, release := issuer.blockRefresh()
	releaseRefresh := closeTestBlock(release)
	defer releaseRefresh()
	conflict := make(chan struct{})
	client.backend = &observingBackend{Backend: backend, leaseConflict: conflict}
	type result struct {
		credential core.Credential
		present    bool
		err        error
	}
	results := make(chan result, 2)
	resolve := func() {
		credential, present, err := client.ResolveSession(requestWithSessionCookie(item.ID))
		results <- result{credential: credential, present: present, err: err}
	}
	go resolve()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("winning refresh did not reach token endpoint")
	}
	go resolve()
	select {
	case <-conflict:
	case <-time.After(2 * time.Second):
		t.Fatal("second resolver did not lose the active refresh lease")
	}
	releaseRefresh()
	first := receiveTestValue(t, results, "first concurrent refresh result")
	second := receiveTestValue(t, results, "second concurrent refresh result")
	if first.err != nil || second.err != nil || !first.present || !second.present || issuer.RefreshCalls() != 1 {
		t.Fatalf(
			"concurrent refresh errors=%v/%v present=%v/%v refresh calls=%d",
			first.err,
			second.err,
			first.present,
			second.present,
			issuer.RefreshCalls(),
		)
	}
	firstToken, firstErr := first.credential.Tokens.AccessToken(t.Context())
	secondToken, secondErr := second.credential.Tokens.AccessToken(t.Context())
	if firstErr != nil || secondErr != nil || firstToken == item.Tokens.AccessToken || firstToken != secondToken {
		t.Fatal("lease loser did not reload the winning access token")
	}
}

func TestRefreshUsesExactlyOneLeasedCASOnlyAfterValidation(t *testing.T) {
	t.Run("successful refresh", func(t *testing.T) {
		client, backend, _ := newRefreshTestClient(t)
		item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
		counting := &countingLeasedCASBackend{Backend: backend}
		client.backend = counting
		if _, present, err := client.ResolveSession(requestWithSessionCookie(item.ID)); err != nil || !present {
			t.Fatalf("ResolveSession() present=%v err=%v", present, err)
		}
		if counting.casCalls.Load() != 1 {
			t.Fatalf("CompareAndSwapWithLease calls=%d", counting.casCalls.Load())
		}
	})

	t.Run("failed validation", func(t *testing.T) {
		client, backend, issuer := newRefreshTestClient(t)
		item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
		counting := &countingLeasedCASBackend{Backend: backend}
		client.backend = counting
		issuer.RefreshAudience = "different-client"
		if _, _, err := client.ResolveSession(requestWithSessionCookie(item.ID)); err == nil {
			t.Fatal("ResolveSession() error=nil")
		}
		if counting.casCalls.Load() != 0 {
			t.Fatalf("CompareAndSwapWithLease calls=%d", counting.casCalls.Load())
		}
	})
}

func TestRefreshBoundsDetachedLeaseCleanup(t *testing.T) {
	client, backend, _ := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	unblock := make(chan struct{})
	defer close(unblock)
	client.refreshLeaseTTL = 20 * time.Millisecond
	client.backend = &blockingReleaseBackend{Backend: backend, unblock: unblock}
	result := make(chan error, 1)
	go func() {
		_, _, err := client.ResolveSession(requestWithSessionCookie(item.ID))
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("ResolveSession() error=%v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("refresh hung in detached lease cleanup")
	}
}

func TestRefreshPreservesOmittedRotatableTokens(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	before := seedExpiringSession(t, backend, []string{"old"}, []string{"openid", "groups"})
	issuer.OmitRefreshToken = true
	issuer.OmitIDToken = true
	if _, present, err := client.ResolveSession(requestWithSessionCookie(before.ID)); err != nil || !present {
		t.Fatalf("ResolveSession() present=%v err=%v", present, err)
	}
	after, err := backend.Get(t.Context(), before.ID)
	if err != nil || after.Tokens.RefreshToken != before.Tokens.RefreshToken || after.Tokens.IDToken != before.Tokens.IDToken ||
		after.Tokens.AccessToken == before.Tokens.AccessToken {
		t.Fatal("refresh did not preserve omitted refresh/ID token fields")
	}
}

func TestRefreshRejectsInconsistentClaimsWithoutPartialCommit(t *testing.T) {
	tests := map[string]func(*refreshIssuer){
		"scope":   func(issuer *refreshIssuer) { issuer.RefreshIDScope = "openid email" },
		"groups":  func(issuer *refreshIssuer) { issuer.RefreshUserInfoGroups = []string{"different"} },
		"subject": func(issuer *refreshIssuer) { issuer.RefreshUserInfoSubject = "different-subject" },
		"missing access token": func(issuer *refreshIssuer) {
			issuer.RefreshTokenBody = `{"token_type":"Bearer","expires_in":300,"scope":"openid"}`
		},
		"null rotated refresh token": func(issuer *refreshIssuer) {
			issuer.RefreshTokenBody = `{"access_token":"opaque","token_type":"Bearer","expires_in":300,"scope":"openid","refresh_token":null}`
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, backend, issuer := newRefreshTestClient(t)
			before := seedExpiringSession(t, backend, []string{"ops"}, []string{"email", "groups", "openid", "profile"})
			mutate(issuer)
			if _, _, err := client.ResolveSession(requestWithSessionCookie(before.ID)); err == nil {
				t.Fatal("ResolveSession() error=nil")
			}
			after, err := backend.Get(t.Context(), before.ID)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("failed refresh partially committed session state")
			}
		})
	}
}

func TestRefreshStartsAtExactConfiguredExpiryBoundary(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	item, err := backend.Get(t.Context(), item.ID)
	if err != nil {
		t.Fatal(err)
	}
	item.Version++
	item.Tokens.AccessTokenExpiry = refreshTestNow.Add(time.Minute)
	if err := backend.CompareAndSwap(t.Context(), item.ID, item.Version-1, item); err != nil {
		t.Fatal(err)
	}
	if _, present, err := client.ResolveSession(requestWithSessionCookie(item.ID)); err != nil || !present {
		t.Fatalf("ResolveSession() present=%v err=%v", present, err)
	}
	if issuer.RefreshCalls() != 1 {
		t.Fatalf("refresh calls at equality=%d", issuer.RefreshCalls())
	}
}

func TestRefreshSchedulingUsesEarlierResponseAndJWTExpiry(t *testing.T) {
	tests := map[string]struct {
		expiresIn int64
		want      time.Time
	}{
		"response is earlier": {expiresIn: 30, want: refreshTestNow.Add(30 * time.Second)},
		"jwt is earlier":      {expiresIn: 600, want: refreshTestNow.Add(5 * time.Minute)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, backend, issuer := newRefreshTestClient(t)
			item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
			issuer.RefreshExpiresIn = test.expiresIn
			if _, present, err := client.ResolveSession(requestWithSessionCookie(item.ID)); err != nil || !present {
				t.Fatalf("ResolveSession() present=%v err=%v", present, err)
			}
			stored, err := backend.Get(t.Context(), item.ID)
			if err != nil || !stored.Tokens.AccessTokenExpiry.Equal(test.want) {
				t.Fatalf("AccessTokenExpiry=%v err=%v want=%v", stored.Tokens.AccessTokenExpiry, err, test.want)
			}
		})
	}
}

func TestRefreshExpiresInStartsWhenTokenResponseIsReceived(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	client.refreshLeaseTTL = time.Minute
	issuer.RefreshExpiresIn = 30
	issuer.AdvanceOnUserInfo = 20 * time.Second
	if _, present, err := client.ResolveSession(requestWithSessionCookie(item.ID)); err != nil || !present {
		t.Fatalf("ResolveSession() present=%v err=%v", present, err)
	}
	stored, err := backend.Get(t.Context(), item.ID)
	want := refreshTestNow.Add(30 * time.Second)
	if err != nil || !stored.Tokens.AccessTokenExpiry.Equal(want) {
		t.Fatalf("AccessTokenExpiry=%v err=%v want=%v", stored.Tokens.AccessTokenExpiry, err, want)
	}
}

func TestRefreshRejectsTokenThatExpiresDuringUserInfoValidation(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	before := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	client.refreshLeaseTTL = time.Minute
	issuer.RefreshExpiresIn = 30
	issuer.AdvanceOnUserInfo = 30 * time.Second
	if _, _, err := client.ResolveSession(requestWithSessionCookie(before.ID)); !errors.Is(err, core.ErrUnauthenticated) {
		t.Fatalf("ResolveSession() error=%v", err)
	}
	after, err := backend.Get(t.Context(), before.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("refresh committed a token that expired during validation")
	}
}

func TestRefreshLeaseExpiryCannotCommitConsumedTokens(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	before := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	issuer.AdvanceOnRefresh = time.Second
	if _, _, err := client.ResolveSession(requestWithSessionCookie(before.ID)); err == nil {
		t.Fatal("ResolveSession() error=nil after lease expiry")
	}
	after, err := backend.Get(t.Context(), before.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("expired refresh lease committed partial state")
	}
}

func TestRefreshLeaseLoserHonorsContextCancellation(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	before, err := backend.Get(t.Context(), item.ID)
	if err != nil {
		t.Fatal(err)
	}
	started, release := issuer.blockRefresh()
	releaseRefresh := closeTestBlock(release)
	defer releaseRefresh()
	conflict := make(chan struct{})
	waitReload := make(chan struct{})
	client.backend = &observingBackend{Backend: backend, leaseConflict: conflict, waitReload: waitReload}
	winnerDone := make(chan error, 1)
	go func() {
		_, _, err := client.ResolveSession(requestWithSessionCookie(item.ID))
		winnerDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("winning refresh did not start")
	}
	ctx, cancel := context.WithCancel(t.Context())
	request := requestWithSessionCookie(item.ID).WithContext(ctx)
	loserDone := make(chan error, 1)
	go func() {
		_, _, err := client.ResolveSession(request)
		loserDone <- err
	}()
	receiveTestValue(t, conflict, "losing refresh lease conflict")
	receiveTestValue(t, waitReload, "lease loser wait reload")
	cancel()
	err = receiveTestValue(t, loserDone, "canceled lease loser result")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lease loser cancellation error=%v", err)
	}
	after, getErr := backend.Get(t.Context(), item.ID)
	if getErr != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("canceled lease loser mutated session state")
	}
	releaseRefresh()
	if err := receiveTestValue(t, winnerDone, "winning refresh result"); err != nil {
		t.Fatalf("winner error=%v", err)
	}
	if issuer.RefreshCalls() != 1 {
		t.Fatalf("refresh calls=%d", issuer.RefreshCalls())
	}
}

func TestRefreshPreservesInFlightUserInfoCancellationWithoutCommit(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	before := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	started, release := issuer.blockUserInfo()
	releaseUserInfo := closeTestBlock(release)
	defer releaseUserInfo()
	ctx, cancel := context.WithCancel(t.Context())
	request := requestWithSessionCookie(before.ID).WithContext(ctx)
	result := make(chan error, 1)
	go func() {
		_, _, err := client.ResolveSession(request)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not reach UserInfo")
	}
	cancel()
	var err error
	select {
	case err = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled refresh did not return")
	}
	releaseUserInfo()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveSession() error=%v", err)
	}
	after, getErr := backend.Get(t.Context(), before.ID)
	if getErr != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("canceled UserInfo committed refresh state")
	}
}

func TestRefreshPreservesCancellationWhileReadingTokenResponse(t *testing.T) {
	client, backend, _ := newRefreshTestClient(t)
	before := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid", "groups"})
	started := make(chan struct{})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       &canceledResponseBody{ctx: request.Context(), started: started},
			Request:    request,
		}, nil
	})}
	ctx, cancel := context.WithCancel(t.Context())
	request := requestWithSessionCookie(before.ID).WithContext(ctx)
	result := make(chan error, 1)
	go func() {
		_, _, err := client.ResolveSession(request)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not begin reading the token response")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ResolveSession() error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled token response read did not return")
	}
	after, err := backend.Get(t.Context(), before.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("canceled token response read mutated session state")
	}
}

func TestRefreshErrorsAndObservationNeverExposeSecrets(t *testing.T) {
	client, backend, issuer := newRefreshTestClient(t)
	observer := &recordingObserver{}
	var logs bytes.Buffer
	client.observer = observer
	client.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	item := seedExpiringSession(t, backend, []string{"ops"}, []string{"openid"})
	issuer.RefreshOAuthError = "temporarily_unavailable"
	issuer.RefreshStatus = http.StatusServiceUnavailable
	_, _, err := client.ResolveSession(requestWithSessionCookie(item.ID))
	if err == nil {
		t.Fatal("ResolveSession() error=nil")
	}
	combined := err.Error() + observer.String() + logs.String()
	for _, secret := range []string{item.ID, item.Tokens.AccessToken, item.Tokens.RefreshToken, item.Tokens.IDToken, testClientSecret} {
		if strings.Contains(combined, secret) {
			t.Fatalf("lifecycle diagnostics exposed secret material")
		}
	}
	if !strings.Contains(observer.String(), "bff.exchange_refresh") || !strings.Contains(logs.String(), `"operation":"bff.exchange_refresh"`) {
		t.Fatal("refresh did not emit sanitized observability")
	}
}
