package bff

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
)

func TestCallbackCreatesAuthenticatedServerSessionFromVerifiedAccessToken(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	created := completeLogin(t, client, issuer)
	wantExpiry := issuer.Clock.Now().Add(5 * time.Minute)
	if created.ID == "" || created.Version != 1 || created.Auth.Subject != testSubject || created.Auth.Issuer != issuer.Server.URL ||
		!slices.Equal(created.Auth.Audience, []string{testClientID}) || !slices.Equal(created.Auth.Scopes, []string{"email", "groups", "openid", "profile"}) ||
		!slices.Equal(created.Tokens.GrantedScopes, created.Auth.Scopes) || !slices.Equal(created.Auth.Groups, []string{"dev", "ops"}) ||
		created.Auth.Username != "ada" || created.Auth.DisplayName != "Ada Lovelace" || created.Auth.Email != "ada@example.test" ||
		created.Tokens.TokenType != "Bearer" || created.Tokens.AccessToken == "" || created.Tokens.IDToken == "" ||
		created.Tokens.RefreshToken != testRefreshToken || !created.Tokens.AccessTokenExpiry.Equal(wantExpiry) {
		t.Fatal("created session fields do not match verified callback data")
	}
	if issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != 1 {
		t.Fatalf("token calls=%d userinfo calls=%d", issuer.TokenCalls.Load(), issuer.UserInfoCalls())
	}
}

func TestCallbackNeverElevatesRequestedScope(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.TokenScope = "openid groups"
	issuer.AccessTokenScope = "openid groups"
	issuer.IDTokenScope = "openid groups"
	created := completeLogin(t, client, issuer)
	if !slices.Equal(created.Tokens.GrantedScopes, []string{"groups", "openid"}) ||
		created.Auth.Username != "" || created.Auth.DisplayName != "" || created.Auth.Email != "" {
		t.Fatal("requested scopes or ungranted profile fields were elevated")
	}
}

func TestCallbackRejectsScopesNotRequestedByThisClient(t *testing.T) {
	tests := map[string]string{
		"roles":                   "openid roles",
		"other scope":             "openid administrative",
		"malformed backslash":     `openid bad\scope`,
		"malformed tab separator": "openid\tgroups",
	}
	for name, remoteScopes := range tests {
		t.Run(name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			issuer.TokenScope = remoteScopes
			issuer.AccessTokenScope = remoteScopes
			issuer.IDTokenScope = remoteScopes
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != 0 || hasSessionCookie(response, client) {
				t.Fatalf("unrequested scopes were accepted: status=%d token=%d userinfo=%d", response.Code, issuer.TokenCalls.Load(), issuer.UserInfoCalls())
			}
		})
	}
}

func hasSessionCookie(response *httptest.ResponseRecorder, client *Client) bool {
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == client.sessionCookie.Name && cookie.Value != "" {
			return true
		}
	}
	return false
}

func TestCallbackKeepsVerifiedAccessProfileWhenUserInfoOmitsOptionalFields(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.AccessUsername = "access-user"
	issuer.AccessDisplayName = "Access Display"
	issuer.AccessEmail = "access@example.test"
	issuer.UserInfoBody = `{"sub":"` + testSubject + `","groups":["dev","ops"]}`
	created := completeLogin(t, client, issuer)
	if created.Auth.Username != "access-user" || created.Auth.DisplayName != "Access Display" || created.Auth.Email != "access@example.test" {
		t.Fatalf("access-token profile was discarded: %#v", created.Auth)
	}
}

func TestCallbackConsumesFlowBeforeStateValidationAndRejectsReplay(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	attempt := beginLogin(t, client, issuer, "/")
	first := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {"wrong-state-sensitive"}}.Encode())
	second := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if first.Code != http.StatusUnauthorized || second.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 0 {
		t.Fatalf("first=%d second=%d calls=%d", first.Code, second.Code, issuer.TokenCalls.Load())
	}
}

func TestCallbackSuccessfulCodeIsOneTime(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	attempt := beginLogin(t, client, issuer, "/")
	query := url.Values{"code": {testCode}, "state": {attempt.State}}.Encode()
	first := serveCallback(t, client, attempt, query)
	second := serveCallback(t, client, attempt, query)
	if first.Code != http.StatusFound || second.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != 1 {
		t.Fatalf("first=%d second=%d token=%d userinfo=%d", first.Code, second.Code, issuer.TokenCalls.Load(), issuer.UserInfoCalls())
	}
}

func TestCallbackRejectsMissingOrDuplicateStateBeforeExchange(t *testing.T) {
	queries := []func(loginAttempt) string{
		func(loginAttempt) string { return "code=" + testCode },
		func(attempt loginAttempt) string { return "code=" + testCode + "&state=&state=" + attempt.State },
		func(attempt loginAttempt) string {
			return "code=" + testCode + "&state=" + attempt.State + "&state=" + attempt.State
		},
	}
	for index, query := range queries {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, query(attempt))
			if response.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 0 {
				t.Fatalf("status=%d calls=%d", response.Code, issuer.TokenCalls.Load())
			}
		})
	}
}

func TestCallbackOAuthAuthorizationErrorConsumesFlowWithoutExchange(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	attempt := beginLogin(t, client, issuer, "/")
	query := url.Values{"error": {"access_denied"}, "error_description": {testCode}, "state": {attempt.State}}.Encode()
	first := serveCallback(t, client, attempt, query)
	second := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if first.Code != http.StatusUnauthorized || second.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 0 ||
		strings.Contains(first.Body.String(), testCode) {
		t.Fatalf("authorization error was not one-time and sanitized: first=%d second=%d calls=%d", first.Code, second.Code, issuer.TokenCalls.Load())
	}
}

func TestCallbackRejectsWrongNonceAndSubjectMismatches(t *testing.T) {
	tests := map[string]func(*bffIssuer){
		"wrong nonce":           func(issuer *bffIssuer) { issuer.IDTokenNonce = "wrong-nonce-sensitive" },
		"id token subject":      func(issuer *bffIssuer) { issuer.IDTokenSubject = "other-subject" },
		"userinfo subject":      func(issuer *bffIssuer) { issuer.UserInfoSubject = "other-subject" },
		"missing id subject":    func(issuer *bffIssuer) { issuer.IDTokenSubject = "" },
		"missing userinfo sub":  func(issuer *bffIssuer) { issuer.UserInfoSubject = "" },
		"userinfo bad response": func(issuer *bffIssuer) { issuer.UserInfoBody = `{"sub":7}` },
		"userinfo null profile": func(issuer *bffIssuer) {
			issuer.UserInfoBody = `{"sub":"` + testSubject + `","username":null,"groups":["dev","ops"]}`
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			mutate(issuer)
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusBadRequest {
				t.Fatalf("identity mismatch or malformed response status=%d", response.Code)
			}
		})
	}
}

func TestCallbackRejectsAnotherAcceptedClientAudience(t *testing.T) {
	tests := map[string]func(*bffIssuer){
		"access token": func(issuer *bffIssuer) { issuer.AccessAudience = "other-audience" },
		"id token":     func(issuer *bffIssuer) { issuer.IDAudience = "other-audience" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			mutate(issuer)
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != http.StatusUnauthorized || issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != 0 {
				t.Fatalf("cross-client audience was not rejected: status=%d token=%d userinfo=%d", response.Code, issuer.TokenCalls.Load(), issuer.UserInfoCalls())
			}
		})
	}
}

func TestCallbackRequiresExactBearerAndPositiveExpiresIn(t *testing.T) {
	tests := map[string]func(*bffIssuer){
		"lowercase bearer": func(issuer *bffIssuer) { issuer.TokenType = "bearer" },
		"different type":   func(issuer *bffIssuer) { issuer.TokenType = "DPoP" },
		"zero expires":     func(issuer *bffIssuer) { issuer.ExpiresIn = 0 },
		"negative expires": func(issuer *bffIssuer) { issuer.ExpiresIn = -1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			mutate(issuer)
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != 0 {
				t.Fatalf("status=%d token=%d userinfo=%d", response.Code, issuer.TokenCalls.Load(), issuer.UserInfoCalls())
			}
		})
	}
}

func TestCallbackRejectsExpiredOrTamperedFlowBeforeExchange(t *testing.T) {
	tests := map[string]func(*recordingBackend, *bffIssuer){
		"expired": func(_ *recordingBackend, issuer *bffIssuer) { issuer.Clock.Advance(11 * time.Minute) },
		"invalid verifier": func(backend *recordingBackend, _ *bffIssuer) {
			backend.mutateLastFlow(t, func(flow *session.Flow) { flow.CodeVerifier = "not valid!" })
		},
		"wrong client": func(backend *recordingBackend, _ *bffIssuer) {
			backend.mutateLastFlow(t, func(flow *session.Flow) { flow.ClientID = "other" })
		},
		"wrong redirect": func(backend *recordingBackend, _ *bffIssuer) {
			backend.mutateLastFlow(t, func(flow *session.Flow) { flow.RedirectURL = "https://evil.example/callback" })
		},
		"future created": func(backend *recordingBackend, issuer *bffIssuer) {
			backend.mutateLastFlow(t, func(flow *session.Flow) { flow.CreatedAt = issuer.Clock.Now().Add(time.Minute) })
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, backend, issuer := newBFFTestClient(t)
			attempt := beginLogin(t, client, issuer, "/")
			mutate(backend, issuer)
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 0 {
				t.Fatalf("status=%d calls=%d", response.Code, issuer.TokenCalls.Load())
			}
		})
	}
}

func TestCallbackMismatchedS256VerifierIsInvalidGrantWithoutRetry(t *testing.T) {
	client, backend, issuer := newBFFTestClient(t)
	attempt := beginLogin(t, client, issuer, "/")
	backend.mutateLastFlow(t, func(flow *session.Flow) { flow.CodeVerifier = strings.Repeat("A", 43) })
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if response.Code != http.StatusUnauthorized || issuer.TokenCalls.Load() != 1 {
		t.Fatalf("status=%d calls=%d", response.Code, issuer.TokenCalls.Load())
	}
}

func TestCallbackRejectsInconsistentScopeSources(t *testing.T) {
	tests := map[string]func(*bffIssuer){
		"token versus access": func(issuer *bffIssuer) { issuer.TokenScope = "openid groups"; issuer.AccessTokenScope = "openid" },
		"access versus id": func(issuer *bffIssuer) {
			issuer.IDTokenScope = "openid groups"
			issuer.AccessTokenScope = "openid"
			issuer.TokenScope = "<absent>"
		},
		"no sources": func(issuer *bffIssuer) {
			issuer.TokenScope, issuer.AccessTokenScope, issuer.IDTokenScope = "<absent>", "<absent>", "<absent>"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			mutate(issuer)
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != 0 {
				t.Fatalf("status=%d token=%d userinfo=%d", response.Code, issuer.TokenCalls.Load(), issuer.UserInfoCalls())
			}
		})
	}
}

func TestCallbackRejectsNullTokenResponseScope(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.TokenScope = "<null>"
	attempt := beginLogin(t, client, issuer, "/")
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if response.Code != http.StatusBadRequest || issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != 0 {
		t.Fatalf("status=%d token=%d userinfo=%d", response.Code, issuer.TokenCalls.Load(), issuer.UserInfoCalls())
	}
}

func TestCallbackValidatesTokenResponseErrorFieldPresenceAndType(t *testing.T) {
	tests := []struct {
		name         string
		configure    func(*bffIssuer)
		wantStatus   int
		wantUserInfo int
	}{
		{name: "absent succeeds", configure: func(*bffIssuer) {}, wantStatus: http.StatusFound, wantUserInfo: 1},
		{name: "null is malformed", configure: func(issuer *bffIssuer) {
			issuer.TokenErrorPresent, issuer.TokenResponseError = true, nil
		}, wantStatus: http.StatusBadRequest},
		{name: "number is malformed", configure: func(issuer *bffIssuer) {
			issuer.TokenErrorPresent, issuer.TokenResponseError = true, 7
		}, wantStatus: http.StatusBadRequest},
		{name: "recognized string error", configure: func(issuer *bffIssuer) {
			issuer.TokenStatus, issuer.TokenError = http.StatusBadRequest, "invalid_grant"
		}, wantStatus: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			test.configure(issuer)
			attempt := beginLogin(t, client, issuer, "/")
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
			if response.Code != test.wantStatus || issuer.TokenCalls.Load() != 1 || issuer.UserInfoCalls() != test.wantUserInfo {
				t.Fatalf("token error field case was misclassified: status=%d token=%d userinfo=%d", response.Code, issuer.TokenCalls.Load(), issuer.UserInfoCalls())
			}
		})
	}
}

func TestCallbackNormalizesAndReconcilesEveryAvailableGroupsSource(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.AccessTokenGroups = optionalStrings{Present: true, Values: []string{" ops ", "dev", "ops", ""}}
	issuer.IDTokenGroups = optionalStrings{Present: true, Values: []string{"dev", "ops"}}
	issuer.UserInfoGroups = optionalStrings{Present: true, Values: []string{"ops", " dev ", "dev"}}
	created := completeLogin(t, client, issuer)
	if !slices.Equal(created.Auth.Groups, []string{"dev", "ops"}) {
		t.Fatalf("groups=%v", created.Auth.Groups)
	}
}

func TestCallbackRejectsInconsistentGroupsAndNeverFallsBackToRoles(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.UserInfoGroups = optionalStrings{Present: true, Values: []string{"different"}}
	attempt := beginLogin(t, client, issuer, "/")
	response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {attempt.State}}.Encode())
	if response.Code != http.StatusBadRequest {
		t.Fatalf("mismatched groups status=%d", response.Code)
	}

	client, _, issuer = newBFFTestClient(t)
	issuer.AccessTokenGroups = optionalStrings{Present: true, Values: []string{}}
	issuer.IDTokenGroups = optionalStrings{Present: true, Values: []string{}}
	issuer.UserInfoGroups = optionalStrings{Present: true, Values: []string{}}
	created := completeLogin(t, client, issuer)
	if len(created.Auth.Groups) != 0 || slices.Contains(created.Auth.Groups, "role-must-never-fallback") {
		t.Fatalf("empty groups fell back to roles: %v", created.Auth.Groups)
	}
}

func TestCallbackDoesNotExposeGroupsWhenGroupsScopeIsNotGranted(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	issuer.TokenScope, issuer.AccessTokenScope, issuer.IDTokenScope = "openid", "openid", "openid"
	issuer.AccessTokenGroups = optionalStrings{Present: true, Values: []string{"access-only"}}
	issuer.IDTokenGroups = optionalStrings{Present: true, Values: []string{"id-only"}}
	issuer.UserInfoGroups = optionalStrings{Present: true, Values: []string{"userinfo-only"}}
	created := completeLogin(t, client, issuer)
	if len(created.Auth.Groups) != 0 {
		t.Fatalf("ungranted groups exposed: %v", created.Auth.Groups)
	}
}

func TestCallbackClearsFlowCookieOnSuccessAndFailure(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "failure"}[valid], func(t *testing.T) {
			client, _, issuer := newBFFTestClient(t)
			attempt := beginLogin(t, client, issuer, "/")
			state := attempt.State
			if !valid {
				state = "wrong"
			}
			response := serveCallback(t, client, attempt, url.Values{"code": {testCode}, "state": {state}}.Encode())
			cleared := false
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == client.flowCookie.Name && cookie.Value == "" && cookie.MaxAge < 0 && cookie.Path == "/" {
					cleared = true
				}
			}
			if !cleared {
				t.Fatal("flow cookie was not cleared with the required attributes")
			}
		})
	}
}

func TestCallbackRejectsMalformedCookieCodeAndMethod(t *testing.T) {
	client, _, issuer := newBFFTestClient(t)
	attempt := beginLogin(t, client, issuer, "/")
	tests := []*http.Request{
		func() *http.Request {
			request := httptest.NewRequest(http.MethodPost, "/callback?code="+testCode+"&state="+attempt.State, nil)
			request.AddCookie(attempt.Flow)
			return request
		}(),
		httptest.NewRequest(http.MethodGet, "/callback?code="+testCode+"&state="+attempt.State, nil),
		func() *http.Request {
			request := httptest.NewRequest(http.MethodGet, "/callback?code=&code="+testCode+"&state="+attempt.State, nil)
			request.AddCookie(attempt.Flow)
			return request
		}(),
		func() *http.Request {
			request := httptest.NewRequest(http.MethodGet, "/callback?code="+testCode+"&state="+attempt.State, nil)
			request.AddCookie(attempt.Flow)
			request.AddCookie(attempt.Flow)
			return request
		}(),
	}
	for _, request := range tests {
		response := httptest.NewRecorder()
		client.CallbackHandler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d", request.Method, response.Code)
		}
	}
}
