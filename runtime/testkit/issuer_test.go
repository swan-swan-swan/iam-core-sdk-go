package testkit_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/testkit"
)

const testAudience = "test-client"

const validVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABC"

func TestIssuerPublishesS256RS256DiscoveryAndJWKS(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()

	var metadata core.Metadata
	getJSON(t, issuer.HTTPClient(), issuer.URL()+"/.well-known/openid-configuration", &metadata)
	if metadata.Issuer != issuer.URL() || metadata.AuthorizationEndpoint != issuer.URL()+"/authorize" ||
		metadata.TokenEndpoint != issuer.URL()+"/token" || metadata.UserInfoEndpoint != issuer.URL()+"/userinfo" ||
		metadata.JWKSURI != issuer.URL()+"/jwks" || metadata.EndSessionEndpoint != issuer.URL()+"/end-session" {
		t.Fatal("discovery endpoints do not point at the issuer")
	}
	if !reflect.DeepEqual(metadata.CodeChallengeMethodsSupported, []string{"S256"}) ||
		!reflect.DeepEqual(metadata.IDTokenSigningAlgValuesSupported, []string{"RS256"}) {
		t.Fatal("discovery does not publish the required S256/RS256 capabilities")
	}
	var jwks struct {
		Keys []struct {
			KeyType   string `json:"kty"`
			Use       string `json:"use"`
			Algorithm string `json:"alg"`
			KeyID     string `json:"kid"`
			Modulus   string `json:"n"`
			Exponent  string `json:"e"`
		} `json:"keys"`
	}
	getJSON(t, issuer.HTTPClient(), metadata.JWKSURI, &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyType != "RSA" || jwks.Keys[0].Use != "sig" ||
		jwks.Keys[0].Algorithm != "RS256" || jwks.Keys[0].KeyID == "" || jwks.Keys[0].Modulus == "" || jwks.Keys[0].Exponent == "" {
		t.Fatal("JWKS did not contain one complete RS256 signing key")
	}
}

func TestIssuerAuthorizeRedirectAndCallCount(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	client := *issuer.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {testAudience},
		"redirect_uri":          {"http://127.0.0.1/callback"},
		"scope":                 {"openid groups"},
		"state":                 {"state-value"},
		"nonce":                 {"nonce-value"},
		"code_challenge":        {pkceChallenge(validVerifier)},
		"code_challenge_method": {"S256"},
	}
	response, err := client.Get(issuer.URL() + "/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	location, err := response.Location()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound || location.Scheme != "http" || location.Host != "127.0.0.1" ||
		location.Path != "/callback" || location.Query().Get("code") == "" || location.Query().Get("state") != "state-value" {
		t.Fatal("authorize endpoint returned an unexpected redirect")
	}
	if calls := issuer.Calls(); calls.Authorize != 1 || calls.Token != 0 || calls.Refresh != 0 {
		t.Fatalf("authorize/token/refresh calls=%d/%d/%d", calls.Authorize, calls.Token, calls.Refresh)
	}
}

func TestIssuerTokenAndRefreshRecordExactFormsAndRotateTokens(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	issuer.SetTokenResponse(testkit.TokenResponse{Scope: "openid groups", Groups: []string{"engineering"}})
	code := authorizeCode(t, issuer, "nonce-value", validVerifier)
	authorizationForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1/callback"},
		"client_id":     {testAudience},
		"client_secret": {"client-secret-value"},
		"code_verifier": {validVerifier},
	}
	first := postToken(t, issuer, authorizationForm)
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"client_id":     {testAudience},
		"client_secret": {"client-secret-value"},
	}
	second := postToken(t, issuer, refreshForm)
	if first.AccessToken == "" || first.IDToken == "" || first.RefreshToken == "" ||
		second.AccessToken == "" || second.IDToken == "" || second.RefreshToken == "" {
		t.Fatal("successful token responses omitted tokens")
	}
	if first.AccessToken == second.AccessToken || first.IDToken == second.IDToken || first.RefreshToken == second.RefreshToken {
		t.Fatal("refresh response did not rotate all token fixtures")
	}
	if first.Scope != "openid groups" || second.Scope != "openid groups" {
		t.Fatal("configured scope was not returned")
	}
	calls := issuer.Calls()
	if calls.Token != 1 || calls.Refresh != 1 || !reflect.DeepEqual(calls.LastTokenForm, refreshForm) {
		t.Fatalf("token/refresh calls=%d/%d", calls.Token, calls.Refresh)
	}
	calls.LastTokenForm.Set("client_secret", "mutated")
	again := issuer.Calls()
	if !reflect.DeepEqual(again.LastTokenForm, refreshForm) {
		t.Fatal("mutating Calls.LastTokenForm changed issuer state")
	}
}

func TestIssuerSignedAccessAndIDTokensVerifyWithCore(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	issuer.SetTokenResponse(testkit.TokenResponse{Scope: "openid profile email groups", Groups: []string{"engineering", "operations"}})
	runtime, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.URL(), Audiences: []string{testAudience}, HTTPClient: issuer.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	access := issuer.SignAccessToken(testAudience)
	auth, err := runtime.VerifyAccessToken(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Subject != "test-subject" || auth.Issuer != issuer.URL() || !reflect.DeepEqual(auth.Audience, []string{testAudience}) ||
		!reflect.DeepEqual(auth.Scopes, []string{"email", "groups", "openid", "profile"}) ||
		!reflect.DeepEqual(auth.Groups, []string{"engineering", "operations"}) {
		t.Fatal("verified access-token claims differ from the configured fixture")
	}
	idToken := issuer.SignIDToken(testAudience, "expected-nonce")
	if _, err := runtime.VerifyIDToken(t.Context(), idToken, "expected-nonce"); err != nil {
		t.Fatal(err)
	}
}

func TestIssuerUserInfoEndSessionAndConfigurationAreCopySafe(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	groups := []string{"engineering", "operations"}
	issuer.SetTokenResponse(testkit.TokenResponse{Scope: "openid groups", Groups: groups})
	groups[0] = "mutated"
	request, err := http.NewRequest(http.MethodGet, issuer.URL()+"/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer userinfo-secret")
	response, err := issuer.HTTPClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var userInfo struct {
		Subject string   `json:"sub"`
		Groups  []string `json:"groups"`
	}
	if err := json.NewDecoder(response.Body).Decode(&userInfo); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if userInfo.Subject != "test-subject" || !reflect.DeepEqual(userInfo.Groups, []string{"engineering", "operations"}) {
		t.Fatal("userinfo did not preserve the configured copy")
	}
	endRequest, err := http.NewRequest(http.MethodGet, issuer.URL()+"/end-session?id_token_hint=end-session-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	endRequest.Header.Set("Authorization", "Bearer end-session-access-secret")
	endResponse, err := issuer.HTTPClient().Do(endRequest)
	if err != nil {
		t.Fatal(err)
	}
	endResponse.Body.Close()
	if endResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("end-session status=%d", endResponse.StatusCode)
	}
	calls := issuer.Calls()
	if calls.UserInfo != 1 || calls.EndSession != 1 {
		t.Fatalf("userinfo/end-session calls=%d/%d", calls.UserInfo, calls.EndSession)
	}
}

func TestIssuerPreservesPresentEmptyGroupsFixture(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	issuer.SetTokenResponse(testkit.TokenResponse{Scope: "openid groups", Groups: []string{}})
	response, err := issuer.HTTPClient().Get(issuer.URL() + "/userinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var userInfo map[string]json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&userInfo); err != nil {
		t.Fatal(err)
	}
	rawGroups, present := userInfo["groups"]
	if !present {
		t.Fatal("present empty groups fixture was omitted")
	}
	var groups []string
	if err := json.Unmarshal(rawGroups, &groups); err != nil || groups == nil || len(groups) != 0 {
		t.Fatal("present empty groups fixture did not remain an empty array")
	}
}

func TestIssuerTokenErrorAndHTTPStatusVariants(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	code := authorizeCode(t, issuer, "error-nonce", validVerifier)
	issued := postToken(t, issuer, authorizationCodeForm(code, validVerifier))
	issuer.SetTokenResponse(testkit.TokenResponse{OAuthError: "invalid_grant", HTTPStatus: http.StatusUnauthorized})
	response, err := issuer.HTTPClient().PostForm(issuer.URL()+"/token", refreshForm(issued.RefreshToken))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	var oauthError string
	if err := json.Unmarshal(body["error"], &oauthError); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized || oauthError != "invalid_grant" || len(body) != 1 {
		t.Fatal("OAuth error response did not preserve the configured status and error")
	}
}

func TestIssuerMutableStateIsConcurrentSafe(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	const workers = 32
	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			issuer.SetTokenResponse(testkit.TokenResponse{Scope: "openid groups", Groups: []string{"group"}})
			if token := issuer.SignAccessToken(testAudience); token == "" {
				errs <- fmt.Errorf("empty signed token")
			}
			_ = issuer.Calls()
			_ = index
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestIssuerRejectsInvalidAuthorizeRequestsWithoutCreatingFlow(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	tests := []struct {
		name   string
		method string
		mutate func(url.Values)
	}{
		{name: "wrong method", method: http.MethodPost},
		{name: "missing response type", mutate: func(values url.Values) { values.Del("response_type") }},
		{name: "duplicate state", mutate: func(values url.Values) { values["state"] = []string{"one", "two"} }},
		{name: "unknown field", mutate: func(values url.Values) { values.Set("subject", "forged") }},
		{name: "wrong response type", mutate: func(values url.Values) { values.Set("response_type", "token") }},
		{name: "plain PKCE", mutate: func(values url.Values) { values.Set("code_challenge_method", "plain") }},
		{name: "empty challenge", mutate: func(values url.Values) { values.Set("code_challenge", "") }},
		{name: "blank client", mutate: func(values url.Values) { values.Set("client_id", "") }},
		{name: "padded scope", mutate: func(values url.Values) { values.Set("scope", " openid") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := authorizationQuery("invalid-nonce", validVerifier)
			if test.mutate != nil {
				test.mutate(query)
			}
			method := test.method
			if method == "" {
				method = http.MethodGet
			}
			status, _, err := rawAuthorizeRequest(t.Context(), issuer, method, query)
			if err != nil {
				t.Fatal(err)
			}
			if status != http.StatusBadRequest && status != http.StatusMethodNotAllowed {
				t.Fatalf("invalid authorize status=%d", status)
			}
			if calls := issuer.Calls(); calls.Authorize != 0 {
				t.Fatalf("invalid authorize calls=%d", calls.Authorize)
			}
		})
	}
}

func TestIssuerFailedAuthorizeCannotMutateExistingFlowNonce(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	code := authorizeCode(t, issuer, "preserved-nonce", validVerifier)
	invalid := authorizationQuery("forged-nonce", strings.Repeat("b", len(validVerifier)))
	invalid.Del("scope")
	status, _, err := rawAuthorizeRequest(t.Context(), issuer, http.MethodGet, invalid)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("invalid authorize status=%d", status)
	}
	issued := postToken(t, issuer, authorizationCodeForm(code, validVerifier))
	claims := decodeTokenClaims(t, issued.IDToken)
	if claims.Nonce != "preserved-nonce" {
		t.Fatal("failed authorize changed an existing flow nonce")
	}
	if calls := issuer.Calls(); calls.Authorize != 1 || calls.Token != 1 {
		t.Fatalf("authorize/token calls=%d/%d", calls.Authorize, calls.Token)
	}
}

func TestIssuerInvalidAuthorizationCodeRequestsPreserveOneTimeCode(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	tests := []struct {
		name        string
		method      string
		contentType string
		mutate      func(url.Values)
	}{
		{name: "wrong method", method: http.MethodGet, contentType: "application/x-www-form-urlencoded"},
		{name: "wrong media type", method: http.MethodPost, contentType: "text/plain"},
		{name: "duplicate", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values["code"] = []string{values.Get("code"), "other"} }},
		{name: "missing", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Del("client_secret") }},
		{name: "missing grant", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Del("grant_type") }},
		{name: "unsupported grant", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("grant_type", "client_credentials") }},
		{name: "wrong code", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("code", "unknown-code") }},
		{name: "short verifier", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("code_verifier", "short") }},
		{name: "PKCE mismatch", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("code_verifier", strings.Repeat("b", len(validVerifier))) }},
		{name: "wrong client", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("client_id", "other-client") }},
		{name: "extra", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("subject", "forged") }},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := fmt.Sprintf("%043d", index+1)
			code := authorizeCode(t, issuer, fmt.Sprintf("nonce-%d", index), verifier)
			valid := authorizationCodeForm(code, verifier)
			invalid := cloneForm(valid)
			if test.mutate != nil {
				test.mutate(invalid)
			}
			before := issuer.Calls()
			status, _, err := rawTokenRequest(t.Context(), issuer, test.method, test.contentType, invalid)
			if err != nil {
				t.Fatal(err)
			}
			if status != http.StatusBadRequest && status != http.StatusMethodNotAllowed {
				t.Fatalf("invalid token status=%d", status)
			}
			after := issuer.Calls()
			if after.Token != before.Token || after.Refresh != before.Refresh || !reflect.DeepEqual(after.LastTokenForm, before.LastTokenForm) {
				t.Fatal("invalid token request mutated call or issuance state")
			}
			_ = postToken(t, issuer, valid)
			if calls := issuer.Calls(); calls.Token != before.Token+1 {
				t.Fatalf("token calls=%d", calls.Token)
			}
		})
	}
}

func TestIssuerAuthorizationCodeIsOneTime(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	code := authorizeCode(t, issuer, "one-time-nonce", validVerifier)
	form := authorizationCodeForm(code, validVerifier)
	_ = postToken(t, issuer, form)
	status, _, err := rawTokenRequest(t.Context(), issuer, http.MethodPost, "application/x-www-form-urlencoded", form)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("replayed code status=%d", status)
	}
	if calls := issuer.Calls(); calls.Token != 1 {
		t.Fatalf("token calls=%d", calls.Token)
	}
}

func TestIssuerInvalidRefreshRequestsPreserveBoundRefreshToken(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	tests := []struct {
		name        string
		method      string
		contentType string
		mutate      func(url.Values)
	}{
		{name: "wrong method", method: http.MethodGet, contentType: "application/x-www-form-urlencoded"},
		{name: "wrong media type", method: http.MethodPost, contentType: "application/json"},
		{name: "duplicate", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values["refresh_token"] = []string{values.Get("refresh_token"), "other"} }},
		{name: "missing", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Del("client_secret") }},
		{name: "wrong token", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("refresh_token", "unknown-refresh") }},
		{name: "wrong client", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("client_id", "other-client") }},
		{name: "wrong secret", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("client_secret", "other-secret") }},
		{name: "extra", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", mutate: func(values url.Values) { values.Set("scope", "openid") }},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := fmt.Sprintf("%043d", index+100)
			code := authorizeCode(t, issuer, fmt.Sprintf("refresh-nonce-%d", index), verifier)
			issued := postToken(t, issuer, authorizationCodeForm(code, verifier))
			valid := refreshForm(issued.RefreshToken)
			invalid := cloneForm(valid)
			if test.mutate != nil {
				test.mutate(invalid)
			}
			before := issuer.Calls()
			status, _, err := rawTokenRequest(t.Context(), issuer, test.method, test.contentType, invalid)
			if err != nil {
				t.Fatal(err)
			}
			if status != http.StatusBadRequest && status != http.StatusMethodNotAllowed {
				t.Fatalf("invalid refresh status=%d", status)
			}
			after := issuer.Calls()
			if after.Refresh != before.Refresh || !reflect.DeepEqual(after.LastTokenForm, before.LastTokenForm) {
				t.Fatal("invalid refresh request mutated call or rotation state")
			}
			_ = postToken(t, issuer, valid)
			if calls := issuer.Calls(); calls.Refresh != before.Refresh+1 {
				t.Fatalf("refresh calls=%d", calls.Refresh)
			}
		})
	}
}

func TestIssuerRefreshTokenIsOneTime(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	code := authorizeCode(t, issuer, "refresh-once-nonce", validVerifier)
	issued := postToken(t, issuer, authorizationCodeForm(code, validVerifier))
	form := refreshForm(issued.RefreshToken)
	_ = postToken(t, issuer, form)
	status, _, err := rawTokenRequest(t.Context(), issuer, http.MethodPost, "application/x-www-form-urlencoded", form)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("replayed refresh status=%d", status)
	}
	if calls := issuer.Calls(); calls.Refresh != 1 {
		t.Fatalf("refresh calls=%d", calls.Refresh)
	}
}

func TestIssuerConcurrentAuthorizationCodesKeepTheirOwnNonce(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	const workers = 16
	fixtures := make([]authorizationFixture, workers)
	errs := make(chan error, workers)
	var authorizeWait sync.WaitGroup
	for index := range workers {
		authorizeWait.Add(1)
		go func() {
			defer authorizeWait.Done()
			verifier := fmt.Sprintf("%043d", index+1000)
			nonce := fmt.Sprintf("isolated-nonce-%02d", index)
			code, err := requestAuthorizationCode(context.Background(), issuer, nonce, verifier)
			if err != nil {
				errs <- err
				return
			}
			fixtures[index] = authorizationFixture{code: code, nonce: nonce, verifier: verifier}
		}()
	}
	authorizeWait.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	seenCodes := make(map[string]struct{}, workers)
	for _, fixture := range fixtures {
		seenCodes[fixture.code] = struct{}{}
	}
	if len(seenCodes) != workers {
		t.Fatalf("unique authorization codes=%d", len(seenCodes))
	}

	errs = make(chan error, workers)
	var tokenWait sync.WaitGroup
	for index := range workers {
		tokenWait.Add(1)
		go func() {
			defer tokenWait.Done()
			fixture := fixtures[index]
			status, raw, err := rawTokenRequest(context.Background(), issuer, http.MethodPost, "application/x-www-form-urlencoded", authorizationCodeForm(fixture.code, fixture.verifier))
			if err != nil {
				errs <- err
				return
			}
			if status != http.StatusOK {
				errs <- fmt.Errorf("token status %d", status)
				return
			}
			var issued tokenWireResponse
			if json.Unmarshal(raw, &issued) != nil {
				errs <- fmt.Errorf("invalid token response")
				return
			}
			claims, err := tokenClaims(issued.IDToken)
			if err != nil || claims.Nonce != fixture.nonce {
				errs <- fmt.Errorf("nonce isolation failed")
			}
		}()
	}
	tokenWait.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if calls := issuer.Calls(); calls.Authorize != workers || calls.Token != workers {
		t.Fatalf("authorize/token calls=%d/%d", calls.Authorize, calls.Token)
	}
}

func TestIssuerTokenLifetimesUseReceiptTimeAndExpiresIn(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	code := authorizeCode(t, issuer, "lifetime-nonce", validVerifier)
	before := time.Now().Unix()
	issued := postToken(t, issuer, authorizationCodeForm(code, validVerifier))
	after := time.Now().Unix()
	assertCoherentTokenPair(t, issued, before, after)

	refreshBefore := time.Now().Unix()
	refreshed := postToken(t, issuer, refreshForm(issued.RefreshToken))
	refreshAfter := time.Now().Unix()
	assertCoherentTokenPair(t, refreshed, refreshBefore, refreshAfter)

	directBefore := time.Now().Unix()
	access := decodeTokenClaims(t, issuer.SignAccessToken(testAudience))
	idToken := decodeTokenClaims(t, issuer.SignIDToken(testAudience, "direct-nonce"))
	directAfter := time.Now().Unix()
	for _, claims := range []jwtFixtureClaims{access, idToken} {
		if claims.IssuedAt < directBefore || claims.IssuedAt > directAfter || claims.ExpiresAt-claims.IssuedAt != 3600 {
			t.Fatal("direct token lifetime was not based on issuance time")
		}
	}
}

func TestIssuerMixedTokenIssuanceUsesUniqueJTIsAndRawTokens(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	runtime, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.URL(), Audiences: []string{testAudience}, HTTPClient: issuer.HTTPClient(),
	})
	if err != nil {
		t.Fatal(err)
	}

	const firstNonce = "mixed-first-nonce"
	code := authorizeCode(t, issuer, firstNonce, validVerifier)
	first := postToken(t, issuer, authorizationCodeForm(code, validVerifier))
	directAccess := issuer.SignAccessToken(testAudience)
	directID := issuer.SignIDToken(testAudience, firstNonce)
	refreshed := postToken(t, issuer, refreshForm(first.RefreshToken))
	laterAccess := issuer.SignAccessToken(testAudience)
	laterID := issuer.SignIDToken(testAudience, "mixed-later-nonce")

	accessTokens := []string{first.AccessToken, directAccess, refreshed.AccessToken, laterAccess}
	accessJTIs := make(map[string]struct{}, len(accessTokens))
	for _, raw := range accessTokens {
		auth, verifyErr := runtime.VerifyAccessToken(t.Context(), raw)
		if verifyErr != nil {
			t.Fatal(verifyErr)
		}
		if _, duplicate := accessJTIs[auth.TokenID]; duplicate {
			t.Fatalf("duplicate access-token jti %q", auth.TokenID)
		}
		accessJTIs[auth.TokenID] = struct{}{}
	}

	idTokens := []struct {
		raw       string
		nonce     string
		refreshed bool
	}{
		{raw: first.IDToken, nonce: firstNonce},
		{raw: directID, nonce: firstNonce},
		{raw: refreshed.IDToken, refreshed: true},
		{raw: laterID, nonce: "mixed-later-nonce"},
	}
	idJTIs := make(map[string]struct{}, len(idTokens))
	allRaw := make(map[string]struct{}, len(accessTokens)+len(idTokens))
	for _, raw := range accessTokens {
		allRaw[raw] = struct{}{}
	}
	for _, fixture := range idTokens {
		var auth core.AuthContext
		var verifyErr error
		if fixture.refreshed {
			auth, verifyErr = runtime.VerifyRefreshedIDToken(t.Context(), fixture.raw)
		} else {
			auth, verifyErr = runtime.VerifyIDToken(t.Context(), fixture.raw, fixture.nonce)
		}
		if verifyErr != nil {
			t.Fatal(verifyErr)
		}
		if _, duplicate := idJTIs[auth.TokenID]; duplicate {
			t.Fatalf("duplicate ID-token jti %q", auth.TokenID)
		}
		idJTIs[auth.TokenID] = struct{}{}
		if _, duplicate := allRaw[fixture.raw]; duplicate {
			t.Fatal("mixed issuance returned a duplicate raw token")
		}
		allRaw[fixture.raw] = struct{}{}
	}
	if len(allRaw) != len(accessTokens)+len(idTokens) {
		t.Fatalf("unique raw tokens=%d", len(allRaw))
	}
}

func TestIssuerConcurrentMixedTokenIssuanceUsesUniqueJTIs(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	defer issuer.Close()
	const workers = 12
	codes := make([]authorizationFixture, workers)
	for index := range workers {
		verifier := fmt.Sprintf("%043d", index+3000)
		codes[index] = authorizationFixture{
			code:     authorizeCode(t, issuer, fmt.Sprintf("mixed-concurrent-nonce-%d", index), verifier),
			verifier: verifier,
		}
	}

	tokens := make(chan string, workers*4)
	errs := make(chan error, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(3)
		go func() {
			defer wait.Done()
			<-start
			status, raw, err := rawTokenRequest(context.Background(), issuer, http.MethodPost, "application/x-www-form-urlencoded", authorizationCodeForm(codes[index].code, codes[index].verifier))
			if err != nil || status != http.StatusOK {
				errs <- fmt.Errorf("endpoint issuance status=%d: %w", status, err)
				return
			}
			var issued tokenWireResponse
			if err := json.Unmarshal(raw, &issued); err != nil {
				errs <- err
				return
			}
			tokens <- issued.AccessToken
			tokens <- issued.IDToken
		}()
		go func() {
			defer wait.Done()
			<-start
			tokens <- issuer.SignAccessToken(testAudience)
		}()
		go func() {
			defer wait.Done()
			<-start
			tokens <- issuer.SignIDToken(testAudience, fmt.Sprintf("direct-concurrent-nonce-%d", index))
		}()
	}
	close(start)
	wait.Wait()
	close(tokens)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	seenJTIs := make(map[string]struct{}, workers*4)
	seenRaw := make(map[string]struct{}, workers*4)
	for raw := range tokens {
		claims, err := tokenClaims(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, duplicate := seenJTIs[claims.TokenID]; duplicate {
			t.Fatalf("duplicate concurrent jti %q", claims.TokenID)
		}
		seenJTIs[claims.TokenID] = struct{}{}
		if _, duplicate := seenRaw[raw]; duplicate {
			t.Fatal("concurrent issuance returned a duplicate raw token")
		}
		seenRaw[raw] = struct{}{}
	}
	if len(seenJTIs) != workers*4 {
		t.Fatalf("unique concurrent jtis=%d", len(seenJTIs))
	}
}

func TestIssuerCloseIsIdempotent(t *testing.T) {
	issuer := testkit.NewIssuer(t)
	issuer.Close()
	issuer.Close()
}

type tokenWireResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

type authorizationFixture struct {
	code     string
	nonce    string
	verifier string
}

type jwtFixtureClaims struct {
	TokenID   string `json:"jti"`
	Nonce     string `json:"nonce"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func postToken(t *testing.T, issuer *testkit.Issuer, form url.Values) tokenWireResponse {
	t.Helper()
	response, err := issuer.HTTPClient().PostForm(issuer.URL()+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint status=%d", response.StatusCode)
	}
	var decoded tokenWireResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func authorizationQuery(nonce, verifier string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {testAudience},
		"redirect_uri":          {"http://127.0.0.1/callback"},
		"scope":                 {"openid groups"},
		"state":                 {"state-value"},
		"nonce":                 {nonce},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
}

func authorizationCodeForm(code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1/callback"},
		"client_id":     {testAudience},
		"client_secret": {"client-secret-value"},
		"code_verifier": {verifier},
	}
}

func refreshForm(refreshToken string) url.Values {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {testAudience},
		"client_secret": {"client-secret-value"},
	}
}

func authorizeCode(t *testing.T, issuer *testkit.Issuer, nonce, verifier string) string {
	t.Helper()
	code, err := requestAuthorizationCode(t.Context(), issuer, nonce, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func requestAuthorizationCode(ctx context.Context, issuer *testkit.Issuer, nonce, verifier string) (string, error) {
	status, location, err := rawAuthorizeRequest(ctx, issuer, http.MethodGet, authorizationQuery(nonce, verifier))
	if err != nil {
		return "", err
	}
	if status != http.StatusFound || location == nil || location.Query().Get("code") == "" {
		return "", fmt.Errorf("authorize status %d", status)
	}
	return location.Query().Get("code"), nil
}

func rawAuthorizeRequest(ctx context.Context, issuer *testkit.Issuer, method string, query url.Values) (int, *url.URL, error) {
	request, err := http.NewRequestWithContext(ctx, method, issuer.URL()+"/authorize?"+query.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}
	client := *issuer.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	response.Body.Close()
	location, locationErr := response.Location()
	if locationErr != nil && response.StatusCode >= 300 && response.StatusCode < 400 {
		return 0, nil, locationErr
	}
	return response.StatusCode, location, nil
}

func rawTokenRequest(ctx context.Context, issuer *testkit.Issuer, method, contentType string, form url.Values) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, issuer.URL()+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := issuer.HTTPClient().Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, body, err
}

func cloneForm(form url.Values) url.Values {
	cloned := make(url.Values, len(form))
	for name, values := range form {
		cloned[name] = append([]string(nil), values...)
	}
	return cloned
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func decodeTokenClaims(t *testing.T, raw string) jwtFixtureClaims {
	t.Helper()
	claims, err := tokenClaims(raw)
	if err != nil {
		t.Fatal("decode signed token claims")
	}
	return claims
}

func tokenClaims(raw string) (jwtFixtureClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return jwtFixtureClaims{}, fmt.Errorf("invalid compact token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtFixtureClaims{}, fmt.Errorf("invalid token payload")
	}
	var claims jwtFixtureClaims
	if json.Unmarshal(payload, &claims) != nil {
		return jwtFixtureClaims{}, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

func assertCoherentTokenPair(t *testing.T, issued tokenWireResponse, before, after int64) {
	t.Helper()
	if issued.ExpiresIn != 3600 {
		t.Fatalf("expires_in=%d", issued.ExpiresIn)
	}
	access := decodeTokenClaims(t, issued.AccessToken)
	idToken := decodeTokenClaims(t, issued.IDToken)
	if access.IssuedAt < before || access.IssuedAt > after || idToken.IssuedAt != access.IssuedAt ||
		access.ExpiresAt != idToken.ExpiresAt || access.ExpiresAt-access.IssuedAt != issued.ExpiresIn {
		t.Fatal("access/ID token lifetime does not agree with receipt time and expires_in")
	}
}

func getJSON(t *testing.T, client *http.Client, endpoint string, target any) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET status=%d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}
