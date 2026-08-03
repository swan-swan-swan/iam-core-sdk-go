package testkit_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/testkit"
)

const testAudience = "test-client"

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
		"code_challenge":        {"challenge-value"},
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
	authorizationForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"authorization-code-secret"},
		"redirect_uri":  {"http://127.0.0.1/callback"},
		"client_id":     {testAudience},
		"client_secret": {"client-secret-value"},
		"code_verifier": {"verifier-secret-value"},
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
	clock := testkit.NewFixedClock(time.Unix(2_000_000_000, 0))
	runtime, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.URL(), Audiences: []string{testAudience}, HTTPClient: issuer.HTTPClient(), Clock: clock,
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
		!reflect.DeepEqual(auth.Scopes, []string{"openid", "profile", "email", "groups"}) ||
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
	issuer.SetTokenResponse(testkit.TokenResponse{OAuthError: "invalid_grant", HTTPStatus: http.StatusUnauthorized})
	response, err := issuer.HTTPClient().PostForm(issuer.URL()+"/token", url.Values{"grant_type": {"refresh_token"}})
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
			form := url.Values{"grant_type": {"refresh_token"}, "client_id": {testAudience}}
			request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, issuer.URL()+"/token", strings.NewReader(form.Encode()))
			if err != nil {
				errs <- err
				return
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := issuer.HTTPClient().Do(request)
			if err != nil {
				errs <- err
				return
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil {
				errs <- err
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
	if calls := issuer.Calls(); calls.Refresh != workers {
		t.Fatalf("refresh calls=%d", calls.Refresh)
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
