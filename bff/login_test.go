package bff

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestBeginLoginStoresVerifierAndSendsS256Challenge(t *testing.T) {
	client, backend, issuer := newBFFTestClient(t)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2Fprofile", nil)
	client.LoginHandler().ServeHTTP(response, request)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal("authorization redirect was not a valid URL")
	}
	query := location.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatal("authorization redirect omitted the S256 challenge")
	}
	flow := backend.LastFlow()
	if flow == nil {
		t.Fatal("flow was not stored")
	}
	if len(flow.CodeVerifier) != 43 || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(flow.CodeVerifier) {
		t.Fatalf("invalid verifier shape: length=%d", len(flow.CodeVerifier))
	}
	digest := sha256.Sum256([]byte(flow.CodeVerifier))
	if query.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("challenge mismatch")
	}
	if strings.Contains(location.String(), flow.CodeVerifier) || issuer.LogContains(flow.CodeVerifier) {
		t.Fatal("verifier leaked")
	}
}

func TestBeginLoginAuthorizationRequestIsExactAndFlowCookieIsOpaque(t *testing.T) {
	client, backend, issuer := newBFFTestClient(t)
	attempt := beginLogin(t, client, issuer, "/profile?tab=security")
	parsed, err := url.Parse(attempt.Location)
	if err != nil {
		t.Fatal("authorization redirect was not a valid URL")
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != issuer.Server.URL+"/authorize" {
		t.Fatal("authorization endpoint is incorrect")
	}
	query := parsed.Query()
	wantNames := []string{"client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri", "response_type", "scope", "state"}
	gotNames := make([]string, 0, len(query))
	for name, values := range query {
		gotNames = append(gotNames, name)
		if len(values) != 1 || values[0] == "" {
			t.Fatalf("authorization field %q has invalid cardinality or an empty value", name)
		}
	}
	slices.Sort(gotNames)
	if !slices.Equal(gotNames, wantNames) || query.Get("response_type") != "code" || query.Get("client_id") != testClientID ||
		query.Get("redirect_uri") != issuer.Server.URL+"/callback" || query.Get("scope") != "openid profile email groups" {
		t.Fatalf("authorization request fields are incorrect: fields=%v", gotNames)
	}
	flow := backend.LastFlow()
	if flow.ClientID != testClientID || flow.RedirectURL != issuer.Server.URL+"/callback" || flow.ReturnTo != "/profile?tab=security" {
		t.Fatal("stored flow binding or return target is incorrect")
	}
	if attempt.Flow.Value != flow.ID || attempt.Flow.Path != "/" || !attempt.Flow.HttpOnly || attempt.Flow.SameSite != http.SameSiteLaxMode {
		t.Fatal("flow cookie attributes or opaque identifier are incorrect")
	}
	for _, sensitive := range []string{flow.State, flow.Nonce, flow.CodeVerifier, testClientSecret} {
		if strings.Contains(attempt.Flow.Value, sensitive) || strings.Contains(attempt.Location, testClientSecret) {
			t.Fatal("browser response exposed a server-side value")
		}
	}
}

func TestBeginLoginRejectsUnsafeReturnToWithoutCreatingFlow(t *testing.T) {
	unsafe := []string{
		"", "//evil.example/path", "https://evil.example/path", `\\evil.example\path`,
		"/%2f%2fevil.example", "/%252f%252fevil.example", "/line\nbreak", " /profile", "/profile ",
	}
	for _, returnTo := range unsafe {
		t.Run(url.QueryEscape(returnTo), func(t *testing.T) {
			client, backend, _ := newBFFTestClient(t)
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(returnTo), nil)
			client.LoginHandler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || backend.LastFlow() != nil || response.Header().Get("Location") != "" {
				t.Fatalf("unsafe return target produced side effects: status=%d", response.Code)
			}
		})
	}
}

func TestBeginLoginAllowsOnlyExactConfiguredAbsoluteReturnTo(t *testing.T) {
	config, _, issuer := newBFFTestConfig(t)
	allowed := "https://app.example.test/after-login?source=iam"
	config.AllowedReturnToURLs = []string{allowed}
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	_ = beginLogin(t, client, issuer, allowed)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(allowed+"&extra=1"), nil)
	client.LoginHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unlisted absolute return status = %d", response.Code)
	}
}

func TestBeginLoginRejectsMalformedRequests(t *testing.T) {
	client, _, _ := newBFFTestClient(t)
	requests := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/auth/login?return_to=%2F", nil),
		httptest.NewRequest(http.MethodGet, "/auth/login", nil),
		httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2F&return_to=%2Fprofile", nil),
		httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%zz", nil),
	}
	for _, request := range requests {
		response := httptest.NewRecorder()
		client.LoginHandler().ServeHTTP(response, request)
		wantStatus := http.StatusBadRequest
		if request.Method != http.MethodGet {
			wantStatus = http.StatusMethodNotAllowed
		}
		if response.Code != wantStatus {
			t.Fatalf("%s %s status = %d", request.Method, request.URL, response.Code)
		}
	}
}
