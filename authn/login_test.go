package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session/memory"
)

func TestLoginHandlerStoresFlowAndSetsSecureCookie(t *testing.T) {
	service, backend := newTestService(t)
	request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2Fassets", nil)
	response := httptest.NewRecorder()
	service.LoginHandler().ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if response.Body.Len() != 0 {
		t.Fatalf("redirect body exposed authorization parameters: %q", response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-iam_core_flow" || !cookie.HttpOnly || !cookie.Secure ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("cookie = %#v", cookie)
	}
	if backend.FlowCount() != 1 {
		t.Fatalf("flow count = %d", backend.FlowCount())
	}
	flow := backend.LastFlow()
	if flow == nil || flow.ReturnTo != "/assets" || flow.ID != cookie.Value ||
		flow.State == "" || flow.Nonce == "" || flow.ID == flow.State ||
		flow.ID == flow.Nonce || flow.State == flow.Nonce {
		t.Fatalf("flow = %#v", flow)
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("state") != flow.State ||
		location.Query().Get("nonce") != flow.Nonce {
		t.Fatalf("location = %q error = %v", response.Header().Get("Location"), err)
	}
}

func TestLoginRejectsUnsafeReturnTo(t *testing.T) {
	tests := []string{
		"https://evil.example",
		"//evil.example",
		`/\evil.example`,
		`/safe\evil`,
		"/%5cevil",
		"/%255cevil",
		"/%0d%0aX-Evil:true",
		"/%250aX-Evil:true",
		"/%2f%2fevil.example",
		"javascript:alert(1)",
		"assets",
		"/\x00bad",
		"/\u0085bad",
	}
	for _, returnTo := range tests {
		t.Run(url.QueryEscape(returnTo), func(t *testing.T) {
			service, backend := newTestService(t)
			request := httptest.NewRequest(
				http.MethodGet,
				"/auth/login?return_to="+url.QueryEscape(returnTo),
				nil,
			)
			response := httptest.NewRecorder()
			service.LoginHandler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
			}
			if backend.FlowCount() != 0 || len(response.Result().Cookies()) != 0 {
				t.Fatalf("flow count = %d cookies=%#v", backend.FlowCount(), response.Result().Cookies())
			}
			if strings.Contains(response.Body.String(), returnTo) {
				t.Fatalf("response reflected hostile return_to: %q", response.Body.String())
			}
		})
	}
}

func TestLoginAllowsSafeRelativeReturnToWithQueryAndFragment(t *testing.T) {
	service, backend := newTestService(t)
	returnTo := "/assets/item?q=hello%20world&next=%2Fprofile#details"
	request := httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(returnTo), nil)
	response := httptest.NewRecorder()
	service.LoginHandler().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d body=%q", response.Code, response.Body.String())
	}
	if flow := backend.LastFlow(); flow == nil || flow.ReturnTo != returnTo {
		t.Fatalf("flow = %#v", flow)
	}
}

func TestLoginReturnToAllowlistIsExact(t *testing.T) {
	newService := func(t *testing.T) (*Service, *inspectableBackend) {
		harness := newTestHarness(t, func(config *Config, _ *testHarness) {
			config.AllowedReturnToURLs = []string{"https://app.example/post-login"}
		})
		return harness.service, harness.backend
	}

	t.Run("accepted exact value", func(t *testing.T) {
		service, backend := newService(t)
		value := "https://app.example/post-login"
		response := httptest.NewRecorder()
		service.LoginHandler().ServeHTTP(
			response,
			httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(value), nil),
		)
		if response.Code != http.StatusFound || backend.LastFlow().ReturnTo != value {
			t.Fatalf("status=%d flow=%#v", response.Code, backend.LastFlow())
		}
	})
	t.Run("suffix rejected", func(t *testing.T) {
		service, backend := newService(t)
		value := "https://app.example.evil.test/post-login"
		response := httptest.NewRecorder()
		service.LoginHandler().ServeHTTP(
			response,
			httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(value), nil),
		)
		if response.Code != http.StatusBadRequest || backend.FlowCount() != 0 {
			t.Fatalf("status=%d flows=%d", response.Code, backend.FlowCount())
		}
	})
}

func TestLoginRejectsMissingOrDuplicateReturnTo(t *testing.T) {
	for _, target := range []string{
		"/auth/login",
		"/auth/login?return_to=%2Fa&return_to=%2Fb",
	} {
		service, backend := newTestService(t)
		response := httptest.NewRecorder()
		service.LoginHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusBadRequest || backend.FlowCount() != 0 {
			t.Fatalf("target=%q status=%d flows=%d", target, response.Code, backend.FlowCount())
		}
	}
}

func TestBeginLoginRandomFailureAtEveryGenerationPointWritesNothing(t *testing.T) {
	for failCall := 1; failCall <= 3; failCall++ {
		t.Run(string(rune('0'+failCall)), func(t *testing.T) {
			harness := newTestHarness(t, func(config *Config, harness *testHarness) {
				harness.random.failCall = failCall
			})
			response := httptest.NewRecorder()
			err := harness.service.BeginLogin(
				response,
				httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil),
				"/assets",
			)
			if err == nil || harness.backend.FlowCount() != 0 ||
				response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" {
				t.Fatalf("error=%v flows=%d headers=%#v", err, harness.backend.FlowCount(), response.Header())
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsanitized error = %v", err)
			}
		})
	}
}

func TestBeginLoginPersistenceFailureWritesNothing(t *testing.T) {
	harness := newTestHarness(t, func(_ *Config, harness *testHarness) {
		harness.backend.putFlowErr = errors.New("database leaked detail")
	})
	response := httptest.NewRecorder()
	err := harness.service.BeginLogin(
		response,
		httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil),
		"/assets",
	)
	if err == nil || response.Header().Get("Set-Cookie") != "" ||
		response.Header().Get("Location") != "" || harness.backend.FlowCount() != 0 {
		t.Fatalf("error=%v headers=%#v flows=%d", err, response.Header(), harness.backend.FlowCount())
	}
	if strings.Contains(err.Error(), "database") {
		t.Fatalf("unsanitized error = %v", err)
	}
}

func TestLoginBackendFailureMapsToUnavailableWithoutSecrets(t *testing.T) {
	harness := newTestHarness(t, func(_ *Config, harness *testHarness) {
		harness.backend.putFlowErr = errors.New("backend password top-secret")
	})
	response := httptest.NewRecorder()
	harness.service.LoginHandler().ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2Fassets", nil),
	)
	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), "top-secret") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestNewRejectsUnsafeCookieConfigurations(t *testing.T) {
	tests := []http.Cookie{
		{Name: "bad\r\nX-Evil: yes", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode},
		{Name: "__Host-custom", Path: "/auth", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode},
		{Name: "__Host-custom", Path: "/", Domain: "example.com", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode},
		{Name: "__Host-custom", Path: "/", Secure: true, SameSite: http.SameSiteLaxMode},
		{Name: "__Host-custom", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode},
		{Name: "custom", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode},
	}
	for _, cookie := range tests {
		t.Run(cookie.Name+cookie.Path+cookie.Domain, func(t *testing.T) {
			fake := newFakeBrowserOIDC(t)
			client, err := oidcClientForTest(t, fake)
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(Config{
				OIDC:          client,
				Backend:       memoryBackendForTest(),
				RedirectURL:   "https://app.example/auth/callback",
				SessionCookie: cookie,
			})
			if err == nil {
				t.Fatalf("New accepted cookie %#v", cookie)
			}
		})
	}
}

func TestNewRejectsInsecureNonLocalRedirectURL(t *testing.T) {
	fake := newFakeBrowserOIDC(t)
	client, err := oidcClientForTest(t, fake)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		OIDC:        client,
		Backend:     memoryBackendForTest(),
		RedirectURL: "http://app.example/auth/callback",
	})
	if err == nil {
		t.Fatal("New accepted an insecure non-local redirect URL")
	}
}

func TestInsecureLocalCookieRequiresLocalRedirectAndRequestHosts(t *testing.T) {
	harness := newTestHarness(t, func(config *Config, _ *testHarness) {
		config.RedirectURL = "http://localhost:8080/auth/callback"
		config.AllowInsecureLocalCookie = true
		config.SessionCookie = safeInsecureCookie("iam_core_session")
		config.FlowCookie = safeInsecureCookie("iam_core_flow")
	})
	for _, host := range []string{"evil.example", "localhost.evil.example"} {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/auth/login", nil)
		response := httptest.NewRecorder()
		err := harness.service.BeginLogin(response, request, "/")
		if err == nil || harness.backend.FlowCount() != 0 || response.Header().Get("Set-Cookie") != "" {
			t.Fatalf("host=%q error=%v flows=%d headers=%#v", host, err, harness.backend.FlowCount(), response.Header())
		}
	}
	response := httptest.NewRecorder()
	err := harness.service.BeginLogin(
		response,
		httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/auth/login", nil),
		"/",
	)
	if err != nil || response.Code != http.StatusFound {
		t.Fatalf("local request error=%v status=%d", err, response.Code)
	}
}

func safeInsecureCookie(name string) http.Cookie {
	return http.Cookie{
		Name:     name,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func oidcClientForTest(t *testing.T, fake *fakeBrowserOIDC) (*oidc.Client, error) {
	t.Helper()
	return oidc.New(t.Context(), oidc.Config{
		IssuerURL:      fake.server.URL,
		ClientID:       "client-1",
		SecretProvider: oidc.StaticSecret("secret"),
		RedirectURL:    "https://app.example/auth/callback",
		Scopes:         []string{"openid"},
		HTTPClient:     fake.server.Client(),
	})
}

func memoryBackendForTest() session.Backend {
	return memory.New(memory.Options{Clock: fixedClock{fixedNow}})
}
