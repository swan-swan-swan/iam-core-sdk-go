package client

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"
)

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "empty base URL", cfg: Config{TokenSource: staticTokenSource("token")}},
		{name: "relative base URL", cfg: Config{BaseURL: "/tenant", TokenSource: staticTokenSource("token")}},
		{name: "non HTTPS", cfg: Config{BaseURL: "http://example.com", TokenSource: staticTokenSource("token")}},
		{name: "userinfo", cfg: Config{BaseURL: "https://user@example.com", TokenSource: staticTokenSource("token")}},
		{name: "query", cfg: Config{BaseURL: "https://example.com?tenant=secret", TokenSource: staticTokenSource("token")}},
		{name: "fragment", cfg: Config{BaseURL: "https://example.com#fragment", TokenSource: staticTokenSource("token")}},
		{name: "empty fragment", cfg: Config{BaseURL: "https://example.com#", TokenSource: staticTokenSource("token")}},
		{name: "empty hostname", cfg: Config{BaseURL: "https://:443", TokenSource: staticTokenSource("token")}},
		{name: "unclean base path", cfg: Config{BaseURL: "https://example.com/root/../tenant", TokenSource: staticTokenSource("token")}},
		{name: "double slash base path", cfg: Config{BaseURL: "https://example.com/root//tenant", TokenSource: staticTokenSource("token")}},
		{name: "escaped base path", cfg: Config{BaseURL: "https://example.com/root%2Ftenant", TokenSource: staticTokenSource("token")}},
		{name: "missing token source", cfg: Config{BaseURL: "https://example.com"}},
		{name: "typed nil token source", cfg: Config{BaseURL: "https://example.com", TokenSource: (*countingTokenSource)(nil)}},
		{name: "negative timeout", cfg: Config{BaseURL: "https://example.com", TokenSource: staticTokenSource("token"), Timeout: -time.Nanosecond}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client, err := New(tt.cfg)
			if client != nil {
				t.Fatalf("New() client = %#v, want nil", client)
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewAllowsHTTPOnlyForLoopbackHosts(t *testing.T) {
	t.Parallel()

	for _, baseURL := range []string{
		"http://localhost",
		"http://service.localhost:8080",
		"http://127.0.0.1",
		"http://127.0.0.2",
		"http://[::1]:8080",
	} {
		baseURL := baseURL
		t.Run(baseURL, func(t *testing.T) {
			t.Parallel()
			if _, err := New(Config{BaseURL: baseURL, TokenSource: staticTokenSource("token")}); err != nil {
				t.Fatalf("New() error = %v, want nil", err)
			}
		})
	}

	for _, baseURL := range []string{
		"http://localhost.example.com",
		"http://192.0.2.1",
		"ftp://localhost",
	} {
		baseURL := baseURL
		t.Run("reject "+baseURL, func(t *testing.T) {
			t.Parallel()
			if _, err := New(Config{BaseURL: baseURL, TokenSource: staticTokenSource("token")}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewClonesHTTPClientAndDisablesCookiesAndRedirects(t *testing.T) {
	t.Parallel()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New(): %v", err)
	}
	checkRedirect := func(*http.Request, []*http.Request) error { return nil }
	caller := &http.Client{
		Timeout:       27 * time.Second,
		Jar:           jar,
		CheckRedirect: checkRedirect,
	}

	client, err := New(Config{
		BaseURL:     "https://example.com/root",
		TokenSource: staticTokenSource("token"),
		HTTPClient:  caller,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if client.httpClient == caller {
		t.Fatal("New() retained caller HTTP client instead of cloning it")
	}
	if client.httpClient.Jar != nil {
		t.Fatal("cloned HTTP client retained caller Cookie Jar")
	}
	if caller.Jar != jar || caller.CheckRedirect == nil || caller.Timeout != 27*time.Second {
		t.Fatal("New() mutated caller HTTP client")
	}
	request, err := http.NewRequest(http.MethodGet, "https://example.com/next", nil)
	if err != nil {
		t.Fatalf("http.NewRequest(): %v", err)
	}
	if got := client.httpClient.CheckRedirect(request, nil); !errors.Is(got, http.ErrUseLastResponse) {
		t.Fatalf("cloned CheckRedirect() error = %v, want http.ErrUseLastResponse", got)
	}
	if client.timeout != defaultTimeout {
		t.Fatalf("client timeout = %v, want %v", client.timeout, defaultTimeout)
	}
}

func TestNewUsesExplicitTimeoutWithoutChangingHTTPClientTimeout(t *testing.T) {
	t.Parallel()

	caller := &http.Client{Timeout: time.Minute}
	client, err := New(Config{
		BaseURL:     "https://example.com",
		TokenSource: staticTokenSource("token"),
		HTTPClient:  caller,
		Timeout:     250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if client.timeout != 250*time.Millisecond {
		t.Fatalf("client timeout = %v, want 250ms", client.timeout)
	}
	if client.httpClient.Timeout != time.Minute || caller.Timeout != time.Minute {
		t.Fatal("New() changed HTTP client Timeout")
	}
}
