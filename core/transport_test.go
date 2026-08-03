package core_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestNewDoesNotMutateInjectedHTTPClient(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	redirect := func(*http.Request, []*http.Request) error { return nil }
	client := issuer.Server.Client()
	client.CheckRedirect = redirect
	client.Jar = &testCookieJar{}
	jar := client.Jar
	_, err := core.New(t.Context(), core.Config{IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if client.Jar != jar || client.CheckRedirect == nil {
		t.Fatal("New() mutated injected HTTP client")
	}
}

type testCookieJar struct{}

func (*testCookieJar) SetCookies(*url.URL, []*http.Cookie) {}
func (*testCookieJar) Cookies(*url.URL) []*http.Cookie     { return nil }
