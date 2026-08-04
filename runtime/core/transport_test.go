package core_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

func TestNewDoesNotMutateInjectedHTTPClient(t *testing.T) {
	cookieSeen := make(chan string, 1)
	var redirectTargetCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirect-target" {
			redirectTargetCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		cookieSeen <- request.Header.Get("Cookie")
		w.Header().Set("Location", "/redirect-target")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	var callerRedirectCalls atomic.Int32
	redirect := func(*http.Request, []*http.Request) error {
		callerRedirectCalls.Add(1)
		return nil
	}
	client := server.Client()
	client.CheckRedirect = redirect
	client.Jar = &testCookieJar{cookies: []*http.Cookie{{Name: "session", Value: "jar-secret"}}}
	jar := client.Jar
	redirectIdentity := reflect.ValueOf(client.CheckRedirect).Pointer()
	_, err := core.New(t.Context(), core.Config{IssuerURL: server.URL, Audiences: []string{"portal"}, HTTPClient: client})
	if err == nil {
		t.Fatal("New() error = nil, want redirect rejection")
	}
	if got := <-cookieSeen; got != "" {
		t.Fatalf("runtime clone sent caller jar cookie %q", got)
	}
	if got := redirectTargetCalls.Load(); got != 0 {
		t.Fatalf("redirect target calls = %d", got)
	}
	if got := callerRedirectCalls.Load(); got != 0 {
		t.Fatalf("caller CheckRedirect calls from runtime = %d", got)
	}
	if client.Jar != jar || client.CheckRedirect == nil || reflect.ValueOf(client.CheckRedirect).Pointer() != redirectIdentity {
		t.Fatal("New() mutated injected HTTP client")
	}
	if err := client.CheckRedirect(nil, nil); err != nil || callerRedirectCalls.Load() != 1 {
		t.Fatalf("caller CheckRedirect behavior changed: calls=%d err=%v", callerRedirectCalls.Load(), err)
	}
}

type testCookieJar struct{ cookies []*http.Cookie }

func (*testCookieJar) SetCookies(*url.URL, []*http.Cookie) {}
func (jar *testCookieJar) Cookies(*url.URL) []*http.Cookie {
	return append([]*http.Cookie(nil), jar.cookies...)
}
