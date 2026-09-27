package httpcatalog_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpcatalog"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/testkit"
)

type typedNilTokenSource struct{}

func (*typedNilTokenSource) AccessToken(context.Context) (string, error) { return "", nil }

func TestRegistryUsesFreshInjectedBearerToken(t *testing.T) {
	var mu sync.Mutex
	var headers []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		headers = append(headers, request.Header.Get("Authorization"))
		mu.Unlock()
		if _, _, ok := request.BasicAuth(); ok {
			t.Fatal("request used Basic authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"success","data":{"application":"beacon","catalog_hash":"sha256:abc","changed":true}}`))
	}))
	defer server.Close()

	tokens := []string{"machine-token-1", "machine-token-2"}
	calls := 0
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{
		BaseURL: server.URL, Application: "beacon", Service: "notify-server", Release: "test",
		Tokens: core.TokenSourceFunc(func(context.Context) (string, error) {
			token := tokens[calls]
			calls++
			return token, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notifications", "notify.task.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := registry.Sync(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 || len(headers) != 2 || headers[0] != "Bearer machine-token-1" || headers[1] != "Bearer machine-token-2" {
		t.Fatalf("calls=%d headers=%q", calls, headers)
	}
}

func TestRegistryRejectsNilAndTypedNilTokenSource(t *testing.T) {
	for name, tokens := range map[string]core.TokenSource{
		"nil":       nil,
		"typed nil": (*typedNilTokenSource)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := httpcatalog.NewRegistry(httpcatalog.Config{
				BaseURL: "http://127.0.0.1:8080", Application: "beacon", Service: "notify-server", Release: "test", Tokens: tokens,
			})
			if err == nil {
				t.Fatal("NewRegistry() error = nil")
			}
		})
	}
}

func TestRegistryBearerFailuresDoNotLeakSensitiveValues(t *testing.T) {
	const token = "machine-token-sensitive"
	const providerSecret = "provider-secret-sensitive"
	const responseSecret = "response-secret-sensitive"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(responseSecret))
	}))
	defer server.Close()

	for name, source := range map[string]core.TokenSource{
		"provider":    core.TokenSourceFunc(func(context.Context) (string, error) { return "", errors.New(providerSecret) }),
		"response":    core.TokenSourceFunc(func(context.Context) (string, error) { return token, nil }),
		"blank token": core.TokenSourceFunc(func(context.Context) (string, error) { return " ", nil }),
	} {
		t.Run(name, func(t *testing.T) {
			registry, err := httpcatalog.NewRegistry(httpcatalog.Config{
				BaseURL: server.URL, Application: "beacon", Service: "notify-server", Release: "test", Tokens: source,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := registry.Register(catalogSpec(t, "/api/v1/notifications", "notify.task.select", "beacon:notify:select")); err != nil {
				t.Fatal(err)
			}
			_, err = registry.Sync(t.Context())
			if err == nil {
				t.Fatal("Sync() error = nil")
			}
			testkit.AssertNoLeak(t, err.Error(), token, providerSecret, responseSecret)
		})
	}
}

func TestRegistryObserverReportsBearerWithoutCredentials(t *testing.T) {
	const token = "observer-token-sensitive"
	var event core.Event
	registry, err := httpcatalog.NewRegistry(httpcatalog.Config{
		BaseURL: "http://127.0.0.1:1", Application: "beacon", Service: "notify-server", Release: "test",
		Tokens:   core.TokenSourceFunc(func(context.Context) (string, error) { return token, nil }),
		Observer: core.ObserverFunc(func(_ context.Context, got core.Event) { event = got }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(catalogSpec(t, "/api/v1/notifications", "notify.task.select", "beacon:notify:select")); err != nil {
		t.Fatal(err)
	}
	_, _ = registry.Sync(t.Context())
	if event.CredentialSource != "bearer" || event.Operation != "httpcatalog.sync" || strings.Contains(event.Operation, token) {
		t.Fatalf("observer event = %#v", event)
	}
}
