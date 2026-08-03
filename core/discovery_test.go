package core_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/testkit"
)

func TestNewRequiresS256AndRS256(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		algs    []string
	}{
		{name: "missing S256", methods: []string{"plain"}, algs: []string{"RS256"}},
		{name: "missing RS256", methods: []string{"S256"}, algs: []string{"RS384"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := newCoreIssuer(t, core.Metadata{
				CodeChallengeMethodsSupported:    test.methods,
				IDTokenSigningAlgValuesSupported: test.algs,
			})
			_, err := core.New(t.Context(), core.Config{
				IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client(),
			})
			if err == nil {
				t.Fatalf("New() error = nil, want %s rejection", test.name)
			}
		})
	}
}

type typedNilClock struct{}

func (*typedNilClock) Now() time.Time { panic("typed nil clock invoked") }

type typedNilObserver struct{}

func (*typedNilObserver) Observe(context.Context, core.Event) { panic("typed nil observer invoked") }

func TestNewTreatsTypedNilOptionalCollaboratorsAsAbsent(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{
		CodeChallengeMethodsSupported:    []string{"S256"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})
	var clock *typedNilClock
	var observer *typedNilObserver
	if _, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client(),
		Clock: clock, Observer: observer,
	}); err != nil {
		t.Fatalf("New() error = %v", err)
	}
}

func TestNewReturnsDefensiveMetadataAndImmutableAudiences(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{
		ScopesSupported:                  []string{"openid", "groups"},
		CodeChallengeMethodsSupported:    []string{"S256"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})
	audiences := []string{" portal ", "api"}
	runtime, err := core.New(t.Context(), core.Config{IssuerURL: issuer.Server.URL, Audiences: audiences, HTTPClient: issuer.Server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	audiences[0] = "mutated"
	metadata := runtime.Metadata()
	metadata.ScopesSupported[0] = "mutated"
	if !runtime.AcceptsAudience(" portal ") || !runtime.AcceptsAudience("api") || runtime.AcceptsAudience("mutated") {
		t.Fatal("configured audience set is not trimmed and immutable")
	}
	if got := runtime.Metadata().ScopesSupported; !slices.Equal(got, []string{"openid", "groups"}) {
		t.Fatalf("Metadata().ScopesSupported = %v", got)
	}
}

func TestNewRejectsIssuerMismatchRedirectAndOversizedDiscovery(t *testing.T) {
	t.Run("issuer mismatch", func(t *testing.T) {
		issuer := newCoreIssuer(t, core.Metadata{
			Issuer:                           "https://wrong.example/secret",
			CodeChallengeMethodsSupported:    []string{"S256"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		})
		_, err := core.New(t.Context(), core.Config{IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client()})
		if err == nil {
			t.Fatal("New() error = nil")
		}
		testkit.AssertNoLeak(t, err.Error(), "secret")
	})

	for name, handler := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/target")
			w.WriteHeader(http.StatusFound)
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			_, err := core.New(t.Context(), core.Config{IssuerURL: server.URL, Audiences: []string{"portal"}, HTTPClient: server.Client()})
			if err == nil {
				t.Fatal("New() error = nil")
			}
			var typed *core.Error
			if !errors.As(err, &typed) || typed.Kind != core.KindProtocol {
				t.Fatalf("New() error = %#v, want protocol error", err)
			}
		})
	}
}
