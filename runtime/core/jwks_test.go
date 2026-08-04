package core_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/testkit"
)

type zeroClock struct{}

func (zeroClock) Now() time.Time { return time.Time{} }

func TestUnknownKIDRefreshesJWKSOnce(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	runtime, err := core.New(t.Context(), core.Config{IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client(), UnknownKIDRefreshInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	initial := &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
	if _, err := runtime.VerifyAccessToken(t.Context(), initial.AccessToken(t, initial.validClaims())); err != nil {
		t.Fatal(err)
	}
	rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer.setJWKS(rotatedKey, "rotated")
	rotated := &tokenSigner{PrivateKey: rotatedKey, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "rotated"}
	time.Sleep(2 * time.Millisecond)
	if _, err := runtime.VerifyAccessToken(t.Context(), rotated.AccessToken(t, rotated.validClaims())); err != nil {
		t.Fatal(err)
	}
	if got := issuer.JWKSCalls.Load(); got != 2 {
		t.Fatalf("JWKS calls = %d, want initial + one refresh", got)
	}
}

func TestJWKSAllowsOptionalUseAndAlgorithmHintsToBeOmitted(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	issuer.omitOptionalJWKSHints()
	runtime, err := core.New(t.Context(), core.Config{IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	signer := &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
	if _, err := runtime.VerifyAccessToken(t.Context(), signer.AccessToken(t, signer.validClaims())); err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
}

func TestUnknownKIDRefreshThrottleWorksWithZeroValuedClock(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	runtime, err := core.New(context.Background(), core.Config{
		IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client(),
		Clock: zeroClock{}, UnknownKIDRefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	signer := &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "unknown"}
	raw := signer.AccessToken(t, signer.validClaims())
	for range 2 {
		if _, err := runtime.VerifyAccessToken(context.Background(), raw); err == nil {
			t.Fatal("unknown kid token accepted")
		}
	}
	if got := issuer.JWKSCalls.Load(); got != 1 {
		t.Fatalf("JWKS calls = %d, want one throttled refresh", got)
	}
}

func TestKnownKIDBadSignatureDoesNotRefreshJWKS(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	runtime, err := core.New(t.Context(), core.Config{
		IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client(),
		UnknownKIDRefreshInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	validSigner := &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
	if _, err := runtime.VerifyAccessToken(t.Context(), validSigner.AccessToken(t, validSigner.validClaims())); err != nil {
		t.Fatal(err)
	}
	forgedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	forgedSigner := &tokenSigner{PrivateKey: forgedKey, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
	time.Sleep(2 * time.Millisecond)
	if _, err := runtime.VerifyAccessToken(t.Context(), forgedSigner.AccessToken(t, forgedSigner.validClaims())); err == nil {
		t.Fatal("forged token accepted")
	}
	if got := issuer.JWKSCalls.Load(); got != 1 {
		t.Fatalf("JWKS calls = %d, want no refresh for known kid", got)
	}
}

func TestVerifyAccessTokenPreservesCancellationDuringSharedJWKSFetch(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	runtime, err := core.New(t.Context(), core.Config{IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	signer := &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
	raw := signer.AccessToken(t, signer.validClaims())
	started, release := make(chan struct{}, 1), make(chan struct{})
	issuer.blockJWKS(started, release)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := runtime.VerifyAccessToken(ctx, raw)
		result <- err
	}()
	<-started
	cancel()
	verificationErr := <-result
	close(release)
	if !errors.Is(verificationErr, context.Canceled) {
		t.Fatalf("VerifyAccessToken() error = %v, want context.Canceled", verificationErr)
	}
	if _, err := runtime.VerifyAccessToken(t.Context(), raw); err != nil {
		t.Fatalf("shared JWKS fetch did not remain usable: %v", err)
	}
	if got := issuer.JWKSCalls.Load(); got != 1 {
		t.Fatalf("JWKS calls = %d, want one shared fetch", got)
	}
}

func TestVerifyAccessTokenClassifiesJWKSFetchFailureAsUnavailable(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	runtime, err := core.New(t.Context(), core.Config{IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	signer := &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
	raw := signer.AccessToken(t, signer.validClaims())
	issuer.Server.Close()

	for attempt := 1; attempt <= 2; attempt++ {
		_, err = runtime.VerifyAccessToken(t.Context(), raw)
		var typed *core.Error
		if !errors.As(err, &typed) || typed.Kind != core.KindIAMUnavailable || !typed.Retryable || !errors.Is(err, core.ErrUnavailable) {
			t.Fatalf("attempt %d error = %#v, want retryable IAM unavailable", attempt, err)
		}
		testkit.AssertNoLeak(t, err.Error(), issuer.Server.URL)
	}
}

func TestVerifyAccessTokenPreservesCallerDeadline(t *testing.T) {
	runtime, signer := newCoreRuntime(t)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := runtime.VerifyAccessToken(ctx, signer.AccessToken(t, signer.validClaims()))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("VerifyAccessToken() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestConcurrentUnknownKIDRefreshIsCoalesced(t *testing.T) {
	issuer := newCoreIssuer(t, core.Metadata{CodeChallengeMethodsSupported: []string{"S256"}, IDTokenSigningAlgValuesSupported: []string{"RS256"}})
	runtime, err := core.New(t.Context(), core.Config{IssuerURL: issuer.Server.URL, Audiences: []string{"portal"}, HTTPClient: issuer.Server.Client(), UnknownKIDRefreshInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	initial := &tokenSigner{PrivateKey: issuer.Key, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "test-key"}
	if _, err := runtime.VerifyAccessToken(t.Context(), initial.AccessToken(t, initial.validClaims())); err != nil {
		t.Fatal(err)
	}
	rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer.setJWKS(rotatedKey, "rotated")
	rotated := &tokenSigner{PrivateKey: rotatedKey, Issuer: issuer.Server.URL, Audience: "portal", KeyID: "rotated"}
	raw := rotated.AccessToken(t, rotated.validClaims())
	started, release := make(chan struct{}, 1), make(chan struct{})
	issuer.blockJWKS(started, release)
	time.Sleep(2 * time.Millisecond)
	const count = 12
	start := make(chan struct{})
	errs := make(chan error, count)
	var ready sync.WaitGroup
	ready.Add(count)
	for range count {
		go func() { ready.Done(); <-start; _, err := runtime.VerifyAccessToken(t.Context(), raw); errs <- err }()
	}
	ready.Wait()
	close(start)
	<-started
	time.Sleep(20 * time.Millisecond)
	close(release)
	for range count {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := issuer.JWKSCalls.Load(); got != 2 {
		t.Fatalf("JWKS calls = %d, want initial + one coalesced refresh", got)
	}
}
