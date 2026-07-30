package authn

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

func TestConcurrentRefreshUsesRefreshTokenOnce(t *testing.T) {
	harness := newRefreshHarness(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	harness.oidc.mu.Lock()
	harness.oidc.refreshStarted = started
	harness.oidc.refreshBlock = release
	harness.oidc.mu.Unlock()

	var group sync.WaitGroup
	results := make(chan *session.Session, 2)
	errs := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := harness.service.refreshSession(context.Background(), "session-1", false)
			results <- got
			errs <- err
		}()
	}
	<-started
	close(release)
	group.Wait()
	close(errs)
	close(results)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for got := range results {
		if got == nil || got.TokenSet.AccessToken != "access-refreshed" || got.Version != 2 {
			t.Fatalf("session = %#v", got)
		}
	}
	if harness.oidc.tokenCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d", harness.oidc.tokenCalls.Load())
	}
}

func TestConcurrentForceRefreshUsesRefreshTokenOnce(t *testing.T) {
	harness := newRefreshHarness(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	harness.oidc.mu.Lock()
	harness.oidc.refreshStarted = started
	harness.oidc.refreshBlock = release
	harness.oidc.mu.Unlock()

	var group sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := harness.service.ForceRefresh(context.Background(), "session-1")
			if err == nil && (got == nil || got.Version != 2) {
				err = errors.New("force refresh returned wrong version")
			}
			errs <- err
		}()
	}
	<-started
	close(release)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if harness.oidc.tokenCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d", harness.oidc.tokenCalls.Load())
	}
}

func TestRefreshWaitsForLockedWinner(t *testing.T) {
	harness := newRefreshHarness(t)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := cloneTestSession(baseline)
	winner.Version++
	winner.TokenSet.AccessToken = "winner-access"
	winner.TokenSet.AccessTokenExpiry = fixedNow.Add(time.Hour)

	var lockCalls atomic.Int32
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.lockFunc = func(ctx context.Context, id string, ttl time.Duration) (session.Lock, error) {
		if lockCalls.Add(1) == 1 {
			if err := harness.backend.CompareAndSwap(ctx, id, baseline.Version, winner); err != nil {
				t.Fatal(err)
			}
			return nil, session.ErrLocked
		}
		return harness.backend.Lock(ctx, id, ttl)
	}
	harness.service.backend = wrapper

	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if got.TokenSet.AccessToken != "winner-access" || got.Version != 2 {
		t.Fatalf("session = %#v", got)
	}
	if harness.oidc.tokenCalls.Load() != 0 {
		t.Fatalf("refresh calls = %d", harness.oidc.tokenCalls.Load())
	}
}

func TestRefreshRejectsLockedWinnerForDifferentSessionID(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.service.refreshLockTTL = 10 * time.Millisecond
	var getCalls atomic.Int32
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.getFunc = func(ctx context.Context, id string) (*session.Session, error) {
		item, err := harness.backend.Get(ctx, id)
		if err != nil || getCalls.Add(1) == 1 {
			return item, err
		}
		item.ID = "different-session"
		item.Version++
		item.TokenSet.AccessTokenExpiry = fixedNow.Add(time.Hour)
		return item, nil
	}
	wrapper.lockFunc = func(context.Context, string, time.Duration) (session.Lock, error) {
		return nil, session.ErrLocked
	}
	harness.service.backend = wrapper

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
	if harness.oidc.tokenCalls.Load() != 0 {
		t.Fatalf("refresh calls = %d", harness.oidc.tokenCalls.Load())
	}
}

func TestRefreshLockLossBeforeCommitReturnsUnavailableAndDoesNotCAS(t *testing.T) {
	harness := newRefreshHarness(t)
	var casCalls atomic.Int32
	wrapper := &refreshBackend{
		Backend: harness.backend,
		lockFunc: func(context.Context, string, time.Duration) (session.Lock, error) {
			return &testRefreshLock{valid: false}, nil
		},
		casFunc: func(context.Context, string, uint64, *session.Session) error {
			casCalls.Add(1)
			return nil
		},
	}
	harness.service.backend = wrapper

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
	if casCalls.Load() != 0 {
		t.Fatalf("CAS calls = %d", casCalls.Load())
	}
	stored, getErr := harness.backend.Get(t.Context(), "session-1")
	if getErr != nil || stored.TokenSet.AccessToken != "access-original" || stored.Version != 1 {
		t.Fatalf("stored = %#v, error = %v", stored, getErr)
	}
}

func TestRefreshCASConflictReturnsSafeWinnerWithoutSecondRefresh(t *testing.T) {
	harness := newRefreshHarness(t)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := cloneTestSession(baseline)
	winner.Version++
	winner.TokenSet.AccessToken = "winner-access"
	winner.TokenSet.AccessTokenExpiry = fixedNow.Add(time.Hour)
	var casCalls atomic.Int32
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.casFunc = func(ctx context.Context, id string, expected uint64, _ *session.Session) error {
		casCalls.Add(1)
		if err := harness.backend.CompareAndSwap(ctx, id, expected, winner); err != nil {
			t.Fatal(err)
		}
		return session.ErrVersionConflict
	}
	harness.service.backend = wrapper

	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if got.TokenSet.AccessToken != "winner-access" || got.Version != 2 {
		t.Fatalf("session = %#v", got)
	}
	if casCalls.Load() != 1 || harness.oidc.tokenCalls.Load() != 1 {
		t.Fatalf("CAS calls = %d, refresh calls = %d", casCalls.Load(), harness.oidc.tokenCalls.Load())
	}
}

func TestRefreshInvalidGrantDeletesSessionByTypedReason(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.oidc.mu.Lock()
	harness.oidc.refreshStatus = http.StatusBadRequest
	harness.oidc.refreshError = "invalid_grant"
	harness.oidc.mu.Unlock()

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindUnauthenticated)
	if _, getErr := harness.backend.Get(t.Context(), "session-1"); !errors.Is(getErr, session.ErrNotFound) {
		t.Fatalf("Get() error = %v, want not found", getErr)
	}
}

func TestRefreshNearMatchDoesNotDeleteSession(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.oidc.mu.Lock()
	harness.oidc.refreshStatus = http.StatusBadRequest
	harness.oidc.refreshError = "invalid-grant"
	harness.oidc.mu.Unlock()

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindIAMUnavailable)
	if _, getErr := harness.backend.Get(t.Context(), "session-1"); getErr != nil {
		t.Fatalf("session was deleted: %v", getErr)
	}
}

func TestRefreshNetworkFailurePreservesSession(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.oidc.mu.Lock()
	harness.oidc.refreshStatus = http.StatusServiceUnavailable
	harness.oidc.refreshError = "temporarily_unavailable"
	harness.oidc.mu.Unlock()

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindIAMUnavailable)
	stored, getErr := harness.backend.Get(t.Context(), "session-1")
	if getErr != nil || stored.Version != 1 || stored.TokenSet.RefreshToken != "refresh-original" {
		t.Fatalf("stored = %#v, error = %v", stored, getErr)
	}
}

func TestRefreshInvalidNewIDTokenPreservesSession(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.oidc.mu.Lock()
	harness.oidc.refreshRawIDToken = "not-a-jwt token=secret"
	harness.oidc.mu.Unlock()

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindIAMUnavailable)
	if stringsContainAny(err.Error(), "not-a-jwt", "secret", "access-original", "refresh-original") {
		t.Fatalf("error leaked secret: %v", err)
	}
	stored, getErr := harness.backend.Get(t.Context(), "session-1")
	if getErr != nil || stored.Version != 1 || stored.TokenSet.IDToken != "id-original" {
		t.Fatalf("stored = %#v, error = %v", stored, getErr)
	}
}

func TestRefreshNewIDTokenSubjectMismatchPreservesSession(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.oidc.mu.Lock()
	harness.oidc.refreshIDSubject = "different-user"
	harness.oidc.mu.Unlock()

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindIAMUnavailable)
	stored, getErr := harness.backend.Get(t.Context(), "session-1")
	if getErr != nil || stored.Version != 1 || stored.Identity.Subject != "user-1" {
		t.Fatalf("stored = %#v, error = %v", stored, getErr)
	}
}

func TestRefreshPreservesOmittedRefreshAndIDTokens(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.oidc.mu.Lock()
	harness.oidc.includeRefreshToken = false
	harness.oidc.includeRefreshIDToken = false
	harness.oidc.mu.Unlock()

	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if got.TokenSet.RefreshToken != "refresh-original" || got.TokenSet.IDToken != "id-original" {
		t.Fatalf("tokens = %#v", got.TokenSet)
	}
}

func TestRefreshCommitsNewRefreshAndIDTokens(t *testing.T) {
	harness := newRefreshHarness(t)
	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if got.TokenSet.RefreshToken != "refresh-rotated" || got.TokenSet.IDToken == "" ||
		got.TokenSet.IDToken == "id-original" || got.Version != 2 {
		t.Fatalf("session = %#v", got)
	}
}

func TestRefreshUnlockFailureDoesNotOverridePrimaryError(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.oidc.mu.Lock()
	harness.oidc.refreshStatus = http.StatusBadRequest
	harness.oidc.refreshError = "invalid_grant"
	harness.oidc.mu.Unlock()
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		lockFunc: func(context.Context, string, time.Duration) (session.Lock, error) {
			return &testRefreshLock{valid: true, unlockErr: session.ErrLockLost}, nil
		},
	}

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindUnauthenticated)
}

func TestRefreshUnlockFailureAfterSuccessReturnsUnavailable(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		lockFunc: func(context.Context, string, time.Duration) (session.Lock, error) {
			return &testRefreshLock{valid: true, unlockErr: session.ErrLockLost}, nil
		},
	}

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
}

func TestRefreshWaitingHonorsContextCancellation(t *testing.T) {
	harness := newRefreshHarness(t)
	var lockCalls atomic.Int32
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		lockFunc: func(context.Context, string, time.Duration) (session.Lock, error) {
			lockCalls.Add(1)
			return nil, session.ErrLocked
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := harness.service.refreshSession(ctx, "session-1", false)
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
	if lockCalls.Load() > 2 {
		t.Fatalf("lock calls = %d, possible busy loop", lockCalls.Load())
	}
}

type refreshHarness struct {
	*testHarness
}

func newRefreshHarness(t *testing.T) *refreshHarness {
	t.Helper()
	harness := newTestHarness(t, func(config *Config, _ *testHarness) {
		config.RefreshLockTTL = 500 * time.Millisecond
		config.RefreshBeforeExpiry = time.Minute
	})
	seedSession(t, harness.backend, &session.Session{
		ID:      "session-1",
		Version: 1,
		TokenSet: oidc.TokenSet{
			AccessToken:       "access-original",
			RefreshToken:      "refresh-original",
			IDToken:           "id-original",
			TokenType:         "Bearer",
			AccessTokenExpiry: fixedNow.Add(30 * time.Second),
		},
		Identity:            oidc.Identity{Subject: "user-1", Roles: []string{"role-1"}, Scopes: []string{"openid"}},
		GrantedScopes:       []string{"openid"},
		CreatedAt:           fixedNow.Add(-time.Hour),
		UpdatedAt:           fixedNow.Add(-time.Hour),
		LastSeenAt:          fixedNow.Add(-time.Minute),
		ExpiresAt:           fixedNow.Add(8 * time.Hour),
		IdleExpiresAt:       fixedNow.Add(time.Hour),
		IdentityValidatedAt: fixedNow.Add(-time.Minute),
	})
	return &refreshHarness{testHarness: harness}
}

func seedSession(t *testing.T, backend session.Backend, item *session.Session) {
	t.Helper()
	if err := backend.Create(t.Context(), item); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
}

func cloneTestSession(item *session.Session) *session.Session {
	cloned := *item
	cloned.GrantedScopes = append([]string(nil), item.GrantedScopes...)
	cloned.Identity.Roles = append([]string(nil), item.Identity.Roles...)
	cloned.Identity.Scopes = append([]string(nil), item.Identity.Scopes...)
	return &cloned
}

type refreshBackend struct {
	session.Backend
	lockFunc func(context.Context, string, time.Duration) (session.Lock, error)
	casFunc  func(context.Context, string, uint64, *session.Session) error
	getFunc  func(context.Context, string) (*session.Session, error)
}

func (b *refreshBackend) Get(ctx context.Context, id string) (*session.Session, error) {
	if b.getFunc != nil {
		return b.getFunc(ctx, id)
	}
	return b.Backend.Get(ctx, id)
}

func (b *refreshBackend) Lock(ctx context.Context, id string, ttl time.Duration) (session.Lock, error) {
	if b.lockFunc != nil {
		return b.lockFunc(ctx, id, ttl)
	}
	return b.Backend.Lock(ctx, id, ttl)
}

func (b *refreshBackend) CompareAndSwap(
	ctx context.Context,
	id string,
	version uint64,
	next *session.Session,
) error {
	if b.casFunc != nil {
		return b.casFunc(ctx, id, version, next)
	}
	return b.Backend.CompareAndSwap(ctx, id, version, next)
}

type testRefreshLock struct {
	valid     bool
	unlockErr error
}

func (l *testRefreshLock) Valid(context.Context) bool { return l.valid }
func (l *testRefreshLock) Unlock(context.Context) error {
	return l.unlockErr
}

func assertSDKKind(t *testing.T, err error, kind sdkerr.Kind) {
	t.Helper()
	var typed *sdkerr.Error
	if !errors.As(err, &typed) || typed.Kind != kind || typed.Cause != nil {
		t.Fatalf("error = %#v, want %s", err, kind)
	}
}

func stringsContainAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
