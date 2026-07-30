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

func TestDistinctServicesShareDistributedRefreshWinner(t *testing.T) {
	testDistinctServicesShareDistributedRefreshWinner(t, false)
}

func TestDistinctServicesForceRefreshShareDistributedWinner(t *testing.T) {
	testDistinctServicesShareDistributedRefreshWinner(t, true)
}

func testDistinctServicesShareDistributedRefreshWinner(t *testing.T, force bool) {
	t.Helper()
	harness := newRefreshHarness(t)
	baselines := make(chan struct{}, 2)
	releaseBaselines := make(chan struct{})
	refreshStarted := make(chan struct{}, 1)
	releaseRefresh := make(chan struct{})
	lockedObserved := make(chan struct{}, 1)
	var initialGets atomic.Int32
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.getFunc = func(ctx context.Context, id string) (*session.Session, error) {
		if initialGets.Add(1) <= 2 {
			baselines <- struct{}{}
			select {
			case <-releaseBaselines:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return harness.backend.Get(ctx, id)
	}
	wrapper.lockFunc = func(ctx context.Context, id string, ttl time.Duration) (session.Lock, error) {
		lock, err := harness.backend.Lock(ctx, id, ttl)
		if errors.Is(err, session.ErrLocked) {
			select {
			case lockedObserved <- struct{}{}:
			default:
			}
		}
		return lock, err
	}
	harness.service.backend = wrapper
	peer := newPeerRefreshService(t, harness, wrapper)
	harness.oidc.mu.Lock()
	harness.oidc.rotateRefreshTokens = true
	harness.oidc.refreshStarted = refreshStarted
	harness.oidc.refreshBlock = releaseRefresh
	harness.oidc.mu.Unlock()

	type result struct {
		item *session.Session
		err  error
	}
	results := make(chan result, 2)
	for _, service := range []*Service{harness.service, peer} {
		go func(service *Service) {
			var item *session.Session
			var err error
			if force {
				item, err = service.ForceRefresh(context.Background(), "session-1")
			} else {
				item, err = service.refreshSession(context.Background(), "session-1", false)
			}
			results <- result{item: item, err: err}
		}(service)
	}
	<-baselines
	<-baselines
	close(releaseBaselines)
	<-refreshStarted
	<-lockedObserved
	close(releaseRefresh)

	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.item == nil || got.item.Version != 2 ||
			got.item.TokenSet.AccessToken != "access-refreshed" {
			t.Fatalf("session = %#v", got.item)
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
	wrapper.fencedCASFunc = func(
		ctx context.Context,
		_ session.Lock,
		id string,
		expected uint64,
		_ *session.Session,
	) error {
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

func TestRefreshStaleOwnerCannotOverwriteNewOwnerWinner(t *testing.T) {
	harness := newRefreshHarness(t)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := rotatedWinner(baseline, "new-owner-access", "new-owner-refresh")
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.fencedCASFunc = func(
		ctx context.Context,
		_ session.Lock,
		id string,
		expected uint64,
		_ *session.Session,
	) error {
		if err := harness.backend.CompareAndSwap(ctx, id, expected, winner); err != nil {
			t.Fatal(err)
		}
		return session.ErrLockLost
	}
	harness.service.backend = wrapper

	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if got.TokenSet.AccessToken != "new-owner-access" || got.Version != 2 {
		t.Fatalf("session = %#v", got)
	}
	stored, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil || stored.TokenSet.AccessToken != "new-owner-access" {
		t.Fatalf("stored = %#v, error = %v", stored, err)
	}
}

func TestRefreshReturnsWinnerWhenRealStaleMemoryLockCannotUnlock(t *testing.T) {
	harness := newRefreshHarness(t)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := rotatedWinner(baseline, "new-owner-access", "new-owner-refresh")
	unlockErrors := make(chan error, 1)
	var replacement session.Lock
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.lockFunc = func(ctx context.Context, id string, ttl time.Duration) (session.Lock, error) {
		lock, lockErr := harness.backend.Lock(ctx, id, ttl)
		if lockErr != nil {
			return nil, lockErr
		}
		return &observedRefreshLock{Lock: lock, unlockErrors: unlockErrors}, nil
	}
	wrapper.fencedCASFunc = func(
		ctx context.Context,
		lock session.Lock,
		id string,
		expected uint64,
		next *session.Session,
	) error {
		observed := lock.(*observedRefreshLock)
		if unlockErr := observed.Lock.Unlock(ctx); unlockErr != nil {
			t.Fatal(unlockErr)
		}
		var lockErr error
		replacement, lockErr = harness.backend.Lock(ctx, id, time.Minute)
		if lockErr != nil {
			t.Fatal(lockErr)
		}
		if commitErr := harness.backend.CompareAndSwapWithLock(
			ctx,
			replacement,
			id,
			expected,
			winner,
		); commitErr != nil {
			t.Fatal(commitErr)
		}
		staleErr := harness.backend.CompareAndSwapWithLock(
			ctx,
			observed.Lock,
			id,
			expected,
			next,
		)
		if !errors.Is(staleErr, session.ErrLockLost) {
			t.Fatalf("stale fenced CAS error = %v", staleErr)
		}
		return staleErr
	}
	harness.service.backend = wrapper

	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if got == nil || got.TokenSet.AccessToken != "new-owner-access" || got.Version != 2 {
		t.Fatalf("session = %#v", got)
	}
	if unlockErr := <-unlockErrors; !errors.Is(unlockErr, session.ErrLockLost) {
		t.Fatalf("old Lock.Unlock() error = %v", unlockErr)
	}
	if replacement == nil {
		t.Fatal("replacement lock was not installed")
	}
	if err := replacement.Unlock(t.Context()); err != nil {
		t.Fatalf("replacement Unlock() error = %v", err)
	}
}

func TestDelayedStaleInvalidGrantCannotDeleteRotatedWinner(t *testing.T) {
	harness := newRefreshHarness(t)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := rotatedWinner(baseline, "new-owner-access", "new-owner-refresh")
	harness.oidc.mu.Lock()
	harness.oidc.refreshStatus = http.StatusBadRequest
	harness.oidc.refreshError = "invalid_grant"
	harness.oidc.mu.Unlock()
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.fencedDeleteFunc = func(
		ctx context.Context,
		_ session.Lock,
		id string,
		expected uint64,
	) error {
		if err := harness.backend.CompareAndSwap(ctx, id, expected, winner); err != nil {
			t.Fatal(err)
		}
		return session.ErrLockLost
	}
	harness.service.backend = wrapper

	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if got.TokenSet.AccessToken != "new-owner-access" {
		t.Fatalf("session = %#v", got)
	}
	stored, getErr := harness.backend.Get(t.Context(), "session-1")
	if getErr != nil || stored.TokenSet.RefreshToken != "new-owner-refresh" {
		t.Fatalf("stored = %#v, error = %v", stored, getErr)
	}
}

func TestInvalidGrantReturnsWinnerWhenRealStaleMemoryLockCannotUnlock(t *testing.T) {
	harness := newRefreshHarness(t)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	winner := rotatedWinner(baseline, "new-owner-access", "new-owner-refresh")
	harness.oidc.mu.Lock()
	harness.oidc.refreshStatus = http.StatusBadRequest
	harness.oidc.refreshError = "invalid_grant"
	harness.oidc.mu.Unlock()
	unlockErrors := make(chan error, 1)
	var replacement session.Lock
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.lockFunc = func(ctx context.Context, id string, ttl time.Duration) (session.Lock, error) {
		lock, lockErr := harness.backend.Lock(ctx, id, ttl)
		if lockErr != nil {
			return nil, lockErr
		}
		return &observedRefreshLock{Lock: lock, unlockErrors: unlockErrors}, nil
	}
	wrapper.fencedDeleteFunc = func(
		ctx context.Context,
		lock session.Lock,
		id string,
		expected uint64,
	) error {
		observed := lock.(*observedRefreshLock)
		if unlockErr := observed.Lock.Unlock(ctx); unlockErr != nil {
			t.Fatal(unlockErr)
		}
		var lockErr error
		replacement, lockErr = harness.backend.Lock(ctx, id, time.Minute)
		if lockErr != nil {
			t.Fatal(lockErr)
		}
		if commitErr := harness.backend.CompareAndSwapWithLock(
			ctx,
			replacement,
			id,
			expected,
			winner,
		); commitErr != nil {
			t.Fatal(commitErr)
		}
		staleErr := harness.backend.DeleteWithLock(ctx, observed.Lock, id, expected)
		if !errors.Is(staleErr, session.ErrLockLost) {
			t.Fatalf("stale fenced delete error = %v", staleErr)
		}
		return staleErr
	}
	harness.service.backend = wrapper

	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if got == nil || got.TokenSet.AccessToken != "new-owner-access" || got.Version != 2 {
		t.Fatalf("session = %#v", got)
	}
	if unlockErr := <-unlockErrors; !errors.Is(unlockErr, session.ErrLockLost) {
		t.Fatalf("old Lock.Unlock() error = %v", unlockErr)
	}
	if replacement == nil {
		t.Fatal("replacement lock was not installed")
	}
	if err := replacement.Unlock(t.Context()); err != nil {
		t.Fatalf("replacement Unlock() error = %v", err)
	}
}

func TestRefreshReconcilesIssuedTokensAfterTouchOnlyConflict(t *testing.T) {
	harness := newRefreshHarness(t)
	var fencedCalls atomic.Int32
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.fencedCASFunc = func(
		ctx context.Context,
		lock session.Lock,
		id string,
		expected uint64,
		next *session.Session,
	) error {
		if fencedCalls.Add(1) == 1 {
			current, err := harness.backend.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			touched := cloneTestSession(current)
			touched.Version++
			touched.LastSeenAt = fixedNow
			if err := harness.backend.CompareAndSwap(ctx, id, expected, touched); err != nil {
				t.Fatal(err)
			}
			return session.ErrVersionConflict
		}
		return harness.backend.CompareAndSwapWithLock(ctx, lock, id, expected, next)
	}
	harness.service.backend = wrapper

	got, err := harness.service.refreshSession(t.Context(), "session-1", false)
	if err != nil {
		t.Fatalf("refreshSession() error = %v", err)
	}
	if fencedCalls.Load() != 2 || harness.oidc.tokenCalls.Load() != 1 ||
		got.Version != 3 || got.TokenSet.AccessToken != "access-refreshed" ||
		got.TokenSet.RefreshToken != "refresh-rotated" {
		t.Fatalf("session = %#v, fenced calls = %d, token calls = %d",
			got, fencedCalls.Load(), harness.oidc.tokenCalls.Load())
	}
}

func TestInvalidGrantRetriesConditionalDeleteAfterTouchConflict(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.oidc.mu.Lock()
	harness.oidc.refreshStatus = http.StatusBadRequest
	harness.oidc.refreshError = "invalid_grant"
	harness.oidc.mu.Unlock()
	var deleteCalls atomic.Int32
	wrapper := &refreshBackend{Backend: harness.backend}
	wrapper.fencedDeleteFunc = func(
		ctx context.Context,
		lock session.Lock,
		id string,
		expected uint64,
	) error {
		if deleteCalls.Add(1) == 1 {
			current, err := harness.backend.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			touched := cloneTestSession(current)
			touched.Version++
			touched.LastSeenAt = fixedNow
			if err := harness.backend.CompareAndSwap(ctx, id, expected, touched); err != nil {
				t.Fatal(err)
			}
			return session.ErrVersionConflict
		}
		return harness.backend.DeleteWithLock(ctx, lock, id, expected)
	}
	harness.service.backend = wrapper

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindUnauthenticated)
	if deleteCalls.Load() != 2 {
		t.Fatalf("delete calls = %d", deleteCalls.Load())
	}
	if _, getErr := harness.backend.Get(t.Context(), "session-1"); !errors.Is(getErr, session.ErrNotFound) {
		t.Fatalf("Get() error = %v", getErr)
	}
}

func TestSafeRotatedRefreshWinnerRejectsIdentityAndRotationAmbiguity(t *testing.T) {
	harness := newRefreshHarness(t)
	baseline, err := harness.backend.Get(t.Context(), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*session.Session){
		"different id": func(item *session.Session) {
			item.ID = "different-session"
		},
		"different subject": func(item *session.Session) {
			item.Identity.Subject = "different-user"
		},
		"unrotated access token": func(item *session.Session) {
			item.TokenSet.AccessToken = baseline.TokenSet.AccessToken
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := rotatedWinner(baseline, "winner-access", "winner-refresh")
			mutate(candidate)
			if safeRotatedRefreshWinner(
				candidate,
				baseline,
				"session-1",
				fixedNow,
			) {
				t.Fatalf("candidate accepted = %#v", candidate)
			}
		})
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
		fencedDeleteFunc: func(
			ctx context.Context,
			_ session.Lock,
			id string,
			_ uint64,
		) error {
			return harness.backend.Delete(ctx, id)
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
		fencedCASFunc: func(
			ctx context.Context,
			_ session.Lock,
			id string,
			expected uint64,
			next *session.Session,
		) error {
			return harness.backend.CompareAndSwap(ctx, id, expected, next)
		},
	}

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
}

func TestRefreshNonLockLostUnlockFailureAfterSuccessReturnsUnavailable(t *testing.T) {
	harness := newRefreshHarness(t)
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		lockFunc: func(context.Context, string, time.Duration) (session.Lock, error) {
			return &testRefreshLock{valid: true, unlockErr: errors.New("unlock backend unavailable")}, nil
		},
		fencedCASFunc: func(
			ctx context.Context,
			_ session.Lock,
			id string,
			expected uint64,
			next *session.Session,
		) error {
			return harness.backend.CompareAndSwap(ctx, id, expected, next)
		},
	}

	_, err := harness.service.refreshSession(t.Context(), "session-1", false)
	assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
}

func TestRefreshWaitingHonorsContextCancellation(t *testing.T) {
	harness := newRefreshHarness(t)
	var lockCalls atomic.Int32
	waiting := make(chan struct{}, 1)
	harness.service.backend = &refreshBackend{
		Backend: harness.backend,
		lockFunc: func(context.Context, string, time.Duration) (session.Lock, error) {
			lockCalls.Add(1)
			select {
			case waiting <- struct{}{}:
			default:
			}
			return nil, session.ErrLocked
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := harness.service.refreshSession(ctx, "session-1", false)
		done <- err
	}()
	<-waiting
	cancel()

	select {
	case err := <-done:
		assertSDKKind(t, err, sdkerr.KindSessionUnavailable)
	case <-time.After(time.Second):
		t.Fatal("refresh did not stop after cancellation")
	}
	if lockCalls.Load() > 3 {
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

func rotatedWinner(baseline *session.Session, accessToken, refreshToken string) *session.Session {
	winner := cloneTestSession(baseline)
	winner.Version++
	winner.TokenSet.AccessToken = accessToken
	winner.TokenSet.RefreshToken = refreshToken
	winner.TokenSet.AccessTokenExpiry = fixedNow.Add(time.Hour)
	return winner
}

func newPeerRefreshService(
	t *testing.T,
	harness *refreshHarness,
	backend session.Backend,
) *Service {
	t.Helper()
	service, err := New(Config{
		OIDC:                    harness.service.oidc,
		Backend:                 backend,
		RedirectURL:             "https://app.example/auth/callback",
		Clock:                   fixedClock{fixedNow},
		Random:                  &sequenceReader{},
		RefreshBeforeExpiry:     time.Minute,
		RefreshLockTTL:          500 * time.Millisecond,
		SessionAbsoluteTTL:      8 * time.Hour,
		SessionIdleTTL:          time.Hour,
		IdentityRecheckInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return service
}

type refreshBackend struct {
	session.Backend
	lockFunc         func(context.Context, string, time.Duration) (session.Lock, error)
	casFunc          func(context.Context, string, uint64, *session.Session) error
	getFunc          func(context.Context, string) (*session.Session, error)
	fencedCASFunc    func(context.Context, session.Lock, string, uint64, *session.Session) error
	fencedDeleteFunc func(context.Context, session.Lock, string, uint64) error
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

func (b *refreshBackend) CompareAndSwapWithLock(
	ctx context.Context,
	lock session.Lock,
	id string,
	version uint64,
	next *session.Session,
) error {
	if b.fencedCASFunc != nil {
		return b.fencedCASFunc(ctx, lock, id, version, next)
	}
	return b.Backend.CompareAndSwapWithLock(ctx, lock, id, version, next)
}

func (b *refreshBackend) DeleteWithLock(
	ctx context.Context,
	lock session.Lock,
	id string,
	version uint64,
) error {
	if b.fencedDeleteFunc != nil {
		return b.fencedDeleteFunc(ctx, lock, id, version)
	}
	return b.Backend.DeleteWithLock(ctx, lock, id, version)
}

type testRefreshLock struct {
	valid     bool
	unlockErr error
}

func (l *testRefreshLock) Valid(context.Context) bool { return l.valid }
func (l *testRefreshLock) Unlock(context.Context) error {
	return l.unlockErr
}

type observedRefreshLock struct {
	session.Lock
	unlockErrors chan<- error
}

func (l *observedRefreshLock) Unlock(ctx context.Context) error {
	err := l.Lock.Unlock(ctx)
	l.unlockErrors <- err
	return err
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
