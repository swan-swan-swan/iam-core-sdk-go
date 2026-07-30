package authn

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

const maxRefreshPollInterval = 25 * time.Millisecond

// ForceRefresh rotates the tokens for sessionID. Concurrent force refreshes
// coordinate through the backend's distributed session lock.
func (s *Service) ForceRefresh(ctx context.Context, sessionID string) (*session.Session, error) {
	return s.refreshSession(ctx, sessionID, true)
}

func (s *Service) refreshSession(
	ctx context.Context,
	sessionID string,
	force bool,
) (result *session.Session, resultErr error) {
	const operation = "authn.refresh"
	if ctx == nil || strings.TrimSpace(sessionID) == "" || ctx.Err() != nil {
		return nil, authError(sdkerr.KindSessionUnavailable, operation)
	}

	baseline, err := s.backend.Get(ctx, sessionID)
	if err != nil {
		return nil, refreshSessionReadError(err, operation)
	}
	now := s.clock.Now()
	if !validSessionForUse(baseline, sessionID, now) {
		return nil, authError(sdkerr.KindUnauthenticated, operation)
	}
	if !force && accessTokenFresh(baseline, now, s.refreshBeforeExpiry) {
		return cloneAuthSession(baseline), nil
	}

	lock, winner, err := s.acquireRefreshLock(ctx, sessionID, baseline)
	if err != nil {
		return nil, err
	}
	if winner != nil {
		return winner, nil
	}
	recoveredAfterLockLoss := false
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.refreshLockTTL)
		defer cancel()
		if unlockErr := lock.Unlock(unlockCtx); unlockErr != nil && resultErr == nil {
			if recoveredAfterLockLoss && errors.Is(unlockErr, session.ErrLockLost) {
				return
			}
			result = nil
			resultErr = authError(sdkerr.KindSessionUnavailable, operation)
		}
	}()

	current, err := s.backend.Get(ctx, sessionID)
	if err != nil {
		return nil, refreshSessionReadError(err, operation)
	}
	now = s.clock.Now()
	if !validSessionForUse(current, sessionID, now) {
		return nil, authError(sdkerr.KindUnauthenticated, operation)
	}
	if current.Version != baseline.Version {
		if safeRotatedRefreshWinner(current, baseline, sessionID, now) {
			return cloneAuthSession(current), nil
		}
		if !sameRefreshTokenSupplier(current, baseline, sessionID) {
			return nil, authError(sdkerr.KindSessionUnavailable, operation)
		}
	}
	if current.Version == baseline.Version && !force &&
		accessTokenFresh(current, now, s.refreshBeforeExpiry) {
		return cloneAuthSession(current), nil
	}
	if strings.TrimSpace(current.TokenSet.RefreshToken) == "" {
		return nil, authError(sdkerr.KindUnauthenticated, operation)
	}
	supplier := cloneAuthSession(current)

	tokens, err := s.oidc.Refresh(ctx, supplier.TokenSet.RefreshToken)
	if err != nil {
		if errors.Is(err, sdkerr.ErrInvalidGrant) {
			result, recoveredAfterLockLoss, resultErr = s.deleteInvalidGrantSession(
				ctx,
				lock,
				sessionID,
				supplier,
			)
			return result, resultErr
		}
		return nil, authError(sdkerr.KindIAMUnavailable, operation)
	}
	if tokens.IDToken != "" {
		claims, verifyErr := s.oidc.VerifyRefreshedIDToken(ctx, tokens.IDToken)
		if verifyErr != nil || !constantTimeEqual(claims.Subject, supplier.Identity.Subject) {
			return nil, authError(sdkerr.KindIAMUnavailable, operation)
		}
	} else {
		tokens.IDToken = supplier.TokenSet.IDToken
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = supplier.TokenSet.RefreshToken
	}
	now = s.clock.Now()
	if strings.TrimSpace(tokens.AccessToken) == "" || !tokens.AccessTokenExpiry.After(now) ||
		constantTimeEqual(tokens.AccessToken, supplier.TokenSet.AccessToken) {
		return nil, authError(sdkerr.KindIAMUnavailable, operation)
	}
	if supplier.Version == ^uint64(0) {
		return nil, authError(sdkerr.KindSessionUnavailable, operation)
	}
	result, recoveredAfterLockLoss, resultErr = s.commitRefreshedTokens(
		ctx,
		lock,
		sessionID,
		supplier,
		tokens,
		now,
	)
	return result, resultErr
}

func (s *Service) commitRefreshedTokens(
	ctx context.Context,
	lock session.Lock,
	sessionID string,
	supplier *session.Session,
	tokens oidc.TokenSet,
	now time.Time,
) (result *session.Session, recoveredAfterLockLoss bool, resultErr error) {
	const operation = "authn.refresh"
	current := supplier
	for {
		if ctx.Err() != nil || current.Version == ^uint64(0) {
			return nil, false, authError(sdkerr.KindSessionUnavailable, operation)
		}
		next := cloneAuthSession(current)
		next.Version = current.Version + 1
		next.TokenSet = tokens
		if now.After(next.UpdatedAt) {
			next.UpdatedAt = now
		}

		err := s.backend.CompareAndSwapWithLock(ctx, lock, sessionID, current.Version, next)
		switch {
		case err == nil:
			return cloneAuthSession(next), false, nil
		case errors.Is(err, session.ErrVersionConflict):
			latest, getErr := s.backend.Get(ctx, sessionID)
			if getErr != nil {
				return nil, false, refreshCommitReadError(getErr, operation)
			}
			checkNow := s.clock.Now()
			if safeRotatedRefreshWinner(latest, supplier, sessionID, checkNow) {
				return cloneAuthSession(latest), false, nil
			}
			if !validSessionForUse(latest, sessionID, checkNow) {
				return nil, false, authError(sdkerr.KindUnauthenticated, operation)
			}
			if !sameRefreshTokenSupplier(latest, supplier, sessionID) ||
				latest.Version <= current.Version || latest.Version == ^uint64(0) {
				return nil, false, authError(sdkerr.KindSessionUnavailable, operation)
			}
			current = latest
		case errors.Is(err, session.ErrLockLost):
			winner, getErr := s.backend.Get(ctx, sessionID)
			if getErr == nil &&
				safeRotatedRefreshWinner(winner, supplier, sessionID, s.clock.Now()) {
				return cloneAuthSession(winner), true, nil
			}
			return nil, false, authError(sdkerr.KindSessionUnavailable, operation)
		case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired):
			return nil, false, authError(sdkerr.KindUnauthenticated, operation)
		default:
			return nil, false, authError(sdkerr.KindSessionUnavailable, operation)
		}
	}
}

func (s *Service) deleteInvalidGrantSession(
	ctx context.Context,
	lock session.Lock,
	sessionID string,
	supplier *session.Session,
) (result *session.Session, recoveredAfterLockLoss bool, resultErr error) {
	const operation = "authn.refresh"
	current := supplier
	for {
		if ctx.Err() != nil {
			return nil, false, authError(sdkerr.KindSessionUnavailable, operation)
		}
		err := s.backend.DeleteWithLock(ctx, lock, sessionID, current.Version)
		switch {
		case err == nil, errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired):
			return nil, false, authError(sdkerr.KindUnauthenticated, operation)
		case errors.Is(err, session.ErrVersionConflict):
			latest, getErr := s.backend.Get(ctx, sessionID)
			if getErr != nil {
				return nil, false, refreshCommitReadError(getErr, operation)
			}
			checkNow := s.clock.Now()
			if safeRotatedRefreshWinner(latest, supplier, sessionID, checkNow) {
				return cloneAuthSession(latest), false, nil
			}
			if !validSessionForUse(latest, sessionID, checkNow) {
				return nil, false, authError(sdkerr.KindUnauthenticated, operation)
			}
			if !sameRefreshTokenSupplier(latest, supplier, sessionID) ||
				latest.Version <= current.Version {
				return nil, false, authError(sdkerr.KindSessionUnavailable, operation)
			}
			current = latest
		case errors.Is(err, session.ErrLockLost):
			winner, getErr := s.backend.Get(ctx, sessionID)
			if getErr == nil &&
				safeRotatedRefreshWinner(winner, supplier, sessionID, s.clock.Now()) {
				return cloneAuthSession(winner), true, nil
			}
			return nil, false, authError(sdkerr.KindSessionUnavailable, operation)
		default:
			return nil, false, authError(sdkerr.KindSessionUnavailable, operation)
		}
	}
}

func (s *Service) acquireRefreshLock(
	ctx context.Context,
	sessionID string,
	baseline *session.Session,
) (session.Lock, *session.Session, error) {
	const operation = "authn.refresh"
	waitCtx, cancel := context.WithTimeout(ctx, s.refreshLockTTL)
	defer cancel()
	poll := s.refreshLockTTL / 10
	if poll <= 0 || poll > maxRefreshPollInterval {
		poll = maxRefreshPollInterval
	}

	for {
		if waitCtx.Err() != nil {
			return nil, nil, authError(sdkerr.KindSessionUnavailable, operation)
		}
		lock, err := s.backend.Lock(waitCtx, sessionID, s.refreshLockTTL)
		if err == nil {
			return lock, nil, nil
		}
		if !errors.Is(err, session.ErrLocked) {
			return nil, nil, authError(sdkerr.KindSessionUnavailable, operation)
		}
		latest, getErr := s.backend.Get(waitCtx, sessionID)
		if getErr != nil {
			return nil, nil, refreshSessionReadError(getErr, operation)
		}
		if safeRotatedRefreshWinner(latest, baseline, sessionID, s.clock.Now()) {
			return nil, cloneAuthSession(latest), nil
		}
		timer := time.NewTimer(poll)
		select {
		case <-waitCtx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, nil, authError(sdkerr.KindSessionUnavailable, operation)
		case <-timer.C:
		}
	}
}

func refreshCommitReadError(err error, operation string) error {
	if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
		return authError(sdkerr.KindUnauthenticated, operation)
	}
	return authError(sdkerr.KindSessionUnavailable, operation)
}

func refreshSessionReadError(err error, operation string) error {
	if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
		return authError(sdkerr.KindUnauthenticated, operation)
	}
	return authError(sdkerr.KindSessionUnavailable, operation)
}

func safeRotatedRefreshWinner(
	candidate *session.Session,
	baseline *session.Session,
	sessionID string,
	now time.Time,
) bool {
	return candidate != nil && baseline != nil && candidate.Version > baseline.Version &&
		validSessionForUse(candidate, sessionID, now) &&
		constantTimeEqual(candidate.Identity.Subject, baseline.Identity.Subject) &&
		strings.TrimSpace(candidate.TokenSet.AccessToken) != "" &&
		candidate.TokenSet.AccessTokenExpiry.After(now) &&
		!constantTimeEqual(candidate.TokenSet.AccessToken, baseline.TokenSet.AccessToken)
}

func sameRefreshTokenSupplier(
	candidate *session.Session,
	baseline *session.Session,
	sessionID string,
) bool {
	return candidate != nil && baseline != nil &&
		constantTimeEqual(candidate.ID, sessionID) &&
		constantTimeEqual(baseline.ID, sessionID) &&
		constantTimeEqual(candidate.Identity.Subject, baseline.Identity.Subject) &&
		constantTimeEqual(candidate.TokenSet.RefreshToken, baseline.TokenSet.RefreshToken)
}

func accessTokenFresh(item *session.Session, now time.Time, window time.Duration) bool {
	if item == nil || strings.TrimSpace(item.TokenSet.AccessToken) == "" ||
		item.TokenSet.AccessTokenExpiry.IsZero() {
		return false
	}
	threshold, ok := addDurationSafe(now, window)
	return ok && item.TokenSet.AccessTokenExpiry.After(threshold)
}

func validSessionForUse(item *session.Session, sessionID string, now time.Time) bool {
	return item != nil && item.Version != 0 && constantTimeEqual(item.ID, sessionID) &&
		strings.TrimSpace(item.Identity.Subject) != "" && item.ExpiresAt.After(now) &&
		(item.IdleExpiresAt.IsZero() || item.IdleExpiresAt.After(now))
}

func addDurationSafe(value time.Time, duration time.Duration) (time.Time, bool) {
	next := value.Add(duration)
	if duration > 0 && next.Before(value) {
		return time.Time{}, false
	}
	if duration < 0 && next.After(value) {
		return time.Time{}, false
	}
	return next, true
}

func cloneAuthSession(item *session.Session) *session.Session {
	if item == nil {
		return nil
	}
	cloned := *item
	cloned.GrantedScopes = append([]string(nil), item.GrantedScopes...)
	cloned.Identity.Roles = append([]string(nil), item.Identity.Roles...)
	cloned.Identity.Scopes = append([]string(nil), item.Identity.Scopes...)
	if item.Identity.ExtraClaims != nil {
		cloned.Identity.ExtraClaims = make(map[string]json.RawMessage, len(item.Identity.ExtraClaims))
		for name, raw := range item.Identity.ExtraClaims {
			cloned.Identity.ExtraClaims[name] = append(json.RawMessage(nil), raw...)
		}
	}
	return &cloned
}
