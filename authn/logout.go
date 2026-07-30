package authn

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

// Logout deletes the local session before attempting remote OIDC logout.
// A remote failure is returned after local deletion and never restores the
// deleted session.
func (s *Service) Logout(ctx context.Context, sessionID string) error {
	_, err := s.logout(ctx, sessionID)
	return err
}

func (s *Service) logout(ctx context.Context, sessionID string) (bool, error) {
	const operation = "authn.logout"
	if ctx == nil || strings.TrimSpace(sessionID) == "" {
		return false, authError(sdkerr.KindSessionUnavailable, operation)
	}

	item, getErr := s.backend.Get(ctx, sessionID)
	alreadyAbsent := errors.Is(getErr, session.ErrNotFound) || errors.Is(getErr, session.ErrExpired)
	if deleteErr := s.backend.Delete(ctx, sessionID); deleteErr != nil {
		return false, authError(sdkerr.KindSessionUnavailable, operation)
	}
	if alreadyAbsent {
		return false, nil
	}
	if getErr != nil || item == nil || !constantTimeEqual(item.ID, sessionID) {
		return false, authError(sdkerr.KindSessionUnavailable, operation)
	}

	if err := s.oidc.Logout(ctx, item.TokenSet.AccessToken, item.TokenSet.IDToken); err != nil {
		return true, sanitizeLogoutRemoteError(err, operation)
	}
	return false, nil
}

func (s *Service) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		const operation = "authn.logout"
		started := time.Now()
		outcome := "success"
		defer func() {
			duration := time.Since(started)
			s.hooks.Observe(request.Context(), observability.Event{
				Operation: operation,
				Outcome:   outcome,
				Duration:  duration,
			})
			s.logger.Info("iamcore operation",
				slog.String("operation", operation),
				slog.String("outcome", outcome),
				slog.Duration("duration", duration),
			)
		}()

		s.clearCookie(w, s.sessionCookie)
		sessionID, present, err := optionalSessionCookie(request, s.sessionCookie.Name)
		if err != nil {
			outcome = "local_error"
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if !present {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		remoteFailure, err := s.logout(request.Context(), sessionID)
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if remoteFailure {
			outcome = "remote_error"
			if s.logoutRemoteFailureIsSuccess {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		} else {
			outcome = "local_error"
		}
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	})
}

func sanitizeLogoutRemoteError(err error, operation string) *sdkerr.Error {
	var typed *sdkerr.Error
	if !errors.As(err, &typed) {
		return authError(sdkerr.KindIAMUnavailable, operation)
	}
	return &sdkerr.Error{
		Kind:       typed.Kind,
		Operation:  operation,
		HTTPStatus: typed.HTTPStatus,
		RequestID:  typed.RequestID,
		TraceID:    typed.TraceID,
		DecisionID: typed.DecisionID,
		Retryable:  typed.Retryable,
	}
}
