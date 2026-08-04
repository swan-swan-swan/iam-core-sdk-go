package bff

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

const maxSessionTouchAttempts = 4

func (c *Client) SessionPresent(request *http.Request) (bool, error) {
	const operation = "bff.session_present"
	if request == nil {
		return false, bffError(core.KindProtocol, operation, 0, false)
	}
	if !rawCookieNamePresent(request, c.sessionCookie.Name) {
		return false, nil
	}
	cookies := request.CookiesNamed(c.sessionCookie.Name)
	if len(cookies) != 1 || !validCookieValue(cookies[0].Value) {
		return true, bffError(core.KindProtocol, operation, 0, false)
	}
	return true, nil
}

func rawCookieNamePresent(request *http.Request, name string) bool {
	if request == nil || name == "" {
		return false
	}
	for headerName, values := range request.Header {
		if !strings.EqualFold(headerName, "Cookie") {
			continue
		}
		for _, value := range values {
			for part := range strings.SplitSeq(value, ";") {
				candidate := strings.TrimSpace(part)
				if before, _, found := strings.Cut(candidate, "="); found {
					candidate = strings.TrimSpace(before)
				}
				if candidate == name {
					return true
				}
			}
		}
	}
	return false
}

func (c *Client) ResolveSession(request *http.Request) (core.Credential, bool, error) {
	const operation = "bff.resolve_session"
	present, err := c.SessionPresent(request)
	if err != nil || !present {
		return core.Credential{}, present, err
	}
	ctx := request.Context()
	if err := ctx.Err(); err != nil {
		return core.Credential{}, true, err
	}
	sessionID, err := oneCookieValue(request, c.sessionCookie.Name)
	if err != nil {
		return core.Credential{}, false, bffError(core.KindProtocol, operation, 0, false)
	}
	item, err := c.backend.Get(ctx, sessionID)
	if err != nil {
		return core.Credential{}, true, c.sessionBackendError(operation, err)
	}
	if err := c.validateResolvedSession(item, sessionID, c.clock.Now()); err != nil {
		return core.Credential{}, true, err
	}
	if refreshRequired(item, c.clock.Now(), c.refreshBeforeExpiry) {
		item, err = c.refreshSession(ctx, item)
		if err != nil {
			return core.Credential{}, true, err
		}
		refreshedAt := c.clock.Now()
		if err := c.validateResolvedSession(item, sessionID, refreshedAt); err != nil {
			return core.Credential{}, true, err
		}
		if !item.Tokens.AccessTokenExpiry.After(refreshedAt) {
			return core.Credential{}, true, bffError(core.KindUnauthenticated, operation, 0, false)
		}
	}
	item, err = c.touchSession(ctx, item)
	if err != nil {
		return core.Credential{}, true, err
	}
	return credentialFromSession(item), true, nil
}

func (c *Client) validateResolvedSession(item *session.Session, expectedID string, now time.Time) error {
	const operation = "bff.resolve_session"
	if item == nil || item.Version == 0 || !constantTimeEqual(item.ID, expectedID) ||
		strings.TrimSpace(item.Auth.Subject) == "" || strings.TrimSpace(item.Tokens.AccessToken) == "" ||
		item.Tokens.TokenType != "Bearer" || item.Tokens.AccessTokenExpiry.IsZero() ||
		!item.ExpiresAt.After(now) || !item.IdleExpiresAt.After(now) {
		return bffError(core.KindUnauthenticated, operation, 0, false)
	}
	return nil
}

func (c *Client) touchSession(ctx context.Context, item *session.Session) (*session.Session, error) {
	const operation = "bff.session_touch"
	current := cloneSessionState(item)
	for range maxSessionTouchAttempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		now := c.clock.Now()
		if err := c.validateResolvedSession(current, item.ID, now); err != nil {
			return nil, err
		}
		if !now.After(current.LastSeenAt) {
			return current, nil
		}
		if current.Version == ^uint64(0) {
			return nil, bffError(core.KindSessionUnavailable, operation, 0, true)
		}
		next := cloneSessionState(current)
		next.Version = current.Version + 1
		next.UpdatedAt = now
		next.LastSeenAt = now
		next.IdleExpiresAt = now.Add(c.sessionIdleTTL)
		if next.IdleExpiresAt.After(next.ExpiresAt) {
			next.IdleExpiresAt = next.ExpiresAt
		}
		err := c.backend.CompareAndSwap(ctx, current.ID, current.Version, next)
		if err == nil {
			return next, nil
		}
		if !errors.Is(err, session.ErrConflict) {
			return nil, c.sessionBackendError(operation, err)
		}
		current, err = c.backend.Get(ctx, current.ID)
		if err != nil {
			return nil, c.sessionBackendError(operation, err)
		}
	}
	return nil, bffError(core.KindSessionUnavailable, operation, 0, true)
}

func credentialFromSession(item *session.Session) core.Credential {
	if item == nil {
		return core.Credential{}
	}
	accessToken := item.Tokens.AccessToken
	return core.Credential{
		Source: core.CredentialSession, SessionID: item.ID, Auth: cloneAuthContext(item.Auth),
		Tokens: core.TokenSourceFunc(func(context.Context) (string, error) {
			if strings.TrimSpace(accessToken) == "" {
				return "", core.NewError(core.KindUnauthenticated, "bff.session_token", 0, false, nil)
			}
			return accessToken, nil
		}),
	}
}
