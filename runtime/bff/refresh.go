package bff

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/bff/session"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

type refreshTokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken json.RawMessage `json:"refresh_token"`
	IDToken      json.RawMessage `json:"id_token"`
	ExpiresIn    int64           `json:"expires_in"`
	Scope        json.RawMessage `json:"scope"`
	Error        json.RawMessage `json:"error"`
}

const maxInvalidGrantDeleteAttempts = 4

func (c *Client) refreshSession(
	ctx context.Context,
	baseline *session.Session,
) (*session.Session, error) {
	const operation = "bff.refresh"
	if ctx == nil {
		return nil, bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if baseline == nil || strings.TrimSpace(baseline.ID) == "" {
		return nil, bffError(core.KindUnauthenticated, operation, 0, false)
	}
	lease, err := c.backend.AcquireRefreshLease(ctx, baseline.ID, c.refreshLeaseTTL)
	if err != nil {
		if errors.Is(err, session.ErrConflict) {
			return c.waitForRefreshWinner(ctx, baseline)
		}
		return nil, c.sessionBackendError(operation, err)
	}
	defer func() {
		cleanupCtx, cancel := c.refreshCleanupContext(ctx)
		defer cancel()
		_ = lease.Release(cleanupCtx)
	}()

	current, err := c.backend.Get(ctx, baseline.ID)
	if err != nil {
		return nil, c.sessionBackendError(operation, err)
	}
	now := c.clock.Now()
	if !refreshRequired(current, now, c.refreshBeforeExpiry) {
		return current, nil
	}
	if strings.TrimSpace(current.Tokens.RefreshToken) == "" {
		return nil, bffError(core.KindUnauthenticated, operation, 0, false)
	}
	tokens, err := c.exchangeRefresh(ctx, current.Tokens.RefreshToken)
	if err != nil {
		if errors.Is(err, core.ErrInvalidGrant) {
			if deleteErr := c.deleteInvalidGrantSession(ctx, lease, current); deleteErr != nil {
				return nil, errors.Join(err, deleteErr)
			}
		}
		return nil, err
	}
	next, err := c.rebuildRefreshedSession(ctx, current, tokens)
	if err != nil {
		return nil, err
	}
	if current.Version == ^uint64(0) {
		return nil, bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	next.Version = current.Version + 1
	next.UpdatedAt = c.clock.Now()
	if err := c.backend.CompareAndSwapWithLease(ctx, lease, current.ID, current.Version, next); err != nil {
		if errors.Is(err, session.ErrConflict) || errors.Is(err, session.ErrLeaseLost) {
			latest, getErr := c.backend.Get(ctx, current.ID)
			if getErr == nil && refreshWinnerChanged(current, latest) {
				return latest, nil
			}
			if getErr != nil {
				return nil, c.sessionBackendError(operation, getErr)
			}
		}
		return nil, c.sessionBackendError(operation, err)
	}
	return next, nil
}

func (c *Client) refreshCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), c.refreshLeaseTTL)
}

func (c *Client) deleteInvalidGrantSession(
	ctx context.Context,
	lease session.Lease,
	current *session.Session,
) error {
	const operation = "bff.refresh_delete"
	cleanupCtx, cancel := c.refreshCleanupContext(ctx)
	defer cancel()
	invalidRefreshToken := current.Tokens.RefreshToken
	for range maxInvalidGrantDeleteAttempts {
		err := c.backend.DeleteWithLease(cleanupCtx, lease, current.ID, current.Version)
		if err == nil || errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
			return nil
		}
		if !errors.Is(err, session.ErrConflict) {
			return c.sessionBackendError(operation, err)
		}
		latest, getErr := c.backend.Get(cleanupCtx, current.ID)
		if errors.Is(getErr, session.ErrNotFound) || errors.Is(getErr, session.ErrExpired) {
			return nil
		}
		if getErr != nil {
			return c.sessionBackendError(operation, getErr)
		}
		if !constantTimeEqual(latest.Tokens.RefreshToken, invalidRefreshToken) {
			return nil
		}
		current = latest
	}
	return c.sessionBackendError(operation, session.ErrConflict)
}

func (c *Client) waitForRefreshWinner(
	ctx context.Context,
	baseline *session.Session,
) (*session.Session, error) {
	const operation = "bff.refresh_wait"
	deadline := time.NewTimer(c.refreshLeaseTTL)
	defer deadline.Stop()
	pollEvery := 5 * time.Millisecond
	if c.refreshLeaseTTL < pollEvery {
		pollEvery = c.refreshLeaseTTL
	}
	if pollEvery <= 0 {
		return nil, bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	return c.waitForRefreshWinnerUntil(ctx, baseline, deadline.C, ticker.C)
}

func (c *Client) waitForRefreshWinnerUntil(
	ctx context.Context,
	baseline *session.Session,
	deadline <-chan time.Time,
	ticks <-chan time.Time,
) (*session.Session, error) {
	const operation = "bff.refresh_wait"
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		latest, err := c.backend.Get(ctx, baseline.ID)
		if err != nil {
			return nil, c.sessionBackendError(operation, err)
		}
		if refreshWinnerChanged(baseline, latest) || !refreshRequired(latest, c.clock.Now(), c.refreshBeforeExpiry) {
			return latest, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			latest, err := c.backend.Get(ctx, baseline.ID)
			if err != nil {
				return nil, c.sessionBackendError(operation, err)
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if refreshWinnerChanged(baseline, latest) ||
				!refreshRequired(latest, c.clock.Now(), c.refreshBeforeExpiry) {
				return latest, nil
			}
			return nil, bffError(core.KindSessionUnavailable, operation, 0, true)
		case <-ticks:
		}
	}
}

func refreshWinnerChanged(before, after *session.Session) bool {
	return before != nil && after != nil && after.ID == before.ID &&
		(after.Version != before.Version &&
			(!constantTimeEqual(after.Tokens.AccessToken, before.Tokens.AccessToken) ||
				!constantTimeEqual(after.Tokens.RefreshToken, before.Tokens.RefreshToken)))
}

func refreshRequired(item *session.Session, now time.Time, beforeExpiry time.Duration) bool {
	return item == nil || item.Tokens.AccessTokenExpiry.IsZero() ||
		item.Tokens.AccessTokenExpiry.Sub(now) <= beforeExpiry
}

func (c *Client) exchangeRefresh(
	ctx context.Context,
	refreshToken string,
) (tokens exchangedTokens, resultErr error) {
	const operation = "bff.exchange_refresh"
	started := c.clock.Now()
	defer func() { c.record(ctx, operation, resultErr, started) }()
	if ctx == nil || ctx.Err() != nil {
		if ctx != nil {
			return exchangedTokens{}, ctx.Err()
		}
		return exchangedTokens{}, bffError(core.KindProtocol, operation, 0, false)
	}
	if refreshToken == "" || refreshToken != strings.TrimSpace(refreshToken) {
		return exchangedTokens{}, bffError(core.KindUnauthenticated, operation, 0, false)
	}
	operationCtx, cancel := context.WithTimeout(ctx, c.tokenTimeout)
	defer cancel()
	secret, err := c.clientSecret.Secret(operationCtx)
	if contextErr := operationContextError(ctx, operationCtx, operation, 0); contextErr != nil {
		return exchangedTokens{}, contextErr
	}
	if err != nil {
		if contextErr := normalizedContextError(err); contextErr != nil {
			return exchangedTokens{}, contextErr
		}
		return exchangedTokens{}, bffError(core.KindInvalidConfig, operation, 0, false)
	}
	if secret == "" || secret != strings.TrimSpace(secret) {
		return exchangedTokens{}, bffError(core.KindInvalidConfig, operation, 0, false)
	}
	form := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"client_id": {c.clientID}, "client_secret": {secret},
	}
	request, err := http.NewRequestWithContext(
		operationCtx,
		http.MethodPost,
		c.core.Metadata().TokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, 0, false)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if contextErr := operationContextError(ctx, operationCtx, operation, 0); contextErr != nil {
			return exchangedTokens{}, contextErr
		}
		return exchangedTokens{}, bffError(core.KindIAMUnavailable, operation, 0, true)
	}
	receivedAt := c.clock.Now()
	defer response.Body.Close()
	body, bodyErr := readOAuthJSON(response)
	if bodyErr != nil {
		if contextErr := operationContextError(ctx, operationCtx, operation, response.StatusCode); contextErr != nil {
			return exchangedTokens{}, contextErr
		}
	}
	if response.StatusCode != http.StatusOK {
		var endpoint refreshTokenResponse
		if bodyErr == nil && decodeUniqueJSON(body, &endpoint) == nil {
			oauthError, present, fieldErr := decodeOAuthError(endpoint.Error)
			if fieldErr != nil {
				return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
			}
			if present {
				return exchangedTokens{}, oauthEndpointError(operation, response.StatusCode, oauthError)
			}
		}
		return exchangedTokens{}, statusOAuthError(operation, response.StatusCode)
	}
	if bodyErr != nil {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	var decoded refreshTokenResponse
	if decodeUniqueJSON(body, &decoded) != nil ||
		decoded.AccessToken == "" || decoded.AccessToken != strings.TrimSpace(decoded.AccessToken) ||
		decoded.TokenType != "Bearer" || decoded.ExpiresIn <= 0 ||
		decoded.ExpiresIn > math.MaxInt64/int64(time.Second) {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	_, errorPresent, err := decodeOAuthError(decoded.Error)
	if err != nil || errorPresent {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	rotated, err := optionalNonemptyString(decoded.RefreshToken)
	if err != nil {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	idToken, err := optionalNonemptyString(decoded.IDToken)
	if err != nil {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	scope, err := optionalString(decoded.Scope)
	if err != nil || (len(decoded.Scope) != 0 && !validScopeString(scope)) {
		return exchangedTokens{}, bffError(core.KindProtocol, operation, response.StatusCode, false)
	}
	return exchangedTokens{
		accessToken: decoded.AccessToken, tokenType: decoded.TokenType, refreshToken: rotated,
		idToken: idToken, expiresIn: decoded.ExpiresIn,
		expiresAt: receivedAt.Add(time.Duration(decoded.ExpiresIn) * time.Second), scope: scope,
	}, nil
}

func (c *Client) rebuildRefreshedSession(
	ctx context.Context,
	current *session.Session,
	tokens exchangedTokens,
) (*session.Session, error) {
	const operation = "bff.refresh_validate"
	accessAuth, err := c.core.VerifyAccessToken(ctx, tokens.accessToken)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(accessAuth.Audience, c.clientID) ||
		!constantTimeEqual(current.Auth.Subject, accessAuth.Subject) {
		return nil, bffError(core.KindUnauthenticated, operation, 0, false)
	}
	accessScope, accessGroups, err := verifiedClaimSources(tokens.accessToken, accessAuth)
	if err != nil {
		return nil, bffError(core.KindProtocol, operation, 0, false)
	}
	var idAuth core.AuthContext
	var idScope, idGroups []string
	if tokens.idToken != "" {
		idAuth, err = c.core.VerifyRefreshedIDToken(ctx, tokens.idToken)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(idAuth.Audience, c.clientID) || !constantTimeEqual(accessAuth.Subject, idAuth.Subject) {
			return nil, bffError(core.KindUnauthenticated, operation, 0, false)
		}
		idScope, idGroups, err = verifiedClaimSources(tokens.idToken, idAuth)
		if err != nil {
			return nil, bffError(core.KindProtocol, operation, 0, false)
		}
	}
	grantedScopes, err := reconcileScopes(tokens.scope, accessScope, idScope)
	if err != nil {
		return nil, err
	}
	if err := validateGrantedScopes(grantedScopes, c.scopes); err != nil {
		return nil, err
	}
	identity, err := c.loadUserInfo(ctx, tokens.accessToken)
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(accessAuth.Subject, identity.subject) {
		return nil, bffError(core.KindUnauthenticated, operation, 0, false)
	}
	auth := cloneAuthContext(accessAuth)
	auth.Scopes = append([]string(nil), grantedScopes...)
	if slices.Contains(grantedScopes, "profile") {
		if identity.usernameSet {
			auth.Username = identity.username
		}
		if identity.displaySet {
			auth.DisplayName = identity.displayName
		}
	} else {
		auth.Username, auth.DisplayName = "", ""
	}
	if slices.Contains(grantedScopes, "email") {
		if identity.emailSet {
			auth.Email = identity.email
		}
	} else {
		auth.Email = ""
	}
	if slices.Contains(grantedScopes, "groups") {
		var userInfoGroups []string
		if identity.groupsPresent {
			userInfoGroups = identity.groups
		}
		auth.Groups, err = reconcileGroups(accessGroups, idGroups, userInfoGroups)
		if err != nil {
			return nil, err
		}
	} else {
		auth.Groups = []string{}
	}
	next := cloneSessionState(current)
	next.Tokens = session.TokenSet{
		AccessToken: tokens.accessToken, TokenType: tokens.tokenType,
		RefreshToken: tokens.refreshToken, IDToken: tokens.idToken,
		AccessTokenExpiry: accessAuth.ExpiresAt,
		GrantedScopes:     append([]string(nil), grantedScopes...),
	}
	responseExpiry := tokens.expiresAt
	if responseExpiry.Before(next.Tokens.AccessTokenExpiry) {
		next.Tokens.AccessTokenExpiry = responseExpiry
	}
	if !next.Tokens.AccessTokenExpiry.After(c.clock.Now()) {
		return nil, bffError(core.KindUnauthenticated, operation, 0, false)
	}
	if next.Tokens.RefreshToken == "" {
		next.Tokens.RefreshToken = current.Tokens.RefreshToken
	}
	if next.Tokens.IDToken == "" {
		next.Tokens.IDToken = current.Tokens.IDToken
	}
	next.Auth = auth
	return next, nil
}

func cloneSessionState(item *session.Session) *session.Session {
	if item == nil {
		return nil
	}
	cloned := *item
	cloned.Tokens.GrantedScopes = slices.Clone(item.Tokens.GrantedScopes)
	cloned.Auth = cloneAuthContext(item.Auth)
	return &cloned
}

func (c *Client) sessionBackendError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
		return bffError(core.KindUnauthenticated, operation, 0, false)
	}
	return bffError(core.KindSessionUnavailable, operation, 0, true)
}
