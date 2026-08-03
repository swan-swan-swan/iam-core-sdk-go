package bff

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/bff/session"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func (c *Client) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if err := c.completeCallback(w, request); err != nil {
			writeBFFError(w, err)
		}
	})
}

func (c *Client) completeCallback(w http.ResponseWriter, request *http.Request) (resultErr error) {
	const operation = "bff.callback"
	started := c.clock.Now()
	ctx := requestContext(request)
	if w != nil {
		c.clearCookie(w, c.flowCookie)
	}
	defer func() { c.record(ctx, operation, resultErr, started) }()
	if w == nil || request == nil || request.Method != http.MethodGet {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	flowID, err := oneCookieValue(request, c.flowCookie.Name)
	if err != nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	flow, err := c.backend.ConsumeFlow(request.Context(), flowID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
			return bffError(core.KindProtocol, operation, 0, false)
		}
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	if !c.validConsumedFlow(flow, flowID, c.clock.Now()) {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	stateValues := query["state"]
	if len(stateValues) != 1 || stateValues[0] == "" {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	if !constantTimeEqual(stateValues[0], flow.State) {
		return bffError(core.KindUnauthenticated, operation, 0, false)
	}
	if errorValues, present := query["error"]; present {
		if len(errorValues) != 1 || errorValues[0] == "" || len(query["code"]) != 0 {
			return bffError(core.KindProtocol, operation, 0, false)
		}
		return oauthEndpointError(operation, 0, errorValues[0])
	}
	codeValues := query["code"]
	if len(codeValues) != 1 || codeValues[0] == "" || codeValues[0] != strings.TrimSpace(codeValues[0]) {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	tokens, err := c.exchange(request.Context(), codeValues[0], flow.CodeVerifier)
	if err != nil {
		return err
	}
	idAuth, err := c.core.VerifyIDToken(request.Context(), tokens.idToken, flow.Nonce)
	if err != nil {
		return err
	}
	accessAuth, err := c.core.VerifyAccessToken(request.Context(), tokens.accessToken)
	if err != nil {
		return err
	}
	if !slices.Contains(accessAuth.Audience, c.clientID) || !slices.Contains(idAuth.Audience, c.clientID) ||
		!constantTimeEqual(accessAuth.Subject, idAuth.Subject) {
		return bffError(core.KindUnauthenticated, operation, 0, false)
	}
	accessScope, accessGroups, err := verifiedClaimSources(tokens.accessToken, accessAuth)
	if err != nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	idScope, idGroups, err := verifiedClaimSources(tokens.idToken, idAuth)
	if err != nil {
		return bffError(core.KindProtocol, operation, 0, false)
	}
	grantedScopes, err := reconcileScopes(tokens.scope, accessScope, idScope)
	if err != nil {
		return err
	}
	if err := validateGrantedScopes(grantedScopes, c.scopes); err != nil {
		return err
	}
	identity, err := c.loadUserInfo(request.Context(), tokens.accessToken)
	if err != nil {
		return err
	}
	if !constantTimeEqual(accessAuth.Subject, identity.subject) {
		return bffError(core.KindUnauthenticated, operation, 0, false)
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
		auth.Username = ""
		auth.DisplayName = ""
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
			return err
		}
	} else {
		auth.Groups = []string{}
	}
	sessionID, err := c.randomID()
	if err != nil {
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	now := c.clock.Now()
	expiresAt := now.Add(c.sessionAbsoluteTTL)
	idleExpiresAt := now.Add(c.sessionIdleTTL)
	if !expiresAt.After(now) || !idleExpiresAt.After(now) {
		return bffError(core.KindInvalidConfig, operation, 0, false)
	}
	created := &session.Session{
		ID: sessionID, Version: 1,
		Tokens: session.TokenSet{
			AccessToken: tokens.accessToken, TokenType: tokens.tokenType, RefreshToken: tokens.refreshToken,
			IDToken: tokens.idToken, AccessTokenExpiry: accessAuth.ExpiresAt,
			GrantedScopes: append([]string(nil), grantedScopes...),
		},
		Auth: auth, CreatedAt: now, UpdatedAt: now, LastSeenAt: now,
		ExpiresAt: expiresAt, IdleExpiresAt: idleExpiresAt,
	}
	if err := c.backend.Create(request.Context(), created); err != nil {
		return bffError(core.KindSessionUnavailable, operation, 0, true)
	}
	if err := c.setCookie(w, c.sessionCookie, sessionID); err != nil {
		return bffError(core.KindInvalidConfig, operation, 0, false)
	}
	redirectWithoutBody(w, flow.ReturnTo)
	return nil
}

func (c *Client) validConsumedFlow(flow *session.Flow, expectedID string, now time.Time) bool {
	return flow != nil && constantTimeEqual(flow.ID, expectedID) && validCookieValue(flow.ID) &&
		validCookieValue(flow.State) && validCookieValue(flow.Nonce) && validPKCEVerifier(flow.CodeVerifier) &&
		constantTimeEqual(flow.ClientID, c.clientID) && constantTimeEqual(flow.RedirectURL, c.redirectURL) &&
		c.validReturnTo(flow.ReturnTo) && !flow.CreatedAt.IsZero() && !flow.CreatedAt.After(now) && flow.ExpiresAt.After(now)
}

func constantTimeEqual(left, right string) bool {
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}

func verifiedClaimSources(raw string, verified core.AuthContext) (scope, groups []string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, errors.New("invalid token")
	}
	var claims map[string]json.RawMessage
	if decodeUniqueJSON(payload, &claims) != nil {
		return nil, nil, errors.New("invalid token")
	}
	if rawScope, present := claims["scope"]; present {
		var value string
		if bytes.Equal(bytes.TrimSpace(rawScope), []byte("null")) || json.Unmarshal(rawScope, &value) != nil ||
			!validScopeString(value) {
			return nil, nil, errors.New("invalid scope")
		}
		scope = append([]string{}, verified.Scopes...)
	}
	if rawGroups, present := claims["groups"]; present {
		var values []string
		if json.Unmarshal(rawGroups, &values) != nil || values == nil {
			return nil, nil, errors.New("invalid groups")
		}
		groups = append([]string{}, verified.Groups...)
	}
	return scope, groups, nil
}

func cloneAuthContext(auth core.AuthContext) core.AuthContext {
	auth.Audience = append([]string(nil), auth.Audience...)
	auth.Scopes = append([]string(nil), auth.Scopes...)
	auth.Groups = append([]string(nil), auth.Groups...)
	return auth
}
