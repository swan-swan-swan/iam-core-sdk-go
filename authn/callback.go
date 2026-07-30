package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

func (s *Service) CompleteCallback(
	w http.ResponseWriter,
	request *http.Request,
) (created *session.Session, resultErr error) {
	const operation = "authn.callback"
	started := time.Now()
	if w != nil {
		s.clearCookie(w, s.flowCookie)
	}
	defer func() {
		outcome := "success"
		if resultErr != nil {
			outcome = "error"
		}
		s.observe(request, operation, outcome, started)
	}()
	if w == nil || request == nil {
		return nil, authError(sdkerr.KindProtocol, operation)
	}
	if err := s.ensureRequestCookieSecurity(request); err != nil {
		return nil, authError(sdkerr.KindProtocol, operation)
	}
	flowID, err := oneCookieValue(request, s.flowCookie.Name)
	if err != nil {
		return nil, authError(sdkerr.KindProtocol, operation)
	}
	flow, err := s.backend.ConsumeFlow(request.Context(), flowID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
			return nil, authError(sdkerr.KindProtocol, operation)
		}
		return nil, authError(sdkerr.KindSessionUnavailable, operation)
	}
	if !validConsumedFlow(flow, flowID, s.clock.Now(), s) {
		return nil, authError(sdkerr.KindProtocol, operation)
	}

	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, authError(sdkerr.KindProtocol, operation)
	}
	stateValues := values["state"]
	if len(stateValues) != 1 || stateValues[0] == "" {
		return nil, authError(sdkerr.KindProtocol, operation)
	}
	if !constantTimeEqual(stateValues[0], flow.State) {
		return nil, authError(sdkerr.KindUnauthenticated, operation)
	}
	errorValues, errorPresent := values["error"]
	if errorPresent {
		if len(errorValues) != 1 || errorValues[0] == "" {
			return nil, authError(sdkerr.KindProtocol, operation)
		}
		return nil, authError(sdkerr.KindUnauthenticated, operation)
	}
	codeValues := values["code"]
	if len(codeValues) != 1 || codeValues[0] == "" {
		return nil, authError(sdkerr.KindProtocol, operation)
	}

	tokens, err := s.oidc.Exchange(request.Context(), codeValues[0])
	if err != nil {
		return nil, sanitizeOIDCError(err, operation)
	}
	if tokens.IDToken == "" {
		return nil, authError(sdkerr.KindUnauthenticated, operation)
	}
	claims, err := s.oidc.VerifyIDToken(request.Context(), tokens.IDToken, flow.Nonce)
	if err != nil {
		return nil, sanitizeOIDCError(err, operation)
	}
	identity, err := s.oidc.UserInfo(request.Context(), tokens.AccessToken)
	if err != nil {
		return nil, sanitizeOIDCError(err, operation)
	}
	if !constantTimeEqual(claims.Subject, identity.Subject) {
		return nil, authError(sdkerr.KindUnauthenticated, operation)
	}
	sessionID, err := s.randomID()
	if err != nil {
		return nil, authError(sdkerr.KindSessionUnavailable, operation)
	}
	now := s.clock.Now()
	expiresAt := now.Add(s.sessionAbsoluteTTL)
	idleExpiresAt := now.Add(s.sessionIdleTTL)
	if !expiresAt.After(now) || !idleExpiresAt.After(now) {
		return nil, authError(sdkerr.KindInvalidConfig, operation)
	}
	created = &session.Session{
		ID:                  sessionID,
		Version:             1,
		TokenSet:            tokens,
		Identity:            identity,
		GrantedScopes:       append([]string(nil), identity.Scopes...),
		CreatedAt:           now,
		UpdatedAt:           now,
		LastSeenAt:          now,
		ExpiresAt:           expiresAt,
		IdleExpiresAt:       idleExpiresAt,
		IdentityValidatedAt: now,
	}
	if err := s.backend.Create(request.Context(), created); err != nil {
		return nil, authError(sdkerr.KindSessionUnavailable, operation)
	}
	if err := s.setCookie(w, s.sessionCookie, sessionID); err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, operation)
	}
	redirectWithoutBody(w, flow.ReturnTo)
	return created, nil
}

func (s *Service) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if _, err := s.CompleteCallback(w, request); err != nil {
			writeAuthError(w, err)
		}
	})
}

func oneCookieValue(request *http.Request, name string) (string, error) {
	cookies := request.CookiesNamed(name)
	if len(cookies) != 1 || !validCookieValue(cookies[0].Value) {
		return "", errors.New("invalid cookie")
	}
	return cookies[0].Value, nil
}

func validConsumedFlow(flow *session.Flow, flowID string, now time.Time, service *Service) bool {
	return flow != nil && constantTimeEqual(flow.ID, flowID) &&
		flow.State != "" && flow.Nonce != "" && service.validReturnTo(flow.ReturnTo) &&
		!flow.CreatedAt.IsZero() && flow.ExpiresAt.After(now) && !flow.CreatedAt.After(now)
}

func constantTimeEqual(left, right string) bool {
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}
