package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

type CredentialSource string

const (
	CredentialSession CredentialSource = "session"
	CredentialBearer  CredentialSource = "bearer"
)

type Credential struct {
	Source      CredentialSource
	SessionID   string
	AccessToken string
	Identity    oidc.Identity
}

func (s *Service) Authenticate(request *http.Request) (credential Credential, resultErr error) {
	const operation = "authn.authenticate"
	if request == nil {
		return Credential{}, authError(sdkerr.KindUnauthenticated, operation)
	}
	started := time.Now()
	defer func() {
		outcome := "success"
		if resultErr != nil {
			outcome = "error"
		}
		s.observe(request, operation, outcome, started)
	}()

	sessionID, hasCookie, err := optionalSessionCookie(request, s.sessionCookie.Name)
	if err != nil {
		return Credential{}, authError(sdkerr.KindUnauthenticated, operation)
	}
	bearerToken, hasBearer, err := bearerCredential(request.Header)
	if err != nil {
		return Credential{}, authError(sdkerr.KindUnauthenticated, operation)
	}
	if !hasCookie && !hasBearer {
		return Credential{}, authError(sdkerr.KindUnauthenticated, operation)
	}
	if !hasCookie {
		identity, err := s.oidc.UserInfo(request.Context(), bearerToken)
		if err != nil {
			return Credential{}, authenticationOIDCError(err, operation)
		}
		return Credential{
			Source:      CredentialBearer,
			AccessToken: bearerToken,
			Identity:    cloneIdentity(identity),
		}, nil
	}

	item, err := s.backend.Get(request.Context(), sessionID)
	if err != nil {
		return Credential{}, authenticateSessionReadError(err, operation)
	}
	now := s.clock.Now()
	if !validSessionForUse(item, sessionID, now) {
		return Credential{}, authError(sdkerr.KindUnauthenticated, operation)
	}
	if hasBearer && !constantTimeEqual(bearerToken, item.TokenSet.AccessToken) {
		return Credential{}, authError(sdkerr.KindCredentialConflict, operation)
	}
	if !accessTokenFresh(item, now, s.refreshBeforeExpiry) {
		item, err = s.refreshSession(request.Context(), sessionID, false)
		if err != nil {
			return Credential{}, err
		}
		now = s.clock.Now()
	}

	var onlineIdentity *oidc.Identity
	validationAt := time.Time{}
	if identityRecheckDue(item.IdentityValidatedAt, now, s.identityRecheckInterval) {
		identity, userInfoErr := s.oidc.UserInfo(request.Context(), item.TokenSet.AccessToken)
		if userInfoErr != nil {
			return Credential{}, authenticationOIDCError(userInfoErr, operation)
		}
		if !constantTimeEqual(identity.Subject, item.Identity.Subject) {
			return Credential{}, authError(sdkerr.KindUnauthenticated, operation)
		}
		copied := cloneIdentity(identity)
		onlineIdentity = &copied
		validationAt = now
	}
	item, err = s.touchAuthenticatedSession(
		request.Context(),
		item,
		now,
		onlineIdentity,
		validationAt,
	)
	if err != nil {
		return Credential{}, err
	}
	return Credential{
		Source:      CredentialSession,
		SessionID:   item.ID,
		AccessToken: item.TokenSet.AccessToken,
		Identity:    cloneIdentity(item.Identity),
	}, nil
}

func optionalSessionCookie(request *http.Request, name string) (string, bool, error) {
	cookies := request.CookiesNamed(name)
	if len(cookies) == 0 {
		return "", false, nil
	}
	if len(cookies) != 1 || !validCookieValue(cookies[0].Value) {
		return "", false, errors.New("invalid session cookie")
	}
	return cookies[0].Value, true, nil
}

func bearerCredential(header http.Header) (string, bool, error) {
	values := header.Values("Authorization")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || strings.ContainsRune(values[0], ',') ||
		!strings.HasPrefix(values[0], "Bearer ") {
		return "", false, errors.New("ambiguous authorization")
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || !utf8.ValidString(token) {
		return "", false, errors.New("invalid bearer token")
	}
	for _, character := range token {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", false, errors.New("invalid bearer token")
		}
	}
	return token, true, nil
}

func (s *Service) touchAuthenticatedSession(
	ctx context.Context,
	current *session.Session,
	now time.Time,
	onlineIdentity *oidc.Identity,
	validationAt time.Time,
) (*session.Session, error) {
	const operation = "authn.authenticate"
	if current == nil || current.Version == ^uint64(0) {
		return nil, authError(sdkerr.KindSessionUnavailable, operation)
	}
	next := cloneAuthSession(current)
	next.Version = current.Version + 1
	if now.After(next.LastSeenAt) {
		next.LastSeenAt = now
	}
	next.IdleExpiresAt = sessionTouchDeadline(
		next.LastSeenAt,
		s.sessionIdleTTL,
		next.ExpiresAt,
		next.IdleExpiresAt,
	)
	if now.After(next.UpdatedAt) {
		next.UpdatedAt = now
	}
	if onlineIdentity != nil {
		next.Identity = cloneIdentity(*onlineIdentity)
		next.GrantedScopes = append([]string(nil), onlineIdentity.Scopes...)
		if validationAt.After(next.IdentityValidatedAt) {
			next.IdentityValidatedAt = validationAt
		}
	}

	err := s.backend.CompareAndSwap(ctx, current.ID, current.Version, next)
	if err == nil {
		return cloneAuthSession(next), nil
	}
	if errors.Is(err, session.ErrVersionConflict) {
		winner, getErr := s.backend.Get(ctx, current.ID)
		if getErr == nil && safeAuthenticationWinner(
			winner,
			current.ID,
			current.Version,
			now,
			next.LastSeenAt,
			next.IdleExpiresAt,
			current.Identity.Subject,
			onlineIdentity,
			validationAt,
		) {
			return cloneAuthSession(winner), nil
		}
	}
	if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
		return nil, authError(sdkerr.KindUnauthenticated, operation)
	}
	return nil, authError(sdkerr.KindSessionUnavailable, operation)
}

func safeAuthenticationWinner(
	winner *session.Session,
	sessionID string,
	priorVersion uint64,
	now time.Time,
	requiredLastSeen time.Time,
	requiredIdleExpiry time.Time,
	requiredSubject string,
	onlineIdentity *oidc.Identity,
	validationAt time.Time,
) bool {
	if winner == nil || winner.Version <= priorVersion ||
		!validSessionForUse(winner, sessionID, now) ||
		winner.LastSeenAt.Before(requiredLastSeen) ||
		winner.IdleExpiresAt.Before(requiredIdleExpiry) ||
		!constantTimeEqual(winner.Identity.Subject, requiredSubject) {
		return false
	}
	return onlineIdentity == nil ||
		(!winner.IdentityValidatedAt.Before(validationAt) &&
			constantTimeEqual(winner.Identity.Subject, onlineIdentity.Subject))
}

func sessionTouchDeadline(
	lastSeen time.Time,
	idleTTL time.Duration,
	absoluteExpiry time.Time,
	currentIdleExpiry time.Time,
) time.Time {
	candidate, ok := addDurationSafe(lastSeen, idleTTL)
	if !ok || candidate.After(absoluteExpiry) {
		candidate = absoluteExpiry
	}
	if currentIdleExpiry.After(candidate) {
		candidate = currentIdleExpiry
	}
	if candidate.After(absoluteExpiry) {
		return absoluteExpiry
	}
	return candidate
}

func identityRecheckDue(validatedAt, now time.Time, interval time.Duration) bool {
	if validatedAt.IsZero() {
		return true
	}
	deadline, ok := addDurationSafe(validatedAt, interval)
	return !ok || !deadline.After(now)
}

func authenticateSessionReadError(err error, operation string) error {
	if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
		return authError(sdkerr.KindUnauthenticated, operation)
	}
	return authError(sdkerr.KindSessionUnavailable, operation)
}

func authenticationOIDCError(err error, operation string) error {
	var typed *sdkerr.Error
	if errors.As(err, &typed) &&
		(typed.Kind == sdkerr.KindUnauthenticated || typed.Kind == sdkerr.KindForbidden) {
		return authError(sdkerr.KindUnauthenticated, operation)
	}
	return authError(sdkerr.KindIAMUnavailable, operation)
}

func cloneIdentity(identity oidc.Identity) oidc.Identity {
	copied := identity
	copied.Roles = append([]string(nil), identity.Roles...)
	copied.Scopes = append([]string(nil), identity.Scopes...)
	if identity.ExtraClaims != nil {
		copied.ExtraClaims = make(map[string]json.RawMessage, len(identity.ExtraClaims))
		for name, raw := range identity.ExtraClaims {
			copied.ExtraClaims[name] = append(json.RawMessage(nil), raw...)
		}
	}
	return copied
}
