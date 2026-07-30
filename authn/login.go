package authn

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/random"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

func (s *Service) BeginLogin(w http.ResponseWriter, request *http.Request, returnTo string) (resultErr error) {
	const operation = "authn.login"
	started := time.Now()
	defer func() {
		outcome := "success"
		if resultErr != nil {
			outcome = "error"
		}
		s.observe(request, operation, outcome, started)
	}()
	if w == nil || request == nil || !s.validReturnTo(returnTo) {
		return authError(sdkerr.KindProtocol, operation)
	}
	if err := s.ensureRequestCookieSecurity(request); err != nil {
		return authError(sdkerr.KindProtocol, operation)
	}
	flowID, err := s.randomID()
	if err != nil {
		return authError(sdkerr.KindSessionUnavailable, operation)
	}
	state, err := s.randomID()
	if err != nil {
		return authError(sdkerr.KindSessionUnavailable, operation)
	}
	nonce, err := s.randomID()
	if err != nil {
		return authError(sdkerr.KindSessionUnavailable, operation)
	}
	authorizationURL := s.oidc.AuthCodeURL(state, nonce)
	if !validAuthorizationURL(authorizationURL) {
		return authError(sdkerr.KindIAMUnavailable, operation)
	}
	now := s.clock.Now()
	expiresAt := now.Add(s.flowTTL)
	if !expiresAt.After(now) {
		return authError(sdkerr.KindInvalidConfig, operation)
	}
	flow := &session.Flow{
		ID:        flowID,
		State:     state,
		Nonce:     nonce,
		ReturnTo:  returnTo,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	if err := s.backend.PutFlow(request.Context(), flow); err != nil {
		return authError(sdkerr.KindSessionUnavailable, operation)
	}
	if err := s.setCookie(w, s.flowCookie, flowID); err != nil {
		return authError(sdkerr.KindInvalidConfig, operation)
	}
	redirectWithoutBody(w, authorizationURL)
	return nil
}

func (s *Service) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		values, err := url.ParseQuery(request.URL.RawQuery)
		returnToValues := values["return_to"]
		if err != nil || len(returnToValues) != 1 || returnToValues[0] == "" {
			writeAuthError(w, authError(sdkerr.KindProtocol, "authn.login"))
			return
		}
		if err := s.BeginLogin(w, request, returnToValues[0]); err != nil {
			writeAuthError(w, err)
		}
	})
}

func (s *Service) randomID() (string, error) {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	return random.ID(s.random, 32)
}

func (s *Service) validReturnTo(value string) bool {
	if _, allowed := s.allowedReturnToURLs[value]; allowed {
		return validateAllowedAbsoluteReturnTo(value) == nil
	}
	return validateRelativeReturnTo(value) == nil
}

func validateRelativeReturnTo(value string) error {
	if value == "" || value != strings.TrimSpace(value) || containsUnsafeURLCharacter(value) {
		return errors.New("invalid return URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Host != "" || parsed.Scheme != "" || parsed.Path == "" ||
		!strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") ||
		parsed.String() != value {
		return errors.New("invalid return URL")
	}
	if err := rejectAmbiguousEncoding(value); err != nil {
		return err
	}
	return nil
}

func validateAllowedAbsoluteReturnTo(value string) error {
	if value == "" || value != strings.TrimSpace(value) || containsUnsafeURLCharacter(value) {
		return errors.New("invalid allowed return URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.String() != value {
		return errors.New("invalid allowed return URL")
	}
	if parsed.Scheme == "http" && !isLocalHostname(parsed.Hostname()) {
		return errors.New("invalid allowed return URL")
	}
	return rejectAmbiguousEncoding(value)
}

func rejectAmbiguousEncoding(value string) error {
	current := value
	for range 6 {
		if containsUnsafeURLCharacter(current) {
			return errors.New("unsafe encoded URL")
		}
		decoded, err := url.PathUnescape(current)
		if err != nil {
			return errors.New("malformed encoded URL")
		}
		if decoded == current {
			return nil
		}
		current = decoded
		parsed, err := url.Parse(current)
		if err != nil || (parsed.Host != "" && strings.HasPrefix(current, "//")) {
			return errors.New("ambiguous encoded URL")
		}
	}
	return errors.New("excessively encoded URL")
}

func containsUnsafeURLCharacter(value string) bool {
	if !utf8.ValidString(value) || strings.ContainsRune(value, '\\') {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func validAuthorizationURL(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || containsUnsafeURLCharacter(value) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Opaque == "" && parsed.User == nil &&
		parsed.Hostname() != "" && (parsed.Scheme == "https" || parsed.Scheme == "http")
}

func redirectWithoutBody(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}
