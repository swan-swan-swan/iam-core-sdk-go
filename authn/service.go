package authn

import (
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/clock"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/nilcheck"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

const (
	defaultFlowTTL                 = 10 * time.Minute
	defaultSessionAbsoluteTTL      = 7 * 24 * time.Hour
	defaultSessionIdleTTL          = 8 * time.Hour
	defaultIdentityRecheckInterval = 30 * time.Second
	defaultRefreshBeforeExpiry     = 60 * time.Second
	defaultRefreshLockTTL          = 15 * time.Second
)

type Config struct {
	OIDC                         *oidc.Client
	Backend                      session.Backend
	RedirectURL                  string
	AllowedReturnToURLs          []string
	SessionCookie                http.Cookie
	FlowCookie                   http.Cookie
	FlowTTL                      time.Duration
	SessionAbsoluteTTL           time.Duration
	SessionIdleTTL               time.Duration
	IdentityRecheckInterval      time.Duration
	RefreshBeforeExpiry          time.Duration
	RefreshLockTTL               time.Duration
	AllowInsecureLocalCookie     bool
	LogoutRemoteFailureIsSuccess bool
	Clock                        Clock
	Random                       io.Reader
	Logger                       *slog.Logger
	Hooks                        observability.Hooks
}

type Clock interface {
	Now() time.Time
}

type Service struct {
	oidc                         *oidc.Client
	backend                      session.Backend
	redirectURL                  string
	allowedReturnToURLs          map[string]struct{}
	sessionCookie                http.Cookie
	flowCookie                   http.Cookie
	flowTTL                      time.Duration
	sessionAbsoluteTTL           time.Duration
	sessionIdleTTL               time.Duration
	identityRecheckInterval      time.Duration
	refreshBeforeExpiry          time.Duration
	refreshLockTTL               time.Duration
	allowInsecureLocalCookie     bool
	logoutRemoteFailureIsSuccess bool
	clock                        Clock
	random                       io.Reader
	randomMu                     sync.Mutex
	logger                       *slog.Logger
	hooks                        observability.Hooks
}

func New(config Config) (*Service, error) {
	if config.OIDC == nil || nilcheck.IsNil(config.Backend) {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	redirectURL, err := validateRedirectURL(config.RedirectURL)
	if err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	if !oidcRedirectMatches(config.OIDC, config.RedirectURL) {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	if redirectURL.Scheme == "http" && !isLocalURL(redirectURL) {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	config.FlowTTL, err = durationOrDefault(config.FlowTTL, defaultFlowTTL)
	if err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	config.SessionAbsoluteTTL, err = durationOrDefault(config.SessionAbsoluteTTL, defaultSessionAbsoluteTTL)
	if err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	config.SessionIdleTTL, err = durationOrDefault(config.SessionIdleTTL, defaultSessionIdleTTL)
	if err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	config.IdentityRecheckInterval, err = durationOrDefault(
		config.IdentityRecheckInterval,
		defaultIdentityRecheckInterval,
	)
	if err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	config.RefreshBeforeExpiry, err = durationOrDefault(config.RefreshBeforeExpiry, defaultRefreshBeforeExpiry)
	if err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	config.RefreshLockTTL, err = durationOrDefault(config.RefreshLockTTL, defaultRefreshLockTTL)
	if err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	sessionCookie, err := normalizeCookie(config.SessionCookie, "__Host-iam_core_session")
	if err != nil {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	flowCookie, err := normalizeCookie(config.FlowCookie, "__Host-iam_core_flow")
	if err != nil || sessionCookie.Name == flowCookie.Name {
		return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
	}
	if !sessionCookie.Secure || !flowCookie.Secure {
		if !config.AllowInsecureLocalCookie || !isLocalURL(redirectURL) {
			return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
		}
	}
	allowed := make(map[string]struct{}, len(config.AllowedReturnToURLs))
	for _, candidate := range config.AllowedReturnToURLs {
		if err := validateAllowedAbsoluteReturnTo(candidate); err != nil {
			return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
		}
		if _, exists := allowed[candidate]; exists {
			return nil, authError(sdkerr.KindInvalidConfig, "authn.configure")
		}
		allowed[candidate] = struct{}{}
	}
	if nilcheck.IsNil(config.Clock) {
		config.Clock = clock.Real{}
	}
	if nilcheck.IsNil(config.Random) {
		config.Random = rand.Reader
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if nilcheck.IsNil(config.Hooks) {
		config.Hooks = observability.Nop{}
	}
	return &Service{
		oidc:                         config.OIDC,
		backend:                      config.Backend,
		redirectURL:                  config.RedirectURL,
		allowedReturnToURLs:          allowed,
		sessionCookie:                sessionCookie,
		flowCookie:                   flowCookie,
		flowTTL:                      config.FlowTTL,
		sessionAbsoluteTTL:           config.SessionAbsoluteTTL,
		sessionIdleTTL:               config.SessionIdleTTL,
		identityRecheckInterval:      config.IdentityRecheckInterval,
		refreshBeforeExpiry:          config.RefreshBeforeExpiry,
		refreshLockTTL:               config.RefreshLockTTL,
		allowInsecureLocalCookie:     config.AllowInsecureLocalCookie,
		logoutRemoteFailureIsSuccess: config.LogoutRemoteFailureIsSuccess,
		clock:                        config.Clock,
		random:                       config.Random,
		logger:                       config.Logger,
		hooks:                        config.Hooks,
	}, nil
}

func oidcRedirectMatches(client *oidc.Client, expected string) bool {
	const validationState = "redirect-validation-state"
	const validationNonce = "redirect-validation-nonce"
	authorizationURL := client.AuthCodeURL(validationState, validationNonce)
	parsed, err := url.Parse(authorizationURL)
	if err != nil || parsed.Opaque != "" || parsed.Hostname() == "" {
		return false
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return false
	}
	redirectValues := values["redirect_uri"]
	return len(redirectValues) == 1 && redirectValues[0] == expected
}

func durationOrDefault(value, fallback time.Duration) (time.Duration, error) {
	if value < 0 {
		return 0, errors.New("negative duration")
	}
	if value == 0 {
		return fallback, nil
	}
	return value, nil
}

func validateRedirectURL(value string) (*url.URL, error) {
	if value == "" || value != strings.TrimSpace(value) || containsUnsafeURLCharacter(value) {
		return nil, errors.New("invalid redirect URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != value {
		return nil, errors.New("invalid redirect URL")
	}
	return parsed, nil
}

func authError(kind sdkerr.Kind, operation string) *sdkerr.Error {
	return sdkerr.New(kind, operation, 0, kind == sdkerr.KindIAMUnavailable ||
		kind == sdkerr.KindSessionUnavailable, nil)
}

func sanitizeOIDCError(err error, operation string) error {
	var typed *sdkerr.Error
	if errors.As(err, &typed) {
		switch typed.Kind {
		case sdkerr.KindIAMUnavailable:
			return authError(sdkerr.KindIAMUnavailable, operation)
		case sdkerr.KindSessionUnavailable:
			return authError(sdkerr.KindSessionUnavailable, operation)
		}
	}
	return authError(sdkerr.KindUnauthenticated, operation)
}

func (s *Service) observe(request *http.Request, operation, outcome string, started time.Time) {
	ctx := request.Context()
	s.hooks.Observe(ctx, observability.Event{
		Operation: operation,
		Outcome:   outcome,
		Duration:  time.Since(started),
	})
	s.logger.Info("iamcore operation",
		slog.String("operation", operation),
		slog.String("outcome", outcome),
		slog.Duration("duration", time.Since(started)),
	)
}

func writeAuthError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	var typed *sdkerr.Error
	if errors.As(err, &typed) {
		switch typed.Kind {
		case sdkerr.KindInvalidConfig, sdkerr.KindProtocol:
			status = http.StatusBadRequest
		case sdkerr.KindUnauthenticated, sdkerr.KindForbidden, sdkerr.KindCredentialConflict:
			status = http.StatusUnauthorized
		case sdkerr.KindSessionUnavailable, sdkerr.KindIAMUnavailable:
			status = http.StatusServiceUnavailable
		}
	}
	http.Error(w, http.StatusText(status), status)
}
