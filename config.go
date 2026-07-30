package iamcore

import (
	"context"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/middleware"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

const (
	defaultDiscoveryJWKSTimeout = 5 * time.Second
	defaultTokenUserInfoTimeout = 10 * time.Second
	defaultPDPTimeout           = 3 * time.Second
	defaultRefreshLockTimeout   = 15 * time.Second
)

var defaultScopes = []string{"openid", "profile", "email", "roles"}

// SessionConfig configures browser flows and server-side sessions.
type SessionConfig struct {
	Backend                      session.Backend
	SessionCookie                http.Cookie
	FlowCookie                   http.Cookie
	FlowTTL                      time.Duration
	AbsoluteTTL                  time.Duration
	IdleTTL                      time.Duration
	IdentityRecheckInterval      time.Duration
	RefreshBeforeExpiry          time.Duration
	AllowedReturnToURLs          []string
	AllowInsecureLocalCookie     bool
	LogoutRemoteFailureIsSuccess bool
}

// TimeoutConfig bounds each independent remote or coordination operation.
type TimeoutConfig struct {
	DiscoveryJWKS time.Duration
	TokenUserInfo time.Duration
	PDP           time.Duration
	RefreshLock   time.Duration
}

// Config composes OIDC, authentication, authorization, and HTTP middleware.
type Config struct {
	IssuerURL            string
	ClientID             string
	ClientSecretProvider oidc.SecretProvider
	RedirectURL          string
	Scopes               []string
	HTTPClient           *http.Client
	Session              SessionConfig
	Timeouts             TimeoutConfig
	Logger               *slog.Logger
	Hooks                Hooks
	ErrorResponder       middleware.ErrorResponder
}

// ClientSecretProvider supplies the confidential OIDC client secret.
type ClientSecretProvider = oidc.SecretProvider

// StaticSecret returns a secret provider for a fixed value.
func StaticSecret(value string) ClientSecretProvider {
	return oidc.StaticSecret(value)
}

func validateRootConfig(ctx context.Context, config Config) error {
	if ctx == nil ||
		strings.TrimSpace(config.IssuerURL) == "" ||
		strings.TrimSpace(config.ClientID) == "" ||
		nilInterface(config.ClientSecretProvider) ||
		strings.TrimSpace(config.RedirectURL) == "" ||
		nilInterface(config.Session.Backend) {
		return rootConfigurationError()
	}
	if config.Timeouts.DiscoveryJWKS < 0 ||
		config.Timeouts.TokenUserInfo < 0 ||
		config.Timeouts.PDP < 0 ||
		config.Timeouts.RefreshLock < 0 ||
		config.Session.FlowTTL < 0 ||
		config.Session.AbsoluteTTL < 0 ||
		config.Session.IdleTTL < 0 ||
		config.Session.IdentityRecheckInterval < 0 ||
		config.Session.RefreshBeforeExpiry < 0 {
		return rootConfigurationError()
	}
	if len(config.Scopes) != 0 && !containsOpenID(config.Scopes) {
		return rootConfigurationError()
	}
	return nil
}

func containsOpenID(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "openid" {
			return true
		}
	}
	return false
}

func resolvedScopes(configured []string) []string {
	if len(configured) == 0 {
		return append([]string(nil), defaultScopes...)
	}
	return append([]string(nil), configured...)
}

func resolvedTimeouts(configured TimeoutConfig) TimeoutConfig {
	return TimeoutConfig{
		DiscoveryJWKS: durationOrDefault(configured.DiscoveryJWKS, defaultDiscoveryJWKSTimeout),
		TokenUserInfo: durationOrDefault(configured.TokenUserInfo, defaultTokenUserInfoTimeout),
		PDP:           durationOrDefault(configured.PDP, defaultPDPTimeout),
		RefreshLock:   durationOrDefault(configured.RefreshLock, defaultRefreshLockTimeout),
	}
}

func durationOrDefault(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

func rootConfigurationError() *sdkerr.Error {
	return sdkerr.New(sdkerr.KindInvalidConfig, "iamcore.configure", 0, false, nil)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
