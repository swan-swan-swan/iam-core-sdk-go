package httpauthz

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/internal/nilcheck"
)

const (
	serviceAuthenticateOperation = "httpauthz.service.authenticate"
	serviceRequireOperation      = "httpauthz.service.require"
)

// SessionResolver detects and resolves server-side Session credentials.
// SessionPresent must report raw platform-credential presence independently
// of validity: a malformed-but-present Session Cookie returns present=true
// together with its sanitized parsing error. This lets Bearer plus Session
// fail as a credential conflict before either credential is parsed.
type SessionResolver interface {
	SessionPresent(*http.Request) (bool, error)
	ResolveSession(*http.Request) (core.Credential, bool, error)
}

// Authorizer obtains one policy decision for a validated credential.
type Authorizer interface {
	Decide(context.Context, core.TokenSource, Route) (Decision, error)
}

// Config supplies the mandatory verifier and PDP plus optional Session and
// response extensions.
type Config struct {
	Verifier  core.AccessTokenVerifier
	PDP       Authorizer
	Sessions  SessionResolver
	Responder ErrorResponder
	Observer  core.Observer
	Logger    *slog.Logger
}

// Service constructs fail-closed net/http authentication and authorization
// handlers.
type Service struct {
	verifier  core.AccessTokenVerifier
	pdp       Authorizer
	sessions  SessionResolver
	responder ErrorResponder
	observer  core.Observer
	logger    *slog.Logger
}

// New validates all collaborators before returning a middleware service.
func New(cfg Config) (*Service, error) {
	if nilcheck.IsNil(cfg.Verifier) || nilcheck.IsNil(cfg.PDP) ||
		(cfg.Sessions != nil && nilcheck.IsNil(cfg.Sessions)) ||
		(cfg.Responder != nil && nilcheck.IsNil(cfg.Responder)) ||
		(cfg.Observer != nil && nilcheck.IsNil(cfg.Observer)) {
		return nil, middlewareConfigurationError()
	}
	responder := cfg.Responder
	if responder == nil {
		responder = defaultErrorResponder{}
	}
	observer := cfg.Observer
	if observer == nil {
		observer = core.NopObserver{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{
		verifier: cfg.Verifier, pdp: cfg.PDP, sessions: cfg.Sessions,
		responder: responder, observer: observer, logger: logger,
	}, nil
}

// Authenticate constructs middleware that validates exactly one request
// credential and adds authentication context.
func (s *Service) Authenticate(next http.Handler) (http.Handler, error) {
	if s == nil || nilcheck.IsNil(next) {
		return nil, middlewareConfigurationError()
	}
	return s.authenticateHandler(next), nil
}

// Require constructs middleware that additionally obtains exactly one PDP
// decision for a compiled route.
func (s *Service) Require(route Route, next http.Handler) (http.Handler, error) {
	if s == nil || !validRoute(route) || nilcheck.IsNil(next) {
		return nil, middlewareConfigurationError()
	}
	return s.requireHandler(route, next), nil
}

func middlewareConfigurationError() *core.Error {
	return core.NewError(core.KindInvalidConfig, configureOperation, 0, false, nil)
}

func (s *Service) record(ctx context.Context, operation, outcome string, source core.CredentialSource, started time.Time) {
	if ctx == nil {
		ctx = context.Background()
	}
	duration := time.Since(started)
	event := core.Event{
		Operation: operation, Outcome: outcome, CredentialSource: string(source), Duration: duration,
	}
	s.observer.Observe(ctx, event)
	s.logger.Info("iamcore service operation",
		slog.String("operation", operation),
		slog.String("outcome", outcome),
		slog.String("credential_source", string(source)),
		slog.Duration("duration", duration),
	)
}

func serviceOutcome(err error) string {
	var typed *core.Error
	if errors.As(err, &typed) && typed != nil {
		switch typed.Kind {
		case core.KindUnauthenticated, core.KindCredentialConflict:
			return "unauthenticated"
		case core.KindForbidden:
			return "forbidden"
		case core.KindIAMUnavailable, core.KindSessionUnavailable:
			return "unavailable"
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "unavailable"
	}
	return "error"
}
