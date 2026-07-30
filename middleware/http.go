// Package middleware provides fail-closed net/http authentication and
// authorization middleware.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/authn"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/authz"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/sdkerr"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/session"
)

const decisionIDHeader = "X-IAM-Decision-ID"

type contextKey uint8

const (
	identityContextKey contextKey = iota
	credentialSourceContextKey
	decisionContextKey
)

// Authenticator resolves one request credential and can force-refresh a
// session after a PDP reports that its access token is stale.
type Authenticator interface {
	Authenticate(*http.Request) (authn.Credential, error)
	ForceRefresh(context.Context, string) (*session.Session, error)
}

// Authorizer asks IAM for one fresh permission decision.
type Authorizer interface {
	Decide(context.Context, string, authz.Permission) (authz.Decision, error)
}

type options struct {
	responder ErrorResponder
	hooks     observability.Hooks
	logger    *slog.Logger
}

// Option configures middleware observability or error handling.
type Option func(*options)

// WithErrorResponder installs the caller's response extension.
func WithErrorResponder(responder ErrorResponder) Option {
	return func(config *options) {
		config.responder = responder
	}
}

// WithHooks installs low-cardinality middleware observations.
func WithHooks(hooks observability.Hooks) Option {
	return func(config *options) {
		config.hooks = hooks
	}
}

// WithLogger installs a structured middleware logger.
func WithLogger(logger *slog.Logger) Option {
	return func(config *options) {
		config.logger = logger
	}
}

// IdentityFromContext returns a defensive copy of the authenticated identity.
func IdentityFromContext(ctx context.Context) (oidc.Identity, bool) {
	if ctx == nil {
		return oidc.Identity{}, false
	}
	identity, ok := ctx.Value(identityContextKey).(oidc.Identity)
	if !ok {
		return oidc.Identity{}, false
	}
	return cloneIdentity(identity), true
}

// CredentialSourceFromContext reports whether authentication used a session
// or a bearer credential.
func CredentialSourceFromContext(ctx context.Context) (authn.CredentialSource, bool) {
	if ctx == nil {
		return "", false
	}
	source, ok := ctx.Value(credentialSourceContextKey).(authn.CredentialSource)
	return source, ok
}

// DecisionFromContext returns the permission decision associated with a
// request, including denied requests passed to a custom ErrorResponder.
func DecisionFromContext(ctx context.Context) (authz.Decision, bool) {
	if ctx == nil {
		return authz.Decision{}, false
	}
	decision, ok := ctx.Value(decisionContextKey).(authz.Decision)
	return decision, ok
}

// Authenticate verifies a credential, stores its identity and source in the
// request Context, and invokes next.
func Authenticate(authenticator Authenticator, optionValues ...Option) func(http.Handler) http.Handler {
	config := resolveOptions(optionValues)
	invalidAuthenticator := isNil(authenticator)
	return func(next http.Handler) http.Handler {
		invalidNext := isNil(next)
		return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			started := time.Now()
			outcome := "error"
			source := authn.CredentialSource("")
			defer func() {
				config.observe(requestContext(request), "middleware.authenticate", outcome, source, started)
			}()

			if invalidAuthenticator || invalidNext || request == nil {
				config.respond(w, request, invalidConfiguration("middleware.authenticate"))
				return
			}
			request = requestWithPropagation(request)
			credential, err := authenticator.Authenticate(request)
			if err != nil {
				config.respond(w, request, err)
				return
			}
			if !validCredential(credential) {
				config.respond(w, request, unavailable("middleware.authenticate"))
				return
			}
			source = credential.Source
			request = request.WithContext(contextWithCredential(request.Context(), credential))
			outcome = "success"
			next.ServeHTTP(w, request)
		})
	}
}

// RequirePermission authenticates, makes one fresh PDP decision, and invokes
// next only when IAM explicitly allows the current request method.
func RequirePermission(
	authenticator Authenticator,
	authorizer Authorizer,
	permission authz.Permission,
	optionValues ...Option,
) func(http.Handler) http.Handler {
	config := resolveOptions(optionValues)
	invalidAuthenticator := isNil(authenticator)
	invalidAuthorizer := isNil(authorizer)
	return func(next http.Handler) http.Handler {
		invalidNext := isNil(next)
		return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			started := time.Now()
			outcome := "error"
			source := authn.CredentialSource("")
			defer func() {
				config.observe(requestContext(request), "middleware.require_permission", outcome, source, started)
			}()

			if invalidAuthenticator || invalidAuthorizer || invalidNext || request == nil {
				config.respond(w, request, invalidConfiguration("middleware.require_permission"))
				return
			}
			request = requestWithPropagation(request)
			credential, err := authenticator.Authenticate(request)
			if err != nil {
				config.respond(w, request, err)
				return
			}
			if !validCredential(credential) {
				config.respond(w, request, unavailable("middleware.require_permission"))
				return
			}
			source = credential.Source
			request = request.WithContext(contextWithCredential(request.Context(), credential))

			currentPermission := permission
			currentPermission.HTTPMethod = request.Method
			decision, err := authorizer.Decide(
				request.Context(),
				credential.AccessToken,
				currentPermission,
			)
			if err != nil && credential.Source == authn.CredentialSession &&
				isPDPUnauthorized(err) {
				refreshed, refreshErr := authenticator.ForceRefresh(
					request.Context(),
					credential.SessionID,
				)
				if refreshErr != nil {
					config.respond(w, request, refreshErr)
					return
				}
				if !validRefreshedSession(refreshed, credential) {
					config.respond(w, request, unavailable("middleware.require_permission"))
					return
				}
				credential.AccessToken = refreshed.TokenSet.AccessToken
				credential.Identity = cloneIdentity(refreshed.Identity)
				request = request.WithContext(contextWithCredential(request.Context(), credential))
				decision, err = authorizer.Decide(
					request.Context(),
					credential.AccessToken,
					currentPermission,
				)
			}
			if err != nil {
				config.respond(w, request, err)
				return
			}

			request = request.WithContext(contextWithDecision(request.Context(), decision))
			setDecisionIDHeader(w.Header(), decision.ID)
			if !decision.Allowed {
				outcome = "deny"
				config.respond(w, request, forbidden(decision))
				return
			}
			outcome = "allow"
			next.ServeHTTP(w, request)
		})
	}
}

func resolveOptions(values []Option) options {
	config := options{}
	for _, option := range values {
		if option != nil {
			option(&config)
		}
	}
	if isNil(config.responder) {
		config.responder = defaultErrorResponder{}
	}
	if isNil(config.hooks) {
		config.hooks = observability.Nop{}
	}
	if config.logger == nil {
		config.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return config
}

func (config options) respond(w http.ResponseWriter, request *http.Request, err error) {
	config.responder.Respond(w, request, err)
}

func (config options) observe(
	ctx context.Context,
	operation string,
	outcome string,
	source authn.CredentialSource,
	started time.Time,
) {
	duration := time.Since(started)
	event := observability.Event{
		Operation:        operation,
		Outcome:          outcome,
		CredentialSource: string(source),
		Duration:         duration,
	}
	config.hooks.Observe(ctx, event)
	config.logger.Info(
		"iamcore middleware",
		slog.String("operation", operation),
		slog.String("outcome", outcome),
		slog.Duration("duration", duration),
		slog.String("credential_source", string(source)),
	)
}

func requestContext(request *http.Request) context.Context {
	if request == nil {
		return context.Background()
	}
	return request.Context()
}

func requestWithPropagation(request *http.Request) *http.Request {
	ctx := transport.WithHeaders(request.Context(), request.Header)
	return request.WithContext(ctx)
}

func contextWithCredential(ctx context.Context, credential authn.Credential) context.Context {
	ctx = context.WithValue(ctx, identityContextKey, cloneIdentity(credential.Identity))
	return context.WithValue(ctx, credentialSourceContextKey, credential.Source)
}

func contextWithDecision(ctx context.Context, decision authz.Decision) context.Context {
	return context.WithValue(ctx, decisionContextKey, decision)
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

func validCredential(credential authn.Credential) bool {
	if strings.TrimSpace(credential.AccessToken) == "" ||
		strings.TrimSpace(credential.Identity.Subject) == "" {
		return false
	}
	switch credential.Source {
	case authn.CredentialBearer:
		return credential.SessionID == ""
	case authn.CredentialSession:
		return strings.TrimSpace(credential.SessionID) != ""
	default:
		return false
	}
}

func validRefreshedSession(refreshed *session.Session, previous authn.Credential) bool {
	return refreshed != nil &&
		previous.Source == authn.CredentialSession &&
		refreshed.ID == previous.SessionID &&
		strings.TrimSpace(refreshed.TokenSet.AccessToken) != "" &&
		refreshed.TokenSet.AccessToken != previous.AccessToken &&
		refreshed.Identity.Subject == previous.Identity.Subject
}

func isPDPUnauthorized(err error) bool {
	var typed *sdkerr.Error
	return errors.As(err, &typed) && typed != nil &&
		typed.Kind == sdkerr.KindUnauthenticated &&
		typed.HTTPStatus == http.StatusUnauthorized &&
		typed.Operation == "authz.decide"
}

func setDecisionIDHeader(header http.Header, value string) {
	if safeHeaderValue(value) {
		header.Set(decisionIDHeader, value)
	}
}

func safeHeaderValue(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func invalidConfiguration(operation string) *sdkerr.Error {
	return sdkerr.New(sdkerr.KindInvalidConfig, operation, 0, false, nil)
}

func unavailable(operation string) *sdkerr.Error {
	return sdkerr.New(sdkerr.KindIAMUnavailable, operation, http.StatusServiceUnavailable, false, nil)
}

func forbidden(decision authz.Decision) *sdkerr.Error {
	return &sdkerr.Error{
		Kind:       sdkerr.KindForbidden,
		Operation:  "middleware.require_permission",
		HTTPStatus: http.StatusForbidden,
		RequestID:  decision.RequestID,
		TraceID:    decision.TraceID,
		DecisionID: decision.ID,
	}
}

func isNil(value any) bool {
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
