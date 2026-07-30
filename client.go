package iamcore

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/authn"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/authz"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/nilcheck"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/internal/transport"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/middleware"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/observability"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
)

// Client composes IAM Core browser authentication, request authentication,
// and fresh authorization decisions.
type Client struct {
	oidc              *oidc.Client
	authentication    *authn.Service
	authorization     *authz.Client
	middlewareOptions []middleware.Option
	timeouts          TimeoutConfig
	httpClient        *http.Client
}

// New validates configuration, performs OIDC Discovery, and composes the
// focused SDK packages with shared dependencies.
func New(ctx context.Context, config Config) (*Client, error) {
	if err := validateRootConfig(ctx, config); err != nil {
		return nil, err
	}
	scopes := resolvedScopes(config.Scopes)
	timeouts := resolvedTimeouts(config.Timeouts)
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	hooks := config.Hooks
	if nilcheck.IsNil(hooks) {
		hooks = observability.Nop{}
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = transport.NewDefaultHTTPClient()
	}

	oidcClient, err := oidc.New(ctx, oidc.Config{
		IssuerURL:            config.IssuerURL,
		ClientID:             config.ClientID,
		SecretProvider:       config.ClientSecretProvider,
		RedirectURL:          config.RedirectURL,
		Scopes:               scopes,
		HTTPClient:           httpClient,
		DiscoveryJWKSTimeout: timeouts.DiscoveryJWKS,
		TokenUserInfoTimeout: timeouts.TokenUserInfo,
		Hooks:                hooks,
		Logger:               logger,
	})
	if err != nil {
		return nil, err
	}
	authentication, err := authn.New(authn.Config{
		OIDC:                         oidcClient,
		Backend:                      config.Session.Backend,
		RedirectURL:                  config.RedirectURL,
		AllowedReturnToURLs:          append([]string(nil), config.Session.AllowedReturnToURLs...),
		SessionCookie:                config.Session.SessionCookie,
		FlowCookie:                   config.Session.FlowCookie,
		FlowTTL:                      config.Session.FlowTTL,
		SessionAbsoluteTTL:           config.Session.AbsoluteTTL,
		SessionIdleTTL:               config.Session.IdleTTL,
		IdentityRecheckInterval:      config.Session.IdentityRecheckInterval,
		RefreshBeforeExpiry:          config.Session.RefreshBeforeExpiry,
		RefreshLockTTL:               timeouts.RefreshLock,
		AllowInsecureLocalCookie:     config.Session.AllowInsecureLocalCookie,
		LogoutRemoteFailureIsSuccess: config.Session.LogoutRemoteFailureIsSuccess,
		Logger:                       logger,
		Hooks:                        hooks,
	})
	if err != nil {
		return nil, err
	}
	authorization, err := authz.New(authz.Config{
		IssuerURL:  config.IssuerURL,
		HTTPClient: httpClient,
		Timeout:    timeouts.PDP,
		Hooks:      hooks,
		Logger:     logger,
	})
	if err != nil {
		return nil, err
	}

	options := []middleware.Option{
		middleware.WithHooks(hooks),
		middleware.WithLogger(logger),
	}
	if !nilcheck.IsNil(config.ErrorResponder) {
		options = append(options, middleware.WithErrorResponder(config.ErrorResponder))
	}
	return &Client{
		oidc:              oidcClient,
		authentication:    authentication,
		authorization:     authorization,
		middlewareOptions: options,
		timeouts:          timeouts,
		httpClient:        httpClient,
	}, nil
}

func (c *Client) OIDC() *oidc.Client {
	if c == nil {
		return nil
	}
	return c.oidc
}

func (c *Client) Authorization() *authz.Client {
	if c == nil {
		return nil
	}
	return c.authorization
}

func (c *Client) LoginHandler() http.Handler {
	if c == nil || c.authentication == nil {
		return browserHandler(invalidClientHandler())
	}
	return browserHandler(c.authentication.LoginHandler())
}

func (c *Client) CallbackHandler() http.Handler {
	if c == nil || c.authentication == nil {
		return browserHandler(invalidClientHandler())
	}
	return browserHandler(c.authentication.CallbackHandler())
}

func (c *Client) LogoutHandler() http.Handler {
	if c == nil || c.authentication == nil {
		return browserHandler(invalidClientHandler())
	}
	return browserHandler(c.authentication.LogoutHandler())
}

func (c *Client) Authenticate(next http.Handler) http.Handler {
	if c == nil {
		return middleware.Authenticate(nil)(next)
	}
	return middleware.Authenticate(c.authentication, c.middlewareOptions...)(next)
}

func (c *Client) RequirePermission(permission Permission) func(http.Handler) http.Handler {
	if c == nil {
		return middleware.RequirePermission(nil, nil, permission)
	}
	return middleware.RequirePermission(
		c.authentication,
		c.authorization,
		permission,
		c.middlewareOptions...,
	)
}

func invalidClientHandler() http.Handler {
	return middleware.Authenticate(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
}

func browserHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request == nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		ctx := transport.WithHeaders(request.Context(), request.Header)
		next.ServeHTTP(w, request.WithContext(ctx))
	})
}
