package core

import (
	"context"
	"slices"
	"time"
)

type AuthContext struct {
	Subject     string
	Issuer      string
	Audience    []string
	TokenID     string
	IssuedAt    time.Time
	NotBefore   time.Time
	ExpiresAt   time.Time
	Scopes      []string
	Groups      []string
	Username    string
	DisplayName string
	Email       string
	DecisionID  string
	ReasonCode  string
	TraceID     string
}

type CredentialSource string

const (
	CredentialBearer  CredentialSource = "bearer"
	CredentialSession CredentialSource = "session"
)

type TokenSource interface {
	AccessToken(context.Context) (string, error)
}

type TokenSourceFunc func(context.Context) (string, error)

func (f TokenSourceFunc) AccessToken(ctx context.Context) (string, error) {
	return f(ctx)
}

type Credential struct {
	Source    CredentialSource
	SessionID string
	Auth      AuthContext
	Tokens    TokenSource
}

type authContextKey struct{}

func ContextWithAuthContext(ctx context.Context, auth AuthContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, authContextKey{}, cloneAuthContext(auth))
}

func AuthContextFromContext(ctx context.Context) (AuthContext, bool) {
	if ctx == nil {
		return AuthContext{}, false
	}
	auth, ok := ctx.Value(authContextKey{}).(AuthContext)
	if !ok {
		return AuthContext{}, false
	}
	return cloneAuthContext(auth), true
}

func cloneAuthContext(auth AuthContext) AuthContext {
	auth.Audience = slices.Clone(auth.Audience)
	auth.Scopes = slices.Clone(auth.Scopes)
	auth.Groups = slices.Clone(auth.Groups)
	return auth
}
