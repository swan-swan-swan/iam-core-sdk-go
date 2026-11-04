package core

import (
	"context"
	"slices"
	"time"
)

type AuthContext struct {
	// AuthenticationMethod 区分在线确认的 API Key 与 JWT 身份。
	AuthenticationMethod string
	// CredentialOpenID 是 API Key 公开标识，不是 OIDC ClientID。
	CredentialOpenID string
	// ApplicationOpenID 是在线解析确认的程序身份归属。
	ApplicationOpenID string
	Subject           string
	// SubjectType 是已验证令牌声明的主体类型；空值仅表示兼容旧用户令牌。
	SubjectType string
	// AuthorizedParty 是已验证令牌中的授权客户端标识。
	AuthorizedParty string
	Issuer          string
	Audience        []string
	TokenID         string
	IssuedAt        time.Time
	NotBefore       time.Time
	ExpiresAt       time.Time
	// AuthTime 是当前认证上下文最初建立的时间。
	AuthTime time.Time
	// AuthenticationMethods 是已验证令牌声明的认证方式，调用方不得据此推断未声明的方法。
	AuthenticationMethods []string
	Scopes                []string
	Groups                []string
	Username              string
	DisplayName           string
	Email                 string
	DecisionID            string
	ReasonCode            string
	TraceID               string
}

type CredentialSource string

const (
	CredentialBearer  CredentialSource = "bearer"
	CredentialSession CredentialSource = "session"
	// CredentialAPIKey 表示直接服务账号凭据。
	CredentialAPIKey CredentialSource = "api_key"
)

type TokenSource interface {
	AccessToken(context.Context) (string, error)
}

type TokenSourceFunc func(context.Context) (string, error)

func (f TokenSourceFunc) AccessToken(ctx context.Context) (string, error) {
	return f(ctx)
}

type Credential struct {
	// APIKeys 仅用于直接程序凭据，不复用 Tokens。
	APIKeys   APIKeySource
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
	auth.AuthenticationMethods = slices.Clone(auth.AuthenticationMethods)
	auth.Scopes = slices.Clone(auth.Scopes)
	auth.Groups = slices.Clone(auth.Groups)
	return auth
}
