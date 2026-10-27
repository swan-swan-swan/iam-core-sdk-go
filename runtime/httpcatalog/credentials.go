package httpcatalog

import (
	"context"
	"net/http"
	"strings"
)

// RegistrarCredentials 定义仅用于 Catalog 协议的客户端凭据，不授予业务 API 权限。
type RegistrarCredentials struct {
	ClientID     string
	ClientSecret string
}

// RegistrarCredentialSource 在每次同步和续约时提供当前有效凭据，生命周期由宿主管理。
type RegistrarCredentialSource interface {
	Credentials(context.Context) (RegistrarCredentials, error)
}

// RegistrarCredentialSourceFunc 将函数适配为 Registrar 凭据源。
type RegistrarCredentialSourceFunc func(context.Context) (RegistrarCredentials, error)

// Credentials 读取当前凭据。
func (f RegistrarCredentialSourceFunc) Credentials(ctx context.Context) (RegistrarCredentials, error) {
	return f(ctx)
}

// authenticateRequest 只使用显式选定的认证模式，不在失败时回退到其他凭据。
func (r *Registry) authenticateRequest(ctx context.Context, request *http.Request) error {
	if r.config.Credentials != nil {
		credentials, err := r.config.Credentials.Credentials(ctx)
		if err != nil || credentials.ClientID != strings.TrimSpace(credentials.ClientID) ||
			!strings.HasSuffix(credentials.ClientID, "-catalog-registrar") || len(credentials.ClientID) <= len("-catalog-registrar") ||
			strings.ContainsAny(credentials.ClientID, ":\r\n") || strings.TrimSpace(credentials.ClientSecret) == "" {
			return errCatalogRegistration
		}
		request.SetBasicAuth(credentials.ClientID, credentials.ClientSecret)
		return nil
	}
	token, err := r.config.Tokens.AccessToken(ctx)
	if err != nil || !validBearerToken(token) {
		return errCatalogRegistration
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (r *Registry) credentialSource() string {
	if r.config.Credentials != nil {
		return "registrar"
	}
	return "bearer"
}
