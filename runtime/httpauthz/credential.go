package httpauthz

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/internal/nilcheck"
)

const credentialOperation = "httpauthz.credential"

func credentialHeader(request *http.Request) (string, bool, error) {
	if request == nil {
		return "", false, credentialError(core.KindProtocol)
	}
	values, present := authorizationHeaderValues(request.Header)
	if !present {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", true, credentialError(core.KindUnauthenticated)
	}
	value := values[0]
	if !strings.HasPrefix(value, "Bearer ") {
		return "", true, credentialError(core.KindUnauthenticated)
	}
	token := strings.TrimPrefix(value, "Bearer ")
	if !validBearerToken(token) {
		return "", true, credentialError(core.KindUnauthenticated)
	}
	return token, true, nil
}

func authorizationHeaderValues(header http.Header) ([]string, bool) {
	var values []string
	present := false
	for name, entries := range header {
		if !strings.EqualFold(name, "Authorization") {
			continue
		}
		present = true
		values = append(values, entries...)
	}
	return values, present
}

func (s *Service) selectCredential(request *http.Request) (core.Credential, error) {
	if request == nil {
		return core.Credential{}, credentialError(core.KindProtocol)
	}
	_, headerPresent := authorizationHeaderValues(request.Header)
	sessionPresent := false
	if s.sessions != nil {
		var err error
		sessionPresent, err = s.sessions.SessionPresent(request)
		if headerPresent && sessionPresent {
			return core.Credential{}, credentialError(core.KindCredentialConflict)
		}
		if err != nil {
			return core.Credential{}, err
		}
	}
	if headerPresent && sessionPresent {
		return core.Credential{}, credentialError(core.KindCredentialConflict)
	}
	if headerPresent {
		token, _, err := credentialHeader(request)
		if err != nil {
			return core.Credential{}, err
		}
		auth, err := s.verifier.VerifyAccessToken(request.Context(), token)
		if err != nil {
			return core.Credential{}, err
		}
		if strings.TrimSpace(auth.Subject) == "" {
			return core.Credential{}, credentialError(core.KindUnauthenticated)
		}
		capturedToken := token
		return core.Credential{
			Source: core.CredentialBearer,
			Auth:   cloneMiddlewareAuthContext(auth),
			Tokens: core.TokenSourceFunc(func(context.Context) (string, error) {
				return capturedToken, nil
			}),
		}, nil
	}
	if !sessionPresent {
		return core.Credential{}, credentialError(core.KindUnauthenticated)
	}
	credential, present, err := s.sessions.ResolveSession(request)
	if err != nil {
		return core.Credential{}, err
	}
	if !present || credential.Source != core.CredentialSession || !validSessionBinding(credential.SessionID) ||
		strings.TrimSpace(credential.Auth.Subject) == "" || nilcheck.IsNil(credential.Tokens) {
		return core.Credential{}, credentialError(core.KindUnauthenticated)
	}
	credential.Auth = cloneMiddlewareAuthContext(credential.Auth)
	return credential, nil
}

func cloneMiddlewareAuthContext(auth core.AuthContext) core.AuthContext {
	auth.Audience = slices.Clone(auth.Audience)
	auth.Scopes = slices.Clone(auth.Scopes)
	auth.Groups = slices.Clone(auth.Groups)
	return auth
}

func credentialError(kind core.Kind) *core.Error {
	return core.NewError(kind, credentialOperation, 0, false, nil)
}
