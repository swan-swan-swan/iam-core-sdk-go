package iamcore

import (
	"context"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/authn"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/authz"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/middleware"
	"github.com/swan-swan-swan/iam-core-client-sdk-go/oidc"
)

type Identity = oidc.Identity
type Permission = authz.Permission
type Decision = authz.Decision
type CredentialSource = authn.CredentialSource

const (
	CredentialSession = authn.CredentialSession
	CredentialBearer  = authn.CredentialBearer
)

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	return middleware.IdentityFromContext(ctx)
}

func CredentialSourceFromContext(ctx context.Context) (CredentialSource, bool) {
	return middleware.CredentialSourceFromContext(ctx)
}

func DecisionFromContext(ctx context.Context) (Decision, bool) {
	return middleware.DecisionFromContext(ctx)
}
