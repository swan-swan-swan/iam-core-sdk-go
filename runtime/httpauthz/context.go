package httpauthz

import (
	"context"

	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

type decisionContextKey struct{}
type credentialSourceContextKey struct{}

func contextWithDecision(ctx context.Context, decision Decision) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, decisionContextKey{}, cloneDecision(decision))
}

// DecisionFromContext returns the authorization decision attached to a
// protected request. The returned value is independent of the stored value.
func DecisionFromContext(ctx context.Context) (Decision, bool) {
	if ctx == nil {
		return Decision{}, false
	}
	decision, ok := ctx.Value(decisionContextKey{}).(Decision)
	if !ok {
		return Decision{}, false
	}
	return cloneDecision(decision), true
}

func cloneDecision(decision Decision) Decision {
	return decision
}

func contextWithCredentialSource(ctx context.Context, source core.CredentialSource) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, credentialSourceContextKey{}, source)
}

// CredentialSourceFromContext reports whether a request was authenticated by
// a Bearer token or a server-side Session.
func CredentialSourceFromContext(ctx context.Context) (core.CredentialSource, bool) {
	if ctx == nil {
		return "", false
	}
	source, ok := ctx.Value(credentialSourceContextKey{}).(core.CredentialSource)
	return source, ok
}
