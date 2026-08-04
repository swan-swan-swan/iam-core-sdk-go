package httpauthz

import (
	"context"
	"testing"

	"github.com/swan-swan-swan/iam-core-client-sdk-go/core"
)

func TestDecisionFromContextReturnsDefensiveValue(t *testing.T) {
	original := Decision{ID: "dec-1", Allowed: true, ReasonCode: "policy_allow", RequestID: "req-1", TraceID: "trace-1"}
	ctx := contextWithDecision(context.Background(), original)

	got, ok := DecisionFromContext(ctx)
	if !ok || got != original {
		t.Fatalf("DecisionFromContext() = %#v, %v", got, ok)
	}
	got.ID = "mutated"
	again, ok := DecisionFromContext(ctx)
	if !ok || again != original {
		t.Fatalf("stored decision was mutable: %#v, %v", again, ok)
	}
}

func TestContextHelpersRejectNilAndMissingValues(t *testing.T) {
	if got, ok := DecisionFromContext(nil); ok || got != (Decision{}) {
		t.Fatalf("DecisionFromContext(nil) = %#v, %v", got, ok)
	}
	if got, ok := DecisionFromContext(context.Background()); ok || got != (Decision{}) {
		t.Fatalf("DecisionFromContext(empty) = %#v, %v", got, ok)
	}
	if got, ok := CredentialSourceFromContext(nil); ok || got != "" {
		t.Fatalf("CredentialSourceFromContext(nil) = %q, %v", got, ok)
	}
	if got, ok := CredentialSourceFromContext(context.Background()); ok || got != "" {
		t.Fatalf("CredentialSourceFromContext(empty) = %q, %v", got, ok)
	}
}

func TestCredentialSourceFromContextReturnsStoredSource(t *testing.T) {
	ctx := contextWithCredentialSource(context.Background(), core.CredentialSession)
	if got, ok := CredentialSourceFromContext(ctx); !ok || got != core.CredentialSession {
		t.Fatalf("CredentialSourceFromContext() = %q, %v", got, ok)
	}
}
