package httpcatalog_test

import (
	"context"
	"testing"

	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/core"
	"github.com/swan-swan-swan/iam-core-sdk-go/v3/runtime/httpcatalog"
)

func TestRegistryRequiresExplicitServiceScope(t *testing.T) {
	for _, service := range []string{"", "   "} {
		_, err := httpcatalog.NewRegistry(httpcatalog.Config{
			BaseURL: "http://127.0.0.1:8080", Application: "beacon", Service: service, Release: "test",
			Tokens: core.TokenSourceFunc(func(context.Context) (string, error) { return "machine-token", nil }),
		})
		if err == nil {
			t.Fatalf("service %q accepted", service)
		}
	}
}
