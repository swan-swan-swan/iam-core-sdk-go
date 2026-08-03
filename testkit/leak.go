package testkit

import (
	"strings"
	"testing"
)

// AssertNoLeak fails when output contains any nonempty secret. Its failure
// diagnostic intentionally includes neither output nor the matching secret.
func AssertNoLeak(t testing.TB, output string, secrets ...string) {
	t.Helper()
	if containsSecret(output, secrets) {
		t.Fatal("output contains sensitive material")
	}
}

func containsSecret(output string, secrets []string) bool {
	for _, secret := range secrets {
		if secret != "" && strings.Contains(output, secret) {
			return true
		}
	}
	return false
}
