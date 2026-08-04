package testkit

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

func TestAssertNoLeakIgnoresEmptySecretsAndAcceptsSafeOutput(t *testing.T) {
	AssertNoLeak(t, "ordinary diagnostic output", "", "different-secret", "")
}

func TestContainsSecretHandlesOverlappingValuesWithoutReturningMaterial(t *testing.T) {
	if !containsSecret("prefix-sensitive-suffix", []string{"sensitive", "sitive"}) {
		t.Fatal("overlapping sensitive values were not detected")
	}
	if containsSecret("ordinary diagnostic output", []string{"", "secret"}) {
		t.Fatal("safe output or an empty secret was reported as a leak")
	}
}

func TestAssertNoLeakFailureDiagnosticDoesNotPrintSecrets(t *testing.T) {
	const helperEnvironment = "TESTKIT_ASSERT_NO_LEAK_HELPER"
	if os.Getenv(helperEnvironment) == "1" {
		AssertNoLeak(t, "diagnostic contains canary-sensitive-value", "canary-sensitive-value", "sensitive-value")
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAssertNoLeakFailureDiagnosticDoesNotPrintSecrets$")
	command.Env = append(os.Environ(), helperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("AssertNoLeak did not fail for leaked material")
	}
	if bytes.Contains(output, []byte("canary-sensitive-value")) || bytes.Contains(output, []byte("sensitive-value")) {
		t.Fatal("AssertNoLeak failure diagnostic disclosed sensitive material")
	}
	if !bytes.Contains(output, []byte("output contains sensitive material")) {
		t.Fatal("AssertNoLeak failure did not contain the safe diagnostic")
	}
}
