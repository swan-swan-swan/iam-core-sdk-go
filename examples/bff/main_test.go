package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExampleBuildsWithoutRepositoryArtifact(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "bff-example")
	command := exec.Command("go", "build", "-o", outputPath, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	if _, err := os.Stat("bff"); !os.IsNotExist(err) {
		t.Fatalf("go build left repository artifact: %v", err)
	}
}
