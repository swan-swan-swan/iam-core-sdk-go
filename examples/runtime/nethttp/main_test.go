package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExampleBuilds(t *testing.T) {
	command := exec.Command("go", "build", "-o", filepath.Join(t.TempDir(), "nethttp"), ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	if _, err := os.Stat("nethttp"); !os.IsNotExist(err) {
		t.Fatalf("go build left repository artifact: %v", err)
	}
}
