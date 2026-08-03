package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestExampleBuilds(t *testing.T) {
	defer os.Remove("nethttp-v2")
	command := exec.Command("go", "build", ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
}
