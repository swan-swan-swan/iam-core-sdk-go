package iamcoresdk_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseWorkflowOnlyRunsForDevPush(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(raw)
	for _, value := range []string{
		"push:\n    branches:\n      - dev",
		"permissions:\n  contents: write",
		"  release:",
		"fetch-depth: 0",
		"GITHUB_SHA: ${{ github.sha }}",
	} {
		if !strings.Contains(workflow, value) {
			t.Errorf("release workflow missing %q", value)
		}
	}
	for _, value := range []string{
		"pull_request:",
		"workflow_dispatch:",
		"  root:",
		"  integration:",
		"  post_release:",
		"needs:",
		"setup-go",
		"go test",
	} {
		if strings.Contains(workflow, value) {
			t.Errorf("release workflow still contains %q", value)
		}
	}
}

func TestReleaseScriptMergesDevCommitAndCreatesVersionTag(t *testing.T) {
	fixture := releaseFixture{version: "1.2.3\n"}
	result := runReleaseScriptFixture(t, releaseScriptFromWorkflow(t), fixture)
	if result.err != nil {
		t.Fatalf("release script: %v\nGit calls:\n%s", result.err, result.calls)
	}
	for _, call := range []string{
		"fetch origin main --tags",
		"checkout -B main origin/main",
		"merge --no-ff deadbeef -m chore(release): v1.2.3",
		"tag -a v1.2.3 -m IAM Core SDK v1.2.3",
		"push --atomic origin main v1.2.3",
	} {
		if !strings.Contains(result.calls, call+"\n") {
			t.Errorf("Git calls missing %q:\n%s", call, result.calls)
		}
	}
	if got := strings.Count(result.calls, "tag -a "); got != 1 {
		t.Errorf("annotated tag calls = %d, want 1", got)
	}
	if got := strings.Count(result.calls, "push --atomic "); got != 1 {
		t.Errorf("atomic push calls = %d, want 1", got)
	}
}

func TestReleaseScriptRejectsMalformedVersionBeforeGit(t *testing.T) {
	script := releaseScriptFromWorkflow(t)
	for _, version := range []string{"", "v0.4.0\n", "0.4\n", "0.4.0-rc.1\n", "0.4.0\nextra\n"} {
		t.Run(fmt.Sprintf("%q", version), func(t *testing.T) {
			result := runReleaseScriptFixture(t, script, releaseFixture{version: version})
			if result.err == nil {
				t.Fatal("malformed VERSION unexpectedly succeeded")
			}
			if result.calls != "" {
				t.Fatalf("malformed VERSION reached Git: %q", result.calls)
			}
		})
	}
}

func TestReleaseScriptRejectsExistingTagBeforeMerge(t *testing.T) {
	result := runReleaseScriptFixture(t, releaseScriptFromWorkflow(t), releaseFixture{
		version:     "0.4.0\n",
		existingTag: "v0.4.0",
	})
	if result.err == nil {
		t.Fatal("existing release tag unexpectedly succeeded")
	}
	for _, mutation := range []string{"checkout ", "merge ", "tag -a ", "push "} {
		if strings.Contains(result.calls, mutation) {
			t.Fatalf("existing tag reached mutation %q in:\n%s", mutation, result.calls)
		}
	}
}

func releaseScriptFromWorkflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	start := -1
	for index, line := range lines {
		if line == "        run: |" {
			if start >= 0 {
				t.Fatal("release workflow must contain exactly one run block")
			}
			start = index + 1
		}
	}
	if start < 0 {
		t.Fatal("release workflow has no run block")
	}
	var script []string
	for _, line := range lines[start:] {
		if line == "" {
			script = append(script, line)
			continue
		}
		if !strings.HasPrefix(line, "          ") {
			break
		}
		script = append(script, strings.TrimPrefix(line, "          "))
	}
	return strings.Join(script, "\n")
}

type releaseFixture struct {
	version     string
	existingTag string
}

type releaseScriptResult struct {
	err   error
	calls string
}

func runReleaseScriptFixture(t *testing.T, script string, fixture releaseFixture) releaseScriptResult {
	t.Helper()
	directory := t.TempDir()
	writeFixtureFile(t, directory, "VERSION", []byte(fixture.version))

	gitScript := `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GIT_CALLED"
if [[ "$1" == "fetch" ]]; then exit 0; fi
if [[ "$1" == "rev-parse" && "$2" == "--verify" && "$3" == "--quiet" ]]; then
  if [[ "$4" == "refs/tags/$EXISTING_TAG" ]]; then exit 0; fi
  exit 1
fi
exit 0
`
	writeFixtureFile(t, directory, "git", []byte(gitScript))
	if err := os.Chmod(filepath.Join(directory, "git"), 0o700); err != nil {
		t.Fatalf("chmod fake git: %v", err)
	}

	gitLog := filepath.Join(directory, "git-called")
	command := exec.Command("bash", "-c", script)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"EXISTING_TAG="+fixture.existingTag,
		"GIT_CALLED="+gitLog,
		"GITHUB_SHA=deadbeef",
		"PATH="+directory+":"+os.Getenv("PATH"),
	)
	output, err := command.CombinedOutput()
	calls, readErr := os.ReadFile(gitLog)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatalf("read Git log: %v", readErr)
	}
	if err != nil {
		err = fmt.Errorf("%w: %s", err, output)
	}
	return releaseScriptResult{err: err, calls: string(calls)}
}

func writeFixtureFile(t *testing.T, root, path string, contents []byte) {
	t.Helper()
	fullPath := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(fullPath, contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
