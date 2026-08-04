package iamcore_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevPushReleaseWorkflowContract(t *testing.T) {
	version, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if string(version) != "0.2.0\n" {
		t.Fatal("VERSION must contain the initial SDK version")
	}

	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	release := releaseJob(t, string(raw))
	assertReleaseJobContract(t, release)

	script := releaseRunScript(t, release)
	for _, test := range []struct {
		name    string
		contents []byte
	}{
		{name: "split line", contents: []byte("0.2\n.0\n")},
		{name: "extra blank line", contents: []byte("0.2.0\n\n")},
		{name: "carriage return", contents: []byte("0.2.0\r\n")},
		{name: "NUL byte", contents: []byte("0.2\x00.0\n")},
		{name: "missing newline", contents: []byte("0.2.0")},
		{name: "multiple valid lines", contents: []byte("0.2.0\n0.2.1\n")},
		{name: "trailing data", contents: []byte("0.2.0\nextra\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertVersionRejectedBeforeGit(t, script, test.contents)
		})
	}
}

func TestReleaseJobExtractionIgnoresSiblingStep(t *testing.T) {
	workflow := `jobs:
  release:
    name: Release
    steps:
      - run: |
          echo release
  trailing:
    if: github.event_name == 'push' && github.ref == 'refs/heads/dev'
    needs:
      - root
      - gin
      - redis
      - integration
    permissions:
      contents: write
    steps:
      - name: Merge dev and create version tag
        run: |
          set -euo pipefail
          git push --atomic origin main "${release_tag}"
`

	release := releaseJob(t, workflow)
	for _, value := range []string{
		"github.event_name == 'push' && github.ref == 'refs/heads/dev'",
		"needs:\n      - root\n      - gin\n      - redis\n      - integration",
		"permissions:\n      contents: write",
		`git push --atomic origin main "${release_tag}"`,
	} {
		if strings.Contains(release, value) {
			t.Fatalf("release job extraction included trailing sibling requirement %q", value)
		}
	}
	if _, err := extractReleaseRunScript(release); err == nil {
		t.Fatal("release run-script extraction accepted the trailing sibling step")
	}
}

func TestReleaseRunScriptRequiresNamedSingleBlockStep(t *testing.T) {
	for _, test := range []struct {
		name    string
		release string
	}{
		{
			name: "earlier unrelated run block",
			release: `  release:
    steps:
      - name: Earlier step
        run: |
          echo earlier
      - name: Merge dev and create version tag
        shell: bash`,
		},
		{
			name: "future unrelated run block",
			release: `  release:
    steps:
      - name: Merge dev and create version tag
        run: |
          echo release
      - name: Future step
        run: |
          echo future`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := extractReleaseRunScript(test.release); err == nil {
				t.Fatal("release run-script extraction accepted an unrelated run block")
			}
		})
	}
}

func releaseJob(t *testing.T, workflow string) string {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	start := -1
	for index, line := range lines {
		if line == "  release:" {
			start = index
			break
		}
	}
	if start < 0 {
		t.Fatal("CI workflow has no release job")
	}

	end := len(lines)
	for index := start + 1; index < len(lines); index++ {
		line := lines[index]
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(line, ":") {
			end = index
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func assertReleaseJobContract(t *testing.T, release string) {
	t.Helper()
	required := []string{
		"if: github.event_name == 'push' && github.ref == 'refs/heads/dev'",
		"needs:\n      - root\n      - gin\n      - redis\n      - integration",
		"permissions:\n      contents: write",
	}
	for _, value := range required {
		if !strings.Contains(release, value) {
			t.Errorf("release job missing required contract %q", value)
		}
	}

	script := releaseRunScript(t, release)
	if !strings.Contains(script, "set -euo pipefail") {
		t.Error("release script must enable strict Bash mode")
	}
	if strings.Contains(script, "tr -d") {
		t.Error("release script must not normalize VERSION content")
	}
	for _, failurePath := range []string{
		"if [[ ! \"${release_version}\" =~ ^([0-9]+)\\.([0-9]+)\\.([0-9]+)$ ]]; then\n  echo \"VERSION must use X.Y.Z format\" >&2\n  exit 1\nfi",
		"if git rev-parse --verify --quiet \"refs/tags/${release_tag}\" >/dev/null; then\n  echo \"tag ${release_tag} already exists\" >&2\n  exit 1\nfi",
	} {
		if !strings.Contains(script, failurePath) {
			t.Errorf("release script missing explicit failure path %q", failurePath)
		}
	}

	for _, value := range []string{
		`^([0-9]+)\.([0-9]+)\.([0-9]+)$`,
		`LC_ALL=C grep -axE '[0-9]+\.[0-9]+\.[0-9]+' VERSION`,
		`LC_ALL=C wc -c < VERSION`,
		`release_tag="v${release_version}"`,
		`git fetch origin main dev --tags`,
		`refs/tags/${release_tag}`,
		`git checkout -B main origin/main`,
		`git merge --no-ff "$RELEASE_SHA"`,
		`git tag -a "${release_tag}"`,
		`git push --atomic origin main "${release_tag}"`,
	} {
		if !strings.Contains(script, value) {
			t.Errorf("release script missing required contract %q", value)
		}
	}

	for _, value := range []string{
		"master",
		"adapters/gin/v",
		"adapters/redis/v",
		"--force",
		"continue-on-error",
		"|| true",
	} {
		if strings.Contains(release, value) {
			t.Errorf("release job contains forbidden behavior %q", value)
		}
	}
}

func releaseRunScript(t *testing.T, release string) string {
	t.Helper()
	script, err := extractReleaseRunScript(release)
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func extractReleaseRunScript(release string) (string, error) {
	lines := strings.Split(release, "\n")
	runBlockCount := 0
	stepIndex := -1
	for index, line := range lines {
		if line == "        run: |" {
			runBlockCount++
		}
		if line == "      - name: Merge dev and create version tag" {
			if stepIndex >= 0 {
				return "", fmt.Errorf("release job has multiple named merge/tag steps")
			}
			stepIndex = index
		}
	}
	if runBlockCount != 1 {
		return "", fmt.Errorf("release job must contain exactly one run: | block, got %d", runBlockCount)
	}
	if stepIndex < 0 {
		return "", fmt.Errorf("release job has no named merge/tag step")
	}

	start := -1
	end := len(lines)
	for index := stepIndex + 1; index < len(lines); index++ {
		line := lines[index]
		if strings.HasPrefix(line, "      - ") {
			end = index
			break
		}
		if line == "        run: |" {
			start = index + 1
		}
	}
	if start < 0 {
		return "", fmt.Errorf("named merge/tag step has no run: | block")
	}
	var script []string
	for _, line := range lines[start:end] {
		if line == "" {
			script = append(script, line)
			continue
		}
		if !strings.HasPrefix(line, "          ") {
			break
		}
		script = append(script, strings.TrimPrefix(line, "          "))
	}
	if len(script) == 0 {
		return "", fmt.Errorf("named merge/tag step run script is empty")
	}
	return strings.Join(script, "\n"), nil
}

func assertVersionRejectedBeforeGit(t *testing.T, script string, version []byte) {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "VERSION"), version, 0o600); err != nil {
		t.Fatalf("write VERSION: %v", err)
	}

	gitLog := filepath.Join(directory, "git-called")
	gitPath := filepath.Join(directory, "git")
	if err := os.WriteFile(gitPath, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$GIT_CALLED\"\nexit 99\n"), 0o700); err != nil {
		t.Fatalf("write fake git: %v", err)
	}

	command := exec.Command("bash", "-c", script)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_CALLED="+gitLog, "PATH="+directory+":"+os.Getenv("PATH"), "RELEASE_SHA=deadbeef")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("malformed VERSION unexpectedly succeeded: %s", output)
	}
	if _, err := os.Stat(gitLog); !os.IsNotExist(err) {
		t.Fatalf("malformed VERSION reached a Git operation: %v", err)
	}
}
