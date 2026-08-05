package iamcoresdk_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	repositoryName = "swan-swan-swan/iam-core-sdk-go"
	rootModule     = "github.com/swan-swan-swan/iam-core-sdk-go"
	ginModule      = rootModule + "/runtime/adapters/gin"
	redisModule    = rootModule + "/runtime/adapters/redis"

	rootTag = "v0.4.0"
)

func TestReleaseWorkflowContract(t *testing.T) {
	version, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if string(version) != "0.4.0\n" {
		t.Fatalf("VERSION = %q, want exact v0.4 release bytes", version)
	}

	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(raw)
	release := releaseJob(t, workflow, "release")
	for _, value := range []string{
		"if: github.event_name == 'push' && github.ref == 'refs/heads/dev'",
		"needs:\n      - root\n      - integration",
		"permissions:\n      contents: write",
		"fetch-depth: 0",
		"RELEASE_SHA: ${{ github.sha }}",
		"REPOSITORY: ${{ github.repository }}",
	} {
		if !strings.Contains(release, value) {
			t.Errorf("release job missing %q", value)
		}
	}
	for _, value := range []string{
		"--force",
		"continue-on-error",
		"|| true",
		"release paused",
		"prerelease-stage guard",
		"runtime/adapters/gin/v0.4.0",
		"runtime/adapters/redis/v0.4.0",
	} {
		if strings.Contains(release, value) {
			t.Errorf("release job contains forbidden behavior %q", value)
		}
	}

	postRelease := releaseJob(t, workflow, "post_release")
	for _, value := range []string{
		"needs: release",
		"GOWORK=off go get " + rootModule + "@v0.4.0",
		`_ "` + ginModule + `"`,
		`_ "` + redisModule + `"`,
		"GOWORK=off go test ./...",
	} {
		if !strings.Contains(postRelease, value) {
			t.Errorf("post-release job missing %q", value)
		}
	}
}

func TestPostReleaseWorkflowAuthenticatesPrivateModulesAndSupportsManualRecovery(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(raw)
	if !strings.Contains(workflow, "  workflow_dispatch:\n") {
		t.Fatal("CI workflow has no manual recovery trigger")
	}

	postRelease := releaseJob(t, workflow, "post_release")
	for _, value := range []string{
		"always()",
		"github.event_name == 'workflow_dispatch'",
		"permissions:\n      contents: read",
		"GITHUB_TOKEN: ${{ github.token }}",
		`git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"`,
		"GOPRIVATE: github.com/swan-swan-swan/*",
	} {
		if !strings.Contains(postRelease, value) {
			t.Errorf("post-release private module recovery missing %q", value)
		}
	}
}

func TestDiffCheckSupportsManualWorkflowDispatch(t *testing.T) {
	repository := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "CI Test"},
		{"config", "user.email", "ci-test@example.com"},
	} {
		command := exec.Command("git", args...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("manual recovery\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	for _, args := range [][]string{{"add", "README.md"}, {"commit", "-q", "-m", "fixture"}} {
		command := exec.Command("git", args...)
		command.Dir = repository
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	headCommand := exec.Command("git", "rev-parse", "HEAD")
	headCommand.Dir = repository
	headOutput, err := headCommand.Output()
	if err != nil {
		t.Fatalf("resolve fixture HEAD: %v", err)
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	command := exec.Command("bash", filepath.Join(workingDirectory, ".github/scripts/check-diff.sh"))
	command.Dir = repository
	command.Env = append(os.Environ(),
		"IAMCORE_CI_EVENT_NAME=workflow_dispatch",
		"IAMCORE_CI_HEAD_SHA="+strings.TrimSpace(string(headOutput)),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("manual workflow diff check: %v\n%s", err, output)
	}
}

func TestReleaseScriptRejectsMalformedVersionBeforeGit(t *testing.T) {
	script := releaseScriptFromWorkflow(t)
	for _, test := range []struct {
		name     string
		contents []byte
	}{
		{name: "old version", contents: []byte("0.3.0\n")},
		{name: "split line", contents: []byte("0.4\n.0\n")},
		{name: "extra blank line", contents: []byte("0.4.0\n\n")},
		{name: "carriage return", contents: []byte("0.4.0\r\n")},
		{name: "NUL byte", contents: []byte("0.4\x00.0\n")},
		{name: "missing newline", contents: []byte("0.4.0")},
		{name: "trailing data", contents: []byte("0.4.0\nextra\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := validReleaseFixture()
			fixture.version = string(test.contents)
			result := runReleaseScriptFixture(t, script, fixture)
			if result.err == nil {
				t.Fatal("malformed VERSION unexpectedly succeeded")
			}
			if result.calls != "" {
				t.Fatalf("malformed VERSION reached Git: %q", result.calls)
			}
		})
	}
}

func TestReleaseScriptRejectsRepositoryAndModuleMismatchBeforeGit(t *testing.T) {
	script := releaseScriptFromWorkflow(t)
	for _, test := range []struct {
		name   string
		mutate func(*releaseFixture)
	}{
		{name: "old repository", mutate: func(f *releaseFixture) { f.repository = "swan-swan-swan/iam-core-client-sdk-go" }},
		{name: "old root module", mutate: func(f *releaseFixture) { f.rootModule = "module github.com/swan-swan-swan/iam-core-client-sdk-go\n" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := validReleaseFixture()
			test.mutate(&fixture)
			result := runReleaseScriptFixture(t, script, fixture)
			if result.err == nil {
				t.Fatal("release preflight mismatch unexpectedly succeeded")
			}
			if result.calls != "" {
				t.Fatalf("release preflight mismatch reached Git: %q", result.calls)
			}
		})
	}
}

func TestReleaseScriptRejectsNestedAdapterModulesBeforeGit(t *testing.T) {
	fixture := validReleaseFixture()
	fixture.nestedAdapterModules = true
	result := runReleaseScriptFixture(t, releaseScriptFromWorkflow(t), fixture)
	if result.err == nil {
		t.Fatal("nested adapter modules unexpectedly passed release preflight")
	}
	if result.calls != "" {
		t.Fatalf("nested adapter modules reached Git: %q", result.calls)
	}
}

func TestReleaseScriptRejectsAnyExistingTagBeforeMutation(t *testing.T) {
	script := releaseScriptFromWorkflow(t)
	fixture := validReleaseFixture()
	fixture.existingTag = rootTag
	result := runReleaseScriptFixture(t, script, fixture)
	if result.err == nil {
		t.Fatal("existing release tag unexpectedly succeeded")
	}
	for _, mutation := range []string{"checkout ", "merge ", "tag ", "push "} {
		if strings.Contains(result.calls, mutation) {
			t.Fatalf("existing tag reached mutation %q in:\n%s", mutation, result.calls)
		}
	}
}

func TestReleaseScriptCreatesOneTagOnMergeCommitAndPushesAtomically(t *testing.T) {
	result := runReleaseScriptFixture(t, releaseScriptFromWorkflow(t), validReleaseFixture())
	if result.err != nil {
		t.Fatalf("release script: %v\nGit calls:\n%s", result.err, result.calls)
	}
	for _, call := range []string{
		"tag -a " + rootTag + " -m IAM Core SDK " + rootTag,
		"rev-list -n 1 " + rootTag,
		"push --atomic origin main " + rootTag,
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

func TestReleaseScriptRejectsOutOfOrderRevisionBeforeMerge(t *testing.T) {
	fixture := validReleaseFixture()
	fixture.releaseInMainExit = 0
	result := runReleaseScriptFixture(t, releaseScriptFromWorkflow(t), fixture)
	if result.err == nil {
		t.Fatal("already-released revision unexpectedly succeeded")
	}
	for _, mutation := range []string{"merge --no-ff", "tag -a ", "push --atomic"} {
		if strings.Contains(result.calls, mutation) {
			t.Fatalf("out-of-order revision reached %q in:\n%s", mutation, result.calls)
		}
	}
}

func TestReleaseScriptRejectsDivergedMainBeforeMerge(t *testing.T) {
	fixture := validReleaseFixture()
	fixture.mainInReleaseExit = 1
	result := runReleaseScriptFixture(t, releaseScriptFromWorkflow(t), fixture)
	if result.err == nil {
		t.Fatal("release from a branch diverged from main unexpectedly succeeded")
	}
	for _, mutation := range []string{"merge --no-ff", "tag -a ", "push --atomic"} {
		if strings.Contains(result.calls, mutation) {
			t.Fatalf("diverged release reached %q in:\n%s", mutation, result.calls)
		}
	}
}

func TestReleaseJobExtractionIgnoresSiblingJob(t *testing.T) {
	workflow := "jobs:\n  release:\n    steps:\n      - run: |\n          echo release\n  sibling:\n    run: forbidden\n"
	release := releaseJob(t, workflow, "release")
	if strings.Contains(release, "forbidden") {
		t.Fatal("release job extraction included sibling content")
	}
}

func releaseJob(t *testing.T, workflow, jobName string) string {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	start := -1
	marker := "  " + jobName + ":"
	for index, line := range lines {
		if line == marker {
			start = index
			break
		}
	}
	if start < 0 {
		t.Fatalf("CI workflow has no %s job", jobName)
	}
	end := len(lines)
	for index := start + 1; index < len(lines); index++ {
		if strings.HasPrefix(lines[index], "  ") && !strings.HasPrefix(lines[index], "    ") && strings.HasSuffix(lines[index], ":") {
			end = index
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func releaseScriptFromWorkflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	release := releaseJob(t, string(raw), "release")
	lines := strings.Split(release, "\n")
	start := -1
	for index, line := range lines {
		if line == "        run: |" {
			if start >= 0 {
				t.Fatal("release job must contain exactly one run block")
			}
			start = index + 1
		}
	}
	if start < 0 {
		t.Fatal("release job has no run block")
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
	version, repository  string
	rootModule           string
	nestedAdapterModules bool
	existingTag          string
	releaseInMainExit    int
	mainInReleaseExit    int
}

func validReleaseFixture() releaseFixture {
	return releaseFixture{
		version:           "0.4.0\n",
		repository:        repositoryName,
		rootModule:        "module " + rootModule + "\n",
		releaseInMainExit: 1,
		mainInReleaseExit: 0,
	}
}

type releaseScriptResult struct {
	err   error
	calls string
}

func runReleaseScriptFixture(t *testing.T, script string, fixture releaseFixture) releaseScriptResult {
	t.Helper()
	directory := t.TempDir()
	writeFixtureFile(t, directory, "VERSION", []byte(fixture.version))
	writeFixtureFile(t, directory, "go.mod", []byte(fixture.rootModule))
	if fixture.nestedAdapterModules {
		writeFixtureFile(t, directory, "runtime/adapters/gin/go.mod", []byte("module "+ginModule+"\n"))
		writeFixtureFile(t, directory, "runtime/adapters/redis/go.mod", []byte("module "+redisModule+"\n"))
	}

	gitScript := `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GIT_CALLED"
if [[ "$1" == "fetch" ]]; then exit 0; fi
if [[ "$1" == "rev-parse" && "$2" == "--verify" && "$3" == "--quiet" ]]; then
  if [[ "$4" == "refs/tags/$EXISTING_TAG" ]]; then exit 0; fi
  exit 1
fi
if [[ "$1" == "merge-base" && "$3" == "$RELEASE_SHA" && "$4" == "HEAD" ]]; then exit "$GIT_RELEASE_IN_MAIN_EXIT"; fi
if [[ "$1" == "merge-base" && "$3" == "HEAD" && "$4" == "$RELEASE_SHA" ]]; then exit "$GIT_MAIN_IN_RELEASE_EXIT"; fi
if [[ "$1" == "rev-list" && "$2" == "--parents" ]]; then printf 'merge parent deadbeef\n'; exit 0; fi
if [[ "$1" == "rev-parse" && "$2" == "HEAD" ]]; then printf 'merge\n'; exit 0; fi
if [[ "$1" == "rev-list" && "$2" == "-n" ]]; then printf 'merge\n'; exit 0; fi
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
		"GIT_RELEASE_IN_MAIN_EXIT="+fmt.Sprint(fixture.releaseInMainExit),
		"GIT_MAIN_IN_RELEASE_EXIT="+fmt.Sprint(fixture.mainInReleaseExit),
		"PATH="+directory+":"+os.Getenv("PATH"),
		"RELEASE_SHA=deadbeef",
		"REPOSITORY="+fixture.repository,
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
