package iamcore_test

import (
	"os"
	"strings"
	"testing"
)

func TestDevPushReleaseWorkflowContract(t *testing.T) {
	version, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if string(version) != "0.2.0\n" {
		t.Fatalf("VERSION must contain the initial SDK version")
	}

	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(raw)
	marker := "\n  release:\n"
	index := strings.Index(workflow, marker)
	if index < 0 {
		t.Fatal("CI workflow has no release job")
	}
	release := workflow[index:]

	required := []string{
		"github.event_name == 'push' && github.ref == 'refs/heads/dev'",
		"needs:\n      - root\n      - gin\n      - redis\n      - integration",
		"contents: write",
		`release_version=$(tr -d '\r\n' < VERSION)`,
		`^([0-9]+)\.([0-9]+)\.([0-9]+)$`,
		`release_tag="v${release_version}"`,
		`git fetch origin main dev --tags`,
		`refs/tags/${release_tag}`,
		`git checkout -B main origin/main`,
		`git merge --no-ff "$RELEASE_SHA"`,
		`git tag -a "${release_tag}"`,
		`git push --atomic origin main "${release_tag}"`,
	}
	for _, value := range required {
		if !strings.Contains(release, value) {
			t.Errorf("release job missing required contract")
		}
	}

	forbidden := []string{
		"master",
		"adapters/gin/v",
		"adapters/redis/v",
		"--force",
		"continue-on-error",
		"|| true",
	}
	for _, value := range forbidden {
		if strings.Contains(release, value) {
			t.Errorf("release job contains forbidden behavior")
		}
	}
}
