# Dev Auto Release Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `dev` push 的完整 CI 通过后，自动合并到 `main` 并根据根目录 `VERSION` 创建唯一的 `vX.Y.Z` Tag。

**Architecture:** 直接扩展现有 `.github/workflows/ci.yml`，新增依赖 `root`、`gin`、`redis`、`integration` 的 `release` Job。发布逻辑只使用 Git、GitHub Actions 自动令牌和根目录版本文件，不增加额外服务、脚本或依赖。

**Tech Stack:** GitHub Actions YAML、Bash、Git、Go 静态契约测试。

## Global Constraints

- 发布只在 `push` 到 `dev` 时执行。
- `VERSION` 内容必须严格为 `X.Y.Z`，初始值为 `0.2.0`。
- 只创建一个根 Tag `vX.Y.Z`；不得创建 adapter Tag。
- 发布必须等待 `root`、`gin`、`redis`、`integration` 全部成功。
- Tag 已存在、版本非法、合并失败或推送失败时必须失败关闭。
- 不使用 force push、`continue-on-error`、`|| true` 或跳过安全测试。
- 不修改分支保护、远端地址、Go module 清单或 SDK 生产代码。

---

## File Map

| File | Responsibility |
| --- | --- |
| `VERSION` | 保存不带 `v` 的 SDK SemVer 版本 |
| `.github/workflows/ci.yml` | 现有 CI 和新增的 dev 自动合并/Tag Job |
| `release_workflow_test.go` | 冻结 VERSION、触发条件、CI 依赖、merge/tag/push 与禁止项 |

### Task 1: Add the Versioned Dev-to-Main Release Job

**Files:**
- Create: `VERSION`
- Create: `release_workflow_test.go`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: GitHub event fields `github.event_name`, `github.ref`, `github.sha`; existing CI jobs `root`, `gin`, `redis`, `integration`; repository branches `dev`, `main`.
- Produces: updated remote `main` and one annotated repository Tag `v${VERSION}`.

- [ ] **Step 1: Write the failing release contract test**

Create `release_workflow_test.go`:

```go
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
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
go test . -run '^TestDevPushReleaseWorkflowContract$' -count=1
```

Expected: FAIL because `VERSION` does not exist.

- [ ] **Step 3: Add the initial VERSION file**

Create `VERSION` with exactly:

```text
0.2.0
```

Do not include a leading `v`, comments, spaces or additional lines.

- [ ] **Step 4: Add the release Job to the existing workflow**

Append this Job after `integration` in `.github/workflows/ci.yml`:

```yaml
  release:
    name: Merge dev to main and create SDK tag
    if: github.event_name == 'push' && github.ref == 'refs/heads/dev'
    needs:
      - root
      - gin
      - redis
      - integration
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: write
    steps:
      - name: Check out dev revision
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Merge dev and create version tag
        shell: bash
        env:
          RELEASE_SHA: ${{ github.sha }}
        run: |
          set -euo pipefail
          release_version=$(tr -d '\r\n' < VERSION)
          if [[ ! "${release_version}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
            echo "VERSION must use X.Y.Z format" >&2
            exit 1
          fi
          release_tag="v${release_version}"

          git fetch origin main dev --tags
          if git rev-parse --verify --quiet "refs/tags/${release_tag}" >/dev/null; then
            echo "tag ${release_tag} already exists" >&2
            exit 1
          fi

          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git checkout -B main origin/main
          git merge --no-ff "${RELEASE_SHA}" -m "chore(release): ${release_tag}"
          git tag -a "${release_tag}" -m "IAM Core SDK ${release_tag}"
          git push --atomic origin main "${release_tag}"
```

- [ ] **Step 5: Run focused GREEN and static checks**

Run:

```bash
go test . -run '^TestDevPushReleaseWorkflowContract$' -count=1
ruby -e 'require "yaml"; YAML.safe_load(File.read(".github/workflows/ci.yml"), aliases: true)'
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 6: Run root regression gates**

Run:

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

Expected: all packages PASS; vet exits 0.

- [ ] **Step 7: Review the exact release diff**

Run:

```bash
git diff -- VERSION .github/workflows/ci.yml release_workflow_test.go
git status --short
```

Confirm only the three planned files changed, the Tag format is only `vX.Y.Z`, and the release Job contains no force push or ignored failure.

- [ ] **Step 8: Commit the implementation**

Run:

```bash
git add VERSION .github/workflows/ci.yml release_workflow_test.go
git commit -m "ci: release dev to main with version tag"
```

Expected: one commit containing only the three planned files.
