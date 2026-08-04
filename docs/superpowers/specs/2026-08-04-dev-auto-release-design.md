# Dev 分支自动发布设计

## 目标

当代码推送到 `dev` 分支时，先执行仓库现有的完整 CI。全部 CI Job 通过后，自动将该次 `dev` 提交合并到 `main`，再根据根目录 `VERSION` 创建并推送 SDK Tag。

## 版本与 Tag

- 根目录新增 `VERSION` 文件，内容只保存版本号，例如 `0.2.0`。
- Workflow 将版本转换为唯一 Tag `v0.2.0`。
- 版本必须符合 `X.Y.Z` 三段数字格式。
- 如果对应 Tag 已存在，发布 Job 失败，不继续合并或推送。
- 每次只创建一个根 Tag `vX.Y.Z`。
- 不创建 `adapters/gin/...` 或 `adapters/redis/...` Tag。

## Workflow

直接修改现有 `.github/workflows/ci.yml`，新增 `release` Job，不创建额外发布系统。

现有四个 CI Job 保持不变：

- `root`
- `gin`
- `redis`
- `integration`

`release` Job 满足以下条件时运行：

- 事件是 `push`；
- 分支是 `dev`；
- 上述四个 CI Job 全部成功。

发布步骤：

1. 以完整 Git 历史检出本次 `dev` 提交。
2. 读取并校验根目录 `VERSION`。
3. 获取远端 `main`、`dev` 和 Tags。
4. 确认 `vX.Y.Z` 尚不存在。
5. 从远端 `main` 创建本地 `main` 分支。
6. 将本次 Workflow 对应的精确 `dev` commit 合并到 `main`。
7. 在合并后的 commit 上创建 annotated Tag `vX.Y.Z`。
8. 推送 `main` 和该 Tag。

## 权限与失败行为

- 现有 CI Job 保持 `contents: read`。
- 仅 `release` Job 使用 `contents: write`，通过 GitHub Actions 自动令牌推送。
- 不使用 force push。
- CI 失败、版本非法、Tag 已存在、合并冲突或推送失败时，发布 Job 失败。
- Workflow 不修改 GitHub 分支保护设置；如果仓库规则禁止 Actions 推送 `main`，发布会失败并显示 Git 错误。

## 验证

实现时先增加失败的静态契约测试，再修改 Workflow：

- `VERSION` 存在且内容为 `0.2.0`；
- `release` Job 依赖四个 CI Job；
- 仅 `dev` push 执行发布；
- Tag 使用 `v` 加 `VERSION`；
- Tag 已存在时失败；
- 合并目标是 `main`；
- Workflow 推送 `main` 和唯一根 Tag；
- 不创建 adapter Tag；
- 不包含 force push、跳过 CI 或容错忽略失败的命令。

完成后运行根测试、Workflow YAML 解析、`git diff --check` 和工作区状态检查。
