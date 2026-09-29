# IAM Core Go SDK 最小人员目录与通知资料解析计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `iam-core-sdk-go` 增加面向业务后端的最小人员目录和通知目的地批量解析客户端，让塔哨服务通过调用方注入的机器 Token 搜索、校验明确 IAM 用户并查询所需渠道。

**Architecture:** 新建独立 `management/userdirectory` 与 `management/notificationcontacts` 领域包，复用 `management/client.Transport`、`TokenSource`、错误解码和 Observer。人员目录与通知目的地保持不同权限和模型；SDK 不承载管理员资料维护或飞书同步，也不获取、缓存或刷新 Token。

**Tech Stack:** Go 1.24、标准库 HTTP、IAM Core SDK 现有 management transport。

**Spec:** `docs/superpowers/specs/2026-09-29-notification-contact-sdk-spec.md`

## 冻结执行身份

```yaml
kind: standalone-goal
goal_id: GOAL-20260929-001
target_repos:
  - client-sdk
repository_dependencies:
  client-sdk: []
verification:
  client-sdk:
    - go test ./... -count=1
    - go test -race ./... -count=1
    - go vet ./...
    - go build ./examples/...
    - git diff --check
```

服务端 `GOAL-20260925-002` 已完成并完成本地 Kubernetes 验收。本文件与同仓规格提交后构成后继 Goal 的冻结来源；本 Goal 不修改服务端。

## Global Constraints

- 本计划只修改当前 `client-sdk` 仓库。
- SDK 不接收飞书 App Secret、OIDC Client Secret，不调用 Token Endpoint，也不缓存联系方式。
- 人员目录只提供账号/显示名搜索和明确主体批量校验；通知资料只提供明确主体目的地解析。不提供部门、角色、标签或用户组展开。
- 单次最多 100 个主体；渠道只允许 `email|sms|feishu_app`。
- 错误、Observer 和测试输出不得包含 Token、手机号、邮箱或完整响应正文。

### Task 1: 建立最小人员目录领域包

**Files:**
- Create: `management/userdirectory/model.go`
- Create: `management/userdirectory/client.go`
- Create: `management/userdirectory/client_test.go`

**Interfaces:**
- Produces: `New(transport)`、`Search(ctx, query, limit)`、`BatchGet(ctx, subjectIDs)`、`UserStatus`。

- [x] **Step 1: 写搜索、批量校验和非敏感模型 RED 测试**

覆盖空白/超长 query、limit 1..50、最多 100 个 subject、输入去重与首次顺序、active/inactive/not_found；公开模型不得包含 email、mobile、roles、department 或 Service Account 字段。

- [x] **Step 2: 运行 RED**

Run: `go test ./management/userdirectory -count=1`

- [x] **Step 3: 复用 management transport 实现目录 Client**

`Search` 调用 `GET /api/v1/user-directory/users`，`BatchGet` 调用 `POST /api/v1/user-directory/users:batch-get`；方法返回现有 `management.Metadata`，不做业务重试或本地缓存。

- [x] **Step 4: 验证并提交**

Run: `go test ./management/userdirectory -count=1 && git diff --check`

```bash
git add management/userdirectory
git commit -m "feat(management): query minimal user directory"
```

### Task 2: 建立通知资料解析领域包

**Files:**
- Create: `management/notificationcontacts/model.go`
- Create: `management/notificationcontacts/client.go`
- Create: `management/notificationcontacts/client_test.go`

**Interfaces:**
- Produces: `New(transport)`、`BatchResolve(ctx, input)`、`Channel`、`SubjectResult`、`Destination`。

- [ ] **Step 1: 写输入校验和响应模型 RED 测试**

```go
func TestBatchResolveRejectsMoreThanOneHundredSubjects(t *testing.T) {
    input := notificationcontacts.BatchResolveInput{SubjectIDs: make([]string, 101), Channels: []notificationcontacts.Channel{notificationcontacts.ChannelEmail}}
    _, _, err := client.BatchResolve(context.Background(), input)
    require.Error(t, err)
}
```

覆盖空主体、重复主体、未知渠道、响应顺序、active/inactive/not_found、可用/缺失目的地和调用方输入不被修改。

- [ ] **Step 2: 运行 RED**

Run: `go test ./management/notificationcontacts -count=1`

- [ ] **Step 3: 复用 management transport 实现 BatchResolve**

客户端向 `POST /api/v1/notification-contacts:batch-resolve` 发送请求；去重保留首次出现顺序。方法返回现有 `management.Metadata`，不在 SDK 内做业务重试。

- [ ] **Step 4: 验证并提交**

Run: `go test ./management/notificationcontacts -count=1 && git diff --check`

```bash
git add management/notificationcontacts
git commit -m "feat(management): resolve notification contacts"
```

### Task 3: 冻结管理合同并验证敏感边界

**Files:**
- Modify: `management/contract_test.go`
- Modify: `management/testdata/contract-v1.8.1.json`
- Modify: `management/security_test.go`
- Modify: `management/dependency_test.go`
- Modify: `README.md`
- Modify: `SPEC.md`

**Interfaces:**
- Produces: 新领域 `userdirectory`、`notificationcontacts` 和三个获批准的管理端点；文档说明调用方注入 `TokenSource`，并区分目录与通知资料权限。

- [ ] **Step 1: 写合同清单、依赖方向和敏感错误 RED 测试**

断言两个包只依赖公共 management transport；合同文件包含且只包含冻结路径；401、403、5xx、无效 JSON 和取消请求不回显 Authorization、查询结果或目的地值。

- [ ] **Step 2: 运行 RED**

Run: `go test ./management/... -run 'Contract|UserDirectory|NotificationContact|Sensitive|Dependency' -count=1`

- [ ] **Step 3: 更新合同 fixture 与使用文档**

不自行发布新 SDK 版本号；沿用仓库当前合同 fixture 命名并按现有门禁更新端点数。示例使用假用户 ID 和假目的地。

- [ ] **Step 4: 全仓验证**

Run: `go test ./... -race -count=1 && go vet ./... && git diff --check`

- [ ] **Step 5: 提交任务**

```bash
git add management/contract_test.go management/testdata/contract-v1.8.1.json management/security_test.go management/dependency_test.go README.md SPEC.md
git commit -m "docs(management): freeze notification contact contract"
```

## 交付边界

- 管理员用户管理、通知资料查询/修改、同步开关和人工绑定继续由 IAM Core Web 直接调用服务端管理 API。
- `beacon-server` 使用 `management/userdirectory` 搜索和校验值班成员，不请求通知目的地。
- `notify-server` 在自己的 IAM 适配层注入机器 `TokenSource`，并依据每个结果的 `available` 决定该渠道能否创建发送记录。
