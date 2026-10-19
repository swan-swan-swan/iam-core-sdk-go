# HTTP Catalog 心跳与自动策略废弃实施计划

> **执行方式：** 以冻结 Goal source 为依据，按仓库依赖逐仓 TDD、验证、提交。保留各仓现有未提交业务变更；实施时先检查冲突路径并隔离本 Goal 修改。

**Goal：** SDK 注册成功后维持服务心跳；IAM Core Server 在 15 天无心跳时安全地区分无绑定自动清理与有绑定人工清理，并在管理端展示结果。

**规格：** `docs/superpowers/specs/2026-10-19-http-catalog-heartbeat-policy-retirement-spec.md`

**架构：** `server` 以 `(application_open_id, service)` 持久化注册版本与心跳，以独立来源/贡献关系证明自动策略归属；事务同步保证目录与策略一致，JobKit 检测失联并按绑定状态处理。`client-sdk` 在成功 Sync 后受宿主生命周期控制续约。`web` 只展示服务端计算的状态。

```yaml
kind: standalone-goal
goal_id: GOAL-20261019-001
target_repos:
  - server
  - client-sdk
  - web
repository_dependencies:
  server: []
  client-sdk:
    - server
  web:
    - server
verification:
  server:
    - go test ./internal/models ./internal/repositories ./internal/services ./internal/handlers ./internal/cron ./internal/authorization -count=1
    - go test ./... -count=1
    - go vet ./...
    - git diff --check
  client-sdk:
    - go test ./... -count=1
    - go test -race ./... -count=1
    - go vet ./...
    - go build ./examples/...
    - git diff --check
  web:
    - pnpm vitest run
    - pnpm typecheck
    - pnpm lint
    - pnpm build:prod
    - git diff --check
```

## 约束与实施顺序

先实现 server 接口与持久化，再实现 client-sdk 和 web。目录注册继续完整覆盖 service，不逐次请求管理员授权。心跳只更新 `heartbeat_at`；检测不删除目录、不改绑定和授权派生规则。IAM 内置目录、手工策略、未知来源历史策略均需保守排除。前向 DDL 放在 server 仓的 `sql/standalone/GOAL-20261019-001/` 目录中，检查实际 SQL 规范后确定 DDL/DML 文件名；不修改历史归档 DDL。数据库迁移、运行服务及本地 K8s 发布必须在代码验证后另行执行并记录结果，不能以 Goal Completion 代替部署成功。

每项任务从失败的行为测试开始，记录 RED，做最小 GREEN，再做 focused VERIFY；最终每仓仅执行上面冻结的验证命令。对跨服务策略、绑定/心跳并发、运行时快照和迁移数据必须有断言。新 Go 注释、Swagger、SQL COMMENT 与迁移符合仓库规范。每仓任务只在该仓 TDD、冻结验证与提交完成后勾选本仓 working Plan；冻结源文件保持不变。

## 任务

- [ ] Task 1（server，AC1、AC3、AC6）：注册状态、自动来源与贡献关系

  RED：扩展现有 model/repository/目录同步测试，证明相同 Manifest 仅刷新注册心跳，变更 Manifest 在一个事务内替换 service 目录并更新策略贡献；证明旧版空心跳保持未知、内置目录无 SDK 记录、手动和来源未知策略不会被认领或覆盖；共享策略记录两个 service 的贡献；其他服务的注册不能根据仍保留的失联目录重建已清理策略。运行 `go test ./internal/models ./internal/repositories ./internal/services -count=1` 保存失败证据。

  GREEN：增加 service 注册状态表或等价持久化结构，包含业务唯一键、当前目录 hash、来源、注册时间和可空 `heartbeat_at`；为 Policy Document 增加受控来源、清理状态及贡献关联。扩展 `syncManagedCatalog` 事务边界，把目录、有效贡献过滤、生成策略、贡献、版本和快照统一提交；无变化路径只更新心跳。历史文档保守标为 unknown，只有可证明的生成链对账才认领；冲突返回可诊断错误。增加前向 DDL、必要的迁移/回滚说明和 SQL 检查。保持已有脏改动的语义。

  VERIFY：运行 focused 测试，审查 SQL 索引和无物理外键约束；确认失败事务未推进心跳或快照，无变化注册不重建授权数据。

- [ ] Task 2（server，AC1、AC2、AC6）：机器心跳接口与目录生效确认

  RED：扩展注册 service/handler/authorization 测试，覆盖机器 token 的 service 归属、缺失/错误 hash、旧版本或已达 15 天阈值时冲突、手工或内置 service 拒绝、成功心跳只改一个字段、失败不更新、完整重注册恢复并再生策略。增加响应版本与发布快照一致的测试。运行 `go test ./internal/services ./internal/handlers ./internal/authorization -count=1` 保存 RED。

  GREEN：在现有机器认证链新增专用心跳路由与精确请求/响应 DTO，复用 `TokenSource` 对应的 Bearer 语义和现有 `catalog_service` 绑定校验。仓储用当前 hash 条件写入心跳；服务返回当前 hash/时间状态并记录脱敏审计。完整 Sync 成功响应只有在目录与快照发布完成后才宣称对应版本生效。更新路由声明、OpenAPI/Swagger 与必要的 README 契约。

  VERIFY：运行 focused 测试，确认心跳请求不会触发目录同步、策略对账、绑定或 Casbin 写入；旧实例心跳不可续约新目录。

- [ ] Task 3（server，AC3、AC4、AC5、AC6、AC7）：15 天检测与管理状态

  RED：以可控 UTC 时钟覆盖边界、null 心跳、内置/手工来源、共享贡献、无绑定删除、有绑定保留并标记、恢复、解绑后清理、重复运行，以及并发绑定/心跳。验证有绑定时 Policy Document、bindings、compiled rules、Casbin 输出不变；删除前规则异常时失败关闭。增加管理列表/详情响应的来源、清理状态、绑定数和最后心跳测试。运行 `go test ./internal/services ./internal/repositories ./internal/cron ./internal/handlers -count=1` 保存 RED。

  GREEN：在 service/repository 实现可重试的批量检测与受锁事务内重新校验，JobKit 仅注册每日分布式单例并委托业务 service；错误记录可追踪但不带敏感正文。仅对满足严格条件的 SDK 自动策略删文档/来源记录；有绑定时只写清理标记；有效贡献恢复时清除标记。扩展受管理权限保护的现有策略查询 DTO 与筛选，不新建第二套授权事实。

  VERIFY：运行 focused 测试并检查受影响行、事务隔离、快照/编译规则不变量；在迁移前后样本上核对历史 unknown 行数与 SDK 来源行数。

- [ ] Task 4（client-sdk，AC1、AC2）：受生命周期控制的心跳

  RED：在 `runtime/httpcatalog` 现有测试中用本地 HTTP server 验证 Sync 成功前不续约、默认 24 小时间隔、Bearer 按次获取、hash 携带、版本不符或失联冲突触发重新 Sync、取消 context 立即退出、失败有界退避和健康可观测；同一 RouteSpec 是 Sync 唯一清单来源。运行 `go test ./runtime/httpcatalog -count=1` 保存 RED。

  GREEN：扩展 Registry 的可控启动/停止续约 API，由宿主 context 负责退出；复用 HTTP client、TokenSource 和 Observer，维护成功 Sync 返回的当前 hash。续约不传完整 Manifest、不缓存凭据；冲突执行完整注册或清晰地返回需要重注册的状态，不以失败心跳伪装健康。更新 SDK README 用法，指导下游在启动 Sync 成功后开启续约，并说明多副本及滚动发布的当前 hash 语义。

  VERIFY：运行 focused 测试、race 测试与示例构建；检查 goroutine 生命周期和超时/重试边界。

- [ ] Task 5（web，AC7）：策略状态与人工清理入口

  RED：扩展策略列表/详情与 service 类型测试，覆盖 SDK 自动、内置、手工、历史未知、待人工清理、恢复及筛选；断言页面只显示服务端状态，不用浏览器时间计算 15 天，不显示自动解绑/删除已绑定策略按钮。运行 `pnpm exec vitest run src/pages/System/Policy src/services` 中对应 focused 用例并记录 RED。

  GREEN：扩展现有策略领域服务类型和管理页面，显示来源、最近心跳、绑定数、待人工清理提示及筛选；沿用现有绑定编辑/删除权限和 `src/services/request.ts`，不复制后端贡献规则。复用 Ant Design 组件和页面既有样式。

  VERIFY：运行 focused 测试与 `pnpm typecheck`；在本地管理页检查待清理与正常策略的布局和操作文案。

## 验收与交付

跨仓联调使用真实注册、续约和 15 天检测的可控时钟/样本数据，核对 API 响应 hash、数据库注册状态、策略来源/绑定、编译规则与管理页显示。优先在隔离测试库运行迁移并核对回滚；本地 K8s 部署时保存迁移和 rollout 结果，再触发一次无变化 Sync 与心跳并验证状态。若环境不可用，记录未完成的环境验证，不能声称已部署。Goal Review 按规格 AC1—AC7 逐项检查生产调用点、负面证据和测试断言，完成后按 standalone 流程生成 Product Archive。

## 三轮语义自审

上下文覆盖：server、client-sdk、web 均在冻结仓库列表中；目录覆盖、SDK 心跳、检测、来源区分、共享贡献、两类清理、管理状态和迁移各有任务。

TDD 可执行性：每个任务列出先失败的关键断言、最小实现和 focused 验证；最终仓库命令固定，跨仓联调不替代单仓测试。

对抗边界：来源未知不自动认领；旧 hash 不续约新版本；共享策略只在最后有效贡献消失后处理；绑定和异常规则均阻止删除；心跳与检测不可改目录或授权派生数据；内置目录不走 SDK。
