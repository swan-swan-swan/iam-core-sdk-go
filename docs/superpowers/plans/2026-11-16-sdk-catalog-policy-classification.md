> SDK working Plan：此文件为冻结计划的执行副本；唯一正式来源位于 IAM Server，commit `9f05a79f23435a2b79f9106d1ddac40484cc1b0a`，原计划 SHA-256 `f1c962cad8cc33cfec2b9f30d12b327df7823c2bf6563949954417e97c2155d3`。
> 仅记录 client-sdk 已完成的适用义务；跨仓 T7/T8 的完整链路和展示验收由主 Goal 继续，保持未勾选。

# SDK Catalog Policy Classification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. 当前只编写并提交文档；不启动实现、迁移或部署。默认由当前持续agent内联执行，不以本计划自动授权子代理。

**Goal:** 沿Ops Gateway → SDK → IAM完整链路交付显式FullAccess/ReadOnlyAccess/CardAccess分类，使卡片入口准确命名，并以授权等价的原位迁移保留现有绑定和SDK来源。

**Architecture:** 在兼容新增SDK API上提供Manifest v4分类事实；IAM按Application聚合并统一生成策略，使用完整bundle、基线CAS及候选快照一次性切换；Ops Gateway从同一classified声明完成PDP保护、Catalog登记和多节点发布。业务代码交付与真实维护窗口分开。

**Tech Stack:** Go 1.24+、Gin、Fx、GORM、MySQL 8、Redis；IAM SDK `/v3`；现有Vitest/Testing Library用于必要的Web展示fixture验证。

**Spec:** [正式规格](../specs/2026-11-16-sdk-catalog-policy-classification-design.md)，身份`SPEC-20261116-CATALOG-POLICY-CLASSIFICATION`。必须连同本计划完整读取，不从聊天摘要补齐范围。

## Global Constraints

- 当前批准仅编写、校验及提交这两份文档；实现、SDK发布、真实SQL、部署及用户权限变更均未批准。
- CardAccess仅包含普通应用卡片open、适用的cloudroles/cloudaccounts；门户discover与OPSGW管理Realm入口排除。
- 分类精确为FullAccess、ReadOnlyAccess、CardAccess；分类不改Action/Resource/Method和目标应用原生权限。
- 保持既有SDK四字段公共类型和v3JSON/digest；使用新增ClassifiedRouteSpec及v4Registry，不修改Go module `/v3`。
- v4分类进入Manifest/Catalog/网关发布hash；既有protocol_version=v2不是Manifest schema版本。
- 同Application同Action跨service分类必须一致；未知/缺失/冲突及降级失败关闭，不自动转换。
- 迁移逐角色规则及候选PDP决策等价；纯重命名保留文档身份、绑定、正文hash及sdk_auto来源。
- SDK/Server/网关各自职责、兼容窗口及独立生产批准以Spec为准；不修改受管Harness，Ops Gateway不得伪装成本工作区目标。
- 采用usecase事务、现有快照准备/发布及CAS，MySQL无物理外键，中文注释与GORM/SQL字段映射一致。
- 保留执行前记录的所有无关dirty；只暂存任务文件，不修改或混入现有服务账号、Redis、配置变更。

## 目标仓及执行顺序

以下是Harness冻结本计划所需的执行元数据，补齐原提交遗漏；它不改变0c71c04的产品语义、验收义务或生产禁令。Goal ID为拟用身份，正式state尚未创建。

```yaml
kind: standalone-goal
goal_id: GOAL-20261116-001
target_repos:
  - client-sdk
  - server
  - ops-gateway-server
repository_dependencies:
  client-sdk: []
  server: [client-sdk]
  ops-gateway-server: [client-sdk, server]
verification:
  client-sdk:
    - go test ./... -count=1
    - go test -race ./... -count=1
    - go vet ./...
    - go build ./examples/...
    - git diff --check
  server:
    - go test ./... -count=1
    - go vet ./...
    - go build ./cmd/...
    - git diff --check
  ops-gateway-server:
    - go test ./... -count=1
    - go vet ./...
    - go build ./cmd/...
    - git diff --check
```

冻结时分别读取IAM与Ops Gateway两个父工作区的effective配置，按原仓ID和原owner取出上述三仓的只读并集，保存owner配置hash、真实仓路径及base commit为执行sidecar；不修改任何harness.yaml，不把网关伪装成IAM工作区内的仓。各仓action仍在其owner工作区校验路径、规则及验证证据。无法证明任一仓在其owner配置中启用、身份不一致或存在同名不同仓时，拒绝冻结，不以手工传入enabled=true绕过。web仅为条件展示验收范围；若发现需修改Web生产代码，须先修订冻结目标而不现场扩大三仓实现范围。

| 标识 | 物理仓库（当前工作机） | 范围 |
| --- | --- | --- |
| server | `/Users/wuhaolai/Documents/Project/iam-core/iam-core-server` | 协议接收、持久化、生成、迁移工具和主规格/计划 |
| client-sdk | `/Users/wuhaolai/Documents/Project/iam-core/iam-core-sdk-go` | 公共分类、v4声明/Registry/导出及兼容验证 |
| ops-gateway-server | `/Users/wuhaolai/Documents/Project/ops-gateway/ops-gateway-server` | 另一Harness工作区内的调用方声明和发布链 |
| web | `/Users/wuhaolai/Documents/Project/iam-core/iam-core-web` | 仅发现必要时调整名称fixture和现有展示测试 |

依赖：T1 → T2；T1 → T3 → T4 → T5；T2/T4 → T6；T2/T5/T6 → T7；T7 → T8。这是同一注册协议修复，不拆成可独立批准的无关功能。每仓任务采用TDD，完成仓库范围验证后提交，不执行生产命令。

正式实现前读取各父工作区与目标仓AGENTS/SPEC；主工作区执行server/client-sdk/web，网关部分在其自己的有效repo map中执行，并引用同一已提交spec/plan。不得为跨工作区方便现场修改Harness配置或跳过身份校验。

## 顶层任务状态

- [x] T1：冻结v4 wire合同与公共分类验证。
- [x] T2：SDK兼容新增classified声明、Registry及完整清单导出。
- [ ] T3：IAM分类持久化、hash、协议状态与并发锁边界。
- [ ] T4：IAM分类生成、名称词汇及v4注册发布。
- [ ] T5：完整Application预检、授权等价原位迁移与CLI。
- [ ] T6：Ops Gateway全链显式分类、旧payload兼容与新快照发布。
- [ ] T7：真实SDK到IAM的跨仓协议/迁移/恢复验证。
- [ ] T8：仓库完成验证、UI验收证据及独立上线runbook。

## T1：分类合同和golden fixture（client-sdk、server）

**Files**

- Create SDK：`runtime/authzcontract/policy_class.go`、`runtime/authzcontract/policy_class_test.go`。
- Create SDK：`docs/iam-core-catalog-v4-policy-classification-contract.md`、`runtime/httpcatalog/testdata/classified-manifest-v4.json`。
- Create Server：`internal/services/testdata/classified-manifest-v4.json`，字节内容来自同一fixture。
- Modify SDK：`COMPATIBILITY.md`、`README.md`；Server命名文档在T4更新。

**Interfaces**

```go
// PolicyClass 表示代码声明的策略类别。
type PolicyClass string
const (
    PolicyClassFullAccess PolicyClass = "FullAccess"
    PolicyClassReadOnlyAccess PolicyClass = "ReadOnlyAccess"
    PolicyClassCardAccess PolicyClass = "CardAccess"
)
func ValidatePolicyClass(method, action string, class PolicyClass) error
```

Server实现同样的精确值与验证语义，但不为校验引入业务SDK对Server的循环依赖；用共享fixture校验一致性。Action解析复用各自已有公共合同。

- [ ] RED：table-driven测试允许GET/access/Card、POST/select/ReadOnly、POST/execute/Full；拒绝空值、`cardaccess`、未知值、DELETE/delete/ReadOnly、GET/reveal/ReadOnly、POST/access/Card、GET/select/Card。

```go
func TestPolicyClassRejectsMutationAsReadOnly(t *testing.T) {
    if err := ValidatePolicyClass("DELETE", "opsgw:application:delete", PolicyClassReadOnlyAccess); err == nil {
        t.Fatal("delete must not be classified read-only")
    }
}
```

- [ ] 运行SDK：`go test ./runtime/authzcontract -run PolicyClass -count=1`，确认因缺失接口/错误分类失败。
- [ ] GREEN：增加上述类型和验证器，已有ParseAction负责命名/动词；ReadOnly白名单`select/discover/preview/export`，Card要求GET/access，Full不推断类别。
- [ ] 编写v4fixture：使用Spec中的Jenkins例子及一条应用查询ReadOnly、一条配置写Full，routes乱序输入后规范输出；记下规范字节及独立计算SHA-256，不手填任意digest。
- [ ] VERIFY：分类测试通过；文档写明Full/ReadOnly集合关系、Card-only不重复生成、三种类型不替代system/custom。
- [ ] 提交仅本任务文件，记录SDK和Server不可变SHA；fixture复制到Server不代表SDK已发布。

## T2：SDK兼容新增v4（client-sdk）

**Files**

- Create：`runtime/httpauthz/classified_manifest.go`、`runtime/httpauthz/classified_manifest_test.go`。
- Create：`runtime/httpcatalog/classified_registry.go`、`runtime/httpcatalog/classified_registry_test.go`。
- Modify：`runtime/httpcatalog/registry.go`、`runtime/httpcatalog/client.go`、已有`registry_test.go`、`heartbeat_test.go`、`registrar_auth_test.go`、`runtime/httpauthz/manifest_test.go`。
- Modify：`examples/runtime`中当前Catalog示例及T1协议文档。

**Consumes**：T1的PolicyClass及ValidatePolicyClass。

**Produces**

```go
type ClassifiedRouteSpec struct {
    Spec RouteSpec
    PolicyClass authzcontract.PolicyClass
}
func NewClassifiedRouteSpec(method, template, name, action string, class authzcontract.PolicyClass) (ClassifiedRouteSpec, error)
// httpcatalog内的ClassifiedRoute按五个wire字段序列化。
// ClassifiedManifest保留既有头字段，Routes为[]ClassifiedRoute。
func NewClassifiedRegistry(config Config) (*Registry, error)
func (r *Registry) RegisterClassified(spec httpauthz.ClassifiedRouteSpec) error
func (r *Registry) ExportClassifiedManifest() (ClassifiedManifest, error)
func (m ClassifiedManifest) ManifestDigest() (string, error)
```

- [ ] RED：用httptest捕获真实PUT注册body，断言schema=4、五字段及类别；旧v3原始body逐字节不变；同名不同class拒绝，class-only修改产生新hash；Register/Registry模式用错拒绝。

```go
func TestClassifiedSpecPreservesPDPFacts(t *testing.T) {
    got, err := NewClassifiedRouteSpec("GET", "/api/v1/apps/:id/open", "portal.app.jenkins.open", "opsgw:jenkins:access", authzcontract.PolicyClassCardAccess)
    if err != nil { t.Fatal(err) }
    want, err := NewRouteSpec("GET", "/api/v1/apps/:id/open", "portal.app.jenkins.open", "opsgw:jenkins:access")
    if err != nil || got.Spec != want { t.Fatal("classification changed PDP route facts") }
}
```

- [ ] 运行：`go test ./runtime/httpauthz ./runtime/httpcatalog -run 'Classified|RouteJSON|DeterministicV3' -count=1`，确认真实报文和digest断言先失败。
- [ ] GREEN：新增wrapper类型和独立v4wire类型，Registry内部选择单一v3或v4事实存储；不在v4遇错时剥掉class；PDP沿用Spec；Export只返回不可变副本，无网络与持久化副作用。
- [ ] 增加Registrar Basic认证、response digest核对、ManifestChanged、generation冲突及heartbeat测试；记录旧SDK支持范围。
- [ ] VERIFY：`go test ./runtime/authzcontract ./runtime/httpauthz ./runtime/httpcatalog -count=1`、`go test -race ./runtime/httpcatalog -count=1`；T1双fixture摘要一致。
- [ ] 提交本任务，提供可供网关集成的真实commit；发布版本/tag由独立发布流程处理，不本地创建tag或永久replace。

## T3：IAM持久化与协议状态（server）

**Files**

- Modify：`internal/models/http_resource_catalog.go`、`http_catalog_route_lifecycle.go`、`http_catalog_service_registration.go`。
- Create：`internal/models/http_catalog_policy_contract.go`（同时定义协议状态与成功迁移记录）、`internal/repositories/http_catalog_policy_contract_repository.go`、`internal/repositories/http_catalog_policy_contract_test.go`。
- Modify：`internal/repositories/http_resource_catalog_repository.go`、`http_catalog_route_lifecycle_repository.go`、现有`http_catalog_generation_test.go`/`http_catalog_registration_test.go`。
- Create：`sql/standalone/GOAL-20261116-001/DDL/001-catalog-policy-classification.sql`。此处只固定未来DDL路径，不创建Goal运行状态。

**Interfaces**：`HTTPMethodMappingRecord.PolicyClass`与持久模型同名；注册record具有独立的ManifestSchemaVersion/PublishedManifestSchemaVersion。新增`HTTPCatalogPolicyContractRepository`按Application公开ID读取/锁定契约及读取/插入不可变migration结果，所有写路径沿用WithTx。复用GetApplication/ResolveApplicationForUpdate父行锁，顺序为Application、契约、service；审计现有策略/绑定写入及失联废弃是否遵循该顺序，缺失者同步接入。

- [ ] RED：实际Repository往返测试从v4定义写入再ListCatalog，断言class保留；v3hash不变；class-only差异改变v4hash；旧protocol_version仍为v2且schema独立；两个并发迁移只能一个取得相同基线。
- [ ] 运行：`go test ./internal/repositories -run 'PolicyContract|CatalogGeneration|CatalogRegistration' -count=1`，确认class/锁边界缺失产生失败。
- [ ] GREEN：DDL新增两个policy_class列、注册schema列、契约表和不可变迁移记录表；字段/索引按Spec第6节，使用MySQL8、unsigned、中文COMMENT，无物理外键。v3hash用原结构，v4hash含class/schema；读取不默认补FullAccess。成功记录和目录切换同事务提交，历史ID/digest可重放核验。
- [ ] 同步已有SQLite fixture/schema及bootstrap迁移注册点；不得只修运行路径而留下同包旧fixture编译/列缺失。
- [ ] VERIFY：`go test ./internal/models ./internal/repositories -count=1`；使用隔离MySQL8验证DDL与事务并发，比较v3旧fixture hash。执行测试仅使用明确的临时测试库。
- [ ] 提交本任务，保持真实环境SQL未执行。DDL列和tag差异必须与Spec一致。

## T4：IAM v4接收与策略生成（server）

**Files**

- Modify：`internal/handlers/http_catalog_registration_handler.go`及其测试；`internal/services/http_catalog_registration_service.go`及其测试。
- Modify：`internal/services/http_resource_catalog_service.go`、`http_catalog_system_policy.go`、`http_catalog_system_policy_test.go`、`http_resource_catalog_service_scope_test.go`。
- Create：`internal/services/http_catalog_policy_classification.go`、`http_catalog_policy_classification_test.go`。
- Modify：`internal/services/authorization_policy_vocabulary.go`及测试、`docs/authorization-policy-vocabulary.md`；必要时同步HTTP Catalog DTO及生成文档。

**Consumes**：T3的classified Catalog与契约行；T1的wirefixture。

**Produces**：`BuildClassifiedHTTPCatalogSystemPolicyDefinitions(catalog)`只处理全分类v4目录；原`BuildHTTPCatalogSystemPolicyDefinitions`保留v3，协调器依据Application契约显式选择。v4注册复用代次协议，不改PDP输入。

- [ ] RED：同domain混合read/full/card生成三份精确正文；纯card只一份；GET execute不进ReadOnly；相同Action跨service冲突拒绝；缺失class和unknown字段拒绝；v3仍生成原名字。
- [ ] 运行：`go test ./internal/services ./internal/handlers -run 'Classified|PolicyClass|CatalogRegistration|SystemPolic' -count=1`，确认分类/名称断言失败。
- [ ] GREEN：按Spec集合公式生成名称及文档；Full/ReadOnly/Card中文分别完整访问/只读访问/应用卡片访问。schema=3/4严格解码，无把v4当v3；保存class、重新从DB读回聚合并校验跨service一致性，冲突回滚。
- [ ] 将内置全局、SelfAccess及v3Application保持原路径；授权来源仍由精确贡献生成sdk_auto。不依靠目前无生产调用的词汇辅助函数制造“已修复”假象。
- [ ] VERIFY：完整services/handlers/repositories包通过；运行`go run ./cmd/authzsql -out <临时绝对目录>`比较内置v3导出不变，不手改000–004。若公共API文档变化，通过既有脚本生成并检查差异。
- [ ] 提交本任务；普通v4首次Application注册须明确初始化schema4契约，仅无已有受管/人工旧目录的新Application允许，已有Application必须走T5。

## T5：预检、原位迁移与维护CLI（server）

**Files**

- Create：`internal/services/http_catalog_policy_migration.go`、`http_catalog_policy_migration_test.go`。
- Create：`cmd/catalogpolicy/main.go`、`main_test.go`。
- Modify：`internal/services/http_catalog_system_policy.go`中的候选/历史别名与来源协调、`internal/repositories/http_catalog_system_policy_repository.go`及来源/生命周期Repository。
- Create：`docs/runbooks/catalog-policy-classification-migration.md`。

**Interfaces**

```go
// 输入/输出模型定义在迁移服务内，不含凭据。
type PolicyMigrationRequest struct {
    Application string
    Direction string
    Manifests []HTTPRouteManifest
    Recovery *PolicyMigrationRecovery
}
type PolicyMigrationPlan struct {
    SchemaVersion int
    MigrationID string
    Direction string
    ApplicationOpenID string
    BaselineRevision uint64
    BaselineHash string
    BindingHash string
    ServiceSetHash string
    Services []PolicyMigrationServiceBaseline
    Manifests []HTTPRouteManifest
    ManifestDigests []string
    NameMappings []PolicyMigrationNameMapping
    RoleDiffs []PolicyMigrationRoleDiff
    Recovery PolicyMigrationRecovery
    Digest string
    CreatedAt time.Time
    ExpiresAt time.Time
}
type PolicyMigrationServiceBaseline struct {
    Service string
    AcceptedGeneration uint64
    PublishedGeneration uint64
    ManifestHash string
    PublishedManifestHash string
    CatalogHash string
}
type PolicyMigrationNameMapping struct {
    DocumentOpenID string
    OldName string
    NewName string
    DocumentHash string
    BindingHash string
    SourceKind string
}
// RuleDiff记录精确坐标，RoleDiff还包含候选PDP decision的前后差异。
type PolicyMigrationRule struct {
    Action string
    Resource string
    Method string
    Effect string
}
type PolicyMigrationRoleDiff struct {
    RoleOpenID string
    Added []PolicyMigrationRule
    Removed []PolicyMigrationRule
    ChangedDecisions []PolicyMigrationRule
}
type PolicyMigrationRecovery struct {
    ForwardMigrationID string
    ForwardPlanDigest string
    OriginalManifests []HTTPRouteManifest
    OriginalMappings []PolicyMigrationNameMapping
}
type PolicyMigrationResult struct {
    ApplicationOpenID string
    MigrationID string
    Digest string
    Revision uint64
    CompletedRevision uint64
    SchemaVersion int
    Status string
    AuthorizationHash string
    BindingHash string
    SourcesVerified bool
    RulesEquivalent bool
}
// JSON报告还须包含Spec要求的per-service代次/摘要、名称映射和逐角色diff。
func (s *HTTPCatalogPolicyMigrationService) Plan(ctx context.Context, req PolicyMigrationRequest) (PolicyMigrationPlan, error)
func (s *HTTPCatalogPolicyMigrationService) Apply(ctx context.Context, plan PolicyMigrationPlan) (PolicyMigrationResult, error)
func (s *HTTPCatalogPolicyMigrationService) Inspect(ctx context.Context, application string) (PolicyMigrationResult, error)
```

JSON采用对应snake_case显式tag并加入序列化契约测试；schema固定1，direction为v3_to_v4/v4_to_v3。RoleOpenID使用公开身份输出，生产Casbin检查仍使用内部subject。Recovery的ForwardPlanDigest在前向plan中为空；反向plan中引用保存的前向plan实际digest，避免本文件digest自引用。每份manifest最多1MiB，bundle最多32MiB/128个service。

- [ ] RED：用真实SQLite事务fixture和现有编译器构造旧Access、新Card同正文；调用Plan验证DB无写，Apply断言id/open_id/binding/docHash不变、sdk_auto保留、全部服务名称引用改写；第二次Apply返回already_applied且revision不增加。
- [ ] 增加反例：30分钟过期、角色绑定漂移、service集合变化、部署代次变化、未知来源、目标名称正文不等、未知引用、人工策略撞名、Deny变化、分拆权限diff；均断言事务零发布。已完成的相同ID/digest即使过期或有更晚合法revision仍返回原完成结果与当前revision，不先走stale/TTL失败分支。
- [ ] 运行：`go test ./internal/services -run PolicyMigration -count=1`，确认迁移入口/身份/等价断言失败。
- [ ] GREEN：Plan从现有完整目录和绑定构造基线hash，纯内存编译候选；Apply先按契约行/service顺序锁定并重验全部基线，再原位改名/安全合并、更新来源和派生规则、准备候选快照、写schema4/新revision及幂等审计。对既有Casbin subject继续使用内部身份，不把open_id当subject。
- [ ] 在写入前对所有角色规则及当前精确坐标PDP决策比较，覆盖ServiceAccount复用角色和Deny；差异非空拒绝，不在CLI暴露force/skip-check开关。
- [ ] 实现CLI的plan/apply/inspect参数及严格单JSON解码；plan/inspect数据库只读，输出权限事实不含secret。Apply只消费已校验报告；应用和输入digest不匹配即拒绝。实现显式`plan --direction v4-to-v3 --recovery <原前向plan> --manifests <新代次v3bundle>`，从不可变成功记录核验恢复资格，发现任何切换后语义/绑定漂移即拒绝，普通注册仍禁止降级。
- [ ] VERIFY：失败注入逐点覆盖改名后、绑定后、来源后、候选准备后和提交后进程退出；提交前完全回滚，提交后Inspect/重放恢复同一migration。隔离MySQL上验证真实锁与并发；TTL、大小上限、错误输出脱敏有测试。
- [ ] 提交本任务。runbook写出完整bundle、预检、维护窗口、apply、inspect及受控反向迁移步骤，不能把代码完成写成迁移完成。

## T6：Ops Gateway调用方与多节点快照（ops-gateway-server）

**Files**

- Modify：`go.mod`/`go.sum`；`internal/iam/permissions.go`、`authorized_router.go`、`catalog_manager.go`、`catalog_publication.go`、`runtime.go`及现有对应测试。
- Modify：`internal/routers/portal_application_policy.go`、`router.go`、`portal_application_policy_test.go`、`current_portal_route_test.go`。
- Modify：`internal/gateway/catalog_publication.go`、`catalog_publication_test.go`；`internal/services/gateway_catalog_coordinator.go`及其测试、`gateway_catalog_coordinator_test.go`。
- Modify：`internal/config/config.go`、配置测试、`configs/application.yaml`，通过统一配置绑定manifest_schema_version。
- Create：`cmd/catalogmanifest/main.go`及测试；更新网关Catalog接入文档。

**Consumes**：T2兼容新SDK正式可达版本；T4/T5Server合同。不得把当前IAM工作区外的仓路径伪造成Harness目标。

**Produces**：Permission携带PolicyClass；动态Manifest/完整CatalogPublication携带`[]httpauthz.ClassifiedRouteSpec`；`catalogmanifest export --out /abs/manifest.json`从同一静态声明和数据库联合快照只读导出v4完整Manifest，不初始化HTTP服务、后台心跳或执行目录注册。

- [ ] RED：构造普通应用、cloud_sso、RealmAdmin redirect、disabled/invalid配置，验证第2节精确范围；普通应用open为Card，cloudaccounts仅cloud_sso，Admin入口Full，门户discover为ReadOnly。
- [ ] 增加publication round-trip/class-only digest测试；旧payload在schema4拒绝、schema3兼容；并发旧节点不能确认新合同；导出过程无网络注册/DB写，导出与运行Manifest一致。
- [ ] 运行：`go test ./internal/iam ./internal/routers ./internal/gateway ./internal/services ./internal/config -run 'Classified|Catalog|PortalApplication|Permission|Publication' -count=1`，确认类别/快照断言失败。
- [ ] GREEN：所有静态Permission逐项给class，动态resolver按应用模式给class，Runtime仅从同一wrapper取Spec用于PDP；CatalogManager在配置4使用ClassifiedRegistry，在显式准备模式3使用Spec构建旧Registry并可独立导出4。禁止请求中修改Manifest和另建分类Map。
- [ ] 修改CatalogPublication format=2、兼容合同、持久化payload及coordinator重建；不只修改JSON序列化却遗漏内存等值比较。切换用已有revision/CAS，新节点未满足已发布目录及IAM hash前不Ready。
- [ ] VERIFY：上述完整包测试、导出CLI测试、现有多节点fixture；编译`go build ./cmd/...`，确认SDK真实依赖可解析且无永久本地replace。
- [ ] 提交网关任务，保留schema3准备配置，不发布服务、不创建SDK tag。

## T7：完整链路与迁移恢复验收（server、client-sdk、ops-gateway-server）

**Files**

- Create Server：`internal/services/http_catalog_policy_cutover_integration_test.go`，仅使用受控fixture/临时库。
- Modify Gateway：`internal/integration/multinode_fixture.go`及已有多节点验收测试；按仓库测试构建标签运行。
- Modify SDK：已有`classified_registry_test.go`补跨组件固定报文、错误响应回归。

**Interfaces**：仅消费T1–T6接口，不发明第二套Manifest/策略编译器；测试中SDK真实序列化请求经过IAM注册handler/service和Repository，候选快照由生产编译器生成。

- [ ] RED：旧v3Catalog及绑定基线 → 同源v4导出 → Plan → Apply → 新SDK完整Sync → 心跳 → PDP，先证明旧实现无法生成CardAccess或保持迁移身份。
- [ ] 覆盖两个service同Application的完整/缺失bundle，预检后并发绑定/目录变化，目标同名冲突，失败注入，以及普通用户/ServiceAccount显式Deny。对照规则及实际decision逐一断言。
- [ ] 验证新Application v4可首次登记；旧Application普通v4注册不能绕过迁移；一个Application切换不改变另一个v3Application的名称/授权/心跳。
- [ ] 验证旧SDK完整注册被catalog_schema_downgrade拒绝，旧心跳失败后不自动重注册；v4高代次合法清单可继续演进。
- [ ] 进行维护窗口和反向恢复演练：保存基线、切换、注入合法后续绑定变化、旧快照反向覆盖必须拒绝；无漂移恢复采用新迁移ID和更高代次，不恢复旧revision。
- [ ] VERIFY：跨仓golden digest一致，三仓最终HEAD的包/集成验证通过；报告每个AC使用的实现/测试/证据路径以及尚未执行的生产操作。
- [ ] 按实际变更逐仓提交，不把本计划勾选等同部署完成；遇到不在范围内的失败记录基线并定位，不顺手改其他业务。

## T8：完成检查、展示与上线runbook（server、client-sdk、ops-gateway-server、必要时web）

**Files**

- Modify Server：T5的`docs/runbooks/catalog-policy-classification-migration.md`及词汇文档。
- Modify SDK：协议/兼容文档、示例。
- Modify Gateway：接入/发布文档及需要的测试fixture。
- Modify Web（仅必要时）：`src/pages/System/Policy/story-6.4.test.tsx`等实际消费名称的既有fixture；不添加前端命名规则，不调整布局。

- [ ] 在每个仓记录精确HEAD及验证命令，按以下矩阵完成本地验证。
- [ ] 用隔离环境浏览器验证策略标识、应用卡片访问中文名、SDK自动注册来源、原角色绑定及入口成功/拒绝；浏览器默认Codex内置，Ego Lite仅用户明确指定时使用。真实账号/权限操作需另行批准，不因已有登录态自动执行。
- [ ] 核对AC-01至AC-14均有证据；单独列出生产DDL、SDK发布、部署、plan/apply和账号验收的未执行项。
- [ ] 输出单一维护runbook：server升级 → SDK发布 → gateway准备模式 → 导出/plan → 维护窗口批准 → apply → gateway4 → inspect/验收 → 30天窗口清点后退役v3。真实SQL由维护者按批准执行，不在代码交付阶段自动运行。
- [ ] 复核新旧工作区dirty归属，只提交当前变更；完成code review、治理及目标级验证后才记录代码完成。

## 最终验证命令

| 仓库 | 命令（该仓工作目录） |
| --- | --- |
| SDK | `go test ./... -count=1`；`go test -race ./... -count=1`；`go vet ./...`；`go build ./examples/...`；`git diff --check` |
| Server | `go test ./... -count=1`；`go vet ./...`；`go build ./cmd/...`；`git diff --check`；隔离MySQL迁移/并发/回滚用例 |
| Ops Gateway | `go test ./... -count=1`；`go vet ./...`；`go build ./cmd/...`；`git diff --check`；按该仓标签运行多节点集成用例 |
| Web（若改动） | `pnpm vitest run`；`pnpm typecheck`；`pnpm lint`；`git diff --check` |

执行前读取go.work：模块缓存缺失integration子模块时可仅对已发布SDK包用`GOWORK=off`验证，不把缓存环境问题伪报业务失败；目标仓正式全量验证按其完整工作区执行。内部Casbin检查维持内部subject，DTO/ORM字段变化同步同包fixture，避免只报focused测试而未编译全包。

## 确认与交接

本轮交付是已提交的两份文档及其SHA-256。全部任务保持未勾选，不生成实施Goal状态、claim结果或已完成Product Archive。用户对该commit/spec/plan明确批准实施后，才在各自有效工作区启动相应交付入口；代码批准不代替生产维护窗口批准。

本计划评审必须核对：Card边界、三类集合关系、v4兼容新增API、Application原子切换、旧实例围栏、授权等价及回滚。语义变更需要新commit及重新确认，不在批准后默改冻结输入。
