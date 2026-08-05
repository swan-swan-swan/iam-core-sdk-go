# Redis 原生命令 Session Backend 设计

## 目标

将 `runtime/adapters/redis` 改为仅使用 Redis 6.2+ 原生命令；彻底移除 Lua、`EVAL`、`EVALSHA` 和 `redis.NewScript`。该 Backend 继续服务于业务应用的 BFF 服务端 Session，不访问或复用 IAM Core Server 的内部 Redis 数据。

调用方继续自行创建并注入 `go-redis` 客户端。SDK 不增加单机、Sentinel 或 Cluster 的配置开关；`goredis.UniversalClient` 继续同时支持这些客户端类型。

## 范围与兼容性

- 保持 `redisadapter.New(client, options)` 和 `session.Backend` 的公开 API 不变。
- 保持 Flow、Session 和 Lease 的 Redis key 命名、AES-256-GCM payload 格式、Prefix 隔离及数据字段兼容。
- 最低 Redis 版本为 6.2，因为一次性 Flow 消费使用 `GETDEL`。
- 支持 Redis Cluster。所有涉及同一 Session 的多键事务只操作具备相同 hash tag 的 Session 和 Lease key。
- 不支持旧 Lua 版与新原生命令版 SDK 在同一 BFF Redis namespace 内滚动共存；升级时应完成实例切换后再恢复流量。

## 命令映射与并发语义

| Backend 操作 | 原生命令 | 一致性规则 |
| --- | --- | --- |
| `PutFlow` | `SET ... NX PX` | 单 key 原子创建；已有未过期 Flow 返回 `session.ErrConflict`。 |
| `ConsumeFlow` | `GETDEL` | 单 key 原子读取并删除；确保 Flow 仅能消费一次。 |
| `Create` | `WATCH`、`MULTI/EXEC`、`HSET`、`PEXPIRE` | 监视 Session 与 Lease key，在同一事务中创建 Session 并清理遗留 Lease。 |
| `Get` 与过期清理 | `HMGET`、`PTTL`，必要时 `WATCH`、`MULTI/EXEC`、`DEL` | Session payload 的逻辑过期不会删除并发更新后的数据。 |
| `CompareAndSwap` | `WATCH`、`MULTI/EXEC`、`HSET`、`PEXPIRE` | 版本、generation 和 payload 前置条件在提交前检查。 |
| 获取 refresh lease | `WATCH`、`MULTI/EXEC`、`HSET`、`PEXPIRE`、`PTTL` | 同时检查 Session TTL、generation、现有 Lease 和 `last_fence`，再原子写入新 Lease。 |
| 围栏令牌 | 在受监视事务内更新 `last_fence` | 使用 Go 的十进制 `uint64` 递增逻辑，避免 Lua 数值精度限制；超出范围返回 `ErrFenceExhausted`。 |
| 带 Lease 的 CAS / 删除 / 释放 | `WATCH`、`MULTI/EXEC`、`HSET` / `DEL`、`PEXPIRE` | 所有权、generation、fence、TTL 由同一事务检查并更新。 |

`WATCH` 导致的 `EXEC` 失败不自动重试，统一映射为 `session.ErrConflict`。Redis 网络、协议或命令失败保持映射为 `ErrBackendUnavailable`；密文、字段或 TTL 异常保持映射为解码/输入错误。事务只在全部前置条件成立时提交，避免部分写入。

Lease 有效性以 Redis 的 `PTTL` 及 Lease 的 owner、generation、fence 字段为准，而不是本机时钟。该规则使响应延迟或多实例时钟偏差不会将过期 Lease 误判为有效。

## 安全边界

- SDK Redis 数据属于业务 BFF，不得访问 IAM Core Server 的内部 Redis key 或 schema。
- 调用方可复用同一个 Redis 集群，但必须通过独立 Prefix、Redis ACL/用户和 AES-GCM keyring 隔离 BFF 数据。
- 浏览器 Cookie 仅保留不透明 Session/Flow ID；OAuth token、refresh token 与 PKCE verifier 继续仅以加密 payload 写入 Backend。
- Redis key 不得包含原始 Session 或 Flow ID；继续使用摘要与 Session/Lease 相同 hash tag。

## 验证

- 单元测试验证所有 `session.Backend` conformance 行为、冲突映射、围栏溢出、过期清理、加密和错误脱敏。
- 命令记录测试断言 SDK 不产生 `EVAL`、`EVALSHA` 或脚本加载请求。
- Redis 6.2 和 7.4 集成测试覆盖完整 Backend 行为。
- Redis Cluster 集成测试验证 Session/Lease 多键事务可执行且不出现 `CROSSSLOT`。
- 运行根模块和 integration 模块的测试、race、vet 与 `govulncheck`。
