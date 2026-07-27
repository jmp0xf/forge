# ADR-0021：Evidence 状态使用不可变对象和有界保留

- Status: Accepted
- Date: 2026-07-27
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Receipt、Evidence 和日志位于 worktree 私有 Git 状态中。若覆盖已有对象、按不完整扫描清理、跨
worktree 共享，或者把 malformed/future state 当作不存在，会造成审计历史丢失或错误复用。
完全不清理又会让长期运行的仓库无限增长。

## Decision

v0 使用以下 worktree 私有布局：

```text
<git-dir>/forge/
├── lock
├── receipts/v1/                 # legacy read-only
├── receipts/v2/<digest>.json    # current immutable objects
├── evidence/v1/                 # legacy read-only
├── evidence/v2/<digest>.json    # current immutable objects
└── logs/v1/<digest>.log         # optional immutable bounded logs
```

Receipt/Evidence public ID 使用带 domain 的 BLAKE3 identity；文件名只使用经过校验的 64 位小写
hex payload。identity 覆盖除自身 ID 外的完整 canonical body，包括时间和 observation，因此不同
执行不会因命令和 scope 相同而覆盖历史。

写入必须在 worktree lock 下通过 `store_new_atomic` 完成：

- 目标不存在时同目录原子创建；
- 已存在且字节完全相同时视为幂等恢复；
- 同 ID 不同字节是 data-integrity error，绝不覆盖；
- Receipt 成功持久化后才可写引用它的 Evidence；
- read-only `show`、`verify` 不创建目录、锁、访问时间或缓存。

默认不保存完整 stdout/stderr，`log_refs` 为空。显式保存日志时，每个文件先受配置字节上限约束、
权限私有化并完成脱敏；Evidence 导出只包含状态相对引用。

GC 在成功写入后、持锁状态下运行。保留集合是以下条件的并集：

- 最近 200 个同类对象；
- 年龄不超过 14 天的对象；
- 被保留 Evidence 引用的 Receipt；
- 被保留 Receipt/Evidence 引用的日志。

清理顺序为：先选择并删除过期 Evidence，重新计算引用闭包，再删除无引用的过期 Receipt，最后
删除孤立日志。扫描上限为每类 4096 个对象；Receipt 单文件上限 4 MiB，Evidence 单文件上限
8 MiB，默认私有状态总预算 256 MiB。若 malformed/future state、非普通文件、symlink、扫描超限或
保留闭包仍超过总预算，GC 和新写入失败并保留现有数据，不进行乐观的部分清理。

原子写入留下的异常临时项、未知文件名或 future schema 都是可诊断状态错误；不能静默忽略。删除
只针对完成上述解析和引用分析的明确旧对象，不触碰其他 Git 私有数据或工作树文件。

## Consequences

### Positive

- Receipt/Evidence 不会因重试、碰撞或 partial failure 被覆盖。
- worktree 间不会串用未提交状态。
- GC 保留近期排障窗口和 Evidence 引用闭包。
- read-only 命令保持真正只读。

### Negative / trade-offs

- GC 需要解析保留对象并维护稳定排序。
- malformed state 会阻止写入，需要用户诊断和恢复。
- 默认不落完整日志时，深度排障只能依赖有界摘要或重新执行。

### Implementation constraints

- 时间使用 UTC RFC 3339；排序以解析后的时间、再以 ID 打破平局，不能依赖目录枚举或 mtime。
- 所有读写和删除都必须复用 state path/symlink confinement。
- crash recovery、碰撞、引用保护、linked-worktree 隔离和 read-only no-create 必须有集成测试。
- GC 参数是保守校准值；调整数值不改变引用保护和 fail-closed 语义。

## Rejected alternatives

### 覆盖每个 intent 的 latest Receipt

会丢失失败历史、竞态信息和 stale 原因，也无法安全恢复 partial write。

### 只按 TTL 删除

时间不是有效性依据，并且可能删除仍被 Evidence 引用的对象。

### 把 Receipt 放入 git-common-dir 共享

dirty/index/worktree 状态不同，跨 worktree 复用会产生危险假阳性。

## Validation and revisit conditions

通过 collision、crash residue、malformed/future schema、超过扫描/字节上限、引用旧 Receipt、linked
worktree 和无状态 read-only fixtures 验证。若未来启用共享内容寻址缓存，只能缓存完整依赖寻址的
不可变派生数据，不能移动本记录中的 worktree-local objects。
