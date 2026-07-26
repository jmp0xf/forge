# ADR-0015：worktree 状态隔离，只共享内容寻址缓存

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

多个 Agent/工程师常用 linked worktree 并行修改同一仓库。若 Receipt、dirty snapshot、日志或适配漂移状态放在 git-common-dir，一个 worktree 的成功检查可能错误满足另一个 worktree，造成危险假阳性。完全不共享缓存又会重复解析相同 commit 和 manifests。

## Decision

- dirty scope、Receipt、Evidence draft、日志、锁、任务引用和漂移状态按 worktree 存放。
- git-common-dir 只存可由内容地址完整证明相同的不可变缓存。
- 共享 cache key 包含 commit/content digest、command spec、toolchain、environment、policy 和 Forge 行为版本。
- 任一关键字段 unknown 时不共享。
- linked worktree E2E 是发布门禁。

## Consequences

### Positive

- 多 Agent 并行不会串用本地验证结果。
- 相同不可变输入仍可复用昂贵元数据。
- 状态归属与 Git worktree 模型一致。

### Negative / trade-offs

- 状态管理和 GC 更复杂。
- 共享缓存键较大，命中率低于简单 mtime 缓存。

### Implementation constraints

- 使用 `--git-dir` 与 `--git-common-dir`，不猜路径。
- cache entry 不含可变引用，内容不可变。
- GC 处理多 worktree 引用。
- tests 验证 A/B worktree 隔离。

## Rejected alternatives

### 所有状态放 common dir

错误复用验证结果，破坏证据语义。

### 所有内容完全不共享

正确但成本不必要；内容寻址缓存可以安全共享。

### 按分支名隔离

detached HEAD、同分支多 worktree、未提交内容都无法可靠区分。

## Validation and revisit conditions

观察共享缓存命中和 GC 成本；可以减少共享类别，但不得放宽“可变状态不共享”。
