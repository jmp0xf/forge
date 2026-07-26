# ADR-0016：Evidence 按依赖变化失效

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

“最近 12 小时测试通过”不能证明当前输入已验证：源码、命令、工具链、环境或策略可能已变化。只绑定 Git commit 又无法覆盖未提交变更和 untracked 文件。保存全部内容副本成本过高。

## Decision

Receipt 有效性由以下依赖共同决定：

```text
scope digest
command digest
toolchain digest
relevant environment digest
effective policy digest
base/task digest（适用时）
Forge behavior version
```

任一变化立即 stale，并给出 stale reason。TTL 只能作为额外保守上限，不能替代依赖比较。

Scope digest 使用 Git blob OID 加工作树内容 BLAKE3；无法读取或可靠确定作用域时不复用。mtime 不作为正确性依据。

## Consequences

### Positive

- 避免过期检查误复用。
- 可精确解释为什么需要重跑。
- 与构建系统的输入—产物失效模型一致。

### Negative / trade-offs

- 摘要计算、环境规范化和缓存键实现复杂。
- 环境依赖不完整时命中率下降。
- 大仓库需要性能优化。

### Implementation constraints

- Receipt 同时记录 before/after scope。
- mutating 命令不能用 before digest 证明 after 状态。
- 未修改 tracked 文件复用 index blob OID；dirty/untracked 流式哈希。
- 不用大文件 size-only 降级。
- stale reasons 进入 JSON 和 human 输出。

## Rejected alternatives

### 统一 TTL

时间不是事实依赖；既会重复未变输入，也会错误复用已变输入。

### 只绑定 HEAD

不能覆盖 dirty/untracked，也不能区分命令和工具变化。

### 只绑定 git diff 文本

未包含命令、环境、策略和某些文件模式。

## Validation and revisit conditions

用历史变更和随机变异验证失效灵敏度；性能优化只能改变计算方式，不能删除依赖维度。
