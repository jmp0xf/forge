# ADR-0019：v0 使用 HEAD 作为工作树比较基线

- Status: Accepted
- Date: 2026-07-27
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Receipt 和 Evidence 需要稳定的比较上下文，策略候选也不能用自身放宽后的结果评价自己。
但是仓库本身无法证明 `main`、upstream、fork target 或某个 merge-base 就是评审者认可的
变更基线。自动选择其中之一会把观测到的 Git 拓扑误当作授权事实。

v0 的 CLI 也没有任务系统或 PR 标识输入。为了完成本地工作树验证闭环，比较协议必须在不
猜测外部权威的前提下给出唯一结果。

## Decision

v0 的 comparison protocol 固定为 `forge.worktree-comparison/v1`：

- 普通或 detached 仓库以执行开始时解析到的当前 `HEAD` commit 作为不可变 baseline；
- candidate 只包含该 `HEAD` 与当前 index/worktree/untracked 状态之间的差异；
- unborn 仓库的 baseline 和 base/task dependency 为 `not-applicable`；
- task acceptance 在 v0 中始终为 `not-applicable`；
- merge、rebase、unmerged/conflicted 或无法稳定读取 `HEAD` 的状态阻止 `evidence run`；
- shallow repository、缺少 upstream 和 detached HEAD 不影响此协议，因为它不遍历祖先；
- v0 不自动选择 upstream、默认分支、fork target 或 merge-base，也不新增会暗示外部批准的
  `--base` 默认值。

Evidence 中的 `base_commit` 与 `head_commit` 都可以是 baseline `HEAD`；工作树 candidate 由
scope/diff dependency 单独表示。字段说明和 human 输出必须明确：这不是 PR 已提交提交集的比较。

同一次评估的 policy base 为 `HEAD:forge.toml` 与内置最低策略的合并结果。当前工作树中的
`forge.toml` 只作为 candidate 再次合并，因此删除、降低等级、缩小路径或清除要求不能评价
当前未提交候选。若 `HEAD` 中没有配置，内置策略就是完整 base。

本地用户仍能控制本地 Git 和 Forge；该 baseline 只防止错误复用与意外自我放宽，不构成
外部 attestation、approval、merge 或 release authority。

## Consequences

### Positive

- comparison 对相同 Git/worktree 状态唯一、离线且不依赖托管平台。
- 未提交的策略放宽不能评价自身。
- unborn、detached 和 shallow repository 有明确行为。
- 不会把 upstream 或分支名误称为批准基线。

### Negative / trade-offs

- v0 不评价 feature branch 上已经提交但不在当前工作树中的 PR diff。
- clean worktree 的风险只能表示为“没有工作树 candidate”，不能推断分支与目标分支相同。
- 需要评审已提交提交集时仍依赖外部 CI/评审，或等待后续显式 branch-comparison protocol。

### Implementation constraints

- baseline OID、scope 和 policy base 必须来自同一有界 Git snapshot；发现竞态时失败而不是重试后拼接。
- Receipt validity 必须包含 comparison protocol 和解析后的 baseline state，不能只保存用户输入 ref。
- `show`、`verify` 和 `export` 重新计算当前依赖时必须使用同一协议。
- human/JSON 文案不得把 worktree comparison 表述为 PR、merge-base 或批准基线。

## Rejected alternatives

### 自动选择 upstream merge-base

upstream 是本地配置事实，不是评审或策略权威；缺失、过期、fork 和多远端场景也没有唯一答案。

### 默认选择 `main` 或 `master`

名字不可移植，也无法证明该 ref 是当前变更的正确目标。

### 要求每次传入 `--base`

这会扩大 v0 命令面并让普通本地验证依赖额外选择；错误输入仍不能提升本地证据的权威。

## Validation and revisit conditions

使用 normal、dirty、unborn、detached、shallow、merge、rebase 和 conflicted fixtures 验证状态表。
若 v0.1 需要评价已提交 PR diff，新增 ADR 和 comparison protocol 版本，不改变本记录的 v1 语义。
