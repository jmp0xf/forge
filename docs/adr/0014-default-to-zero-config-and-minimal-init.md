# ADR-0014：默认零配置与最小 init

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

初始化工具常复制固定目录树和配置，导致 brownfield 仓库被强加工具偏好，生成资产无人维护。Forge 的核心优势是从仓库事实推导，而不是要求项目先描述一遍自己。

## Decision

- 仓库可可靠推导时不创建 `forge.toml`。
- `init` 默认 dry-run；`--apply` 才写。
- 默认只可能创建/更新薄 AGENTS、按需宿主指针和确实必要的单个配置。
- 已有内容够用时，合法结果是“无变更”。
- 空仓库拒绝并引导官方生成器。
- 未确认事实进入 assumptions，不写成既成事实。
- 生成计划包含路径理由、完整 diff 和 Git 回滚方法。

## Consequences

### Positive

- 存量仓库侵入低，采用和退出成本小。
- 配置不会成为自动探测结果的重复副本。
- 生成 diff 易评审。

### Negative / trade-offs

- 首次运行需要较强探测与诊断。
- 期待“一键铺满最佳实践”的用户会觉得保守。
- 无法推导时仍需用户显式决策。

### Implementation constraints

- zero-config fixture。
- dry-run/read-only 测试。
- idempotent/deterministic render。
- dirty worktree 可预览，apply 默认阻止。
- assumptions 强制输出。

## Rejected alternatives

### 每仓库生成完整配置

把可推导事实复制为长期维护税。

### 固定模板树

无法尊重 brownfield 结构和组织决策。

### 内置 `forge new`

与 Cargo/Go 官方生成器竞争，把栈选择错误地交给通用工程层。

## Validation and revisit conditions

若真实仓库中某类自动推导误判成本高，可为该歧义增加最小显式字段；不能退回默认复制所有探测结果。
