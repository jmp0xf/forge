# ADR-0005：运行状态存入 Git 私有目录

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 需要保存 ProjectModel 缓存、Receipt、Evidence 草稿、日志、锁和适配 manifest。这些不是项目权威资产，不应提交。根级 `.forge/` 会污染工作树、诱导团队把规则和日志集中到工具目录，也难以正确处理 linked worktree。

## Decision

- 每个 worktree 的可变状态放在 `git rev-parse --git-dir` 返回目录下的 `forge/`。
- 仓库共享的不可变内容寻址缓存放在 `git rev-parse --git-common-dir` 下的 `forge/cache/`。
- 必要配置使用根级 `forge.toml`；它不是运行状态。
- 删除状态目录必须安全，Forge 能重新探测和重建。
- Forge 不创建提交到工作树的 `.forge/`。

## Consequences

### Positive

- 工作树保持普通工程布局。
- clone/删除仓库时状态自然消失。
- linked worktree 可有独立 Receipt 和日志。

### Negative / trade-offs

- bare/特殊 Git 环境和权限问题需要明确诊断。
- 用户不熟悉私有路径，doctor/explain 必须显示实际位置。

### Implementation constraints

- 用 Git 命令获取路径，不能假设根下 `.git/` 是目录。
- 状态带 Schema、锁、原子写和 GC。
- Evidence 引用的对象在 GC 中受保护。
- 不保存 secrets 或完整对话。

## Rejected alternatives

### 仓库根 `.forge/`

按产品而非职责归档，污染版本控制并形成第二套工程世界。

### 仅用户 XDG 状态目录

难以与 worktree 精确绑定，仓库移动或 remote 重名时容易串扰。

### 将 Receipt 提交到仓库

增加噪声、冲突与隐私成本；长期证明应由外部 artifact/attestation 保存。

## Validation and revisit conditions

linked-worktree E2E 必须证明状态不串扰。跨机器长期证据应设计外部 attestation，不把本地 state 入库。
