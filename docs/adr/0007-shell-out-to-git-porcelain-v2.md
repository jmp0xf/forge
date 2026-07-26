# ADR-0007：调用 Git porcelain v2，不嵌入 Git 实现

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 依赖 worktree、submodule、sparse checkout、attributes、ignore、特殊文件名和用户实际 Git 语义。嵌入 libgit2/gix 会增加依赖、交叉编译和行为偏差风险。解析面向人的 Git 输出又会受本地化、颜色和 quoting 影响。

## Decision

- 通过 typed `GitPort` 调用安装的 `git` 可执行文件。
- 状态使用 `git status --porcelain=v2 -z --branch --untracked-files=all`。
- 文件列表和 name-status 使用 NUL 分隔形式。
- 不解析默认人类输出，不经 shell。
- doctor 检查最低 Git 能力；缺失时明确前置失败。
- v0 不链接 libgit2 或 gix。

## Consequences

### Positive

- 与用户实际 Git、worktree、attributes 和 ignore 语义一致。
- 特殊文件名可无歧义处理。
- 无 C 依赖，交叉编译更简单。

### Negative / trade-offs

- 系统必须安装 Git。
- 需要维护 robust parser 和进程错误语义。
- 多次 Git 调用可能需要合并和缓存。

### Implementation constraints

- 原始路径保留字节/宽字符表示。
- porcelain parser 必须 fuzz。
- 命令超时和输出上限走统一 runtime。
- 业务模块不得直接调用 Git。

## Rejected alternatives

### libgit2

C 依赖和语义差异增加分发成本。

### gix

纯 Rust 有吸引力，但 v0 不需要承担完整 Git 语义差异和依赖体积。

### 解析人类文本

不稳定，受配置、本地化和 quoting 影响。

## Validation and revisit conditions

只有 profile 证明系统 Git 进程开销是主要瓶颈，且嵌入实现在完整 fixture 上证明语义等价时，才新 ADR 评估局部替代。
