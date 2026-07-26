# ADR-0017：默认不生成 runner、CI 或组织文档

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

候选设计常让 `init` 在缺文件时自动创建 Makefile/justfile、GitHub Actions、CONTRIBUTING、ADR、Runbook、CODEOWNERS 和安全扫描。这样看似开箱即用，但 runner 偏好、CI 版本/secrets、责任人和架构历史无法从 Cargo.toml/go.mod 唯一推出。生成错误资产的代价大于缺失诊断。

## Decision

- 单语言 Rust/Go 仓库无 runner 时使用语言原生命令，不生成 runner。
- 混合仓库也默认只建议；用户显式 `--with-runner` 才生成。
- CI 只有显式 `--with-ci github` 且无等价 workflow 时生成草稿；不配置 branch protection。
- CONTRIBUTING、ADR、Runbook、CODEOWNERS 默认不生成正文。
- 不编造 owner/team、版本、secret 或发布策略。
- doctor 可以报告缺口、原因和人工动作。
- Forge 自身仓库可以人工拥有这些正常资产；这不是 init 默认行为。

## Consequences

### Positive

- 避免模板铺设和组织决策越权。
- 单语言仓库保持最小接口。
- brownfield 采纳风险显著降低。

### Negative / trade-offs

- greenfield 用户需先用生态工具/团队流程建立资产。
- mixed repo 不会自动获得统一命令。
- init 输出比传统脚手架少。

### Implementation constraints

- 组织资产缺失作为 suggestion/unknown，不默认 edit。
- 生成 runner/CI 的显式 plan 显示假设和删除方法。
- 已有同名目标永不覆盖。
- 真实仓库验收要求“零不该建文件”。

## Rejected alternatives

### 缺什么就自动生成什么

存在性不能证明内容，容易制造错误权威和维护税。

### 默认生成 justfile 或 Makefile

单语言项目已有原生命令；runner 偏好和平台并不统一。

### 自动生成 CODEOWNERS

无法可靠推断责任人，错误所有权是安全问题。

## Validation and revisit conditions

若真实数据表明某个显式生成选项高频且撤销率极低，可优化交互，但默认仍保持 opt-in，除非新 ADR 提供跨仓库证据。
