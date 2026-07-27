# ADR-0020：版本化完整的本地 Evidence 契约

- Status: Accepted
- Date: 2026-07-27
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

已经签入的 `forge.receipt/v1` 无法表示 repository identity、base/task、Forge behavior 以及
dependency 的 `known`、`unknown`、`not-applicable` 状态。直接改变现有 digest 字段的含义会违反
ADR-0009；填入伪造的“unknown digest”又会让未知事实看起来可比较。

另一方面，当前 `forge.toml` 命令只携带 program、args、cwd 和 inputs。它仍可执行，但缺少
mutability、network、coverage 等事实时不能产生可复用 Receipt。

## Decision

Receipt 和 Evidence 的当前写入契约升为 `forge.receipt/v2` 与 `forge.evidence/v2`。其他 public
schema 继续使用各自当前版本。Schema catalog 从“所有 domain 固定 v1”改为逐 domain、逐 major
列出支持的文档：

- 短名 `receipt`、`evidence` 解析到当前 v2；
- 完整 ID `forge.receipt/v1`、`forge.receipt/v2`、`forge.evidence/v1`、
  `forge.evidence/v2` 均可显式查询；
- v1 schema 和 reader 至少保留一个 minor compatibility period；
- v1 Receipt 只能作为 `historical-incompatible` observation 展示，缺失的依赖维度视为 unknown，
  永远不能满足当前 Evidence。

Receipt v2 必须包含：

```text
repository identity
intent and ordered command observations
HEAD state
scope before and after
command, toolchain, environment, policy and Forge behavior dependencies
base/task dependency（known / unknown / not-applicable）
start time, duration, normalized outcome, coverage and log references
```

普通 dependency 使用 `known(value)` 或 `unknown`；只有 base/task 允许额外的 `not-applicable`。
Receipt 写入本身不等于 Receipt 可用于满足策略。unknown dependency、失败 outcome、mutating command
缺少后续只读确认或执行中 scope 变化都必须由 typed validity reason 表达。

Evidence v2 必须包含 comparison context、risk、typed valid/stale Receipt、四分
`coverage_and_gaps`、local evidence state、external requirements 和 external attestations。v0 生成器
强制 `external_attestations = []`，不能从用户文本提升 trust level。

`forge.toml` 仍保持 `schema = 1`。按照 ADR-0009 的同-major 兼容规则，命令增加可选的
`mutability`、`network`、`success`、`coverage` 和 `enforcement` 字段：

- 缺失字段保留原有执行行为；
- 缺失 mutability/network 或空 coverage 的配置命令可以执行并记录历史 observation，但 command
  dependency 为 unknown，不能满足 Evidence；
- `success` 缺失继续使用既有 `exit-zero` 语义，`enforcement` 缺失继续为 `required`；
- `inputs` 缺失或无法安全缩小时使用整个 repository scope，不能用空 scope 乐观复用；
- 未知 TOML 字段仍报数据错误。

完整 Forge behavior dependency 使用单独的 `forge.evidence-behavior/v1` composition，至少绑定：

```text
comparison, scope acquisition and aggregation
command/toolchain/environment/policy fingerprints
process-output digest and success normalization
Receipt validity and coverage aggregation
Receipt/Evidence canonical serialization
```

任一子协议发生不兼容变化时必须改变 behavior composition，旧 Receipt 自动 stale。

## Consequences

### Positive

- unknown 不需要伪装成 digest。
- v1 消费者和历史状态有明确兼容路径。
- 配置命令可以逐步补足可信元数据，不破坏既有执行配置。
- Forge 自身行为变化成为可解释的失效原因。

### Negative / trade-offs

- Schema catalog、reader 和测试必须同时维护 v1/v2。
- 老配置命令默认不能满足 Evidence，直到项目显式声明必要语义。
- 全 repository scope 会增加摘要成本和保守失效。

### Implementation constraints

- v1 checked-in schema 不得被 v2 导出覆盖或静默删除。
- JSON consumer 忽略未知字段/枚举；future major state 必须 fail closed。
- SuccessPredicate 到 Outcome 的归一化必须是纯函数并有表驱动测试。
- 所有 stale/applicability reason 使用稳定 machine code；human 说明不是唯一判据。
- 默认 Receipt/Evidence 不保存环境值、secret、完整 stdout/stderr 或源文件副本。

## Rejected alternatives

### 原地扩展 v1 required 字段

旧消费者和旧状态会在不改变 schema ID 的情况下得到不同契约。

### 用特殊 Digest 字符串表示 unknown

它把不可比较状态降格为可比较字符串，容易被错误判等并复用。

### 立即升级整个 `forge.toml` 到 v2

所需字段可以作为可选同-major 扩展加入；强迫所有现有配置迁移不会降低当前风险。

## Validation and revisit conditions

checked-in v1/v2 schema、v1 historical reader、future-major rejection、每个依赖轴变异、配置字段缺失和
behavior-version 变异都必须有自动化测试。新增外部 attestation import 时按 ADR-0010 另行决策。
