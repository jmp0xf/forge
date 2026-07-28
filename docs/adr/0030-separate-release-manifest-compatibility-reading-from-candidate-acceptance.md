# ADR-0030：分离 release manifest 的兼容读取与候选验收

- Status: Accepted
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

ADR-0009 要求同一 machine-contract 主版本只能增加可选字段，旧 JSON 消费者忽略未知字段和枚举值。
ADR-0029 同时要求 v0 release candidate 的固定资产集合、manifest 与 checksum 必须精确、可重算，不能因
宽容读取而接受候选字节漂移。

最初的 `forge.release-manifest/v1` Rust 类型在每层对象上使用 `deny_unknown_fields`，且 release 枚举
没有 `Unknown` 状态。这使旧 v1 reader 无法读取未来同-major 文档，也把兼容读取与候选验收错误地
绑定成同一种严格度。

## Decision

- `ReleaseManifestData` 及其嵌套对象遵循 ADR-0009：保留全部当前必填字段，但忽略未知可选字段。
- release manifest 的公开枚举是 non-exhaustive reader；未知 wire 值统一映射为显式 `Unknown`，不得
  推断为已签名、已授权、已发布或任何当前已知状态。
- 当前 writer 仍只生成冻结的已知值。`release-finalize` 和 `release-check` 不把兼容 reader 当作授权；
  它们从固定输入重建 canonical manifest，并逐字节比较候选文件。
- checked-in v1 JSON Schema 允许对象增加可选属性；Schema 继续描述当前 producer 的已知枚举词汇。
  consumer 对未来枚举值的宽容由反序列化回归测试保证。

## Migration

已有 v1 manifest 无需重写，当前 canonical writer 字节不变。迁移只扩大旧 reader 可接受的同-major
输入，并为未来枚举增加非授权 `Unknown` 投影。任何已保存候选只要多出未知字段或值，仍会因与当前
canonical manifest 不同而被 `release-check` 拒绝；因此迁移不扩大本地发布权限。

## Consequences

### Positive

- release manifest 与其他 Forge JSON consumer 使用同一前向兼容规则。
- 未来增加可选观测字段时，不需要为了旧 reader 人为升级主版本。
- 兼容性不会削弱固定候选资产的精确验收。

### Negative / trade-offs

- 仅成功反序列化不再证明 manifest 是当前可发布候选。
- 调用者必须把 `Unknown` 保守地当作未授权或不可判定状态。

### Implementation constraints

- root 与每个嵌套对象都有未知字段 consumer 测试。
- 每个 release 枚举的未来值都映射为 `Unknown`，缺失当前必填字段仍失败。
- release round-trip 测试必须证明带未知字段的 manifest 仍被 procedural `release-check` 拒绝。
- `xtask check-schemas` 必须审查这次有意的 Schema 漂移。

## Rejected alternatives

### 保留严格 reader，只在新增字段时升 v2

这直接违反 ADR-0009 的同-major 可选扩展规则，并把普通兼容扩展误作破坏性协议变化。

### 让 release-check 复用宽容 reader 判断通过

反序列化成功不证明固定名称、顺序、长度、摘要或当前 authority 状态；这会削弱 ADR-0029 的候选边界。

## Validation and revisit conditions

若未来需要保留未知枚举的原始 wire 值，必须另行设计有界的 lossless reader；在此之前 `Unknown` 只用于
保守消费，不能重新序列化成原始未来值或参与授权。
