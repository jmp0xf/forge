# ADR-0010：本地证据与外部授权分离

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

本地 CLI 可以记录命令、输入摘要和结果，但本地用户也能修改代码、状态和 Forge 本身。把本地哈希称为不可伪造证明，或把 `verify` 通过称为“可合并”，会制造虚假安全感。完全不记录本地结果又会让执行者容易自述“已经测过”。

## Decision

信任分四层：`local-observation`、`external-attestation`、`approval`、`deployed-observation`。

- v0 Receipt/Evidence 只生成 local observation。
- Evidence 必须列出 verified、advisory、not_verified、external_required。
- `evidence verify` 只判断本地策略充分性，不授予合并/发布/生产权限。
- 外部 attestation 必须有可验证来源；用户文本不能提升信任等级。
- 批准和生产观察由外部系统产生。
- 文案不得称本地哈希“不可伪造”。

## Consequences

### Positive

- 保留本地反馈价值而不夸大信任。
- 评审者可看到验证盲区。
- CI、审批和生产边界清楚。

### Negative / trade-offs

- 用户不能只看一个绿色布尔值。
- 外部 import 需要平台集成、签名或 API 验证。
- Evidence 模型更复杂。

### Implementation constraints

- 状态机中 LocalVerified 与 external/approved 分开。
- UI/JSON 显示 trust level，`not_verified` 强制存在。
- 文档和测试禁止“local proof = authorization”表述。

## Rejected alternatives

### 本地签名即最终证明

签名密钥和状态仍在本地控制范围，无法证明独立性。

### 不记录本地结果

失去可复用反馈和防止无意误报的价值。

### 单一 `pass` 状态

混淆检查、CI、审批和生产观察。

## Validation and revisit conditions

v0.1 引入外部 attestation 时必须另有 ADR 定义来源验证、撤销和离线行为。
