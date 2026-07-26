# ADR-0009：版本化所有机器接口

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Agent、脚本和 CI 会依据 JSON 字段、枚举、退出码、诊断码和受管块采取动作。它们不是界面细节。没有独立版本，字段重命名或退出语义调整会悄悄破坏消费者；把 Schema 绑定二进制 SemVer 又会使每次普通发版看似协议变化。

## Decision

- 所有 JSON 顶层包含 `"schema": "forge.<domain>/v<n>"`。
- 配置使用独立 `schema = 1`。
- 本地状态、Receipt、Evidence、适配 manifest 和 marker 各有版本。
- 二进制 SemVer 与 Schema 版本解耦。
- 同一主版本只允许新增可选字段；删除、改名、类型或语义变化升主版本。
- 旧 Schema 至少保留一个 minor 的兼容期。
- JSON 消费者忽略未知字段/枚举；TOML 配置拒绝未知字段。
- 退出码和诊断码语义也是协议；human 文案用快照审查。

## Consequences

### Positive

- 宿主和脚本可稳定集成。
- 兼容变化在 PR 中显式可见。
- Schema 可独立导出和测试。

### Negative / trade-offs

- 需要兼容读取和弃用代码。
- 输出类型设计必须更谨慎。
- marker 也要维护迁移。

### Implementation constraints

- `forge-schema` 导出 checked-in JSON Schema。
- `xtask check-schemas` 阻断未审查漂移。
- AppError/退出码有穷举测试。
- N−1 consumer/plan compatibility 测试。

## Rejected alternatives

### 只依赖二进制 SemVer

无法表达某个输出稳定而另一个协议升级。

### v0 不承诺兼容

Forge 从第一版起就是其他工具的行为接口。

### 配置忽略未知字段

拼写错误会被静默吞掉，危险高于兼容收益。

## Validation and revisit conditions

若兼容层维护税过高，可缩短支持期，但必须新 ADR 和迁移工具，不能静默丢弃旧状态。
