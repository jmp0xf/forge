# ADR-0032：记录不含输出内容的命令诊断摘要

- Status: Accepted
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

设计提案 21.4 要求每个命令 observation 保存“有界摘要或 finding 计数”。Receipt v2 已保存完整
stdout/stderr digest、stdout 总字节数和每条流的截断状态，但 digest 只回答内容身份，截断状态只回答
内存保留边界；它们不能直接区分静默失败、只向 stderr 输出、大量输出以及进程边界根本没有形成输出
观察。wire 也缺少 stderr 的完整字节数。

直接保存有界 stdout/stderr 前缀仍可能泄露源码、凭据或无标签高熵 secret。正则、变量名和 UTF-8
清洗都不能对任意项目命令给出无泄漏保证。Forge 也没有所有项目工具的完整 typed parser，因而不能把
“没有 parser”伪装成 finding count 为零。

## Decision

Receipt v2 的 `CommandObservationV2Data` 新增可选 `diagnostic_summary`：

```json
{
  "state": "observed",
  "stdout_total_bytes": 17,
  "stderr_total_bytes": 42
}
```

正常完成、超时、中断以及执行前由 operation control 明确阻止的 observation 使用 `observed`，并记录
两条完整流的总字节数。ADR-0024 所定义、未形成进程输出观察的 typed process-boundary failure 使用：

```json
{"state": "unavailable"}
```

此时两个字节数字段不得携带数值。current writer 必须省略它们；same-major reader 将字段缺失和显式
`null` 都解释为“没有 count”，与生成的 optional-field JSON Schema 一致。摘要固定为 O(1)，不得包含
输出文本、路径、底层错误文案、环境值、finding 推测或模型生成内容。已有顶层
`stdout_total_bytes` 作为兼容和 success-predicate 输入保留，并必须与摘要值相等。

字段保持 optional 以兼容 early-v2 reader：旧对象缺失摘要、future/unknown state 均可读取并按原始
JSON 校验 identity，但不得支持 current Evidence。已知 state 的字段组合矛盾属于 malformed。当前
writer 每条 observation 必须写已知且一致的摘要；写入边界拒绝缺失或 unknown 摘要。

新增 `forge.command-diagnostic-summary/v1` 子协议。完整 Evidence behavior composition 从
`forge.evidence-behavior/v6` 升为 `forge.evidence-behavior/v7`。Receipt schema 仍为 v2，Receipt identity
domain 和 canonical JSON 协议不变；新增字段自然参与 canonical bytes 与内容身份，既有对象不重写。

## Consequences

### Positive

- 在固定大小和无输出内容的前提下，可诊断双流活动与输出不可用边界。
- stderr 总量进入可验证协议，大输出和截断状态不再只有单流视角。
- 不依赖无法对任意输出成立的 secret redaction 假设。

### Negative / trade-offs

- v6 Receipt 会因 Forge behavior dependency 变化而 stale；需要重跑才能形成 v7 observation。
- stdout 总字节数在兼容字段与摘要内短期重复，validator 必须防止形成两个事实来源。
- v0 仍不能报告工具语义级 finding 数量。

### Implementation constraints

- `observed` 必须同时有两个 count，且 stdout count 与兼容字段完全相等。
- `unavailable` 只能与 ADR-0024 的 exact typed process-error、独立 unavailable digest marker 和空日志
  引用组合；不得带 count 数值，current writer 必须省略两个 count 字段。
- missing/unknown summary 只能 historical/non-proving；current writer 不能产生。
- 测试必须覆盖 schema、legacy/future reader、known-state 矛盾、write boundary、identity、behavior 固定
  向量、超大/非 UTF-8 输出、超时/中断及 secret 哨兵不进入持久 bytes。

## Rejected alternatives

### 保存截断后的 stdout/stderr 文本

任意短前缀都可能正好是 secret；无上下文正则脱敏不能提供安全边界。

### 用 exit code 推导 finding count

进程失败不等于一个 finding，成功也不证明零 finding；该映射会制造并不存在的领域事实。

### 默认保存完整日志或调用模型摘要

这会同时扩大存储、权限、脱敏、确定性和架构边界，不是补齐 v0 observation 的最小变化。

## Validation and revisit conditions

checked-in schema、固定 identity/behavior 向量、legacy/future 兼容、字段组合 mutation、writer 全分支和
隐私哨兵测试必须通过。未来只有 provider 拥有完整 typed parser 时，才可通过新行为协议增加 optional
finding count；不得静默改变本协议中 byte-count summary 的语义。
