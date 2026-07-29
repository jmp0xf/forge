# ADR-0039：保留当前 Receipt 的 typed unknown 事实

- Status: Accepted
- Date: 2026-07-30
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None
- Depends on: ADR-0020, ADR-0032

## Context

Receipt v2 可以把某一个无法可靠取得的 dependency 记录为 typed `unknown`，同时保留其他已知
dependency、命令语义、scope、outcome 和 mutability。ADR-0020 要求 unknown 永远不能满足当前
Evidence，但 validity evaluator 仍能逐轴给出稳定的 `dependency-unknown` reason。

当前 reader 把“可以按当前协议投影和比较”与“可以支持 current Evidence”合成一个布尔值。只要
任一 dependency unknown，它就丢弃整份 current projection，再用所有 dependency 和 mutability 都
unknown 的占位输入生成结果。这不会错误授予信任，却会抹掉已经验证的事实，制造无关 reason，并
降低 `show`、`verify` 的可诊断性。

## Decision

Receipt v2 reader 分开两个内部判定：

- current-validity projection 要求 receipt 使用当前已知的 schema、命令语义、observation、coverage、
  comparison basis 和 log-reference 契约；其中一个或多个显式 typed unknown dependency 不阻止投影；
- proving support 还必须要求普通 dependency 全部 known、base/task 为 known 或 not-applicable，并继续
  作为持久化 `valid_receipts` binding 的强制门槛。

因此，一个语义完整但 toolchain unknown 的 passing、read-only Receipt 仍是 non-proving；它的
validity 只报告 `dependency-unknown/toolchain`，并可准确报告 scope-preserving applicability。未知
命令语义、future/opaque same-major 内容、旧 observation 形态、不完整日志引用或其他无法按当前协议
解释的内容仍不得产生 current projection，继续使用全 unknown 的 historical/non-proving 表示。

这次变化不改变 Receipt/Evidence schema、identity 或 canonical bytes，但会改变既有 Receipt 的
validity 解释。`forge.receipt-validity` 从 v1 升为 v2，完整 behavior composition 从
`forge.evidence-behavior/v7` 升为 `forge.evidence-behavior/v8`；旧 Receipt 自动因 Forge behavior
dependency 变化而 stale，不重写原对象。

## Consequences

### Positive

- typed unknown 只污染它实际对应的 dependency axis，不再抹掉其他已知事实。
- `show` 和 `verify` 给出可操作、确定且最小的 stale reason。
- unknown dependency、future content 和不完整语义仍不能进入 `valid_receipts` 或满足 Evidence。

### Negative / trade-offs

- v7 Receipt 在 v8 reader 下会额外报告 Forge behavior changed，需重跑才能形成 v8 observation。
- reader 维护两个相邻但强度不同的判定，测试必须防止后续再次误合并。

### Implementation constraints

- `can_support_current_evidence` 必须保持比 current-validity projection 更强，且所有 persisted
  `valid_receipts` binding 必须继续检查前者。
- 每一个 typed unknown dependency 都必须有测试证明：可以投影、不能 proving、只产生对应 axis 的
  unknown reason。
- unknown/future 命令语义和 opaque contract content 必须有测试证明仍不能产生 current projection。
- process-boundary infrastructure observation 可以保留已知 dependency 与 mutability，但 outcome
  仍不能 supporting；当它是当前 required failure 时可以令本地状态 unknown，但永远不能满足
  requirement。若 advisory infrastructure failure 后的 required gate 令纯 validity 看似 passing，
  reader 必须回退到 opaque non-proving 表示，不能生成 valid 或 passing newest Receipt。

## Rejected alternatives

### 继续用全 unknown 占位投影

它虽然 fail closed，却制造错误诊断，并让一次不可取得的工具链版本看起来像整个 Receipt 都不可读。

### 只让全 known Receipt 进入 validity evaluator

这会浪费 typed unknown 的结构化价值，无法区分“一个事实未知”和“对象协议不可解释”。

### 让 typed unknown Receipt 支持 Evidence

这违反 ADR-0020 的证明边界；unknown 不可比较，也不能被乐观视为相等。

## Validation and revisit conditions

通过逐 dependency mutation、future/unknown command semantics、process-boundary failure，以及真实
`evidence run -> show -> verify` round-trip 验证。若未来修改 typed dependency、validity projection 或
proving predicate，必须再次升级对应 behavior protocol，且不得把 unknown 自动提升为 known。
