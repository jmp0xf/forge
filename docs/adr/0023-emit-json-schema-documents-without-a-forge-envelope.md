# ADR-0023：JSON Schema 文档不套 Forge 结果信封

- Status: Accepted
- Date: 2026-07-27
- Deciders: Forge maintainers
- Supersedes: ADR-0009（仅 JSON Schema 文档输出例外）
- Superseded by: None

## Context

ADR-0009 要求所有 JSON 顶层携带 `forge.<domain>/vN` Schema 标识。这个规则适用于 Forge 的
结果、诊断和持久状态实例，但 `forge schema <kind>` 输出的不是某个 Forge 结果实例，而是供
标准验证器直接读取的 JSON Schema 文档。

JSON Schema 的根对象需要保留 `$schema`、`$id`、`$ref`、`$defs` 等标准关键字。若再把它包进
Forge envelope，用户必须先做产品专属解包，通用验证器、编辑器和现有
`xtask schema-export/check-schemas` 也不能直接消费 stdout。把 envelope 字段混入 Schema 根对象
同样不合适：它会改变被导出的 Schema 文档自身，而不是标识一次命令结果。

## Decision

- Forge 的结果、诊断和持久状态 JSON 继续使用 ADR-0009 规定的版本化 Forge 顶层 Schema。
- `forge schema <kind>` 成功时直接输出该 kind 的标准 JSON Schema 文档，不套 Forge envelope；
  `--json` 不改变这项内容语义。
- 导出的文档使用标准 `$schema` 声明和稳定 `$id` 标识自身。该 `$id`、文档结构以及所描述的
  Forge wire contract 都属于机器兼容面。
- 不带 kind 的 `forge schema --json` 仍输出版本化的 `forge.schema-index/v1` envelope，因为它是
  Forge 的索引结果，不是 JSON Schema 元文档。
- 参数、序列化或写出失败仍走普通 Forge 诊断/退出码边界；本 ADR 只规定成功的 Schema 文档
  payload。

这是一项窄例外，不允许其他命令以“原始 JSON 更方便”为理由绕过版本化 envelope。

## Consequences

### Positive

- stdout 可直接交给标准 JSON Schema validator、编辑器和代码生成工具。
- checked-in Schema 与 CLI 导出保持字节级可比，不需要维护产品专属解包步骤。
- ADR-0009 对普通机器结果的版本约束保持不变，例外边界清楚且可自动测试。

### Negative / trade-offs

- 消费者必须知道 `forge schema <kind>` 返回元文档，而不是 Forge envelope。
- `--json` 在这个子命令上选择机器可读输出，但不意味着一定存在 Forge envelope。

### Implementation constraints

- CLI contract 测试必须断言 kind 输出以标准 `$schema`/`$id` 为根，并可被 JSON Schema validator
  直接加载。
- `forge schema --json` 必须继续通过 `forge.schema-index/v1` 的实例 Schema 验证。
- `xtask check-schemas` 必须阻断未同步的 checked-in Schema 漂移。

## Rejected alternatives

### 在 envelope 的 `data` 中嵌入 JSON Schema

通用工具不能直接读取，需要每个消费者理解 Forge envelope。

### 把 Forge `schema` 字段加入 JSON Schema 根对象

它混淆“描述目标实例的 Schema”和“命令结果实例的 Schema”，也会让标准文档多出产品专属语义。

### 新增 `--raw` 并改变当前默认

当前 v0 尚无已发布的旧格式需要迁移；新增同义模式只会扩大命令面。直接冻结现有、标准工具友好的
元文档行为更小。

## Validation and revisit conditions

Schema 导出、checked-in drift、SchemaIndex 实例验证和代表性 CLI 实例验证必须共同通过。若未来
需要返回多个 Schema、签名或传输元数据，应新增显式 bundle contract，不得悄悄改变单 kind 的
标准文档输出。
