# ADR-0013：延后 AST、语义索引与模型集成

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

上下文与影响分析可以使用路径、manifest、依赖图、测试命名、所有权、Git 历史、AST/LSP、向量检索或模型摘要。首版直接引入 tree-sitter、LSP、embedding 或 LLM 会增加语言矩阵、索引生命周期、网络和隐私成本，却仍不能覆盖配置、数据、部署和动态行为。

## Decision

- v0 使用路径、manifest、Provider 图、测试命名、CODEOWNERS 和精确文档命中。
- 输出路径和理由，默认不输出大量正文。
- v0 不引入 tree-sitter、LSP、PageRank、embedding、向量库或 LLM SDK。
- 无法确认时明确 unknown 并扩大验证范围。
- 为未来 ContextProvider 保留 provenance/confidence 数据接口，但不提交死实现。
- 新信号必须通过相同任务、相同基线的成对实验说明边际收益。

## Consequences

### Positive

- 首版更小、离线、透明、易测试。
- 不会错误宣称 AST 等于完整影响面。
- 模型升级不会使核心投资贬值。

### Negative / trade-offs

- 复杂仓库的召回和 changed-scope 精度有限。
- 宏、反射、动态绑定会频繁扩大范围。
- 语义散文检索较弱。

### Implementation constraints

- 每个 context item 有来源和置信度。
- 超预算退化为路径指针。
- 不允许无 provenance 的“相关文件”。
- 收集基线指标，为后续实验提供比较。

## Rejected alternatives

### 首版 tree-sitter 公共 API 指纹

收益未经验证，宏/生成代码仍不完备，并增加 parser 维护。

### 纯向量 RAG

难解释、需要索引/模型、易受过期和隐私影响，不适合作为主信号。

### LLM 总结仓库

成本、不确定性和宿主绑定高，制造第二份摘要。

## Validation and revisit conditions

当路径/元数据方案形成可量化瓶颈时，对 AST、Git 耦合或语义检索分别做成对实验；每种信号单独 ADR。
