# ADR-0012：v0 首先支持 Rust 与 Go

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 的语言层需要真实实现 workspace/module 探测、命令语义、影响范围、路径规则和验证盲区。首版同时支持过多生态会把核心协议与语言例外混在一起，并延迟可验证闭环。用户明确要求首版 Rust 与 Go，其他语言保持扩展能力。

## Decision

- v0 内置 RustProvider 和 GoProvider。
- 支持 Rust package/workspace/多个 workspace；Go module/go.work/多个独立 module；以及混合仓库。
- Provider 通过稳定领域类型输出 Units、CommandSpecs、coverage、risk 和 conservative impact。
- v0 不使用 Rust dylib 插件。
- 后续优先声明式 Language Pack；需要生态元数据工具时才增加编译期 Provider，或采用版本化 JSONL 子进程协议。
- 不支持语言但有明确项目命令时可生成语言无关薄适配；否则诊断，不猜测。

## Consequences

### Positive

- 首版范围可控，同时覆盖两种不同生态模型。
- 核心扩展点在真实差异下得到验证。
- 其他语言不会迫使核心协议改写。

### Negative / trade-offs

- Python、TypeScript、Java 用户首版无专门支持。
- 保守影响范围可能频繁退化全量检查。
- 声明式 Pack 能覆盖的比例尚未验证。

### Implementation constraints

- Provider 不得写工作树或执行授权。
- unknown 时扩大范围。
- Rust 不默认 `-D warnings/all-features`；Go 不默认 race/fresh/第三方 lint。
- 语言扩展不得依赖动态 Rust ABI。

## Rejected alternatives

### 一次支持所有主流语言

语言矩阵、fixture 和命令语义会淹没最小闭环。

### 所有语言只靠 manifest 规则

Cargo metadata、go.work/GOWORK 等需要生态专门处理。

### Rust 动态库插件

ABI、版本、信任和分发复杂，不适合用户扩展。

## Validation and revisit conditions

加入第三种语言前先做 Language Pack spike；只有无法表达且价值充分时才新增内置 Provider ADR。
