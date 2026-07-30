# ADR-0026：声明 Provider 命名空间覆盖与缺口

- Status: Accepted
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Evidence v2 的 `coverage_and_gaps` 是一个扁平四分集合。`format`、`compile`、`unit-test` 等通用维度
适合单语言汇总，但在 Rust/Go mixed repository 中，Go Receipt 的 `compile` 不能证明 Rust 已编译。
另一方面，没有 Receipt 时，旧投影只显示 policy 所需 intent，无法列出设计提案 14.5 已要求 Rust
Provider 明确声明的 build、target、cross-target 和 performance 盲区。

为 Provider 增加新字段或升级 schema major 会扩大 v0 协议；只使用通用维度又会产生跨语言串证。

## Decision

保持 Evidence v2 结构不变，使用现有 `CoverageDimension::Custom` 表达 Provider 限定维度。检测到至少
一个 Rust package/workspace 时，Rust Provider 声明：

```text
通用：
format, compile, lint, unit-test, integration-test, build

Rust 限定：
custom:rust-format
custom:rust-compile
custom:rust-lint
custom:rust-unit-test
custom:rust-integration-test-local
custom:rust-build
custom:rust-examples-compile
custom:rust-benches-compile
custom:rust-cross-target
custom:rust-performance
```

默认命令声明保持可核对：

- `cargo fmt --check`：通用 format 与 `custom:rust-format`；
- `cargo check --all-targets`：通用 compile 与 `custom:rust-compile`；
- `cargo clippy --all-targets`：通用 lint 与 `custom:rust-lint`，其 required/advisory 仍由已检测事实决定；
- `cargo test`：通用 unit/integration 与 Rust local unit/integration；
- 默认命令不声明 examples/benches compile、build、cross-target 或 performance。

`--all-targets` 会选择 examples/benches，但 Cargo 会跳过当前 feature set 未满足
`required-features` 的 target；默认命令也不擅自增加 `--all-features`。因此它不能证明 Provider
范围内的全部 examples/benches 已编译，这两个维度保持 gap，除非项目已有入口或显式配置提供更强且
可核对的命令声明。

Evidence 先按当前 Receipt 得到 `verified`、`advisory` 和显式 `not_verified`，再计算：

```text
missing = provider_expected - verified - advisory - explicit_not_verified
not_verified = explicit_not_verified union missing
```

最终互斥优先级保持：

```text
external_required > not_verified > advisory > verified
```

Provider expectations 只影响 coverage 展示，不进入 `evaluate_local_evidence`，因此不改变 policy 的
本地充分性、退出码或外部授权边界。无 Rust unit 的模型不产生 Rust expectations；不完整 Provider
探测继续通过已有 partial/unknown 事实失败关闭，不按文件名猜测。

Coverage aggregation 升为 `forge.coverage-aggregation/v2`，完整 behavior composition 从 ADR-0025
描述的设计顺序 v5 前进到最终 `forge.evidence-behavior/v6`。v5 没有作为独立可执行候选写入或发布。
Receipt/Evidence schema major 和字段均不改变；旧 Receipt 由 behavior dependency 明确 stale。

## Consequences

### Positive

- 空 Receipt 也明确显示 Rust Provider 的已知验证盲区。
- mixed repository 中通用汇总仍可读，同时 Rust 限定维度阻止跨 Provider 串证。
- feature-gated examples/benches 不会被一次默认 feature set 的检查错误提升为已验证。

### Negative / trade-offs

- Rust Evidence 同时出现通用和 Provider 限定维度，列表更长。
- 显式自定义 Rust 命令若未声明相应 `custom:rust-*`，会保守地留下 Provider gap。

### Implementation constraints

- expectations 与 Receipt coverage 都使用 `BTreeSet` 去重并确定排序。
- observed coverage 不能被 expectation 补缺降级；显式失败仍优先于 pass/advisory。
- Go-only model 的 Rust expectation 必须为空；多个 Rust units 只声明一套集合。
- 不修改 Evidence/Receipt JSON Schema major。
- behavior 固定向量必须同时审计 operation-control/v1、coverage-aggregation/v2 与最终 v6。

## Rejected alternatives

### 只使用通用维度

Go 的通过结果会在 mixed repository 中遮蔽 Rust 缺口。

### 把 Provider 或 Unit 增加为 Evidence 字段

这需要新的机器契约和迁移，不是 v0 补齐既有 coverage 语义的最小变化。

### 把 `--all-targets` 视为全部 examples/benches 已编译

Cargo 会跳过未满足 `required-features` 的 target；不解析并绑定完整 target/feature 选择就不能支持该
结论。

## Validation and revisit conditions

必须覆盖空 Receipt、部分当前 Receipt、失败优先级、mixed repository、重复 Rust units、
`required-features` target 的保守边界、local sufficiency 不变和 v6 behavior 固定向量。未来若
Evidence 需要逐 Unit 查询，再以新 ADR 和新 schema major 引入结构化 Provider/Unit coverage。
