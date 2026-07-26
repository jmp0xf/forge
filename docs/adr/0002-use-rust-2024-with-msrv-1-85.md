# ADR-0002：使用 Rust 2024 Edition，MSRV 1.85

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 是跨平台、短命、重视启动、错误处理、路径安全和单文件分发的本地 CLI。实现语言需要强类型领域模型、精确错误、可预测开销、跨平台分发，以及用编译器约束依赖方向。Rust 2024 Edition 自 1.85 起可用。

## Decision

- Forge 使用 Rust 2024 Edition，初始 MSRV 为 1.85。
- 开发默认使用 stable；CI 同时运行 1.85 与 stable。
- Forge 所分析的项目不必使用 2024 Edition，也不必满足 Forge 自身 MSRV；Provider 尊重项目 toolchain override。
- `Cargo.lock` 必须提交。提升 MSRV 是显式兼容性变化，至少按 minor 发布并记录。

## Consequences

### Positive

- Edition 与 MSRV 自洽，可使用现代 Cargo resolver 和语言能力。
- 跨平台单文件二进制和强类型边界适合本产品。
- MSRV job 能约束依赖升级。

### Negative / trade-offs

- 编译时间和学习成本高于部分脚本语言。
- 平台能力仍需条件编译和少量受审计 FFI。

### Implementation constraints

- workspace 声明 `edition = "2024"`、`rust-version = "1.85"`。
- 默认 `unsafe_code = "deny"`；Windows FFI 只在单一平台模块局部允许。
- 业务路径禁止 unwrap/expect/panic。

## Rejected alternatives

### Python/Node

运行时和环境依赖更重，不符合单文件和项目外安装边界。

### 追随每次最新 stable 作为最低版本

把无关工具链更新变成用户安装前置，降低可复现性。

## Validation and revisit conditions

若关键依赖不再支持 1.85，先评估替代/降级；只有维护收益明确大于迁移成本时才新建 ADR 提升 MSRV。
