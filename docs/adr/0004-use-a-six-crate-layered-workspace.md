# ADR-0004：使用六 crate 分层工作区

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 同时包含稳定 wire contracts、纯领域规则、操作系统副作用、仓库探测、确定性渲染和 CLI 组合。单 crate 只靠模块约定难以阻止领域逻辑直接访问文件或进程；过多 crate 又会造成类型中转和维护成本。

## Decision

采用六个产品 crate：`forge-schema`、`forge-core`、`forge-runtime`、`forge-detect`、`forge-render`、`forge-cli`，另有不被产品依赖的 `xtask`。

依赖方向为 `schema ← core ← runtime/detect/render ← cli`。

- schema：wire types、Schema 版本和导出；
- core：纯领域、状态机、风险、证据与 ports；
- runtime：Git/FS/process/state/clock/hash；
- detect：ProjectModel、runner、Rust/Go Provider；
- render：受管块、ChangePlan、apply、适配；
- cli：参数、装配、输出和退出码。

## Consequences

### Positive

- 编译期强制副作用边界和依赖方向。
- Schema 可独立复用和兼容测试。
- detect/render 不互相扫描或写入。

### Negative / trade-offs

- 类型需要更早稳定，初期目录显得较多。
- 跨 crate 编译和中转有成本。

### Implementation constraints

- core 不得依赖 runtime/detect/render/cli。
- render 只消费 ProjectModel/RenderContext，不重新探测。
- 外部进程集中 runtime；架构 lint 禁止其他 crate 直接 `Command::new`。
- 用 cargo metadata 测试阻断非法依赖边。

## Rejected alternatives

### 单 binary crate

边界依赖评审记忆，副作用会逐渐渗入领域逻辑。

### 每种语言和宿主单独 crate

v0 过早拆分增加接口成本；先模块化，真实扩展压力出现后再 ADR。

### 独立 forge-git crate

Git 与 FS/process/state 都是 runtime 副作用，内部模块化即可。

## Validation and revisit conditions

只有独立发布、feature 裁剪或编译瓶颈有实证时才拆分，不为文件数量本身拆 crate。
