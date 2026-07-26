# ADR-0003：项目原生命令是稳定接口

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

辅助 CLI 很容易把 `cargo test`、`go test`、`make verify` 再包装为 `forge test`，随后 CI、文档和人都开始依赖 Forge。工具移除或停止维护时，项目基本开发能力随之破坏。另一方面，Forge 需要记录回执，直接运行项目命令不会自动形成 Receipt。

## Decision

- Cargo、Go、Make、Just、Task 或已有脚本是项目长期操作接口。
- Forge 可以发现并调用这些命令，不能拥有其业务语义。
- v0 不提供顶层 `forge check/fix/test/build`。
- `forge evidence run <intent>` 是可选透明执行和回执入口，必须显示并执行同一个项目 CommandSpec。
- 没有 Receipt 时，`next` 降级为“未验证”，项目本身仍可工作。
- 主验证 CI 只调用项目原生命令；引用 Forge 的 adapters/evidence job 独立。
- fixture 必须有卸载完整性测试。

## Consequences

### Positive

- Forge 可删除、可替换，不锁定项目。
- 人、Agent、CI 使用同一工程入口。
- Receipt 能力不篡夺命令所有权。

### Negative / trade-offs

- 项目命令输出和覆盖语义不完全统一。
- 直接运行项目命令不会自动产生 Receipt。
- mixed repo 的统一入口需要显式选择。

### Implementation constraints

- CLI 注册测试确保没有同义顶层包装。
- AGENTS 同时显示真实项目命令与可选 Receipt 命令。
- 删除二进制和生成物后，项目命令必须通过。

## Rejected alternatives

### Forge 拥有统一 check/test/build

初期体验统一，但长期形成反向依赖和第二套语义。

### 项目命令内部调用 Forge 记录结果

仍把项目目标与外部工具耦合，默认禁止。

### 只输出建议，不提供 Receipt 入口

`next` 无法可靠判断当前输入是否被验证，会退化为自述。

## Validation and revisit conditions

只有真实数据证明独立顶层动词显著降低成本且不成为项目依赖，才可用新 ADR 加入。
