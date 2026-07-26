# ADR-0008：使用同步执行，不引入 Tokio

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 是短命本地 CLI，主流程是少量 Git/文件操作和子进程。异步运行时会把 ports、错误、取消和测试全部改为 async，并带来 runtime 生命周期和阻塞调用混用。v0 没有网络服务或高并发 I/O。

## Decision

- v0 使用同步 API 和单进程控制流。
- 子进程使用阻塞 spawn/wait，加独立读线程、有界 channel、超时和取消。
- 少量独立纯探测可用受限线程池，但不改变公共 API 为 async。
- 同一 workspace/module 命令按 concurrency key 串行。
- 不引入 Tokio、async-std 或 async-trait。

## Consequences

### Positive

- 控制流、错误和测试更简单。
- 二进制、编译和依赖面更小。
- 取消与 kill tree 可围绕真实子进程设计。

### Negative / trade-offs

- 大量独立工具探测并发需要线程管理。
- 未来若增加网络/守护进程，可能需要新模型。
- stdout/stderr 仍须并发读取避免管道死锁。

### Implementation constraints

- 同步不等于忽略取消：必须终止整个进程树。
- 输出读取使用有界机制，结果按计划稳定排序。
- 线程池集中 runtime 管理。

## Rejected alternatives

### 首版 Tokio

没有对应工作负载，增加复杂度而不改善最小闭环。

### 全串行且只读单一输出流

可能因 stdout/stderr 管道填满死锁；需要并发读取但不需要异步 runtime。

## Validation and revisit conditions

只有真实 profile 显示同步模型无法满足明确用例，或产品增加长期网络/服务能力时，才新 ADR 评估异步。
