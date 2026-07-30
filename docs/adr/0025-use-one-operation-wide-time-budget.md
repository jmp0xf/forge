# ADR-0025：每条命令使用一个操作级总预算

- Status: Accepted
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 的一次命令会依次经过 Git 定位、inventory、配置和 Provider 探测、scope 获取、状态读取以及
项目子进程。若每一阶段都重新获得完整的 `--timeout`，总耗时会随阶段数增长；后续阶段也可能在用户
给定预算已经耗尽后继续产生看似当前的事实。仅向子进程传 timeout 还不能约束原生文件遍历、哈希和
两次稳定性确认。

取消也有相同问题：各阶段使用不同标志会使先观察到的中断在后续阶段消失。

## Decision

`--timeout` 表示一条完整 Forge 命令的 wall-clock 总预算，不是每个子进程或阶段可重新使用的额度。

core 冻结 `forge.operation-control/v1`：

- 一次命令只构造一个固定的单调时钟 deadline 和一个共享 cancellation source；
- `checkpoint` 原子返回中断、超时或当时的 remaining duration；
- child limit 只能取 `min(child_limit, remaining)`，不能延长或重建父 deadline；
- production control 一旦观察到 timeout/interruption，后续阶段不能恢复为可继续状态；
- inventory、Provider、scope、状态和子进程边界在形成新事实前检查同一个 control；
- 已完成的有界观察可以保留，未完成范围保持 unknown；顶层分别返回 124 或 130；
- 兼容入口可以显式使用 unlimited control，但不得把它用于已有总预算的命令链。

该控制保持同步、无 Tokio，并继续使用平台原生的进程树终止实现。

Operation control 进入完整 Evidence behavior composition。按决策演进顺序，它使 behavior 从 v4
前进到 v5；同一未发布候选随后由 ADR-0026 的 coverage aggregation 变更前进到最终 v6。仓库不生成、
写入或声称验证过一个可执行的中间 v5 artifact。

## Consequences

### Positive

- 用户给定的上限约束整条命令，而不是阶段数乘以上限。
- 第二次 detection/scope 确认不能获得新的完整预算。
- timeout、Ctrl-C 和未完成事实的关系可由同一协议测试。

### Negative / trade-offs

- 后执行的阶段只能使用剩余时间，较慢的早期探测会压缩项目命令预算。
- 原生长循环需要显式 checkpoint，新增边界必须接受 operation control。

### Implementation constraints

- CLI help 必须称 `--timeout` 为 complete-command total budget。
- deadline 使用单调时钟；不得从 wall-clock 时间重建。
- timeout/interruption 映射保持 124/130，不能伪装为项目失败。
- Evidence behavior 固定向量必须包含 `forge.operation-control/v1`。

## Rejected alternatives

### 每阶段重新设置 `--timeout`

它不能约束总耗时，并让阶段拆分方式改变外部 SLA。

### 只限制项目子进程

Git、inventory、哈希和状态确认仍可能无限占用命令预算。

### 为此引入异步 runtime

同步 CLI 已能通过显式 control 和平台进程树终止实现相同边界；异步依赖不会降低当前复杂度。

## Validation and revisit conditions

连续 Git 阶段不得各自获得完整预算；clone 必须保留同一 deadline/cancellation；过期与取消必须稳定
映射为 typed terminal state；root、runtime、CLI timeout E2E 和 Evidence behavior 固定向量必须通过。
