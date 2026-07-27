# ADR-0024：进程边界失败写入类型化非证明 Receipt

- Status: Accepted
- Date: 2026-07-27
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

`forge evidence run` 可能在项目进程形成正常终止观察前失败，例如可执行文件不存在、权限不足、
工作目录无效、进程树初始化失败或等待/输出管道出错。项目命令已经被选择，链中更早的命令也可能
已经运行；若 Forge 只返回顶层错误而不写 Receipt，这些已发生事实没有可追踪对象。

另一方面，进程边界错误没有可信的 exit code、signal、完整 stdout/stderr 或总字节数。把它们编码
成空输出或普通 product failure 会制造并不存在的观察，也可能错误满足 success predicate。原始 OS
错误文本还可能包含绝对路径、本机信息或不可稳定比较的文案，不应进入公开或持久协议。

## Decision

Receipt v2 对进程边界失败采用以下兼容扩展：

- observation 的归一化 outcome 为 `infrastructure-failure`；
- 新 writer 填写可选的 `process_error_kind`，只使用稳定、有界的枚举，不保存原始 OS 错误文本；
- `raw_exit_code`、`signal`、`stdout_total_bytes`、per-stream truncation 和 JSON error status 均为空，
  `timed_out`/`interrupted` 只表示已经形成的正常 process observation，不借给 spawn 等错误使用；
- stdout 与 stderr 使用各自独立、带域分离的
  `forge.process-output-unavailable/v1` digest marker；marker 不表示空字节流；
- 兼容字段 `output_truncated` 设为 true，明确表示没有完整输出事实；此类 observation 不携带日志引用；
- required command 的进程边界失败终止后续 required 链；advisory command 仍允许后续命令运行；已完成
  prefix 的 observation 与 dependency 全部保留；
- Receipt reader 精确校验上述字段组合。早期 v2 中没有 kind 的 infrastructure failure 继续可读，
  但不能满足当前 Evidence；未知 future kind 同样可读且 non-proving。

这些字段是 ADR-0009 允许的同-major 可选扩展，不升级 `forge.receipt/v2`。完整 Evidence behavior
composition 升为 `forge.evidence-behavior/v4`，并纳入 marker protocol 与 digest domain；因此旧行为的
Receipt 不会被新 writer 错误复用。

## Consequences

### Positive

- 缺失工具和 spawn/pipe/wait 失败仍留下可审计、不可伪装为通过的 Receipt。
- 多命令链不会丢失失败前已经完成的观察。
- 持久对象不泄露不稳定或敏感的底层错误文本。
- marker 与真实空输出在哈希域上不可混淆。

### Negative / trade-offs

- v2 reader 需要同时维护 early-v2 无 kind 的兼容路径和当前严格 writer 路径。
- 顶层诊断仍需单独给出本次操作的可执行修复建议；Receipt 只保存稳定事实。

### Implementation constraints

- wire enum、core process kind 与 CLI projection 必须穷举对应，并保留 unknown read state。
- 当前 writer 的 typed failure 必须使用两个精确 marker；任一字段组合不一致都视为 malformed。
- mutation/回归测试必须覆盖 required 停止、advisory 继续、prefix 保留、marker 分流、legacy/future
  non-proving 和缺失 executable 的 CLI 持久化路径。
- 后续增加 kind 是同-major 可选枚举扩展；若字段组合或 marker 语义改变，必须再次升级完整 behavior
  composition。

## Rejected alternatives

### 不写 Receipt，只返回 AppError

会丢失已完成命令和实际失败边界，无法供 `next`、`show` 或事后诊断使用。

### 把错误当作 exit code 1

这会把环境/运行基础设施失败伪装成项目检查失败。

### 对不可用输出使用空流 digest

“没有观察”不等于“观察到零字节”，两者必须在哈希域上分离。

### 保存完整 `io::Error` 文本

错误文案不稳定、可能暴露主机路径或平台细节，也不能形成跨版本机器契约。

## Validation and revisit conditions

Receipt Schema drift、legacy/future reader、固定 marker/behavior 向量、缺失 executable E2E 和多命令
required/advisory 测试必须通过。若未来要保存经脱敏的底层诊断，应使用独立、有界、非证明字段和新
行为版本，不得改变现有 kind 的含义。
