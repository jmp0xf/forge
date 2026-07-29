# ADR-0038：v0 不持久化任意项目命令的完整输出

- Status: Accepted
- Date: 2026-07-29
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None
- Depends on: ADR-0020, ADR-0021, ADR-0032

## Context

Forge 会执行项目原生命令。它能对 stdout/stderr 做有界捕获、计算覆盖完整字节流的摘要并记录字节
数，但无法理解所有项目工具可能输出的源码、凭据、环境值或其他敏感内容。截断前缀仍可能恰好包含
secret；通用正则脱敏也不能对任意二进制和文本输出给出无泄漏保证。

ADR-0021 为可选的不可变日志对象定义了状态布局和保留边界，ADR-0032 则明确拒绝把任意输出内容
写入命令诊断摘要。v0 还没有一个拥有完整 typed parser、可证明先脱敏再持久化的生产者。若仅为兑现
设计稿中的“完整日志外置”描述而暴露通用保存开关，会把尚不存在的隐私保证伪装成能力。

## Decision

v0 的生产 CLI 不持久化任意项目命令的完整 stdout/stderr，也不提供通用 `--save-logs` 开关：

- Receipt 只保存覆盖完整输出的 digest、完整字节数、截断状态和 ADR-0032 定义的无内容诊断摘要；
- current Receipt/Evidence writer 的 `log_refs` 始终为空；该 versioned 字段保留用于兼容读取和未来
  typed producer，不构成 v0 可用能力；
- `EvidenceStore::persist_current_log` 只作为受 ADR-0021 约束的运行时基础原语存在；v0 生产 CLI
  不调用它，且它自身不声称会脱敏调用者提供的字节；
- CI、终端宿主或直接调用者可以按各自既有权限和保留策略持有原始日志，但这些日志不进入 Forge
  Evidence，也不由 Forge 返回状态引用；
- 不以正则、变量名、UTF-8 清洗或模型摘要声称任意命令输出已经安全脱敏。

未来只有拥有完整 typed parser 的 provider 或其他能在进入日志存储边界前证明内容策略的生产者，才
能通过新的 ADR 和行为协议显式启用日志引用。不得通过配置默认值或未版本化开关静默改变本决定。

## Consequences

### Positive

- v0 不会为了排障便利而扩大任意项目输出的持久化和泄漏面。
- Receipt 仍可通过完整 digest、双流字节数和截断状态诊断输出规模与身份。
- versioned `log_refs` 和受约束存储原语保留未来演进空间，无需破坏机器契约。

### Negative / trade-offs

- Forge Evidence 不能独立还原失败命令的原始输出；深度排障依赖调用者日志或重新执行。
- 运行时已有日志原语在 v0 没有生产调用者，必须避免被误读为已交付 CLI 能力。

### Implementation constraints

- current writer 的所有成功、失败、超时、中断和 process-boundary error 分支都必须产生空
  `log_refs`。
- 隐私测试必须使用输出和底层错误哨兵，证明持久化 observation 不包含捕获内容或错误文本。
- 文档不得把运行时日志原语、CI 自身日志或 reserved wire 字段表述为 Forge v0 已保存的日志。
- 日志状态布局仍受 ADR-0021 及后续 state-confinement ADR 的大小、身份、权限、扫描和 GC 约束。

## Rejected alternatives

### 默认或显式保存截断前缀

短前缀仍可能完整包含凭据，而且会让相同命令因捕获上限而产生难以解释的部分审计记录。

### 对任意输出运行通用脱敏规则后保存

未知格式、二进制数据、编码边界和新型 secret 无法由通用规则完备覆盖；“已脱敏”会成为错误的安全
承诺。

### 删除日志 wire 字段和运行时存储原语

这会不必要地破坏已版本化契约，并删除已经具备独立安全边界、可供未来 typed producer 复用的基础
能力。

## Validation and revisit conditions

通过 writer 全分支的空 `log_refs` 断言、超大/非 UTF-8 输出、secret/error 哨兵和 Evidence
round-trip 测试验证。若未来出现可判定的 typed 内容策略、明确 opt-in、每对象上限和独立隐私审查，
应新增 ADR、升级 Evidence behavior dependency，并增加迁移与泄漏测试后再启用。
