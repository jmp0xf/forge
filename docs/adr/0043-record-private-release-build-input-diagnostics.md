# ADR-0043：记录私密的发布构建输入诊断

- Status: Accepted
- Date: 2026-08-03
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None
- Depends on: ADR-0010, ADR-0041

## Context

Forge 的候选构建会固定源码、锁文件、目标和一部分进程边界，但实际 Cargo 程序、参数、工作目录以及
Windows MSVC 的 `PATH`、`LIB`、`INCLUDE` 仍是构建输入。既有 qualification failure 缺少安全且精确的
prepared-input 记录，无法在不重放本机路径的前提下判断候选究竟把哪组已准备输入交给了 Cargo。构建后
重新探测环境不能证明它与真实进程使用的是同一组值；把环境直接写入日志又会公开 runner、SDK 和工具链路径。

候选自己记录的值仍是自述，不具备独立性。若把它放进 release output、Receipt、provenance 或公开
artifact，会同时混淆十三文件发布合约和 ADR-0010/0041 的外部权威边界。默认构建也不应因诊断需求新增
持久化副作用。

## Decision

- `release-build` 增加显式可选的 `--build-input-observation-dir <DIR>`。未提供时，命令行为和输出集合完全
  不变。
- 观察目录必须预先存在、固定并位于源码仓库及其 Git 私有目录之外；它与 release output 必须互不包含。
  每个 target 只创建固定名 `release-build-input-observation-<TRIPLE>.json`，已有同名文件时失败且不覆盖。
- 文档使用 `forge.release-build-input-observation/v1` 独立版本化合约。它绑定源码 commit、target、观察
  phase、同一个待执行 Cargo invocation 的原生编码 program/有序 argv/cwd，以及 Windows MSVC 构建从
  同一 `EnvPolicy` 投影出的 `PATH`、`LIB`、`INCLUDE`。v1 不声称覆盖完整进程环境、工具链身份或所有
  builder inputs。
- Forge 在完成环境准备之后、启动 Cargo 之前，从同一个 `PreparedCargoInvocation` 借用这些值并原子
  create-only 写入 owner-private 文件；随后把该 invocation 的原值直接移入真实进程。观察写入失败时
  不启动 Cargo，且不做第二次环境探测。
- 原始文档是 `diagnostic-only-not-release-evidence`。它可能包含本机路径，不属于 binary、SBOM、manifest、
  checksum、Receipt、Evidence、provenance、签名、批准或发布 Authority，不得原样记录到日志或上传。
- 候选只读 CI 可以在同一临时 runner 内对原始文档做无内容回显的 E2E 检查，并在正常成功/失败路径的
  `finally` 中移除 raw 文件命名空间；这仍只证明候选路径可运行。Authority-owned sanitizer 可以在本机
  按 allowlist 生成不含路径的安全摘要并移除 raw 文件，但净化只降低泄漏面，不增加候选自述的独立性。
  此摘要只能帮助 canary 诊断和冻结 policy；正式 qualification 必须在 fresh run 中由 Authority-owned observation、
  enforcement 和 builder record 独立绑定真实输入，raw 或 sanitized candidate report 均不能单独满足门禁。
- rc.2 的十三文件发布集合、默认 release-build、副作用、finalize/check 和所有权限域保持不变。

## Consequences

### Positive

- 失败可以追到真实 Cargo 调用边界，而不是依赖事后环境猜测或日志中的路径片段。
- 同一 invocation 的先观察后消费消除了“观察一组值、执行另一组值”的本地实现漂移。
- 私密诊断与公开资产、证据和外部批准保持可机械检查的分离。

### Negative / trade-offs

- 启用者必须管理独立临时目录，并在失败或中断后清理可能残留的私密文件。
- 候选代码与候选 CI 属于同一信任域；即使 E2E 通过，仍不能证明记录真实或授予发布权。
- v1 只对 Windows MSVC 环境投影给出专门字段；其他平台的完整 builder-input 冻结仍由外部 Authority
  负责。

### Implementation constraints

- 原生字符串必须有界、无损并在 Base64 解码前先做编码长度门；不得用 lossy UTF-8 代替 Windows wide
  或 Unix bytes。
- raw 文件必须 create-only、owner-private、大小有界并精确回读；不得加入任何发布资产枚举或 upload
  路径。
- Windows native CI 必须真实执行 opt-in 路径、检查固定 contract/target/source/MSVC 状态和二文件
  release output，并在正常成功/失败路径以 `finally` 清理 raw 目录；强制中断由 disposable runner 销毁
  或 persistent runner 的 trusted post-job cleanup 覆盖。
- schema、CLI、runbook 和架构回归测试必须同时固定上述信任边界。

## Rejected alternatives

### 把完整环境打印到 Actions 日志

日志保留时间和读权限不同于本机临时文件，且会公开 SDK、工具链和用户路径；非结构化文本也难以做
有界、版本化校验。

### 构建后重新探测或从失败日志反推

事后状态可能已改变，日志只包含被选择输出的片段，都不能证明真实 Cargo 进程消费的精确值。

### 把 raw 作为第十四个发布资产或 provenance subject

这既泄露本机路径，又静默改变 ADR-0041 的固定分发集合，并把候选自述伪装成外部证明。

### 默认对每次 release-build 持久化

大多数调用不需要该诊断；默认副作用会增加隐私、清理和兼容成本。显式 opt-in 使风险和生命周期可见。

## Validation and revisit conditions

- raw 类型的 constructor 与 serde 必须在解码前限长，并拒绝非规范 Base64；Windows UTF-16 raw 还必须
  拒绝解码后 NUL 和奇数字节。consumer 必须独立拒绝当前语境不接受的 `unknown` 或错误编码分支。生成的
  JSON Schema 只固定可表达的字符形状、长度和分支，不能冒充 decoded semantic validation。
- 单元测试必须证明同一 prepared invocation 的 program/argv/cwd/env 被先观察再消费，且非 Windows 主机
  不猜测 ambient MSVC 值。
- Windows target 严格 Clippy、native workspace tests 和 protected `verify.yml` E2E 必须通过；候选 CI
  仍保持 read-only 且无 artifact upload。
- Authority sanitizer、无路径安全摘要及独立 observation/enforcement/builder record 必须用新的 Authority
  合约和 fresh qualification 验证；不得把 raw 或 sanitized candidate observation 单独计入 release evidence。
- 若未来需要记录其他平台环境、完整 `ExecSpec`、默认持久化或公开安全摘要，新增 schema major 与 ADR，
  不得原地扩大 v1 的证明含义。
