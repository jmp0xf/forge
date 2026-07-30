# ADR-0040：项目工具外部配置未闭合时安全失败

- Status: Accepted
- Date: 2026-07-30
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None
- Depends on: ADR-0016, ADR-0020, ADR-0039

## Context

项目命令收到的净化环境会继承 `HOME`、`CARGO_HOME` 等必要路径。现有环境摘要绑定了路径值，
却没有绑定路径下会被标准工具自动读取的配置内容。于是路径和值都不变时，新增或修改
`$CARGO_HOME/config.toml` 可以改变 `rustflags`、linker 或 `rustc-wrapper`；旧的 passing Receipt
仍可能被判为 current。显式配置的 `go test/build/vet` 同样可能读取用户 GOENV 文件中的
`GOFLAGS`。这违反 ADR-0016 的依赖失效不变量。

直接摘要这些外部文件会把可能含代理、registry、凭据或其他低熵私密配置的内容放进可重复比较的
Receipt preimage。只绑定文件路径、mtime 或工具版本又不能证明实际执行语义。v0 也没有隔离并锁定
完整外部工具闭包的沙箱。

## Decision

新增 `forge.project-command-environment-acquisition/v1`，把“是否完整取得项目命令环境依赖”与
既有 `forge.environment-fingerprint/v1` 的纯净化环境编码分开。`evidence run` 与
`show/verify/export` 必须调用同一采集边界：

- 对精确 `cargo` 程序，检查实际 cwd 到文件系统根的每一级 `.cargo/config` 与
  `.cargo/config.toml`，并检查净化后环境解析出的 `$CARGO_HOME/config*`；未显式设置
  `CARGO_HOME` 时使用平台 home 下的 `.cargo/config*`；
- 任一标准 Cargo 配置候选存在、metadata 结果不确定、home 不能解析为绝对路径、argv 含
  `--config`，或原生 argv 无法安全分类时，环境 dependency 为 typed `unknown`；不读取配置内容，
  也不阻止命令作为 observation 执行；
- 配置发现链可以确定为空时，继续摘要实际净化环境，因此普通无配置 Cargo 项目仍能形成 known
  environment dependency；后续出现配置时，同一 reader 会返回 unknown，使旧 Receipt 失效；
- 精确 `go` 程序只有在来源是 Forge 的 Go language provider，并同时固定 `GOENV=off`、
  `GOFLAGS=""`、`GOTOOLCHAIN=local`、`GOWORK=off` 时保持 known；显式配置的 Go 命令、缺少任一
  隔离项或使用 go.work 的命令在 v0 为 environment unknown；独立 `gofmt` 不读取这套 Go 命令
  配置，不受此判定影响。

unknown 只污染 environment 轴。command、toolchain、scope、outcome 和其他已知事实继续保留；
ADR-0039 仍保证该 Receipt 可诊断但不能满足 Evidence。

这次变化不修改 Receipt/Evidence schema、identity、canonical JSON、toolchain probe 或 validity
协议。完整 behavior composition 从 `forge.evidence-behavior/v8` 升为 v9；旧 Receipt 保持不可变，
并因 Forge behavior dependency 变化而 stale。

## Consequences

### Positive

- 外部 Cargo/Go 配置不能再让旧 passing Receipt 保持有效。
- 配置内容和潜在秘密不进入 Receipt，也不进入诊断。
- run 与只读重算共享一个判定，避免写入与读取语义漂移。
- 无标准 Cargo 配置的普通项目和隔离的单 module Go 项目保留证明能力。

### Negative / trade-offs

- 使用 Cargo 配置、显式 Go 命令或 go.work 的项目暂时只能得到 observation-only Receipt。
- “配置不存在”是与现有 scope before/after 相同威胁模型下的本地快照，不是抵御恶意同主体并发
  篡改的沙箱承诺。
- 未来恢复这些项目的证明能力，需要隐私安全地解析配置、绑定间接工具和在执行前后验证闭包。

### Implementation constraints

- Cargo 配置检查必须使用实际传给子进程的净化环境，不能重新猜测父进程环境。
- 任一存在性检查中除 `NotFound` 外的错误都必须 fail closed；符号链接、目录或非普通文件也按存在
  处理，不能读取后乐观忽略。
- 配置候选内容、路径值和错误细节不得写入 Receipt 或诊断。
- writer 与 reader 必须共用同一公开采集函数，并有真实 `run -> show -> verify` 变异测试。
- 后续若扩大 known 边界，必须新增替代 ADR、升级采集协议和 behavior composition，并证明所有间接
  配置与工具依赖都已闭合。

## Rejected alternatives

### 只摘要 HOME/CARGO_HOME 路径

路径不变而内容变化正是本次失败模式。

### 直接摘要外部配置文件内容

外部配置可含秘密或低熵私密值；未解析的内容摘要会形成离线猜测 oracle，也仍未绑定其中引用的
wrapper、linker 和 source replacement。

### 把未知记到 toolchain 轴

Cargo/rustc/Go 版本探针仍可能完整；未知事实是命令会读取的外部执行环境。污染 toolchain 会违反
ADR-0039 的最小 typed-unknown 诊断。

### 所有 Cargo 和 Go 命令永久 unknown

它安全但不必要地取消了配置发现链为空、或 Go 用户配置已被明确禁用时的证明能力。

## Validation and revisit conditions

使用 runtime 表驱动测试覆盖 Cargo config 两种文件名、祖先配置、显式 `--config`、无配置 known，
以及 Go 每个隔离键、来源与 GOWORK 分支；使用真实 Rust fixture 先形成 valid Receipt，再在仓库外同一
`CARGO_HOME` 新增和修改配置，要求 `show/verify` 只报告
`dependency-unknown: environment`。实现安全的配置解析、外部工具绑定与前后稳定性检查后，以新 ADR
和新协议替代本决定的保守 unknown 边界。
