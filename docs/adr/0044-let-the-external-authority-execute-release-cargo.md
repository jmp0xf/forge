# ADR-0044：由外部 Authority 执行发布 Cargo

- Status: Accepted
- Date: 2026-08-03
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None
- Depends on: ADR-0010, ADR-0011, ADR-0041, ADR-0043

## Context

ADR-0041 把最终 qualification 放到物理分离的 Authority Set；ADR-0043 又增加了候选侧私密诊断，能够从
同一个 `PreparedCargoInvocation` 先记录 program、argv、cwd 和部分环境，再由候选启动 Cargo。在受保护
精确提交的五平台 canary 中已观察到 candidate diagnostic 样本通过合约审计、raw 路径可净化为有界摘要，
同时所有下游权威 job 保持不可达；这只验证旧诊断协议，不能跨越信任域。准备调用、写出自述、启动 Cargo、
读取产物和暂存资产的仍是同一个候选 `xtask` 进程。

因此，Authority 在候选进程退出后净化它的报告，只能证明报告符合候选侧合约，不能独立证明真实 Cargo
进程使用了报告中的输入。把这种摘要改名为 builder record、在构建后重新探测环境，或让 Authority 脚本
包裹整个候选命令，都没有改变“候选既描述调用又执行调用”的根因。若直接据此开放 qualification，外部
裁判会依赖候选对自身行为的陈述，违反 ADR-0010/0041 的权威分离。

本地 `release-build` 仍需要保持一个易用的单命令工作流；改变正式 qualification 的执行边界不应让普通
维护者为了组装本地审查候选而模拟外部 Authority。

## Decision

正式 qualification 使用独立的 **plan / execute / apply** 协议。每个 target invocation 都有一个
Authority-owned driver 贯穿自身三阶段保持存活，并在与候选不同的 OS 强制保护域中控制状态；实际 release
Cargo 进程树必须由它构造和启动，而不是由候选 `xtask` 启动。只有父子进程关系而没有 principal、
ACL/sandbox 和写域隔离，不满足本决定。

候选写集必须满足：

```text
W_candidate ∩ {
  Authority checkout / policy / probe / driver state,
  execution result / builder record / sealed handoff,
  artifact metadata / job-output metadata,
  GITHUB_ENV / GITHUB_PATH / GITHUB_OUTPUT / GITHUB_STATE / GITHUB_STEP_SUMMARY,
  any other runner command or capability channel
} = ∅
```

这一不相交关系必须由 OS 权限边界强制，而不是由候选约定、自检或目录命名证明。

### 1. Candidate plan 只表达请求

- Forge 新增显式、版本化、机器可读的 release build plan。plan 绑定精确 source commit、lockfile、target、
  package、binary、profile、离线/锁定要求和预期的仓库相对输出；它不携带可直接执行的任意命令。
- plan 是 candidate-controlled request，不是 builder record、provenance、qualification、批准或 release
  evidence。Authority 必须把它当作不可信输入，拒绝未知 target、额外 package/bin、任意 executable、任意
  flag、绝对 cwd/target-dir、环境覆盖和未被当前 policy 精确允许的字段组合。
- 生成 plan 的候选阶段不得产生 release binary、SBOM 或可被后续复用的 Cargo target。候选阶段的检查结果
  只能用于诊断；Authority 仍须独立绑定受保护源码和 policy。
- 若 plan 需要执行候选代码，该进程也必须运行在受限 candidate principal/namespace 中，只能写入本阶段
  fresh scratch。它不得继承 token、OIDC、secret、GitHub workflow command-file 路径或 Authority 私有路径，
  也不得写 Authority checkout、policy、driver、后续 build/apply 命名空间或父控制器状态。

### 2. Authority 亲自构造并执行真实调用

- Authority 从自己受保护的 policy 和 runner probe 选择真实 Cargo/toolchain、工作目录、完整允许环境、
  cache、linker/SDK、fresh target directory 和资源边界。它从已验证 plan 中只提取 policy 明确允许的语义，
  不执行 plan 提供的 program/argv/env。
- 真实 Cargo 和工具链 executable 必须由 Authority 解析为固定绝对路径并绑定 identity/digest，再以原生
  argv 直接启动；不得经过候选提供的 wrapper、`PATH` 搜索、shell 重解释或未解析的 rustup shim。若安装
  使用 rustup，Authority 必须在候选代码启动前解析并固定最终 toolchain binary。
- Authority checkout、driver、policy、workflow command files、父控制器状态、execution record 和 handoff
  namespace 必须只对 Authority principal 可写。候选源码、工具链和依赖 cache 对 candidate principal
  只读；candidate 只能写入当前 target/phase 的 fresh scratch 与候选输出。仅靠路径约定、chmod 后由同一
  principal 执行，或把记录放在候选知道但仍可写的位置，都不是隔离。
- Authority-owned driver 是受控 Cargo 进程树的 supervising parent。若平台需要固定的降权 launcher，
  launcher 本身属于 Authority TCB，driver 必须记录并验证从 launcher 到真实 Cargo 的完整关系。driver
  关闭 stdin，以闭合环境执行锁定且离线的固定调用，并在 OS 层拒绝网络、越界文件写入、脱离受控 job/
  process group 和向 Authority/GitHub 控制通道写入。`--offline`、环境过滤或进程退出码不能替代这些强制边界。
- candidate package、proc macro 和 `build.rs` 会在 Cargo 进程树内执行，因此必须继承同一个受限 principal、
  filesystem、network 和 descendant containment。driver 在继续前必须证明所有 descendants 已终止，并对
  只读源码、工具链/cache 边界和 target 输出重新核验。
- Windows containment 必须先 suspended create，再把进程分配到禁止 breakaway、kill-on-close 的 Job Object
  后 resume，并等待 active process count 归零；restricted token 与 DACL 强制写集。Linux/macOS 必须使用
  普通 `setsid`、双重 fork 或重新分组无法逃逸的等价 sandbox/namespace/supervisor。进程组本身不是充分
  边界。
- 源码 checkout、Cargo home、target directory、handoff 和记录命名空间均由 Authority 创建为 fresh、
  target-bound、create-only 边界。失败、取消或边界不完整时整次 invocation 失败；不得复用旧目录、旧记录或
  旧 artifact，也不得 rerun 原 run 来补齐证据。
- 所有 execute descendants 终止且边界复验通过后，仍存活的 Authority driver 必须先撤销 candidate 对
  target 的写权，再从 Cargo 的真实输出读取、校验并摘要绑定目标 binary；不能先让另一个 workflow step
  根据候选文件重建事实。读取必须使用已固定的 no-follow handle，拒绝 symlink/reparse、路径替换和摘要后
  race；同时复核 source、lock/config、toolchain/SDK 和 accepted dependency cache 未漂移。这个摘要与
  plan digest、source commit、authority commit 和完整 build profile 先组成 driver 内存或 Authority-only
  临时域中的 **pending execute fact**。它是 non-proof、non-uploadable 的阶段状态，不是 success execution
  result；候选 raw observation v1、sanitized summary 和 canary observation v2 均不得进入该状态或后续证明链。

### 3. Candidate apply 只能组装，Authority 再独立复验

- apply 阶段在新的受限 candidate principal/namespace 中运行，只能只读消费 plan identity/digest、绑定的
  binary 和生成 target-bound SBOM 所需的最小、脱敏、严格 allowlist descriptor，并只能写 fresh
  candidate-output namespace。完整 private probe、execution result 和 Authority controller state 永不交给
  candidate。apply 不得启动 Cargo、替换 target、改写 Authority handoff/workflow command files，或从另一个
  build directory 选取产物。
- apply namespace 不挂载 Cargo、编译器或 toolchain executable，并由 child-exec denial 或固定 executable
  allowlist 从外部阻止编译器启动；不能只依赖 apply 自己遵守协议或测试事后发现。
- apply 产生的 binary/SBOM 仍是 candidate output。Authority 必须重新哈希最终 binary，要求与自己在 execute
  阶段捕获的摘要满足 `H(B_apply) = H(B_execute)`，并独立复核该 target 的 SBOM 与 package graph。
- apply 及其所有 descendants 终止后，同一个 Authority driver 必须重新取得输出的独占写控制、核验所有
  preimage/digest/namespace，并完成可信 cleanup，才把 pending fact 原子转为 create-only success execution
  result，再独立生成 builder record 和该 target 的 binary/SBOM 逐名 handoff。后续 upload action 只能读取
  这个已封口目录及显式名称，并校验 exact digest；不能上传 candidate scratch、目录 glob、pending fact 或
  候选写出的 job output。
- 五个 native handoff 组成一个 qualification cohort，必须同时满足：恰好五个唯一 target、相同
  Authority-generated fresh dispatch nonce、`github.run_id`、`github.run_attempt == 1`、source commit、authority
  commit 和 policy digest，并且每份 record 都绑定唯一 target invocation ID、自己的 plan digest、完整相关
  build profile、binary digest 和 SBOM digest。nonce 必须在任何 candidate code 运行前由 Authority preflight
  生成并进入保护状态；workflow rerun 因 attempt 不为 1 必须在 preflight 失败，不能复用原 nonce/record。
  不得跨 dispatch、attempt、commit 或 profile 拼接。cohort 通过后，ADR-0041 的无权限 finalize job 才能消费
  五对已封口 binary/SBOM；最终十三文件仍须由 Authority 独立 verifier 逐名复验，并要求其中五个 binary
  继续等于对应 execute digest。
- signer/attest 权限域继续只执行 Authority verifier，不 checkout Forge、不运行 `cargo`/`xtask`、不执行
  candidate binary。plan/execute/apply 阶段的 candidate code 或 executable 均不能进入拥有 OIDC 或
  protected environment 的进程；受保护 verifier 可以读取已封口的 allowlisted record 和 digest。

### 4. 隐私与失败状态机

- secret、CI runtime token、OIDC 请求端点、Authority-private host probe/document、完整 ambient environment、
  原始 stdout/stderr 及可枚举 raw 值的 hash 不得进入 candidate 输入、日志、artifact、builder record 或
  provenance。candidate 只能接收 Authority 合成的最小必要 build environment；Cargo、linker、SDK、
  `PATH`/`LIB`/`INCLUDE`、`OUT_DIR` 等构建必需值必须映射到 sandbox 内稳定、合成的 namespace，且只存在于
  受限进程环境，不得回显或进入公开记录/资产。若某平台不能隐藏私密宿主路径，事后扫描无法阻止恶意
  `build.rs` 把它编码到输出，该平台 qualification 必须关闭。公开 record 只保留 allowlisted semantic
  identity、closed classification 和必要内容摘要；私密 probe/result 只存在于 Authority 控制域并按有界
  生命周期清理。
- candidate stdout/stderr 不得直接进入 Actions workflow-command parser；driver 只保留有界、转义且不含
  原文内容的诊断摘要。需要私密排障内容时只能留在不可上传的 Authority 临时域。
- nonzero、signal、timeout、cancel、cleanup failure、descendant/network containment unknown、输入漂移、
  namespace/preimage 变化或 digest mismatch 任一发生时，不生成 success execution result/builder record，
  不 handoff、upload 或进入 finalize。失败摘要使用独立 non-proof identity，不得与 success record 兼容读取。
- partial candidate output 按 invocation 隔离且永不进入下一次 invocation。raw residue 只由 trusted post-job
  清除；若不能证明 cleanup 完成，必须销毁 disposable runner 或关闭该平台。失败只能 fresh dispatch，
  不得 rerun 原 run 补证据。

### 5. 本地兼容与激活边界

- 当前单命令 `xtask release-build` 及其可选 `--build-input-observation-dir` 保持本地审查/诊断行为，不改名、
  不改变默认输出，也不被重新解释为 Authority 执行。
- plan/apply 是正式 qualification 专用的显式 seam；不得让本地默认路径隐式依赖 Authority 仓库、网络或
  安装好的 Forge。
- 在新协议、Authority driver、builder-record v2、独立 verifier、两次五平台完整 fresh canary 及其 artifact
  audit 全部通过前，现有 qualification/finalize/attest 路径必须继续静态不可达。过去的 canary 不因本 ADR
  被追认成 release evidence。

## Consequences

### Positive

- “谁描述 Cargo”与“谁实际启动 Cargo”不再属于同一候选进程，builder record 可以绑定 Authority 自己观察
  的真实进程边界。
- 本地维护者继续使用一个命令组装审查候选；外部发布流程承担与其权威等级相称的额外步骤。
- plan 是小而可审查的声明接口；Authority 不需要复用候选的任意命令执行能力。

### Negative / trade-offs

- release build 要拆出 plan/apply seam，Authority 还要实现跨 Unix、macOS 和 Windows 的降权执行、文件
  ACL/sandbox、网络/进程树控制与私密输入记录，迁移成本高于包装现有 `release-build`。
- candidate build scripts 仍会在 Cargo 进程树内执行；Authority 必须有真实 descendant containment 和
  fresh namespace，不能仅靠“候选主进程已经退出”的假设。
- plan、execution result、builder record 和最终资产之间增加了多个摘要绑定；每个边界都需要独立 schema、
  负向测试和故障恢复规则。

### Implementation constraints

- plan 使用新的 `forge.release-build-plan/v1` identity；不得复用或扩大
  `forge.release-build-input-observation/v1`。最小 apply descriptor 使用独立、规范化、大小有界的
  `forge.release-build-apply-descriptor/v1` identity。Authority pending fact、success execution result 和
  builder record 也必须使用互不兼容、Authority-owned 的 versioned identities。
- 每个 target 的 build-critical profile 必须作为完整相关元组验收；不得把两个 canary 样本的 compiler、
  SDK、runtime、cache 或环境字段逐项取并集后拼成从未真实运行过的 profile。
- source/authority commit、plan digest、binary digest 和 SBOM digest 按 invocation 动态绑定；样本 commit、
  runner image 或易变诊断值不得固化为长期真理。
- plan/apply 与本地 `release-build` 必须共享纯 plan/组装领域逻辑，而不是复制两套发布语义；本地命令现有
  stdout/stderr、退出码、默认副作用和二文件输出必须有 golden/regression 覆盖。
- plan 与 apply 的架构测试必须证明它们不能落入普通 `release-build` 的 Cargo 执行分支；Authority workflow
  测试必须证明真正的 Cargo 子进程由 Authority driver 启动，并且 native handoff 在激活前不可上传。
- build job 必须从封闭 allowlist 构造 candidate 环境，清除 `GITHUB_ENV`、`GITHUB_OUTPUT`、`GITHUB_PATH`、
  `GITHUB_STATE`、step summary、未来新增 runner command channel、token/credential/OIDC 等控制能力，并用
  OS 权限使对应路径不可写，而不是只依赖候选不读取这些变量。
- 每个平台都必须用恶意 fixture 证明 candidate plan、build.rs 和 apply 无法写 Authority checkout/policy/
  record/handoff、无法修改只读 source/toolchain/cache、无法写 GitHub command files、无法逃逸 descendant
  containment 或联网；fixture 还必须证明 driver 在攻击后 fail closed 且不产出 builder record。
- 若任一平台无法可靠约束 Authority 写路径、CI command channels、进程树、网络、真实 Cargo、工作目录、
  输入不可变性、输出所有权或失败清理，该平台的正式 qualification 必须保持关闭，而不是降级为 candidate
  self-report。

## Rejected alternatives

### 把 sanitized candidate summary 升格为 builder record

净化只减少路径泄漏，不增加观察者独立性；同一个候选仍能同时选择报告和实际执行。

### 只把 `CARGO` 指向 Authority wrapper

候选可以绕过 wrapper、启动其他编译进程或暂存另一份 binary。除非 wrapper 属于能约束完整进程树和输出
所有权的 Authority parent protocol，否则它只是一个可绕过的接缝，不能单独满足本 ADR。

### Authority 包裹现有单进程 `release-build`

外层 shell 能看到退出码，却看不到候选进程内部哪一个 prepared invocation 真正产生了被暂存的 binary；
事后 probe 和候选 observation 都不能补足这条因果绑定。

### 在 signer job 中重新运行候选进行确认

这会让 candidate code 进入拥有 OIDC/attestation 权限的进程，直接破坏 ADR-0041 的权限域隔离。

## Validation and revisit conditions

- Forge 必须为 plan schema、create-only 输出、target/source/lock 绑定、plan/apply 状态机、禁止 apply 编译和
  本地 `release-build` 兼容增加单元、CLI、fixture 与架构不变量测试。
- Authority 必须为严格 plan 解析、完整 profile、跨阶段 driver 生命周期、受限 principal/ACL、Cargo
  process-tree ownership、network/descendant cleanup、execution-result 生成时序、封口 handoff、最终 binary
  等值和 candidate self-report 拒绝增加正反测试；Windows 必须在 native CI 验证原生字符串、DACL、Job
  Object 和 create-only 清理边界，macOS/Linux 必须验证各自实际采用的 sandbox/principal 机制。
- 外部负向 fixture 必须尝试写 Authority/GitHub command files、逃逸 descendant containment、联网、修改
  source/toolchain/cache、在 digest 后 race/symlink/reparse、从 apply 启动 Cargo、伪造 record、跨 run/profile
  拼接及制造 cancel/cleanup residue；`release-finalize` / `release-check` 的候选阶段也必须覆盖同类越权尝试。
  每项都必须得到“无 success record、无 handoff、无下游可达”。
- 协议合入后必须针对新的 Forge 与 Authority 精确 commit 发起 fresh canary；旧 run 或 rerun 不能验证新
  架构。只有两次独立完整样本和 artifact 审计通过后，才能单独评审 qualification activation。
- 若未来采用可证明提供同等父控制、输出所有权和不可绕过性的沙箱/远程执行系统，应新增 ADR 取代本记录，
  不得只改变 wrapper 名称后声称等价。
