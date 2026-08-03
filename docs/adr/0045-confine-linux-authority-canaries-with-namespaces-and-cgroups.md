# ADR-0045：用 namespace 与 cgroup 隔离 Linux Authority canary

- Status: Accepted
- Date: 2026-08-03
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None
- Depends on: ADR-0010, ADR-0011, ADR-0041, ADR-0044

## Context

ADR-0044 要求外部 Authority 亲自启动发布 Cargo，并用与候选不同的 OS 强制保护域闭合 principal、文件、
网络、进程树、资源、隐私和 cleanup。它没有选择 Linux 的具体原语。当前外部 Authority 只有抽象的
`forge.release-sandbox-phase-policy/v1` 和一个始终 unavailable 的 backend；可达 workflow 仍以 runner
用户直接运行旧 canary Cargo/xtask。两者都不是 sandbox，也不能成为发布证据。

Linux 是最适合先验证真实边界的平台，但仅用 `setsid`、进程组、同 UID 下的 `chmod`、Cargo
`--offline`、清理环境变量或 job 结束后销毁 hosted runner，都不能证明候选及其 `build.rs`、proc macro
和后代无法越界。反过来，在五平台 backend、v2 policy/session、必要的记录/verifier 和两次完整 fresh
canary 之前开放 qualification，又会违反 ADR-0041/0044。

因此需要先冻结一个 Linux-only、non-proof canary 的不可降级实现边界，再实现和实测；它不是正式发布
激活决定。

## Decision

外部 Authority 的 Linux canary 使用一个 Authority-owned 原生 launcher/reaper 与持续存活的 Authority
driver。launcher 以受控特权建立隔离后，把候选降为不同于 runner/Authority 的 fresh host UID/GID；候选
从不取得 host root、sudo、宿主 namespace、cgroup 管理权或除显式审计的标准流之外的 Authority 文件句柄。
launcher 的源码、构建输入、最终 executable identity 和运行时闭包属于 Authority TCB，必须在任何候选
代码运行前固定。不得通过 `PATH`、shell、未解析 rustup shim 或候选 wrapper 找到它。

下列原语是第一个 Linux implementation profile，不是仅供参考的菜单。实现不能在同一 profile identity 下
省略或替换它们；若 native probe 不能确认任一机制，backend 保持 unavailable。将来采用等强的不同机制，
必须用新 ADR 和新 profile identity 明确迁移。

本决定只允许 Linux x86_64/aarch64 的失败即关闭 canary。它不得生成 ADR-0044 定义的可发布 success
execution result、builder record、native handoff、qualification、attestation、签名、tag 或发布资产；
这里不把当前一次性的内部 `SandboxExecutionResult` 生命周期值误称为发布记录。现有 finalize、independent
qualification 和 protected attest 必须保持静态不可达。

### 1. 建立边界必须先于候选第一条指令

每个 invocation 和 phase 都使用 fresh、不可复用的资源。launcher 必须在候选第一条指令前完成并确认：

- Authority parent 先建立 non-delegated cgroup v2 parent、supervisor leaf 与 candidate leaf，再以
  `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC |
  CLONE_NEWUTS)` 在 supervisor leaf 启动 Authority-owned native namespace init/reaper。它是新 PID namespace
  的可信 PID 1，负责回收 orphan；candidate 永远不是 PID 1。缺少 `clone3`、`CLONE_INTO_CGROUP`、pidfd 或
  cgroup v2 的 kernel/profile unavailable；不得用“先运行、后迁移”代替原子进入；
- trusted PID 1 完成 privileged mount/root 设置后，以
  `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD | CLONE_NEWUSER)` 把仍停在可信 stub、尚未执行 candidate 指令的
  root 原子放入 candidate leaf，同时创建 candidate user namespace。`uid_map`/`gid_map` 各只有一个长度为
  1 的映射，绑定 fresh subordinate host ID，且不包含 host root、runner/Authority 或其他 invocation 的
  UID/GID；写 `gid_map` 前永久禁止 `setgroups`，补充组为空。mapping 完成后，仍在可信 setup 中的 stub
  才从 candidate leaf 调用 `unshare(CLONE_NEWCGROUP)`；native probe 必须确认新 cgroup namespace 以该 leaf
  为 `/`，随后才允许 credential/capability drop、filter 与 candidate exec；
- 建立顺序单向固定为：privileged TCB setup，FD/root/cgroup 复验，real/effective/saved/fs ID 固定，逐项清空
  inheritable/permitted/effective/bounding/ambient capability 并锁定 securebits，设置 `no_new_privs`，加载
  phase filter，最后从已经固定的 FD 执行 candidate。exec 后再次复验 capability 仍全空。executable closure
  不得含 setuid/setgid 或 file-capability 文件；
- 构造任何 mount 前把新 namespace 的 `/` 递归设为 private，最终 synthetic tree 设为 unbindable；再构造
  synthetic root、`pivot_root` 并卸载 old root。候选的 cwd、root 和所有可见 FD 都不得再引用 old root；
  synthetic root 与 mountpoint parent 对候选只读；
- source、Cargo/toolchain、dependency cache、linker/SDK 和必要 runtime closure 由 Authority 通过 no-follow
  handle 先固定身份，再用 `mount_setattr(AT_RECURSIVE)` 强制 `ro,nosuid,nodev`，并按角色设置 `noexec`；
  不支持递归 mount attribute 时 unavailable。只暴露 profile 逐项声明的 nested mount；同时按 ancestor/
  descendant、mount ID、device/inode 与 bind/submount topology 拒绝权限不同的 alias。fresh writable roots
  不得与只读、Authority/control 或任何其他 phase 的 root 复用，满足
  `W_candidate ∩ (A_authority ∪ R_readonly ∪ C_control) = ∅`；
- 默认不挂载 host `/proc`、`/sys`、`/run` 或 host `/dev`，也不挂载 sysfs/debugfs/tracefs。若固定工具链确
  需 procfs，必须由 trusted PID 1 在对应 PID namespace 内挂载最小 fresh proc，并从内核层屏蔽 host
  UID/GID map、mount、cgroup、boot 与其他 identity；候选可见值必须稳定、synthetic、可公开。UTS hostname
  与必要的 `/dev`、`/etc` 内容同样由 profile 合成；不能闭合任一值时，该 kernel/profile unavailable；
- candidate 看不到可写 cgroupfs、控制 FD 或外部 cgroup handle，不能迁出 candidate leaf。native probe
  必须在 candidate exec 前确认 cgroup namespace 是在 root 已原子进入 leaf 后建立，且该 leaf 显示为 `/`；
- trusted stub 在单线程状态以
  `close_range(3, UINT_MAX, CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC)` 标记私有 FD，并显式关闭除 pinned
  executable 与 seccomp 握手所需 FD 外的其余对象；listener 交给 Authority broker 后也在 stub 关闭。
  pinned executable FD 带 `CLOEXEC`，所以成功 exec 后候选恰好继承 0/1/2：stdin 是只读打开的
  `/dev/null`，stdout/stderr 只进入 Authority 私有、有界、持续 drain 的 pipe，绝不直通 Actions
  workflow-command parser；
- `clearenv` 后只注入 Authority 合成的 closed allowlist，且所有路径值都位于 synthetic namespace。
  `PATH` 不得含空项、相对项或候选可写目录；不得继承 `GITHUB_ENV`、`GITHUB_OUTPUT`、`GITHUB_PATH`、
  `GITHUB_STATE`、step summary、token/OIDC、credential、proxy、`LD_*`、`GLIBC_TUNABLES`、Cargo/Rust
  wrapper、Git helper/config 或其他 runtime 注入变量；
- 使用空 network namespace，并加载 Authority 版本化、按 native syscall ABI 与 arch 固定的 default-deny
  seccomp/LSM profile。每次 syscall 都先校验唯一允许的 audit arch；x86_64 profile 同时拒绝 x32/i386
  syscall ABI，aarch64 profile 拒绝 compat ABI。profile 至少闭合 socket、旧/新 mount API、setns/unshare、
  带 namespace flag 的 clone、ptrace/process_vm/pidfd_getfd、keyring、bpf、perf、userfaultfd、io_uring、提权
  和未知 syscall；path 与 executable 权限由 mount/LSM 而非 seccomp 路径参数闭合。禁止事件使用
  `KILL_PROCESS`，或由
  Authority-owned notifier 在回复 candidate 前原子 latch；`TRAP` 只有在可信监视器先于信号交付完成 latch
  时才可使用，candidate 可处理的 `SIGSYS` 不是 observation。仅返回可吞掉的 errno 也不是 fatal-event
  observation；
- 对 wall、aggregate CPU、memory/swap、cgroup tasks、open files、private streams、writable bytes 和 inode
  设置来自 Authority policy 的有限预算。CPU 使用 cgroup bandwidth、Authority wall watchdog 与 observed
  aggregate ceiling 共同约束；每个 writable root 使用有 `size`/`nr_inodes` hard limit 的独立 fresh tmpfs，
  并在 fresh cgroup 上取基线、复验 `memory.events.local`、`pids.events.local` 与 aggregate CPU usage。任何预算
  或强制机制缺失、未知或无上限都不得启动候选。其他 writable-filesystem 机制需要新 profile identity。

Linux 静态 launch config 只描述待建立的闭合输入，不是 OS observation、live capability、cleanup
confirmation 或 release evidence；它含有的宿主细节不得序列化、记录或进入公开 contract。通用
`SandboxSession` 也只是由 backend 签发的生命周期 wrapper，不独立证明 OS 边界。当前 session factory 只
接受 phase-policy v1；在 phase-policy v2 和 version-aware session API 合入前，Linux backend 必须保持
unavailable。届时只有持有 namespace fd、pidfd、cgroup、mount 和 reaper ownership 的 opaque live lease，
才可在所有建立检查通过后调用对应版本的 session factory。

### 2. Authority 拥有真实执行因果链

driver/backend 必须创建根进程；候选回调不能自行 `subprocess` 后用返回值推进状态。根进程与每个后代都
必须继承相同的 principal、mount、network、seccomp 与 cgroup 边界。candidate-generated `build.rs`
executable 和 proc-macro code 是预期的不可信代码，不得因其由固定 Cargo/rustc 产生而跳过隔离。

阶段 command graph 为闭合 allowlist：

- **BOOTSTRAP**：固定 Cargo 构建 xtask；允许固定 rustc/linker 与 target 内生成的 build-script/proc-macro
  code，但全部留在同一边界。后代归零、输入复验并撤销候选写权后，Authority 以 no-follow handle 固定
  唯一 xtask 的 native identity、length 和 digest；以后执行的是该同一个打开对象，而不是按 path 重开；
- **PLAN**：只执行同一个 pinned xtask 的固定 plan argv；不挂载 Cargo/compiler，只允许必要的固定 Git/
  runtime closure；只能写 fresh plan output；
- **EXECUTE**：Authority 从 exact accepted plan 与私有 build profile 构造固定绝对 Cargo/argv/cwd/env；
  允许固定 toolchain/linker 和 target 内生成的不可信代码。所有后代归零并撤销 target 写权后，Authority
  才能读取 metadata/tree/messages 和 binary，形成不可上传的 pending fact；
- **APPLY**：只读消费 pinned xtask、accepted plan、最小 apply descriptor 与 captured binary；不挂载 Cargo/
  compiler/toolchain，fresh writable mounts 使用 `noexec`。candidate 独立 leaf 在根进程原子进入前设置
  `pids.max=1`，运行期间 `pids.current` 不得超过 1，因此当前 apply xtask 不得创建线程。trusted stub 只从
  pinned no-follow FD 发起 `execveat(AT_EMPTY_PATH)`；Authority-owned seccomp user-notification broker 通过
  session-bound listener 与 pidfd 只授权这一次、同一 FD identity 的 root exec，并在回复前把一次性状态
  消耗。此后 fork/vfork/process clone/clone3 与任何 `execve`/`execveat`/`fexecve` 都被 kill/latch；candidate
  无法取得 listener、pinned FD 或相同 session 的再授权。executable mount/LSM allowlist 只含初始 pinned
  xtask 及固定 loader/runtime；dynamic-loader、executable memfd 与 re-exec fixture 必须证明不能扩展进程/
  exec graph。root 本身始终视为任意不可信代码；本条不把 `noexec` 误称为代码来源证明。若 broker/LSM
  不能闭合一次性初始 exec，或 apply 将来确需线程，backend 必须保持 unavailable，直到新 profile 明确
  区分并验证 thread/process clone。最终 binary 必须满足
  `H(B_apply) = H(B_execute)`，SBOM 与 exact two-file namespace 由 Authority 独立复验。

Authority 直接启动的 phase root、pinned xtask 与固定 launcher helper 都相对于 Authority-pinned dirfd
使用带 `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` 的 `openat2` 固定同一个只读 FD，
在该对象上核验 identity、length、digest 与 immutable mount 后，再从同一 FD 通过
`execveat(AT_EMPTY_PATH)` 启动；不得验证一个 root 再按路径执行另一个 root。固定 Cargo/toolchain/linker/
Git descendant 可以由未修改的父程序按 synthetic path 执行，但只能来自 Authority-pinned、candidate
不可写的 immutable executable mount，并由 mount/LSM role allowlist 闭合。target-generated build script、
proc macro 与其他动态 descendant 是 arbitrary candidate code，只能来自 fresh designated target executable
root，并继承全部 sandbox/cgroup 边界；它们不是可信 executable identity，也不要求改写成 fd-based exec。
PLAN 的 Git 使用
Authority-owned closed config，禁用 system/global/repository config、hook、pager、credential/diff/fsmonitor/
SSH helper；EXECUTE 的 Cargo home 与 `.cargo/config*` 是完整受保护输入，wrapper、alias、runner、linker、
source/VCS/credential helper 只能来自 v2 profile 的闭合字段。任何额外 executable 都必须进入对应 phase
graph，否则 unavailable。

若实现需要额外 validation phase 来运行 check/test，必须先版本化扩展 phase policy；不得把未经描述的
Cargo/test 调用塞入现有阶段。`cargo fetch` 也不能留在 backend 外，因为候选 `.cargo/config` 可能改变
credential/VCS helper 等执行边界。

### 3. 成功与 cleanup 是合取条件

对每个阶段定义下列 canary 诊断后置条件；它不表示 semantic value 正确、ADR-0044 的可发布 success
execution result 或 qualification：

```text
canary_phase_completed =
  setup_verified
  ∧ root_spawned_by_backend
  ∧ every_descendant_inherited_every_boundary
  ∧ exit_status_accepted
  ∧ candidate_subtree_empty_before_forced_cleanup
  ∧ no_forbidden_effect_observed
  ∧ no_monitor_loss_or_unlatched_fatal_event
  ∧ input_identity_stable
  ∧ candidate_write_rights_revoked
  ∧ output_exact_and_sealed
  ∧ cleanup_confirmed
```

Authority-owned native launcher/reaper 独占 namespace、cgroup、output backing mount 与 control pipe；candidate
不继承 control FD。driver/control pipe 关闭、timeout、cancel 或异常时，reaper 必须先 kill/reap，再进入下列
顺序。launcher/reaper 自身死亡只能得到 unknown/discard，runner disposal 不能补成 confirmed。

root 正常退出后，trusted PID 1 必须先回收 orphan，并在任何 forced cleanup 前观察 candidate subtree 的
`cgroup.events` 恰好包含 `populated 0`。若此时仍为 populated，阶段先 latch/discard，随后 `cgroup.kill` 只作
失败清理；强制 kill 绝不能把阶段转成 completed。普通被只读 mount/DAC 拒绝且没有产生 forbidden effect
的访问不要求推断 candidate 意图；hostile fixture 必须从 Authority-private sentinel 独立证明拒绝生效。

其中 `cleanup_confirmed` 必须由 backend 对直接 OS observation 计算，不能由任意 callback 自报，并且至少
要求：

- 失败路径执行已在 setup probe 确认可用的 `cgroup.kill`；subtree-empty 证据是 non-delegated candidate
  subtree 的 `cgroup.events` 恰好解析为 `populated 0`，不是 pidfd 枚举。trusted PID 1 回收 orphan，Authority
  再 wait/reap 已持有的 candidate root 与 init pidfd；
- candidate subtree 清空后，特权 reaper 通过 profile 固定的 mount/ownership transition，先原子撤销
  candidate 对 exact allowlisted output 的全部可达写路径，再把 output 转入 fresh、invocation/phase-bound
  的 Authority-only、只读 internal store。该 store 只供本次 canary 后续 phase 使用，不是 native handoff、
  release evidence 或可上传 artifact；
- Authority 通过自己一直持有的 no-follow handle 复验 output 名称、owner、link count、identity、长度、
  digest 与预算，也复验 source/toolchain/cache/config 的身份和内容未漂移；确认转移后才删除其余 candidate
  scratch/writable roots；
- 最后终止 supervisor leaf 中的 trusted PID 1/reaper 与 stream drainers，卸载 synthetic tree，关闭
  namespace/mount/socket/FD，删除空 cgroup，并按有界生命周期清除 private raw stdout/stderr/probe。本次
  canary 全部结束后再删除 internal store。

任一事实为 unknown、任一 violation、nonzero/signal/timeout/OOM/PID/disk/output limit、cleanup 异常或输入漂移，
都必须得到：

```text
DISCARDED ∧ no publishable success result ∧ no builder record ∧ no handoff ∧ no downstream
```

job/VM disposal 只能清除失败残留，不能把 unknown 改写成 success。失败后只能 fresh dispatch；不得 rerun
原 attempt 补证据。

### 4. 版本化与激活

- 保留 `forge.release-sandbox-phase-policy/v1` 原义和严格解析；它只表达当前抽象意图。保持
  `forge.release-sandbox-capability-observation/v1` 的 unavailable-only 语义，且当前 v1-bound session API
  不得被 Linux backend 用来绕过迁移。
- 真实 backend 前新增不兼容、平台中立的 phase-policy v2 与 version-aware session API，明确 principal、
  filesystem、network、process、resource、privacy、generated code、FD/environment、预算和 cleanup 不变量。
  Linux host path、UID、mount、syscall 与资源句柄只存在于不序列化的私有 launch config/live lease。不得向
  v1 静默加字段或把宽松组合解释为兼容。
- candidate-visible plan v1/apply descriptor v1 暂不承载 host 私密 profile。以后 qualification 激活若改变
  pending fact、success result、failure summary、handoff、builder record、build type 或 builder identity 的
  语义，分别引入必要的新 identity；本 ADR 不预先扩大这些 machine contract。
- Linux canary 只能输出明确 non-proof、content-free 的 closed diagnostic receipt：exact Authority commit、
  Forge/fixture commit、target、phase-policy identity、Linux implementation-profile identity、固定 test-case
  ID、闭合结果 enum/计数，以及固定的 `evidence_status=excluded-from-release-evidence`、
  `qualification_eligible=false`、`builder_record_written=false`、`handoff_written=false`。host path、UID/GID、
  mountinfo、cgroup、argv/env、stdout/stderr、errno、probe、hash-of-private-value 都不得进入日志或 artifact；
  原始观察只在 Authority-private bounded state 中短暂存在。
- 两个 Linux target 的 backend 与恶意 fixture 通过，仍不允许部分平台发布。五平台完整实现、独立 verifier、
  signer-builder 绑定和两次 fresh canary artifact audit 后，另写 activation ADR。

## Consequences

### Positive

- 候选、`build.rs`、proc macro 与后代的权限由内核边界共同约束，不再依赖候选自述或进程组。
- backend 对真实 Cargo 的父控制、输出所有权和 cleanup 成为一条可验证因果链。
- Linux 可以先产生有价值的非证明 canary，同时不降低五平台发布门槛。

### Negative / trade-offs

- Authority 增加受控特权 launcher、namespace/cgroup/seccomp、mount/runtime closure 与资源清理 TCB。
- hosted runner 的 kernel/cgroup/特权差异可能使 backend 长期 unavailable；本决定禁止降级绕过。
- Cargo 真实依赖 candidate-generated code，使 executable allowlist 和 writable-but-executable target 边界复杂；
  必须用恶意 fixture 而非单元 mock 证明。

## Rejected alternatives

### 只使用 bubblewrap/nsjail/unshare 命令

工具名或安装存在不证明其 identity、配置、动态运行时、cgroup ownership 和 cleanup 满足本决定。经固定并
完整审计的外部 launcher 可以成为未来替代 TCB，但必须新增 ADR 与 profile identity；等价性分析只是该
迁移的评审证据，不能在当前 profile identity 下替换机制。

### Docker 或 GitHub-hosted VM 自身就是 sandbox

普通 job 内候选仍与 Authority/command files 共享 runner 权限；容器默认也不闭合 daemon、mount、network、
capability 和 sibling state。job 后销毁只提供失败清理，不证明运行期间隔离。

### 同 UID chmod、环境过滤和 Cargo offline

同 UID 可改写权限和同主体文件；过滤变量不撤销可见 FD、path 或网络；`--offline` 是 Cargo 行为，不是
对 build script/child 的内核网络拒绝。

### 先在 workflow 直跑候选，再调用 backend

候选一旦在 backend 外执行 `cargo check/test/build`、xtask 或 staged binary，就已能修改同 job 状态；后置
sandbox 无法恢复信任边界。

## Validation and revisit conditions

真实 Linux 测试至少要让 candidate plan、build.rs、proc macro 与 apply 尝试：写 Authority/GitHub command
files；修改 source/toolchain/cache；读取 host `/proc`/UID map/mount/cgroup/boot facts；DNS、IPv4/IPv6 TCP/UDP、
Unix socket；`setsid`、double-fork、clone/setns；环境/FD/secret 枚举；PATH/config/wrapper poisoning；fork/
memory/CPU/disk/FD/output bomb；symlink/hardlink/rename/digest race；apply 通过 `execve`、`execveat`/`fexecve`、
dynamic loader、memfd 或 re-exec 启动 Cargo；跨 run/profile/target replay；以及每阶段 cancel/cleanup residue。

每项必须在 Authority-private state 中独立观察到外部 sentinel 未变、listener 收到零字节、cgroup 清空、无
raw 泄漏、无 ADR-0044 可发布 success record、无 handoff、无下游可达；公开 diagnostic 只允许前述固定闭合
字段。若 hosted Linux 不能同时满足 principal、filesystem、network、process tree、resource、privacy、
output ownership 和 cleanup，Linux backend 保持 unavailable。

若未来采用已固定且可证明提供等价隔离的远程执行/微虚拟机系统，应新增 ADR supersede 本记录；不得仅替换
launcher 名称或降低未知状态的处理。
