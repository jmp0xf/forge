# ADR-0028：仓库写入固定目录句柄

- Status: Accepted
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 已拒绝绝对路径、`..`、symlink/reparse point、非普通目标以及 canonical root 之外的路径，并在
原子替换前重新检查。这些路径检查仍留下一个无法靠“再检查一次”消除的窗口：另一进程可以在最后
检查之后、rename 之前替换仓库根或任一祖先目录，使同一字符串解析到另一个目录。若临时文件创建和
最终替换都继续按完整路径执行，检查与使用的就不是同一对象。

这一问题是经典的 capability/TOCTOU 边界，不是 Forge、AI Agent 或受管块特有的问题。正确的最小
修复是让操作系统目录句柄承担对象身份，而不是再增加一种文档约定或锁定协议。仓库锁也不能解决：
不遵守 Forge 锁的本地进程仍可改名目录。

## Decision

所有通过 `RepositoryWriter` 进行的受限仓库文件写入在 Unix 和 Windows 上采用目录句柄相对操作：

1. 构造 writer 时以 no-follow/reparse-resistant 方式打开并固定 canonical repository root；
2. 将已验证的相对路径逐段从该句柄打开；缺失目录也只相对当前已固定父目录创建，然后立即以
   no-follow 方式重新打开；
3. 在已固定的最终父目录中以 exclusive create 建立临时普通文件，写入、flush、权限收敛并同步；
4. 替换操作和 create-only 操作都只使用该父目录句柄和单个 leaf name；create-only 不得退化为
   “先检查再覆盖”；
5. 提交后重新从固定 root 遍历目标父目录并比较对象身份，同时比较当前可见 root 与初始 root
   身份；不一致返回失败；
6. Unix 使用 `openat`、`mkdirat`、`renameat`、`linkat`/`unlinkat` 与目录 fsync；Windows 使用
   `NtCreateFile` 的 `RootDirectory` 相对打开及 `SetFileInformationByHandle(FileRenameInfo)` 的
   `RootDirectory` 相对提交，并拒绝每一层 reparse point；
7. 新平台若没有等价 capability primitive，写入必须报 unsupported，不能静默回退到路径式写入。

相对路径、现有目标种类、普通文件权限和私有状态权限的既有合同不变。该变更不修改任何 versioned
machine contract。

## Failure semantics

祖先在提交窗口被替换时，句柄相对提交可能已经安全地落在原先固定、随后被移走的目录中，之后的
身份复核再返回失败。这是一个显式的“结果不再位于已确认可见路径”失败，而不是回滚承诺；Forge
不得把它报告为成功，调用者必须重新探测和规划。关键安全性质是：操作不会跟随替换后的祖先，因而
不会把目标内容写入替换树。

这仍不是对同一用户其他进程的 sandbox 或 tamper resistance。同一权限主体可以在 Forge 返回后
修改文件，也可以干扰 Git、读取和状态观察；这些事实仍由稳定性确认、Evidence 边界和外部审查处理。

## Consequences

### Positive

- 最后检查到 rename 的祖先替换不再能重定向仓库文件写入。
- 临时文件、最终目标和 durability 操作绑定同一父目录对象。
- create-only 与 replace 在相同 confinement 原语上实现，减少两套安全语义。

### Negative / trade-offs

- Unix 与 Windows 需要各自很小但不可避免的平台实现；Windows FFI 必须集中隔离并逐项记录 safety
  invariant。
- 目录被移走时可能发生“安全写入旧对象后返回失败”，上层不能假设所有错误都等于零副作用。
- 本机只能执行本机竞态测试；Windows 行为仍须在真实 Windows runner 上执行，cross-compile 不是
  runtime 证明。

## Rejected alternatives

### 在 rename 前后重复 canonicalize

路径可在任意两次检查之间变化；增加检查次数不建立对象身份连续性。

### 只固定 repository root

中间祖先仍可被替换。必须逐段打开到最终父目录，并让临时创建与提交都相对该句柄。

### 用 repository lock 作为安全边界

锁只协调守约调用者，不能约束恶意、失控或不认识 Forge 的同权限进程。

### 引入新的通用 capability filesystem 依赖

v0 需要的表面积只有目录遍历、创建、临时普通文件和提交；现有 `nix` 与 `windows-sys` 已覆盖所需
原语。增加新的抽象层不会降低当前维护成本。

## Validation and revisit conditions

- Unix 与 Windows 都必须有确定性的 root-swap 和 ancestor-swap 测试：替换树不得收到目标内容，
  固定旧树可以收到完整原子内容，但命令必须返回身份变化失败；
- symlink/reparse、非普通目标、create-only collision、权限、失败清理和既有 apply race 测试继续
  通过；
- Linux、macOS 和 Windows 的目标编译/Clippy 必须通过；Windows runtime 结论只能来自真实
  Windows 执行；
- 若未来扩展多文件事务、删除或目录移动，必须另行决定其 capability 与恢复协议，不能从本 ADR
  推断跨文件原子性。
