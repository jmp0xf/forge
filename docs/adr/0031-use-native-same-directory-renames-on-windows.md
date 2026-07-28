# ADR-0031：Windows 使用原生同目录句柄重命名

- Status: Accepted
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: ADR-0028
- Superseded by: None

## Context

ADR-0028 正确决定以目录句柄而不是路径字符串维持仓库写入的对象身份，但为 Windows 选择了
`SetFileInformationByHandle(FileRenameInfo)` 的非空 `RootDirectory` 相对提交。真实 Windows runner
持续把这一组合拒绝为 `ERROR_INVALID_PARAMETER`；补足 `FILE_RENAME_INFO` 的可变长度缓冲区后仍可
稳定复现，因而不能把失败归因于结构体尺寸。

Forge 已用 `NtCreateFile` 相对固定父目录创建临时文件。Windows 原生
`FILE_RENAME_INFORMATION` 合约对同目录重命名有更直接的形式：以临时文件句柄为 source，传简单
leaf name，并将 `RootDirectory` 置空。目标由 source 当前所在的目录对象解析，不经过进程 cwd 或可被
替换的完整路径。这与 Forge 要证明的 capability 边界一致，也避免混用 Win32 与 NT 两套相对路径
语义。

## Decision

ADR-0028 的路径验证、逐段 no-follow 打开、固定 root/parent、同目录临时文件、提交后身份复核和
失败语义全部保留；仅替换 Windows 最终提交原语：

1. 临时普通文件仍由 `NtCreateFile` 相对固定父目录独占创建，并以 `DELETE` 权限打开；
2. 最终提交使用 `NtSetInformationFile(FileRenameInformation)`；
3. `FILE_RENAME_INFORMATION.RootDirectory` 必须为 NULL，`FileName` 必须是已验证的单个 leaf；该组合
   明确表示在 source 文件所在目录内改名，因此并发移动可见祖先不会重定向目标；
4. 缓冲区至少分配并传入 `sizeof(FILE_RENAME_INFORMATION) + FileNameLength`，保留字节清零，名称按
   counted UTF-16 复制；
5. `replace=false` 继续承担 create-only collision，`replace=true` 继续承担原子替换；不得回退为
   路径式 `MoveFileEx`、先检查再覆盖或复制后删除；
6. NTSTATUS 必须经 `RtlNtStatusToDosError` 映射为现有 `io::Error`，上层 commit-state 合同不变。

该变化不修改 versioned machine contract；它修正同一 `RepositoryFilePort` 行为在 Windows 上无法
执行的问题。

## Consequences

### Positive

- 临时创建与最终提交使用同一套 NT 句柄语义，边界更小且更直接。
- 同目录 rename 由 source 文件对象隐式固定其父目录，不依赖进程 cwd 或重新解析可见祖先。
- 保留 ADR-0028 的 create-only、祖先交换检测和已提交但未验证状态。

### Negative / trade-offs

- Windows 实现继续依赖已集中隔离的少量 `windows-sys` WDK FFI。
- 本机非 Windows 只能交叉编译；运行时正确性仍必须由真实 Windows runner 证明。
- ADR-0028 的 Windows API 细节不再有效，阅读者必须沿 supersession 链到本记录。

## Rejected alternatives

### 继续使用 Win32 API 并只扩大缓冲区

真实 runner 已证伪这一修复的充分性，继续重试会保留可重复的 error 87。

### Win32 API 使用 NULL RootDirectory 与相对路径

Win32 文档把这种相对名称关联到进程 cwd，不能承担固定父目录 capability。

### 传完整路径或使用 MoveFileEx

这会在最后一次验证与提交之间重新引入路径解析和祖先替换窗口，直接退化 ADR-0028 的安全性质。

## Validation and revisit conditions

- Windows 真实 runner 必须通过 create-only collision、replace、root swap、final/intermediate parent swap
  以及失败临时文件清理测试；
- CLI init/adapters、私有 state/cache/evidence 和 release asset 的所有原子写调用点必须共同收敛；
- Linux 与 macOS 的既有句柄相对实现和测试不得变化；
- 若未来需要跨目录移动，必须另行决定显式目标目录 capability，不能从本 ADR 推断。
