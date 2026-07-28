# ADR-0033：Windows 重命名显式使用固定目标目录句柄

- Status: Accepted
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: ADR-0031
- Superseded by: None

## Context

ADR-0031 保留了正确的目录 capability 边界，并把 Windows 最终提交统一到
`NtSetInformationFile(FileRenameInformation)`；但它进一步规定同目录 rename 必须使用 NULL
`RootDirectory`，由 source 文件隐式确定父目录。GitHub Actions run `30368491032` 的 Windows job
`90305854467` 对这一选择给出了反例：可见中间祖先在 prewrite 后被移动时，replace 在提交前返回
`NotCommitted`；create-only 的 root/ancestor swap 场景也没有在固定旧树中产生目标文件。替换树没有
收到内容，安全边界没有被绕过，但该原语无法满足 ADR-0028 已接受的“安全提交到固定旧对象，然后以
CommittedUnverified 报告可见身份变化”语义。

Microsoft 的 [`FILE_RENAME_INFORMATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
合同还提供另一种原生形式：`RootDirectory` 是目标目录句柄，`FileName` 是相对该句柄解析的简单名称。
Forge 在最终提交前已经持有并验证这个父目录句柄，无需重新解析任何可见绝对路径。

## Decision

保留 ADR-0031 的 NT API、缓冲区、NTSTATUS、replace/create-only 和失败语义，仅修正目标目录选择：

1. 最终提交继续使用 `NtSetInformationFile(FileRenameInformation)`；
2. `FILE_RENAME_INFORMATION.RootDirectory` 必须是逐段 no-follow 打开并固定的最终父目录句柄；
3. `FileName` 必须是已经验证的单个 leaf，不得包含父目录或绝对路径；
4. source 临时文件仍在同一固定父目录中独占创建，因此该操作是同卷、同目录的原子 rename；
5. 提交后继续重新遍历可见父目录和 root 并比较身份。提交已经发生但可见身份变化时，继续返回
   `CommittedUnverified`；提交前失败继续返回 `NotCommitted`；
6. 不得退回 `SetFileInformationByHandle`、`MoveFileEx`、完整路径、cwd 相对路径或先检查再写入。

该修复不改变 versioned machine contract，只使既有 `RepositoryFilePort` 合同能在 Windows 祖先交换下
按同一语义执行。

## Consequences

### Positive

- source 与 destination 都绑定同一个显式父目录 capability，不依赖文件系统对 NULL `RootDirectory`
  同目录 rename 的具体处理。
- 修复同时覆盖 replace 和 create-only，不引入第二套提交路径。
- 替换后的可见树仍不会收到内容；移动后的固定旧树可收到完整原子内容并触发提交后身份失败。

### Negative / trade-offs

- Windows 实现仍依赖集中隔离的 WDK FFI，真实运行行为不能由交叉编译证明。
- Windows runner 必须继续保留 ancestor/root swap 测试；普通成功路径不足以验证 capability 语义。
- ADR-0031 的 NULL `RootDirectory` 细节不再有效，维护者必须沿 supersession 链阅读本记录。

## Rejected alternatives

### 继续使用 NULL RootDirectory 并只调整测试预期

这会把真实的未提交降级解释成可接受行为，破坏跨平台 commit-state 合同并弱化既有安全回归测试。

### 重新使用 Win32 FileRenameInfo

ADR-0031 记录的 Windows runner 已稳定以 `ERROR_INVALID_PARAMETER` 拒绝该组合；本次证据不推翻这一
结论。需要修正的是 native 调用的目标目录选择，不是 API 层级。

### 使用可见完整路径

这会重新引入祖先替换 TOCTOU，使 rename 可能落入替换树，直接违反 ADR-0028 的核心边界。

## Validation and revisit conditions

- Windows 真实 runner 必须通过 create-only collision、replace、root swap、final/intermediate parent swap
  和失败临时文件清理；
- root/ancestor swap 必须同时证明替换树未收到内容、固定旧树收到完整内容，并返回提交后未验证状态；
- Linux 与 macOS 的现有 `renameat` 行为和测试必须保持不变；
- 若后续需要跨目录移动，必须为目标目录引入独立显式 capability 决策，不能扩张本 ADR。
