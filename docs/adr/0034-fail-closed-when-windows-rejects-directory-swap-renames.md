# ADR-0034：Windows 拒绝目录交换提交时安全失败

- Status: Accepted
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: ADR-0033
- Superseded by: None

## Context

ADR-0033 把 `FILE_RENAME_INFORMATION.RootDirectory` 设为固定父目录句柄，意图让 Windows 的同目录
rename 在祖先被移动后仍提交到旧树。这个决定误读了 Microsoft 的
[`FILE_RENAME_INFORMATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
合同：同目录、单 leaf rename 的规范形式是 `RootDirectory = NULL`；非 NULL `RootDirectory` 表示相对
目标目录解析的移动。固定父目录仍负责临时文件创建、目标读取和身份复核，但不应作为同目录 rename 的
目标参数重复传入。

GitHub Actions run `30374770619` 的 Windows job `90327596634` 还区分了两个此前混在一起的阶段：

- 中间祖先在 prewrite 后、临时文件创建前成功移动时，最终 rename 返回提交前失败；commit state 是
  `NotCommitted`，替换树没有收到 Forge 内容；
- root/最终父目录在 `BeforeCommit` 回调中移动的用例，此时临时文件已经打开。Windows 可以先拒绝回调
  内的目录移动，所以测试不能假设 `saved-*` 树一定已经产生，更不能把随后读取不存在路径的错误当成
  rename 已经执行的证据；
- 同一候选上的 Linux 和 macOS `renameat` 可以安全提交到固定旧目录，随后因可见身份变化返回
  `CommittedUnverified`。

共同安全性质不是“每个平台必须取得相同进展”，而是：内容不得进入替换树，commit state 必须反映
真实提交点，失败临时文件必须清理。设 `C` 表示原子 rename 是否成功，`R` 表示替换树内容，则要求
`R_after = R_before`，并且失败结果只能在 `C = 0` 时报告 `NotCommitted`、在 `C = 1` 时报告
`CommittedUnverified`。Windows 拒绝操作时令 `C = 0` 是安全失败，不应伪造成 Unix 的 `C = 1`。

## Decision

1. Windows 同目录提交继续使用 `NtSetInformationFile(FileRenameInformation)`，但恢复规范的 NULL
   `RootDirectory` 和已经验证的单 leaf `FileName`；
2. repository root 继续固定为句柄；目标父目录从该 root 逐段 no-follow 遍历，并保留最终 parent
   capability。目标读取、临时文件创建、失败清理和提交后身份复核继续使用这些已验证句柄；
3. 原生 rename 成功后才越过提交点。之后的回调、可见父目录/root 身份复核或读取失败报告
   `CommittedUnverified`；原生 rename 或更早阶段失败报告 `NotCommitted`；
4. Windows 因已打开文件或陈旧祖先名称拒绝目录移动/rename 时允许安全失败。不得为了取得与 Unix 相同
   的进展而改写 commit state、解析可见完整路径或把内容写到替换树；
5. 确定性测试必须按实际阶段证明拓扑：
   - Windows 中间祖先交换完成但 rename 被拒绝时，替换树保留 replacement、旧树保留 reviewed、无临时
     文件，commit state 为 `NotCommitted`；
   - Windows `BeforeCommit` 测试记录目录移动是否完成：若文件系统拒绝移动，原拓扑不变；若移动完成，
     替换树仍不得收到内容，旧树目标只能缺失或包含完整 postimage；所有仍存在的相关目录都无临时
     文件；
   - Unix 相应用例继续要求旧树收到完整内容、替换树不变，并报告 `CommittedUnverified`。

`RepositoryWriteCommit` 已经同时表达这两种真实结果，本决定不修改 versioned machine contract。

## Consequences

### Positive

- 恢复 Microsoft 文档规定的同目录 rename 形式，不再把错误参数选择当作 capability 增强。
- 安全不变量跨平台一致，同时让平台特有的文件系统进展保持可观察、可诊断且不被伪造。
- 测试区分回调失败、提交前 rename 失败和提交后身份失败，减少由最终路径读取错误造成的误归因。

### Negative / trade-offs

- Windows 在某些祖先交换时会返回 `NotCommitted`，而 Unix 可以返回
  `CommittedUnverified`；调用者必须依据 commit state，而不能从操作名推断副作用。
- 当前 Windows 结果来自 GitHub-hosted NTFS runner；SMB、ReFS、其他文件系统和其他 Windows 版本仍需
  独立运行证据。
- 句柄固定保证不跟随替换树，但不能强迫文件系统完成它拒绝的 rename；这是安全边界，不是进展保证。

## Rejected alternatives

### 保留非 NULL RootDirectory

这与 Microsoft 对同目录单 leaf rename 的规范形式矛盾，且 run `30374770619` 没有证明它能修复中间
祖先交换。

### 失败后按可见完整路径重试

可见路径已经是攻击者可替换的名称；重试会重新引入 ADR-0028 要消除的 TOCTOU，可能把内容写入替换
树。

### 以同一个父目录句柄重新打开 source 后重试

中间祖先测试已经在交换完成后通过该父目录句柄创建临时文件，仍得到提交前失败。重复同构操作没有
新增身份信息或真实运行证据。

### 立即引入 OpenFileById 恢复路径

这会增加文件 ID 类型、文件系统和网络共享兼容面；Microsoft 文档明确记录 `OpenFileById` 不支持
SMB 3.0，128 位 `ExtendedFileIdType` 主要用于 ReFS。没有真实对抗运行证据前，这种复杂恢复路径不比
明确 `NotCommitted` 的安全失败更可靠。

## Validation and revisit conditions

- Windows 真实 runner 必须覆盖中间祖先交换、`BeforeCommit` root/父目录移动、最终父目录交换、root
  prewrite 交换、create-only collision 和失败临时文件清理；
- Linux 与 macOS 必须继续证明 `renameat` 提交到固定旧树且不触及替换树；
- Windows cross-check/Clippy 只证明 cfg 与类型边界，不能替代上述 runtime 证据；
- 若将来引入 file-ID reopen 或其他恢复机制，必须先提供 NTFS、ReFS、SMB/UNC 的兼容矩阵和真实对抗
  测试，并以新的 superseding ADR 记录进展保证，不能静默扩大本决定。
