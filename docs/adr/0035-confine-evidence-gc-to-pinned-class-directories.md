# ADR-0035：Evidence GC 固定类目录并使用同目录隔离名

- Status: Accepted
- Date: 2026-07-29
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: ADR-0036（仅旧版目录残留自动迁移）
- Depends on: ADR-0021, ADR-0034

## Context

ADR-0021 要求 Receipt、Evidence 和日志不可变、有界保留，并规定所有删除都复用 state
confinement。现有 GC 在完整路径下创建隔离子目录，再用完整路径 `rename`、`hard_link`、
`remove_file` 和 `remove_dir` 完成隔离、恢复与删除。即使每一步之前都检查路径，另一个同权限进程
仍可在检查与操作之间替换 repository root、类目录或中间祖先，使相同路径字符串解析到替换树。
仓库锁只约束守约调用者，不能建立对象身份连续性。

ADR-0028 为写入固定了 root 和逐层目录句柄，但明确要求删除与目录移动另行决策。当前隔离子目录还
把同目录文件删除变成跨目录移动；Windows 若安全实现该形状，需要引入并证明一个新的非空目标目录
`RootDirectory` 合同，与 ADR-0034 已验证的同目录 rename 不是同一能力。

GC 不能因修复安全边界而被关闭或缩小：完整的保留集合、引用闭包、预算和有界回收仍是 v0 的数据
完整性合同。需要把 destructive mutation 约束到已固定对象，同时为 crash residue 保留可恢复状态。

## Decision

GC 将过期对象改名为同一个已固定类目录内的私有普通文件：

```text
<digest>.<json|log> -> .forge-gc-quarantine-<digest>
```

隔离名与类目录共同唯一确定原文件名，不携带第二份内容或新的 machine contract。状态机为：

1. 从固定 worktree root 逐层 no-follow 打开类目录，并记录 root、类目录和 source 的对象身份；
2. 以原子、无覆盖的同目录 rename 将 source `O` 移到隔离名 `Q`。`Q` 已存在时不覆盖并失败；
3. 只通过已经打开并核对身份的 `Q` 文件句柄验证普通文件种类、私有权限、大小、内容摘要和规划时
   snapshot；
4. 验证成功时通过固定父目录或已打开 `Q` 句柄删除，并同步/重读父目录；验证失败时以原子、无覆盖
   同目录 rename 恢复 `Q -> O`；
5. 删除、恢复或身份复核失败时必须报告真实提交阶段。不得把已经隔离、已经恢复或已经删除的结果
   伪报成零副作用；
6. 持锁恢复看到 `Q` 且 `O` 缺失时保守执行 `Q -> O`；两者指向同一对象时保留 `O` 并删除多余
   `Q`；两者不同则保留二者并报冲突。只读扫描看到 `Q` 继续失败并要求持锁恢复；
7. GC 的扫描、preflight、类目录 durability barrier 和 recovery 都必须绑定同一个固定 root/类目录
   capability。可见 root 或类目录身份变化时失败，替换树内容必须保持不变；
8. 旧版 `.forge-gc-quarantine-<digest>/object` 目录残留只作为内部 crash-residue 迁移读取。恢复过程
   固定并验证旧目录，只接受空目录或唯一普通文件 `object`，先确保原名下至少有一份完整字节，再以
   句柄相对操作清理旧残留；冲突时保留双方并失败。

Unix 上，Linux 使用 `renameat2(RENAME_NOREPLACE)`，macOS 使用
`renameatx_np(RENAME_EXCL)`；没有等价原子无覆盖能力的平台必须返回 unsupported，不能退化为普通
`renameat`。删除使用固定父目录的 `unlinkat`，并在最终删除前重新打开 `Q` 核对 identity。

Windows 上，同目录隔离与恢复复用 ADR-0034 的
`NtSetInformationFile(FileRenameInformation)`、NULL `RootDirectory`、简单 leaf 和
`ReplaceIfExists = false`；删除绑定已经验证且持有 `DELETE` 权限的 `Q` 句柄。Windows 可以因打开
句柄或目录交换而比 Unix 更早安全失败，不能为取得相同进展而改用可见完整路径。

此决定不改变 Receipt、Evidence、log、GC report 或其他 versioned machine contract；它只改变私有
崩溃恢复布局和 mutation capability。

## Consequences

### Positive

- root、祖先或类目录替换不能把 GC 的 rename、恢复或删除重定向到替换树。
- 同目录状态机比跨目录隔离少一个目录创建与同步阶段，也复用已验证的 Windows primitive。
- 所有错误都能区分尚未变化、已隔离、已恢复和已删除，恢复逻辑可以据此保守继续。
- 有界保留、引用保护、回收顺序和预算保持不变。

### Negative / trade-offs

- Unix 与 Windows 仍需要各自很小但不可避免的平台实现和真实运行验证。
- Unix 的 `unlinkat` 最终仍按固定父目录中的 leaf 执行；同权限进程在最后 identity 检查与单条
  unlink 指令之间替换同一 leaf，不属于 Forge 对恶意同主体的 sandbox 保证。
- Windows NTFS 运行证据不能外推为 ReFS、SMB/UNC 或其他文件系统证据。
- 旧目录残留需要一条受限迁移路径，直到所有受支持 v0 状态都完成恢复。

### Implementation constraints

- 隔离和恢复必须原子且无覆盖；目标存在时绝不先删后改名。
- token/drop 不自动删除 `Q`；未完成状态必须留下可恢复证据。
- 最终删除前必须重新验证 `Q` identity，删除后必须从固定父目录确认命名空间结果。
- replacement tree 前后必须字节等价；Windows 测试需记录目录交换是否被操作系统拒绝，并让提交
  状态与实际命名空间一致。
- Evidence -> Receipt -> log 的删除顺序及各类之间的 durability barrier 不变。

## Rejected alternatives

### 保留隔离子目录并实现跨目录句柄移动

这会引入第二个目标目录 capability、Windows 非空 `RootDirectory` 兼容矩阵、空目录 crash 状态和
更多恢复分支，没有改善当前同目录单文件 GC 的本质需求。

### 在操作前后重复完整路径检查

检查次数不能消除最后一次检查与 mutation 之间的 TOCTOU，也不能证明两个相同字符串命名同一
对象。

### 暂停或缩小 GC

这会把安全修复变成无界磁盘增长或弱化引用闭包，违反 ADR-0021 接受的数据完整性和运行边界。

### 用普通 rename 并在此前检查 `Q` 不存在

检查与 rename 之间仍可出现目标；覆盖隔离残留会丢失恢复证据。缺少原子 no-replace 的平台必须
fail closed。

## Validation and revisit conditions

- Linux、macOS 和真实 Windows 分别覆盖正常删除、`Q` collision、验证失败恢复、恢复冲突、crash
  residue、root/final/intermediate parent swap，以及失败后无临时项泄漏；
- 每个 swap 测试同时检查 replacement tree 未变化、固定旧树状态与提交阶段一致；
- 旧空目录、仅 `object`、原名/`object` 同一对象和冲突残留均有迁移测试；
- 完整 GC 测试继续证明保留集合、引用闭包、扫描/字节上限、回收统计与类顺序不变；
- 若未来需要跨目录批量事务、按 file ID 恢复或针对恶意同主体的 sandbox，必须新增 ADR 和平台兼容
  证据，不能扩大本决定的保证。
