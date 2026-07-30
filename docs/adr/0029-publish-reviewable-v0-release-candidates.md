# ADR-0029：发布可审查、可回滚的 v0 候选版本

- Status: Superseded
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: ADR-0041

## Context

设计要求 v0 通过 GitHub Release 提供预编译二进制、checksum、SBOM 和发布签名，并保留
N−1 回滚路径。仓库此前只有源码安装说明，没有冻结首个候选版本、目标平台、资产命名、物料
清单或签名信任边界。候选仓库又不能给自己授予发布权；本地脚本生成的哈希或 provenance
草稿不等于外部构建、批准或签名。

## Decision

### 版本与分发渠道

- 首个公开候选版本固定为 SemVer `0.1.0-rc.1`。
- 候选版本只通过 GitHub Release 分发；v0 RC 不发布到 crates.io，也不承诺 Homebrew、Scoop
  或自动更新通道。
- GitHub Release 资产不可原位替换。内容变化必须产生新的候选版本和新资产名。

### 目标与资产

发布矩阵覆盖设计中的五个目标：

| 目标 | 平台等级 | 二进制资产 |
|---|---|---|
| `x86_64-unknown-linux-musl` | 一级 | `forge-0.1.0-rc.1-x86_64-unknown-linux-musl` |
| `aarch64-unknown-linux-musl` | 一级 | `forge-0.1.0-rc.1-aarch64-unknown-linux-musl` |
| `x86_64-apple-darwin` | 一级 | `forge-0.1.0-rc.1-x86_64-apple-darwin` |
| `aarch64-apple-darwin` | 一级 | `forge-0.1.0-rc.1-aarch64-apple-darwin` |
| `x86_64-pc-windows-msvc` | 二级 | `forge-0.1.0-rc.1-x86_64-pc-windows-msvc.exe` |

Linux 采用 musl 静态链接目标，避免把未验证的 glibc baseline 变成兼容性承诺。ELF 结构检查只能
证明产物与静态链接相容（没有 `PT_INTERP` 且入口位于可执行 `PT_LOAD`），不能单独证明它确由
musl 链接；这一点还要由受保护构建环境、provenance 和平台 E2E 共同证明。每个目标还生成
同 basename 的 `.cdx.json` CycloneDX 1.6 SBOM。完整资产集包含上述十个目标资产、
`release-manifest.json` 和 `SHA256SUMS`。直接分发的 Unix 二进制下载后需要用户显式设置可执行位；
不增加只为归档而存在的压缩依赖和重复包装层。

仓库内 `xtask` 只提供 `release-build`、`release-finalize` 和 `release-check`，不接受任意外部二进制的
`release-stage` 入口。`release-build` 必须从干净 Git checkout 在一次性临时 Cargo target directory
中构建，然后组装本地候选目录。它必须：

- 只接受固定矩阵中的目标，要求输出目录已存在、位于源码仓库及实际 git-dir/common-dir 之外且为真实
  目录，并通过 `forge-runtime` 的 `RepositoryWriter` 固定目录句柄；所有候选内容读写都相对此句柄
  进行并拒绝 symlink，尤其不得在 Git private path 中留下 Git status 看不见的发布文件；
- 先重复固定原 worktree 的 canonical path、`HEAD`、完整 porcelain v2、raw/semantic index 和
  `Cargo.lock`，拒绝 index lock、split index、非 stage-zero、Gitlink、symlink、assume-unchanged、
  skip-worktree、sparse、unmerged 及任何 tracked/untracked 变化；
- 在位于源码仓库、实际 git-dir/common-dir 和候选输出之外的私有临时目录做 `--no-local` clone，
  隔离 system/global Git config、hooks、template、submodule 和 LFS smudge，校验对象库且拒绝 external
  alternates；isolated index、commit 与 `Cargo.lock` 必须和原 worktree 一致；
- 用 `git hash-object --no-filters` 分批核对每个 checkout 文件与 index blob；若 `.gitattributes` 的
  EOL、encoding、ident 或其他转换改变字节则失败。拒绝 commit index 之外的 ignored/untracked 文件，
  随后移除 `.git` marker，让 Cargo 只能从固定的 detached source tree 运行；
- 对 detached tree 的全部目录、regular file bytes 和平台 permission/attribute bits 做有界快照，
  Cargo metadata 的 workspace root、所有本地 package manifest 和 target source 都必须位于该快照内；
  源码祖先和有效 Cargo home 中的外部 Cargo config 在每次 Cargo 调用前后均被拒绝；
- 在启动 Cargo build 前固定一次性临时 target directory 的句柄；构建结束后只从该句柄相对读取目标
  二进制，拒绝构建脚本造成的根目录替换、祖先 symlink 或产物 symlink；
- Git 和 Cargo 都通过同一套有界输出、超时、关闭 stdin 和跨平台进程树边界执行；输出超限、超时、
  中断、signal 或非零退出都使命令失败。首次 candidate write 前的失败不产生资产；最后一次 source/root
  revalidation 的失败可能发生在 create-only 写入之后，此时已写文件安全保留但整个目录不被接受；
- 从准确的 workspace member `forge-cli` 依赖图生成确定性的 CycloneDX JSON，并绑定源码 commit、
  `Cargo.lock` SHA-256、二进制 SHA-256 和字节长度；release graph 中任何 `source = null` 的本地包都
  必须是准确 workspace member，拒绝 Git snapshot 未覆盖的外部 path dependency；
- 校验 ELF executable type、file-backed 入口、可执行 `PT_LOAD` 且不存在 `PT_INTERP`，Mach-O
  `MH_EXECUTE`、非空 file-backed 可执行 `LC_SEGMENT_64` 和 file-backed `LC_MAIN`，以及 PE32+
  executable、非 DLL、file-backed 入口和可执行 section；
- 只按固定的十二个候选文件名读取和生成资产，不把目录中其他文件纳入候选、manifest、checksum 或
  provenance subject；manifest 的 `provenance.subjects` 明列这十二个名称。发布系统不得用通配符上传
  目录内容；应逐个使用这十二个固定名称；
- 每次双文件操作先同时预检两个目标，使预检时已经存在的冲突在创建首个兄弟文件前拒绝；预检后的
  并发竞争按单文件 create-only 处理，同名同字节为幂等 no-op，同名不同字节失败，不覆盖、不删除
  已有文件。这里不承诺多文件事务；并发失败可能保留此前已成功创建的同字节兄弟文件；
- 用标准 SHA-256 计算资产摘要，生成稳定排序的 manifest 与 `SHA256SUMS`；
- 通过固定目录句柄重新读取每个候选文件并校验名称、长度、摘要、版本、目标、SBOM 和完整候选集合；
- 把结果明确标记为 `local-review-candidate`，不得声称已发布、已签名或已获授权。

`release-manifest.json` 是正式的 `forge.release-manifest/v1` machine contract，由 `forge-schema` 生成并
通过 checked-in JSON Schema gate 审查。`xtask` 对 `forge-core` 和 `forge-runtime` 的依赖只复用既有
进程契约、安全进程执行与文件系统边界；产品 crate 仍不依赖 `xtask`，ADR-0004 的产品依赖方向不变。

### Provenance、签名与权限

- 最终 provenance 使用 SLSA provenance v1，由受保护的外部构建/发布系统以完整十二个最终本地资产
  （五个二进制、五个 SBOM、`release-manifest.json`、`SHA256SUMS`）的精确名称、长度和 SHA-256
  作为 subjects 生成；不能只覆盖 manifest 中的十个 artifact 条目。
- 签名使用 Sigstore keyless OIDC；可信 issuer、subject、GitHub Environment、批准规则和
  Rekor/透明日志校验策略必须由候选写集之外的 Authority Set 冻结。
- 仓库内工具不创建占位签名、伪 provenance 或“已验证”标志。`release-check` 只证明本地资产
  自洽，不证明构建来源、评审、批准、签名、上传或发布。
- 当前 `SECURITY.md` 尚无可用安全联系人；release approver、security approver、rollback owner、
  OIDC issuer/subject 和受保护环境均是首发前必须由项目维护者填实的外部 ownership 缺口。
- 本地 Cargo 命令只继承最小工具链环境和明确的编译器、包装器、链接器、SDK/target 控制变量，并拒绝
  secret-like 名称；它不冻结这些值、依赖缓存或全部构建环境。受保护 builder 必须冻结并在 provenance
  中记录这些输入；本地 source/lock/binary 绑定不能替代这项外部证据。
- 仓库声明 `MIT OR Apache-2.0`，但当前没有已确认可随二进制分发的 license/notice 文本。owner/legal
  必须在公开发布前确认合规资产；若因此改变十二文件集合，新增 ADR 和新候选，不能静默修改本 RC。

### 保留与回滚

- GitHub 至少保留当前版本及其直接前一公开版本（N−1）的全部原始资产、provenance 和签名；
  不覆盖、不重签旧资产。
- 回滚以撤下/标记有问题的 Release、恢复文档指向 N−1、核对 N−1 的独立 provenance/签名并
  发布修复候选完成；不在同一版本号下替换文件。
- `0.1.0-rc.1` 没有已发布 N−1。若首个候选需要回滚，只能撤下并停止分发，直到发布新的已审查
  候选，不能虚构回退版本。

## Consequences

### Positive

- 首发矩阵、文件名、摘要和 SBOM 可以在没有发布权限时完整复查。
- 静态 Linux 资产缩小运行时 baseline 歧义；候选版本不会被误认为稳定兼容承诺。
- 候选可自测资产，但无法靠修改自身脚本获得发布或签名权。
- 不可变资产和 N−1 保留使事故恢复路径明确。

### Negative / trade-offs

- 五个目标都需要独立 runner、工具链和平台 E2E；单台开发机不能证明发布矩阵。
- musl 目标可能需要目标专用 C 编译器，macOS 和 MSVC 资产必须在相应受信环境构建。
- source tree 有条目和字节上限，但 `--no-local` clone 的历史/object database 只有时间限制、没有字节
  限制；release builder 还必须提供独立容量限制和可丢弃临时空间。
- 本地检查不是同用户恶意并发下的 OS sandbox，也不绑定 ACL、xattr、ownership、依赖 cache、工具链、
  build-script 外部行为或所有允许的环境值；受保护 builder 和 provenance 必须补齐这些边界。
- 最终 source/root guard 失败时，create-only 资产可能已经安全写入；非零退出后的目录必须隔离检查或
  放弃，并在新的空目录重建，不能把残留当作已接受候选。
- 直接二进制不携带 Unix executable bit；用户安装时需要 `chmod +x`。
- CycloneDX 来自锁文件，只陈述候选锁定依赖；许可证补全和漏洞判断属于独立发布审查。
- 在外部 Authority Set、负责人和安全联系人落地前，任何本地产物都不是可公开发布证据。

## Rejected alternatives

### 在候选仓库内生成并接受自己的签名

候选能同时修改产物、签名流程和判定条件，违反 ADR-0011 的物理权限边界。

### 用平台原生命令生成 checksum

`sha256sum`、`shasum` 和 PowerShell 的参数与输出不同，难以形成同一套可测试、跨平台的字节契约。
项目使用一个受维护的 Rust SHA-256 实现，避免自写密码学实现。

### 为每个平台增加压缩归档

归档会增加格式、时间戳、权限位和解压安全边界；v0 的单二进制没有足够收益抵消这些成本。

### 首个 RC 同时发布 crates.io

包名所有权、撤回权限和 registry 流程尚未独立确认；先完成 GitHub Release 闭环更容易审查和回滚。

## Validation and revisit conditions

- `xtask release-build` 的确定性、干净 checkout、hidden index flags、exact blob、external Cargo config、
  temporary-root、source snapshot 拒绝路径和固定候选集合检查必须有测试。
- `xtask release-finalize` 必须用已知 SHA-256 向量和产物篡改测试验证。
- ELF、Mach-O 和 PE 验证器必须同时覆盖有效结构及动态 ELF、错误 file type、无入口、DLL、无可执行段等
  负向样本；Windows 还必须在原生 runner 验证 `.exe` 路径和进程行为。
- 每个实际目标仍必须通过对应平台的 required gates、基本 E2E、SBOM/manifest/checksum 校验和
  外部 provenance/签名验证；本地假二进制 fixture 不替代这些结果。
- 首次公开发布前必须独立评审 musl 静态链接结果、macOS 最低系统版本、Windows 运行时依赖、
  Windows 目录项实际大小写与十二个固定名称完全一致、OIDC identity、GitHub Environment 权限、
  security/release/rollback ownership 和撤回演练。大小写不敏感文件系统上的 pinned open 本身不证明
  目录项原始拼写，外部上传 gate 必须逐名复核。
- 若将来加入归档、crates.io、Homebrew、Scoop 或其他签名方案，新增 ADR；不得静默改变同一 RC 的
  资产契约。
