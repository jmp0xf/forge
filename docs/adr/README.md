# Forge Architecture Decision Records

ADR 记录已经接受、需要跨重构保持稳定的架构决定。设计总览见
[`../design-proposal.md`](../design-proposal.md)。

## 规则

- 状态使用 `Proposed`、`Accepted`、`Deprecated`、`Superseded`、`Rejected`。
- 已接受 ADR 不通过重写历史改变结论；新增 ADR，并使用 `Supersedes` / `Superseded by` 连接。
- 改变设计提案中的“必须/不得”条款必须有 ADR。
- 普通阈值校准不需要 ADR；协议、依赖方向、信任边界和默认副作用变化需要。

## 索引

| ADR | 状态 | 标题 |
|---|---|---|
| [0001](0001-name-the-cli-forge-and-centralize-product-identity.md) | Accepted | CLI 命名为 Forge，并集中产品身份 |
| [0002](0002-use-rust-2024-with-msrv-1-85.md) | Accepted | 使用 Rust 2024，MSRV 1.85 |
| [0003](0003-project-native-commands-are-the-stable-interface.md) | Accepted | 项目原生命令是稳定接口 |
| [0004](0004-use-a-six-crate-layered-workspace.md) | Accepted | 使用六 crate 分层工作区 |
| [0005](0005-store-runtime-state-in-git-private-directories.md) | Accepted | 运行状态存入 Git 私有目录 |
| [0006](0006-use-managed-blocks-for-generated-host-adapters.md) | Accepted | 宿主适配使用受管块 |
| [0007](0007-shell-out-to-git-porcelain-v2.md) | Accepted | 调用 Git porcelain v2 |
| [0008](0008-use-synchronous-execution-without-tokio.md) | Accepted | 使用同步执行，不引入 Tokio |
| [0009](0009-version-all-machine-readable-contracts.md) | Accepted | 版本化所有机器接口 |
| [0010](0010-separate-local-evidence-from-external-approval.md) | Accepted | 本地证据与外部授权分离 |
| [0011](0011-bound-self-hosting-with-an-external-authority-set.md) | Accepted | 自托管受外部 Authority Set 约束 |
| [0012](0012-support-rust-and-go-first.md) | Accepted | v0 首先支持 Rust 与 Go |
| [0013](0013-defer-ast-semantic-indexing-and-model-integration.md) | Accepted | 延后 AST、语义索引与模型集成 |
| [0014](0014-default-to-zero-config-and-minimal-init.md) | Accepted | 默认零配置与最小 init |
| [0015](0015-isolate-worktree-state-and-share-only-content-addressed-cache.md) | Accepted | worktree 状态隔离，只共享内容寻址缓存 |
| [0016](0016-use-dependency-based-evidence-invalidation.md) | Accepted | Evidence 按依赖变化失效 |
| [0017](0017-do-not-generate-runner-ci-or-organization-docs-by-default.md) | Accepted | 默认不生成 runner、CI 或组织文档 |
| [0018](0018-derive-local-repository-identity-from-git-common-dir.md) | Accepted | 从 Git common-dir 派生本地仓库身份 |
| [0019](0019-use-head-as-the-v0-worktree-comparison-baseline.md) | Accepted | v0 使用 HEAD 作为工作树比较基线 |
| [0020](0020-version-the-complete-local-evidence-contract.md) | Accepted | 版本化完整的本地 Evidence 契约 |
| [0021](0021-store-immutable-evidence-with-bounded-retention.md) | Accepted | Evidence 状态使用不可变对象和有界保留 |
| [0022](0022-canonicalize-json-numbers-without-floating-point.md) | Accepted | 不可变证据身份对 JSON 数字做无浮点精确规范化 |
| [0023](0023-emit-json-schema-documents-without-a-forge-envelope.md) | Accepted | JSON Schema 文档不套 Forge 结果信封 |
| [0024](0024-record-typed-process-boundary-failures.md) | Accepted | 进程边界失败写入类型化非证明 Receipt |
| [0025](0025-use-one-operation-wide-time-budget.md) | Accepted | 每条命令使用一个操作级总预算 |
| [0026](0026-declare-provider-namespaced-coverage-gaps.md) | Accepted | 声明 Provider 命名空间覆盖与缺口 |
| [0027](0027-generate-github-ci-as-an-explicit-create-only-workflow.md) | Superseded | 显式生成只创建不覆盖的 GitHub CI 工作流 |
| [0028](0028-pin-directory-handles-for-repository-writes.md) | Superseded | 仓库写入固定目录句柄 |
| [0029](0029-publish-reviewable-v0-release-candidates.md) | Superseded | 发布可审查、可回滚的 v0 候选版本 |
| [0030](0030-separate-release-manifest-compatibility-reading-from-candidate-acceptance.md) | Accepted | 分离 release manifest 的兼容读取与候选验收 |
| [0031](0031-use-native-same-directory-renames-on-windows.md) | Superseded | Windows 使用原生同目录句柄重命名 |
| [0032](0032-record-content-free-command-diagnostic-summaries.md) | Accepted | 记录不含输出内容的命令诊断摘要 |
| [0033](0033-use-pinned-target-directory-for-windows-renames.md) | Superseded | Windows 重命名显式使用固定目标目录句柄 |
| [0034](0034-fail-closed-when-windows-rejects-directory-swap-renames.md) | Accepted | Windows 拒绝目录交换提交时安全失败 |
| [0035](0035-confine-evidence-gc-to-pinned-class-directories.md) | Accepted | Evidence GC 固定类目录并使用同目录隔离名 |
| [0036](0036-fail-closed-on-unreleased-legacy-evidence-gc-residues.md) | Accepted | 未发布的旧 Evidence GC 目录残留安全失败并原样保留 |
| [0037](0037-pin-github-checkout-v7-on-node24.md) | Accepted | GitHub CI 固定 checkout v7 与 Node 24 运行时 |
| [0038](0038-do-not-persist-arbitrary-project-command-output-in-v0.md) | Accepted | v0 不持久化任意项目命令的 stdout/stderr 内容 |
| [0039](0039-preserve-current-typed-unknown-receipt-facts.md) | Accepted | 保留当前 Receipt 的 typed unknown 事实 |
| [0040](0040-fail-closed-on-unbound-project-tool-configuration.md) | Accepted | 项目工具外部配置未闭合时安全失败 |
| [0041](0041-publish-license-complete-rc2-through-external-authority.md) | Accepted | 通过外部权威发布许可证完整的 rc.2 |

使用 [`0000-template.md`](0000-template.md) 创建新记录。
