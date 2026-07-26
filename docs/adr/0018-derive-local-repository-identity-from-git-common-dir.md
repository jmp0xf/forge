# ADR-0018：从 Git common-dir 派生本地仓库身份

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

`ProjectModel`、InitPlan 和 Evidence 的 v1 wire contract 都要求 `RepoId`，但设计提案只冻结了类型，
没有冻结生成算法。实现不能用裸路径填充强类型标识，也不能在不同调用点分别猜测。

身份需要同时满足：

- linked worktree 属于同一个仓库身份；
- `explain` 和 dry-run 保持只读、确定性；
- unborn、无 remote、离线和 shallow repository 仍可工作；
- 不把 remote URL 或本地路径明文嵌入标识；
- 无法证明身份相同的时候宁可失效缓存和 Receipt，不能错误复用。

Git 没有内建的稳定 repository UUID。remote URL 可缺失、可变且一仓库可有多个；commit/root commit
会随历史重写、shallow 边界和多根历史变化；首次读取时生成随机 ID 则会让只读命令产生写入，并与
ADR-0015 的 common-dir 共享边界冲突。

## Decision

- v0 的 `RepoId` 是**本地仓库绑定**，不是全球项目身份或外部授权身份。
- 输入使用 `git rev-parse --path-format=absolute --git-common-dir` 返回的原生路径表示；linked
  worktree 因共享 common-dir 而得到相同身份。
- 使用现有 `Hasher` 对以下分帧输入计算 BLAKE3：

  ```text
  forge.repository-id/v1
  + native path encoding tag
  + native common-dir bytes or Windows wide units
  ```

- wire 字符串格式为 `local:<Digest>`，v0 即 `local:blake3:<hex>`。
- 不保存 identity 文件，不读取 remote，不写 Git config，不联网。
- 仓库或其 common-dir 移动后 RepoId 变化。该变化必须使旧缓存、Receipt 和 Evidence 引用失效；
  不能尝试自动关联为同一仓库。
- RepoId 不能用于证明来源、授权、所有权、仓库内容相同或不同机器上的逻辑项目相同。

## Consequences

### Positive

- 只读命令和 dry-run 可立即产生确定、强类型的 v1 输出。
- linked worktree 共享仓库身份，同时继续隔离可变验证状态。
- unborn 和无 remote 仓库不需要特例。
- 输出不包含 common-dir 明文；算法集中且可测试。
- 移动、复制或无法确认同一性时安全失效，不会把旧验证错误套到新位置。

### Negative / trade-offs

- 仓库移动会改变 RepoId，并使本地历史结果不可复用。
- 相同逻辑项目的两个 clone 有不同 RepoId，不能用该字段跨机器聚合。
- 路径摘要不是秘密；低熵路径可能被猜测，因此仍不得把 RepoId 当隐私或安全令牌。

### Implementation constraints

- 派生只通过 `Hasher`，业务代码不得直接实例化 BLAKE3 或复制前缀。
- Unix 保留原始路径字节；Windows 把原始 UTF-16 宽单元编码为 little-endian 字节，并加入编码标签。
- 算法必须有固定向量、linked-worktree 等价、不同 common-dir 分离和非 UTF-8 路径测试。
- `RepoFacts`/`ProjectModel` 必须携带该强类型标识，wire 投影不得重新计算。
- repository identity 变化必须进入 Receipt/Evidence 失效原因。

## Rejected alternatives

### remote URL 摘要

remote 可缺失、可有多个、可变并可能包含凭证或内部地址；fork 与 mirror 语义也不等同。

### HEAD、初始提交或对象集合摘要

unborn 无提交；rebase、shallow clone、多根历史和历史清理都会改变结果，且复制历史并不代表同一
本地验证边界。

### 首次使用时写入随机 UUID

会让 `explain`/dry-run 产生副作用；放在 common-dir 又会新增非内容寻址共享状态，违反现有状态
边界。放在 worktree-dir 则同仓库的 linked worktree 身份不同。

### 仓库根明文

泄露本地路径并把平台路径误当作类型化标识。

## Validation and revisit conditions

若未来外部 attestation 需要跨 clone、跨机器的项目身份，必须新增独立的显式外部 identity 类型与
验证来源；不得扩大本地 `RepoId` 的语义。只有能保持只读、隐私和安全失效的迁移方案时，才用新
ADR 替换本算法。
