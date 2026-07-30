# ADR-0042：使用标准 in-toto subject 描述符

- Status: Accepted
- Date: 2026-07-30
- Deciders: Forge maintainers
- Supersedes: ADR-0041（仅 SLSA Statement subject 的长度编码）
- Superseded by: None
- Depends on: ADR-0041

## Context

ADR-0041 要求外部 SLSA provenance v1 的十三个 subject 同时携带 basename、长度和 SHA-256。实现
Authority build type 时复核 SLSA Provenance v1 与 in-toto Statement v1 后发现，Statement 的
`subject` 元素使用标准 `ResourceDescriptor`；该类型包含 `name`、`digest`、`uri`、`content`、
`downloadLocation`、`mediaType` 和 `annotations`，没有 `length` 字段。

把未命名空间的 `length` 塞进 subject 会成为未定义扩展，并可能被标准 consumer 忽略。把长度重复写入
`internalParameters` 也不正确：长度是输出观测，不是 build 的内部输入。为保留长度而自建 Statement
签名格式，还会放弃标准 attestation action 的解析、验证与互操作边界。长度并不增加 SHA-256 已提供的
字节身份强度；真正需要保留的是构建和验收时的资源上限、逐字节长度检查与可诊断 manifest 记录。

## Decision

- 外部 in-toto Statement 的 `subject` 集合仍必须恰好覆盖十三个最终文件。
- 每个 subject 使用标准 ResourceDescriptor：精确 basename 写入 `name`，实际文件的 SHA-256 写入
  `digest.sha256`；不增加 `length` 或其他自定义 subject 字段。
- Authority verifier 在形成 attestation 前仍须读取实际文件并执行既有的单文件/总量上限、manifest v2
  长度、checksum、结构和一致性检查。十一项 artifact 的长度继续由 manifest v2 固定并逐字节复核；
  `release-manifest.json` 与 `SHA256SUMS` 由各自上限、精确内容合约和实际 SHA-256 约束。
- verifier 生成的 subject checksum 输入必须只来自已经完整验收的十三个实际文件。attestation 后的
  下载复验仍逐名比较 SHA-256，并同时执行 release manifest/checksum/资源上限检查。
- ADR-0041 除“subject 直接携带长度”外的全部决定保持不变；十三文件集合、create-only 发布、外部
  Authority、受保护批准和许可证门均不放宽。

## Consequences

### Positive

- 产物证明符合 SLSA Provenance v1 与 in-toto Statement v1 的标准模型，可由通用 verifier 解析。
- 不把输出观测伪装成输入，也不依赖 consumer 可能忽略的自定义字段。
- 长度仍在产生证明前和下载复验时受 fail-closed 合约约束。

### Negative / trade-offs

- 只读取 Statement subject 的 consumer 得到 basename 与 SHA-256，不能直接读取长度；需要读取实际文件
  或 release manifest 才能获得并复核长度。
- 十三个 subject 的长度不再全部作为冗余元数据嵌入 provenance。

## Rejected alternatives

### 在 subject 中增加裸 `length`

它不是标准 ResourceDescriptor 字段，且未命名空间扩展容易造成互操作和语义误判。

### 把 subject 长度列表放入 internalParameters

输出文件的长度不是平台选择的 build 输入；这样会错误描述 SLSA build definition。

### 为长度自行构造非标准签名封装

长度不提高 SHA-256 的字节身份强度，不足以证明引入自定义签名与 consumer 兼容面的成本。

## Validation and revisit conditions

- Authority contract test 必须固定 predicate 与 Statement 的职责边界，并拒绝 predicate 内伪造的 subject
  列表。
- protected workflow 必须从 verifier 输出的精确 checksum 集合形成十三个标准 subject，并在远端回读
  后逐名复核。
- 若未来标准 ResourceDescriptor 增加长度字段，或外部合规规则要求证明本身携带长度，以新的 ADR 和
  新 build-type identity 迁移，不能原地改变 v1 语义。
