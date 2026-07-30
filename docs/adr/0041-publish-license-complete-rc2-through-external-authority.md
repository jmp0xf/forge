# ADR-0041：通过外部权威发布许可证完整的 rc.2

- Status: Accepted
- Date: 2026-07-30
- Deciders: Forge maintainers
- Supersedes: ADR-0029
- Superseded by: None

## Context

ADR-0029 冻结了 `0.1.0-rc.1` 的五平台、十二资产候选，但同时把许可证与 notice 交付留作公开发布前
的外部门。首轮精确 release dependency 审计证明这不是只补两份项目许可证即可关闭的文档缺口：发布图
包含 BSD-2-Clause、Unicode-3.0 和上游 `NOTICE` 义务，而十二个裸资产、tag 源码和现有 SBOM 都不交付
这些材料。`ctrlc 3.5.2` 还在 Apple target 引入 `dispatch2/objc2` 链；对应上游许可证说明明确保留了
Apple SDK 派生内容能否再分发的不确定性。

`0.1.0-rc.1` 从未打 tag 或公开发布。ADR-0029 已规定：若许可证合规改变固定资产集合，必须使用新 ADR
和新候选，不能在同一 RC 下静默增加文件。直接修改 `forge.release-manifest/v1` 的固定数组和枚举也会把
兼容变更伪装成同一机器合约。

与此同时，设计要求最终构建、证明、批准、发布和撤回权物理外置。仅在 Forge 仓库增加一条高权限
workflow 会让候选同时定义并行使自己的发布权，不构成 Authority Set。

## Decision

### 候选身份与分发

- `0.1.0-rc.1` 作为未发布的内部候选终止，不创建 tag、Release、签名或公开资产。
- 首个公开候选改为 SemVer `0.1.0-rc.2`，tag 固定为 `v0.1.0-rc.2`。tag 必须指向通过 PR 合入
  `main`、在合并提交上重新通过全部适用 gate 的精确提交。
- 仍只通过不可变 GitHub prerelease 分发；不发布到 crates.io，也不承诺 Homebrew、Scoop、自动更新
  或稳定兼容性。
- tag、Release 和资产均 create-only。已有名称、已有 tag 或已有 Release 一律失败，不覆盖、不删除后
  重建、不在同一版本重签。

五个平台和等级保持不变，但二进制与 SBOM basename 中的版本改为 `0.1.0-rc.2`：

| 目标 | 平台等级 | 二进制资产 |
|---|---|---|
| `x86_64-unknown-linux-musl` | 一级 | `forge-0.1.0-rc.2-x86_64-unknown-linux-musl` |
| `aarch64-unknown-linux-musl` | 一级 | `forge-0.1.0-rc.2-aarch64-unknown-linux-musl` |
| `x86_64-apple-darwin` | 一级 | `forge-0.1.0-rc.2-x86_64-apple-darwin` |
| `aarch64-apple-darwin` | 一级 | `forge-0.1.0-rc.2-aarch64-apple-darwin` |
| `x86_64-pc-windows-msvc` | 二级 | `forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe` |

完整 Release 集合固定为十三个文件：五个二进制、五个同 basename 的 `.cdx.json` CycloneDX 1.6
SBOM、`THIRD-PARTY-LICENSES.txt`、`release-manifest.json` 和 `SHA256SUMS`。上传、下载、证明和远端复验
均逐名操作，不允许 glob、目录枚举或同版本额外资产。

### 许可证与依赖闭包

- 源码树加入标准 `LICENSE-MIT` 和 `LICENSE-APACHE`。`MIT OR Apache-2.0` 与 `publish = false` 保持
  不变。
- 源码树固定一份由精确五 target release dependency union 生成并人工审查的
  `THIRD-PARTY-LICENSES.txt`。它必须包含 Forge 许可证全文、package/version/source/Cargo.lock checksum/
  license expression 账本、所选择的完整上游许可证文本、所有版权声明，以及独立的 BSD、Unicode 和
  `NOTICE` 内容。相同文本可以去重，但每个 package 必须可追到实际随附文本。
- `release-finalize` 从已绑定的候选源码逐字节复制这份文件；不得在发布时临时从网络、Cargo cache 或
  当前 registry 工作目录抓取许可材料。
- 每个 SBOM component 增加机器可读的 license expression。SBOM 字段便于审计，不能替代
  `THIRD-PARTY-LICENSES.txt` 的完整随附文本。
- release graph、lock checksum、license expression、已选文本或 notice 任一漂移都必须使 checked-in
  license gate 失败，直到账本和文本被重新生成并审查。
- Apple target 的 `ctrlc -> dispatch2 -> objc2` 链必须从 release graph 消失。v0 固定 `ctrlc 3.4.7`，
  使用其最后一个 pipe-based 实现并由现有真实 SIGINT/进程树测试验证。若未来升级重新引入该链，必须
  先有新的许可证判断和回归证据。
- owner/legal 仍须在受保护外部环境确认其有权以项目声明许可证分发原创贡献，精确依赖账本与所有
  notice 已复核，而且十三资产交付不再需要其他许可证文件。聊天、PR 文本或候选自述不满足此门。

### 机器合约

- `forge.release-manifest/v1` 保持可读且字节级 schema 不变，只描述旧的十二资产 rc.1 候选。
- rc.2 使用新的 `forge.release-manifest/v2`：artifact kind 增加 `license-notices`；`artifacts` 固定为
  十一个二进制/SBOM/notice 文件；`provenance.subjects` 固定为全部十三个最终文件。
- `SHA256SUMS` 以词法序覆盖十一个 artifact 和 `release-manifest.json`，共十二行；它不自哈希。
- 外部 SLSA provenance v1 的 subject 集合必须恰好包含十三个最终文件的 basename、长度和 SHA-256。
  v1 reader 的兼容读取不能成为 v2 候选验收的替代路径。

### 外部 Authority Set

最终权威由独立公开仓库
[`jmp0xf/forge-release-authority`](https://github.com/jmp0xf/forge-release-authority) 承载。其 immutable
repository identity 是 owner ID `2247932`、repository ID `1317240187`，OIDC issuer 固定为
`https://token.actions.githubusercontent.com`，subject 前缀固定为
`repo:jmp0xf@2247932/forge-release-authority@1317240187`，批准环境固定为 `forge-release`。

qualification 必须隔离三个权限域：

1. 五平台 build jobs 可以 checkout 并执行精确 Forge 候选，但没有 OIDC、environment、secret 或发布
   凭据；
2. finalize job 可以执行候选 `release-finalize` / `release-check`，但同样没有 OIDC、environment 或写入
   GitHub Release 的权限；
3. protected attest job 只 checkout 和执行 Authority 仓库的独立 verifier。它可以取得 OIDC 和
   attestation write，但不得 checkout Forge、运行 Cargo/xtask 或执行任何候选二进制。

签名使用 Sigstore keyless OIDC 和公开透明日志。Authority verifier 必须独立复核十三文件、manifest
v2、checksums、SBOM、可执行结构、builder records 和 SLSA predicate；不能导入 Forge crate 或把
候选 `release-check` 当最终裁判。

v0 首发不把长期 personal access token 放入 Actions。protected workflow 产出 qualified assets 与
attestation 后，由 operator 在本地再次复验，再以已授权 GitHub 身份 create-only 创建 tag、draft
prerelease、逐名上传、远端回读，最后发布。将来自动发布必须使用只安装到 Forge 的最小权限 GitHub
App 和独立发布环境，并由新 ADR 冻结。

`jmp0xf` 暂任 release approver、security approver、rollback owner、withdrawal owner 和 private
vulnerability triage owner。这是责任归属，不是独立第二人 review。Authority 仓库与环境保护的实际
状态、Forge 的 private vulnerability reporting、main/tag 保护和 release immutability 都必须由平台
API 证明，候选文档不能自证。

### 保留与回滚

`rc.1` 从未公开，因此 `rc.2` 仍没有真实 N−1。首发事故只能撤下/标记 Release、停止分发并等待新的
已审查候选；不得把未发布的 rc.1 说成可回滚版本。后续继续至少保留当前公开版本与其直接前一版本的
原始资产、attestation 和签名。

## Consequences

### Positive

- 原创与第三方许可材料进入可下载、可哈希、可证明的固定资产，而不是留在构建机或聊天判断中。
- `release-manifest/v1` 不被原地破坏；rc.2 的 13 文件集合有独立 v2 合约和迁移边界。
- 消除 Apple SDK 派生依赖链，比接受不明确的再分发风险更容易复核和接手。
- 候选代码不会在拥有 OIDC 的 job 中执行，签名身份与候选写集保持物理分离。

### Negative / trade-offs

- 候选版本、schema、fixture、golden、文档和外部 policy 都要同步升级。
- `ctrlc 3.4.7` 会带来旧版 `nix/windows-sys` 的并存，增加少量 lock graph 与二进制构建成本。
- 单一 notice 资产仍要求下载者把它视为 release distribution 的组成部分；若 owner/legal 要求每个平台
  必须把 notice 与二进制封装在同一 archive，需新 ADR 和新候选。
- 当前单一 GitHub owner 不能提供独立第二人 review；不得在状态报告中声称已有该证据。

### Implementation constraints

- 所有 rc.1 常量、资产名、fixtures、release docs 和 external policy 必须迁移到 rc.2；不得保留会误发
  rc.1 的活动入口。
- schema export 和 compatibility tests 必须同时固定 v1 历史读取与 v2 当前严格验收。
- license gate 必须从与 SBOM 相同的五 target release closure 计算，排除纯 dev-only edge、保留 normal
  和 build edge；不能用整个 `Cargo.lock` 或 host-only graph 近似。
- `release-finalize` 对 notice、manifest、checksums 继续 create-only；失败后的部分文件按既有规则保留供
  隔离审计，不回滚或覆盖。
- Forge 候选仓库的 workflow allowlist 仍只能包含只读 `verify.yml`。

## Rejected alternatives

### 继续发布 rc.1，只链接 tag 中的项目许可证

项目许可证不能替代第三方版权、BSD、Unicode 和 notice 随附义务；tag 也不包含 registry package 的
legal corpus。这违反 ADR-0029 自己的外部门。

### 原地修改 release-manifest/v1

把固定 12 改为 13、增加必需 artifact kind 是候选验收语义变化。复用 v1 会让旧 reader/schema 对同一
ID 产生冲突理解。

### 在有 OIDC 的 job 中再次运行候选检查

候选代码可以读取或滥用签名能力，使“外部”签名退化为候选自签。最终 job 只能执行 Authority 自己的
独立 verifier。

### 为每个平台立即增加压缩 archive

archive 能更紧密地绑定二进制和 notice，但同时引入格式、权限、时间戳、解压安全和重复资产边界。
十三个逐名 Release 资产已能形成一个明确分发集合；只有合规判断要求同包交付时才承担该复杂度。

## Validation and revisit conditions

- 新 dependency ledger 必须证明 `dispatch2`、`block2`、`objc2` 和 `objc2-encode` 不在任一目标闭包中，
  并对每个剩余 package 给出 license/notice 去向。
- 五个平台必须用固定工具链完成 source gates、原生 E2E、13 文件 assemble、独立 verifier、protected
  approval、Sigstore/Rekor attestation 和下载后复验。
- 公开前必须完成 Forge 全历史秘密/隐私复扫、删除不可审计的旧 Actions cache、启用 PVR、main/tag
  保护和 immutable releases，并记录平台 API 与 run URL。
- macOS 最低版本、Windows runtime DLL allowlist、musl/linker/SDK/compiler/cache/environment 仍须在
  Authority policy 中以真实 runner probe 冻结。
- 未来加入 archive、自动发布 App、registry/channel 或重新引入存在许可证不确定性的依赖时，新增 ADR；
  不得静默改变 rc.2。
