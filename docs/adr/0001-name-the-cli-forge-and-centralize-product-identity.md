# ADR-0001：CLI 命名为 Forge，并集中产品身份

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

实现需要一个稳定、可用于二进制、crate、Schema、受管块和本地状态的名称。长期使用 `<cli>` 占位符会让命令帮助、快照、诊断和测试无法落到具体接口；在业务代码中到处写死名称又会把产品命名变成高风险全局耦合。用户已经决定 CLI 命名为 `forge`。

## Decision

- 二进制和 CLI 名为 `forge`，Rust package 使用 `forge-*` 前缀。
- 机器接口命名空间使用 `forge.<domain>/v<n>`。
- 可选根配置名为 `forge.toml`；worktree 私有状态和受管块命名空间为 `forge`。
- 所有身份值由 `forge-core::branding` 或 `forge-schema` 集中提供；业务模块不得复制字面量。
- 工程资产按职责命名。CI 叫 `verify.yml`，基线按质量职责命名，不因由 Forge 生成而统一带工具前缀。

## Consequences

### Positive

- 命令、文档和测试可以立即稳定。
- 产品身份只有一个可审计定义点。
- 生成文件仍按职责归档。

### Negative / trade-offs

- 未来改名涉及公开协议和状态迁移，不能当成纯机械替换。
- 公开发布前仍需核验商标、crate 和分发渠道可用性。

### Implementation constraints

- 增加测试，扫描核心代码中的未授权品牌字面量。
- Schema 和 marker 一旦公开，改名必须有迁移 ADR 和兼容期。

## Rejected alternatives

### 永久使用 `<cli>` 占位符

实现和行为快照无法冻结，推迟的不是营销而是接口定义。

### 在模板和各 crate 散布名称

改名、修复和一致性检查成本过高，容易产生混合命名。

### 新建 `.forge/` 工作树目录集中所有内容

名称一致不等于职责正确；运行状态进入 Git 私有区，工程资产进入标准位置。

## Validation and revisit conditions

若公开发布前必须改名，新 ADR 必须同时定义 Schema、配置、状态和受管块迁移。
