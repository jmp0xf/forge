# ADR-0011：自托管受外部 Authority Set 约束

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 将用于开发自身。候选版本如果能修改评估自己的测试、评分器、发布流程或密钥，就可以通过削弱裁判而“改进”。仅让 N−1 二进制运行候选仓库里的测试仍不够，因为测试和配置仍由候选控制。

## Decision

- v0 只做普通 dogfooding，不声称可信自授权。
- v0.3 自托管采用 N−1 + 外部 Authority Set。
- `W_candidate ∩ A_authority = ∅` 必须通过物理权限边界落实。
- 保留测试、评分器、release/signing、最终 required-check 来源、晋升和回滚权限位于候选不可修改的组织级 workflow、独立 App、受保护仓库或隔离系统。
- 候选仓库中的公开测试和脚本只是公开自检，不是最终裁判。
- 策略放宽不能在同一候选中生效。

## Consequences

### Positive

- 降低评分器投机和循环信任。
- 自托管保留反馈飞轮但不等于自我授权。
- 发布和签名边界可审计。

### Negative / trade-offs

- 需要额外托管系统、权限和保留语料维护。
- fork PR 和内部 PR 的凭证能力不同。
- 保留测试有隐私和更新成本。

### Implementation constraints

- 候选写集和权威集有组织级配置。
- N−1 比较公开 Schema/plan/diagnostic 变化。
- held-out token 不暴露给不可信 PR。
- release workflow 和签名身份不能由普通候选自行改后生效。

## Rejected alternatives

### 只在仓库放 authority.toml 和 shell 检查

候选可以同时修改文件和检查脚本，不是物理边界。

### 只用 N−1 二进制

若测试/评分器由候选控制，旧二进制仍执行被削弱的标准。

### 完全禁止自托管

失去真实使用反馈；正确做法是分离候选与裁判。

## Validation and revisit conditions

v0.3 前必须完成威胁建模和一次故意评分器投机演练。未建立外部 Authority Set 时不得称为可信自托管。
