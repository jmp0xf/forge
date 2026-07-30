# ADR-0037：GitHub CI 固定 checkout v7 与 Node 24 运行时

- Status: Accepted
- Date: 2026-07-29
- Deciders: Forge maintainers
- Supersedes: ADR-0027
- Superseded by: None
- Depends on: ADR-0017

## Context

ADR-0027 冻结了显式、只创建不覆盖的 GitHub Actions 工作流，但同时把
`actions/checkout` 固定在 v4.2.2。该 Action 使用的旧 JavaScript 运行时已经在当前 GitHub-hosted
runner 上产生弃用告警。继续让 Forge 自身工作流与新生成的项目工作流使用该版本，会把已知的运行时
迁移留给每个下游项目，并使两份本应共享供应链边界的模板发生分叉。

上游 `actions/checkout` v7.0.1 tag 直接指向 commit
`3d3c42e5aac5ba805825da76410c181273ba90b1`，该不可变 commit 的 `action.yml` 声明
`runs.using: node24`。证据分别见上游
[release](https://github.com/actions/checkout/releases/tag/v7.0.1) 与
[固定 commit 的 action.yml](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml)。

升级 Action 不能扩大 workflow 权限、恢复 credential 持久化，或让 Forge 获得更新已有项目 CI 的
所有权。create-only 和完整 YAML 三态等价判定仍是更重要的安全边界。

## Decision

- Forge v0 新生成的 GitHub workflow 与 Forge 仓库自身的主验证 workflow 都使用
  `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`（v7.0.1 的完整不可变
  commit）。不得改用浮动 tag。
- 保持 `permissions: contents: read` 与 `persist-credentials: false`；checkout 升级不授权新增
  secret、cache、matrix、release、签名、部署、branch protection 或写权限。
- `forge init --with-ci github` 仍仅在目标缺失时创建完整 workflow。Forge 不更新、迁移或覆盖已存在
  的 v4、v7 或其他 workflow。
- 当前模板升级后，旧 v4 模板与新 v7 模板是 `not-equivalent`。这必须安全失败并由项目维护者正常
  评审、手工迁移，不能把供应链升级伪装成等价 no-op。
- ADR-0027 的其余决定保持：默认不生成 CI；唯一触发器为 `workflow_dispatch`；生成物直接调用已解析
  的项目原生命令而不调用 Forge；完整文件不使用 managed block；未知或不同内容永不覆盖。
- 此变更不修改 `forge.init-plan/v1` 或其他版本化 machine contract，只改变后续显式创建的 CI 文件
  postimage 与 Forge 自身受评审的工作流依赖。

## Consequences

### Positive

- 新创建的工作流与 Forge 自身验证使用同一个可审计的 Node 24 checkout 实现。
- 供应链引用仍由完整 commit 固定，计划不会随上游 tag 移动。
- 最小 token 权限和无 credential 持久化边界保持不变。

### Negative / trade-offs

- 已存在的 v4 模板不会由 Forge 自动升级；维护者必须显式评审并迁移。
- 精确模板等价判定会把仅 checkout 版本不同的文件归为 `not-equivalent`，这是 create-only 所有权边界
  的预期成本。
- 未来 checkout 或 GitHub runner 运行时再次变化时，仍需独立供应链评审与新的 superseding ADR。

### Implementation constraints

- checkout commit 和显示版本必须在 renderer 中集中定义，并由 renderer、CLI E2E 与架构不变量测试
  锁定。
- Forge 自身所有 checkout step 必须使用同一完整 SHA、`persist-credentials: false` 和只读内容权限。
- 不得因 Action 版本升级放宽已有 workflow 的禁止能力或 create-only 规则。
- 本地测试成功不能被描述为 GitHub CI、review、merge、release 或签名通过。

## Rejected alternatives

### 仅升级 Forge 自身 workflow

这会让项目内验证与产品新生成模板长期分叉，并继续把已知运行时迁移成本传播给下游。

### 自动改写已存在的 v4 workflow

已有 workflow 是项目资产，可能包含团队权限、触发器和工具链决定。checkout 升级不授予 Forge 接管
完整文件的权力。

### 使用 `actions/checkout@v7`

浮动 tag 可改变相同 ChangePlan 实际执行的上游代码，不满足确定性和供应链可审查性。

## Validation and revisit conditions

- renderer 单测和 CLI E2E 必须断言 v7.0.1 的完整 commit、只读权限与 credential 不持久化；
- 架构测试必须拒绝 Forge 自身 workflow 中的其他 checkout 引用、浮动 Action 引用和写权限；
- GitHub-hosted runner 必须实际完成该固定 commit 的 checkout；通过只证明该候选 commit 和 runner，
  不证明 branch protection、独立审批或发布授权；
- 下一次 checkout major、JavaScript runtime 或 runner 兼容边界变化时新增 superseding ADR，不重写本记录。
