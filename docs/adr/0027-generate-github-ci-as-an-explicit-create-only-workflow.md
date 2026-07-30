# ADR-0027：显式生成只创建不覆盖的 GitHub CI 工作流

- Status: Superseded
- Date: 2026-07-28
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: ADR-0037

## Context

ADR-0017 允许用户显式选择 `forge init --with-ci github`，但没有冻结可执行模板、已有目标的等价判定，
也没有说明 Forge 是否持续拥有该文件。GitHub Actions 的触发器、权限、Action 引用、secret、缓存、发布步骤和
branch protection 都属于安全或组织决策；仅从 clone 不能可靠推断。另一方面，完全拒绝显式请求，会让每个项目
重复手写同一条最小验证路径。

CI 文件也是候选提交的一部分，不能成为独立审批权威。生成物必须继续直接调用项目原生命令，不得让项目验证依赖
Forge 二进制。

## Decision

- 默认 `init` 行为不变，仍不生成 CI。只有显式 `--with-ci github` 才规划
  `.github/workflows/verify.yml`。
- v0 模板是可手动运行的 active workflow：唯一触发器为 `workflow_dispatch`，唯一 job 运行于
  `ubuntu-24.04`。
- checkout 使用 `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`
  （v4.2.2 的完整不可变 commit），权限仅为 `contents: read`，并关闭 credential 持久化。
- job 逐条调用当前 ProjectModel 已解析、required、且可信度可发布的 `format-check`、`check`、`test`、
  `build` 项目原生命令。生成物不调用 Forge。
- v0 模板不生成 secret、cache、matrix、release、签名、部署或 branch-protection 配置，也不猜测工具链安装策略。
- 工作流是普通完整文件，不使用 managed block。Forge 只拥有本次缺失文件的 create 操作；创建后文件立即成为
  项目资产。
- 若目标已存在，Forge 对完整 UTF-8 YAML 值做三态等价判定：
  - `equivalent`：完整解析值与当前模板相同，保留已有字节并 no-op；
  - `not-equivalent`：两者都能完整解析但值不同，返回 data error；
  - `unknown`：现有内容无法安全解析或超过有界读取范围，返回 data error。
- `not-equivalent` 与 `unknown` 都不得被 `--apply` 或 `--force-block` 覆盖。要采用模板，用户必须先显式删除或
  重命名已有文件，再重新 dry-run。
- ChangePlan 使用既有 `Create` wire 变体携带完整 postimage，不改变 `forge.init-plan/v1`。应用前仍重新探测、
  重建并逐字节比较计划；写入仍要求目标缺失、通过全计划 preflight、同目录原子写和写后摘要校验。

## Consequences

### Positive

- 显式请求得到可审查、可直接手动运行的最小 CI，而默认和 brownfield 行为不扩大。
- 不可变 Action 引用、最小权限和无 credential 持久化缩小供应链与 token 暴露面。
- 完整文件 create-only 规则消除了 managed marker 混入 YAML、静默覆盖项目 CI 和模板升级夺权。
- 生成工作流与 Forge 可独立删除；CI 仍以项目命令为长期接口。

### Negative / trade-offs

- 工作流默认不会在 push 或 pull request 上自动运行；项目所有者需自行评审并添加触发器。
- Forge 不升级已创建的工作流。模板、checkout SHA 或 runner 更新由正常项目评审完成。
- 仅比较完整 YAML 值，不能证明任意不同工作流在运行时等价；保守失败会要求人工处理。
- Ubuntu 镜像是否具备项目工具链仍由项目 CI 负责；无法安全表示的 argv、cwd 或环境会拒绝生成。

### Implementation constraints

- 模板必须有确定性测试，且不含时间、绝对路径、用户信息或随机值。
- 测试必须覆盖 missing create、exact/semantic equivalent no-op、not-equivalent/unknown fail-closed、
  apply 后 fixed point、并发出现目标和逐字节写后校验。
- checkout commit 更新视为供应链依赖变更，必须单独评审并更新本 ADR 或新的 superseding ADR。
- 本地成功不能被描述为 GitHub CI、review、merge、release 或签名通过。

## Rejected alternatives

### 在已有 workflow 中插入 managed block

YAML 结构、job 权限和表达式上下文不能安全地靠文本块局部合并；这会把局部所有权误当成完整工作流正确性。

### 已有文件不同就覆盖或提供 force

CI 是高风险项目权威面。覆盖会丢失项目策略、权限和 secret 约束，`force-block` 也不是完整文件授权。

### 默认生成 push/PR CI

触发范围、计费、fork secret、安全策略和 required-check 名称都不能从 clone 唯一推出。

### 使用 checkout 浮动 tag

同一个 ChangePlan 会随上游 tag 移动而改变实际执行代码，不满足确定性和供应链可审查性。

## Validation and revisit conditions

只有在真实项目证据支持更广触发器、其他 runner/provider 或安全的迁移协议时，才通过新 ADR 扩展。任何自动更新
已有 workflow、配置 branch protection、导入外部 attestation 或承担发布职责的方案都需要独立授权和 ADR。
