# Forge：仓库原生工程运行层 CLI — 完整设计提案

| 项 | 内容 |
|---|---|
| 文档状态 | **Accepted / Ready for Implementation** |
| 文档版本 | 1.0 |
| 日期 | 2026-07-26 |
| CLI 与二进制名 | `forge` |
| 实现语言 | Rust 2024 Edition |
| 最低支持 Rust 版本 | 1.85 |
| v0 语言支持 | Rust、Go |
| 目标平台 | Linux、macOS 为一级；Windows 为二级并进入持续集成矩阵 |
| 目标读者 | 直接负责实现、测试、评审和发布 Forge 的工程师或编码 Agent |
| 设计完成标准 | 读完本文后，不应再对产品边界、crate 边界、命令面、数据模型、状态位置、Rust/Go 行为、失败语义、安全边界、测试与实现顺序存在关键决策疑问 |

> 本文中的“必须”“不得”表示实现约束；“应”表示除非有新的 ADR 推翻，否则采用的稳健默认；“可以”表示兼容扩展点。任何改变“必须/不得”条款的实现都必须以新 ADR 明确取代已有决策。

---

## 目录

1. [结论摘要](#1-结论摘要)
2. [问题、目标与非目标](#2-问题目标与非目标)
3. [设计不变量](#3-设计不变量)
4. [系统边界、权威层次与依赖方向](#4-系统边界权威层次与依赖方向)
5. [名称、配置与文件位置](#5-名称配置与文件位置)
6. [Rust 工作区与 crate 边界](#6-rust-工作区与-crate-边界)
7. [版本路线与 CLI 命令面](#7-版本路线与-cli-命令面)
8. [统一输出、诊断和退出码](#8-统一输出诊断和退出码)
9. [核心领域模型](#9-核心领域模型)
10. [Git 与工作树模型](#10-git-与工作树模型)
11. [配置、状态、缓存与并发](#11-配置状态缓存与并发)
12. [仓库探测管线](#12-仓库探测管线)
13. [项目命令发现与验证](#13-项目命令发现与验证)
14. [Rust LanguageProvider](#14-rust-languageprovider)
15. [Go LanguageProvider](#15-go-languageprovider)
16. [`forge init`](#16-forge-init)
17. [受管块与宿主适配](#17-受管块与宿主适配)
18. [`forge doctor`](#18-forge-doctor)
19. [`forge next`](#19-forge-next)
20. [风险与上下文选择](#20-风险与上下文选择)
21. [执行回执与证据协议](#21-执行回执与证据协议)
22. [进程执行、安全与隐私](#22-进程执行安全与隐私)
23. [受控改进与可信自托管](#23-受控改进与可信自托管)
24. [测试、fixture 与兼容性](#24-测试fixture-与兼容性)
25. [非功能要求与平台支持](#25-非功能要求与平台支持)
26. [实现里程碑与任务依赖图](#26-实现里程碑与任务依赖图)
27. [v0 发布验收清单](#27-v0-发布验收清单)
28. [明确否决的设计](#28-明确否决的设计)
29. [待实测校准但不阻塞编码的参数](#29-待实测校准但不阻塞编码的参数)
30. [ADR 索引](#30-adr-索引)
31. [实现者从哪里开始](#31-实现者从哪里开始)

---

## 1. 结论摘要

Forge 不是新的编码 Agent，不生成业务代码，不调用模型 API，不维护对话记忆，也不拥有项目的构建、测试、验证或发布逻辑。它是一个安装在项目运行时之外的、**仓库原生、执行者无关的工程运行层**：读取 Git、语言清单、项目原生命令、测试、CI 与正常工程文档，形成可解释的项目模型；再据此完成最小初始化、环境诊断、确定性下一步导航、作用域绑定的执行回执、证据充分性判断，以及面向 Cursor、Claude Code、Codex 等宿主的可再生薄适配。

长期稳定的产品不是 `forge` 二进制，而是三项协议：

1. **项目操作协议**：项目自己的 `cargo`、`go`、`make`、`just`、`task` 或已有脚本及其退出语义；
2. **证据协议**：说明什么命令在什么输入、工具链、环境和策略上运行过，结果是什么，以及什么没有被验证；
3. **宿主适配投影协议**：从仓库权威资产生成 `AGENTS.md`、`CLAUDE.md` 等薄入口，而不复制第二份项目知识。

Forge 可以调用项目命令，但项目命令不得必须调用 Forge。删除 Forge 二进制、运行状态和生成的薄适配后，项目仍必须能独立构建、测试、验证和发布。这条单向依赖用自动化“卸载完整性测试”保证，而不是依赖代码评审记忆。

v0 只完成最小可信闭环：

```text
仓库探测
+ 最小初始化
+ 诊断
+ 确定性导航
+ 作用域绑定的执行回执
+ 证据充分性判断
+ 可再生宿主适配
```

v0 不建设完整检查平台、任务数据库、AST/LSP 索引、向量检索、MCP 服务、后台守护进程或自动自我改进。Forge 的“进化”始终只产生候选；最终准入由候选不能控制的外部系统完成。

一句话收束全部决策：

> **项目接口优于工具包装，事实优于自述，作用域证据优于“我跑过了”，外部批准优于本地哈希，按需补齐优于模板铺设，可删除的普通工程机制优于不断膨胀的专属体系。**

---

## 2. 问题、目标与非目标

### 2.1 问题

人类工程师和 Cursor、Claude Code、Codex 等编码 Agent 面对的是同一类工程问题：

- 不知道仓库真正的构建、检查、测试和验证入口；
- 项目知识散落在源码、CI、CONTRIBUTING、ADR、Runbook 和所有权文件中；
- 宿主各自维护说明，内容逐渐漂移；
- 长任务中错误复合，执行者容易在没有充分验证时宣布完成；
- 本地“全绿”被误写成可以合并、发布或操作生产；
- 多工作树或多 Agent 并行时，验证结果和未提交状态被错误复用；
- 失败只留在一次对话或一次 CI 日志中，没有沉淀成成本合理、可删除的工程机制；
- 工具为了“帮忙”不断生成配置、规则和包装命令，最终成为项目新的反向依赖。

Forge 不试图控制模型内部推理。它只控制任何执行者都必须经过的外部环节：

```text
发现什么
调用什么
读取什么
如何验证
证据何时失效
哪里必须停下
谁拥有最终批准权
```

### 2.2 北极星：可信变更吞吐量

所有功能都按“可信变更吞吐量”审查：

\[
J=
\frac{
\mathbb{E}[\text{经独立验收的有效变更价值}]
}{
\mathbb{E}[\text{工程师注意力}+\text{计算成本}+\text{交付时延}+\text{维护成本}+\text{事故与返工损失}]
}
\]

并同时满足：

\[
P(\text{严重回归}\mid\text{已接受})\le\varepsilon
\]

\[
W_{candidate}\cap A_{authority}=\varnothing
\]

第二个式子是最重要的安全约束：候选变更可写集合不得包含批准该候选所依赖的最终权威。保留测试、最终评分器、签名、分支保护、晋升逻辑和生产权限不能由正在被评估的候选控制。

`J` 只用于设计审查，不实现为单一自动评分。代码更多、规则更多、测试更多、Agent 更忙，都不自动等于系统更好。

### 2.3 v0 目标

v0 必须：

- 支持 Rust package、Cargo workspace、多个独立 Cargo workspace；
- 支持 Go module、Go workspace、多个独立 Go module；
- 支持 Rust + Go 混合仓库；
- 从仓库事实形成稳定、可解释的 `ProjectModel`；
- 发现现有项目命令并在缺失时使用语言原生默认；
- 默认零配置，只有无法可靠推导时才需要根级 `forge.toml`；
- 以 dry-run 为默认执行最小、幂等、可逆的初始化；
- 生成或更新薄 `AGENTS.md` 与按需宿主指针；
- 以确定性状态机返回下一步、理由、来源、风险和未知项；
- 运行项目命令时形成与当前作用域绑定的 Receipt；
- 汇总 Evidence Bundle，并明确 `coverage_and_gaps`；
- 严格区分本地观察、外部证明和授权；
- 支持 Linux、macOS、Windows 的基本文件、Git 和进程语义；
- 提供稳定 JSON Schema、诊断码、退出码和兼容策略；
- 提供足以阻止反向依赖、状态串扰、静默覆盖和证据错误复用的测试。

### 2.4 v0 明确不做

```text
内置 LLM 或调用模型 API
自研 Agent 循环或多 Agent 编排
MCP server
常驻后台服务
数据库
向量数据库、embedding、语义索引
AST/LSP 全仓索引
任务数据库或 Issue 镜像
顶层 check/fix/test/build 同义包装
自动安装 Rust、Go 或第三方工具链
自动修改依赖或 lockfile
自动创建、批准或合并 PR
自动配置 branch protection
自动晋升规则
跨仓库经验传播
代码层无人审批的自我演化
操作系统级权限沙箱的虚假承诺
```

### 2.5 成功与停止条件

Forge 成功不是“功能越来越多”，而是：

- 首次 CI 通过率上升；
- 人工主动投入和重大返工减少；
- 逃逸缺陷和回滚不恶化；
- 默认上下文、运行成本和维护投入可控；
- 生成物很少被人工撤销；
- 建议有较高采纳率；
- 成熟规则持续下沉到项目原生机制，Forge 自身变薄。

出现以下任一情况，应缩减或删除对应能力：

- 节省的注意力低于维护成本；
- 误报导致大量绕过；
- 适配和规则增长长期快于删除；
- 宿主或项目原生工具已稳定覆盖该能力；
- 可见测试变好但保留任务和真实结果没有改善；
- 连续两个发布周期无人使用；
- 输出的下一步长期不被采纳。

---

## 3. 设计不变量

所有不变量必须有自动化测试。命名固定，便于实现、CI 和 ADR 引用。

| ID | 不变量 | 自动化落实 |
|---|---|---|
| `INV-NO-REVERSE-DEPENDENCY` | 删除 Forge 后，项目仍可构建、测试、验证、发布 | fixture 卸载完整性测试；主验证 CI 不引用 Forge |
| `INV-PROJECT-OWNS-COMMANDS` | 项目原生命令是长期接口；Forge 只能发现、调用、记录 | 生成物与 CI 扫描；禁止 `forge check/test/build` |
| `INV-DRY-RUN-DEFAULT` | `init` 默认不写工作树；落盘必须显式 `--apply` | CLI E2E |
| `INV-IDEMPOTENT` | 连续两次 `init --apply`，第二次零字节差异 | fixture 属性测试 |
| `INV-DETERMINISTIC-RENDER` | 同一 ProjectModel 与模板版本产生字节级相同输出 | golden/属性测试 |
| `INV-NO-PRIVATE-WORKTREE-DIR` | 不创建入库的 `.forge/`、`.ai/`、`.agent/` 等目录 | fixture 路径断言 |
| `INV-ZERO-CONFIG-DEFAULT` | 可可靠推导时不创建 `forge.toml` | 零配置 fixture |
| `INV-MANAGED-BLOCK-ONLY` | 生成器只修改自己拥有的受管块；块外正文逐字节保持 | 属性测试与冲突 fixture |
| `INV-ARGV-ONLY` | 外部命令以 `program + argv` 执行；核心路径禁止 shell 拼接 | 架构 lint 与代码搜索 |
| `INV-READ-ONLY-COMMANDS` | `doctor`、`next`、`adapters check`、`evidence show/verify` 不修改工作树 | 前后 Git 摘要比较 |
| `INV-WIRE-CONTRACT` | JSON、配置、状态、受管块与退出码都有稳定版本语义 | Schema golden、兼容和退出码矩阵 |
| `INV-LOCAL-EVIDENCE-NOT-AUTHORITY` | 本地 Receipt/Evidence 不等于 CI、审批或生产授权 | 状态机不变量测试 |
| `INV-AUTHORITY-SEPARATION` | 候选写集与最终权威集不相交 | 外部 required workflow / GitHub App / 受保护仓库校验 |
| `INV-WORKTREE-ISOLATION` | 未提交状态、Receipt、日志和证据草稿不得跨 worktree 复用 | linked-worktree E2E |
| `INV-DEPENDENCY-BASED-INVALIDATION` | 输入、命令、工具链、环境或策略变化即使 Receipt 失效 | 表驱动测试 |
| `INV-NO-SELF-WEAKENING` | 策略变更不得用修改后的宽松策略评价自己 | base/candidate policy 测试 |
| `INV-NATIVE-PATHS` | Git 路径不得因非 UTF-8、空格或换行丢失 | Unix 原始字节 fixture；Windows wide path fixture |
| `INV-PROCESS-TREE-TERMINATION` | 超时和取消后无遗留子孙进程 | 跨平台进程树测试 |
| `INV-BOUNDED-OUTPUT` | 内存和终端输出有上限；完整日志外置并可引用 | huge-output fixture |
| `INV-UNKNOWN-IS-NOT-PASS` | 证据不足必须标记 unknown/not-verified，不得冒充通过 | doctor/evidence 测试 |

这些不变量比某个性能数字、文件行数或风险阈值更稳定。实现冲突时，优先保护不变量。

---

## 4. 系统边界、权威层次与依赖方向

### 4.1 分层架构

```text
┌──────────────────────────────────────────────────────────┐
│ 执行者：人类 / Cursor / Claude Code / Codex / 其他宿主   │
└───────────────────────────┬──────────────────────────────┘
                            │ 读取薄入口，调用项目命令
                            ▼
┌──────────────────────────────────────────────────────────┐
│ 可再生宿主适配：AGENTS.md / CLAUDE.md / 可选投影         │
└───────────────────────────┬──────────────────────────────┘
                            │ adapters sync/check
                            ▼
┌──────────────────────────────────────────────────────────┐
│ Forge：探测、初始化、诊断、导航、回执、证据、适配同步     │
└───────────────────────────┬──────────────────────────────┘
                            │ 调用但不拥有
                            ▼
┌──────────────────────────────────────────────────────────┐
│ 项目原生工程接口：cargo / go / make / just / task / 脚本 │
└───────────────────────────┬──────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────┐
│ 仓库权威资产：源码 / 类型 / 测试 / 构建 / CI / 正常文档 │
└───────────────────────────┬──────────────────────────────┘
                            │ 候选不可控制
                            ▼
┌──────────────────────────────────────────────────────────┐
│ 外部裁判：独立 CI / 受保护分支 / 所有者审批 / 保留测试  │
│           发布签名 / 灰度 / 生产观察                      │
└──────────────────────────────────────────────────────────┘
```

### 4.2 权威五层

| 层 | 内容 | 说明 |
|---:|---|---|
| 1 | 源码、类型、Schema、测试、构建、部署配置、CI | “现在是什么”的可执行事实 |
| 2 | README、CONTRIBUTING、ADR、Runbook、CODEOWNERS | “为什么、边界和责任” |
| 3 | Cargo/Go 命令、Makefile、justfile、Taskfile、已有脚本 | 项目操作协议 |
| 4 | Forge 的 ProjectModel、配置、运行状态、Receipt、Evidence | 可删除、可重建的映射与观察 |
| 5 | AGENTS.md、CLAUDE.md、宿主规则与 Skills | 只能由前四层生成的投影 |

第五层不能反向定义前三层。适配文件中的信息若需要长期保留，必须先进入正确的权威资产，再由适配重新生成。

### 4.3 单向依赖

允许：

```text
Forge → 读取 → 仓库资产
Forge → 调用 → 项目命令
Forge → 生成 → 宿主适配
独立 CI → 可选读取 → Forge Evidence
```

禁止：

```text
项目 build/test/verify ─X→ Forge
主验证 CI              ─X→ Forge
项目发布流程            ─X→ Forge
生产系统                ─X→ Forge
```

Forge 自身仓库的主验证流程同样使用 Cargo 直接执行，不要求先构建或安装 `forge`。

### 4.4 人机统一与权限分层

人和 Agent 对同一变更、同一证据必须得到同一质量结论。差异只在授权：

| 动作 | 默认边界 |
|---|---|
| 读代码、搜索、运行只读检查 | 可自动执行 |
| 修改普通代码 | 隔离分支或 worktree |
| 本地提交或草稿 PR | 可按团队策略授权 |
| 修改 CI、CODEOWNERS、安全、发布、签名 | 强制额外审查 |
| 删除数据、改变权限、向外发送信息 | 明确确认或禁止 |
| 合并、发布、生产操作 | 由授权系统和责任人执行 |

自治程度由四个变量决定，而不是由“是不是 AI”决定：验收可判定性、操作可逆性、验收独立性、失败爆炸半径。

---

## 5. 名称、配置与文件位置

### 5.1 产品身份

CLI、二进制和公开协议命名空间统一使用 `forge`。所有名称集中在 `forge-core::branding`，业务逻辑不得散布品牌字符串：

```rust
pub const CLI_NAME: &str = "forge";
pub const CONFIG_FILE: &str = "forge.toml";
pub const STATE_NAMESPACE: &str = "forge";
pub const BLOCK_NAMESPACE: &str = "forge";
pub const SCHEMA_NAMESPACE: &str = "forge";
```

名称已经由产品决策确定，但集中定义仍可防止实现层耦合，并为未来迁移提供单点清单。

### 5.2 路径选择顺序

任何新产物按以下顺序选择位置：

\[
\text{已有标准位置}
>
\text{已有文件的标准扩展点}
>
\text{单个根配置文件}
>
\text{工具私有工作树目录}
\]

第四级默认禁止。职责归属如下：

| 产物 | 位置 |
|---|---|
| 回归测试 | 仓库已有测试目录 |
| 自定义检查 | 仓库惯用的 `scripts/`、`tools/` 或 `hack/` |
| ADR / Runbook | `docs/adr/` / `docs/runbooks/` 或既有等价位置 |
| CI | `.github/workflows/` 等宿主标准位置，按职责命名 |
| 可选配置 | 仓库根 `forge.toml`，只有无法推导时才存在 |
| worktree 私有状态 | `git rev-parse --git-dir` 返回目录下的 `forge/` |
| 可共享只读缓存 | `git rev-parse --git-common-dir` 下的 `forge/cache/` |
| 用户级语言包或默认 | XDG/平台标准配置目录 |
| 完整本地日志 | worktree 私有 Git 目录；CI 使用 artifact 系统 |
| 保留测试、签名与最终晋升 | 候选不可修改的外部系统 |

不得生成：

```text
.forge/
.ai/
.agent/
docs/ai/
CODEX.md
工具命名的脚本目录
```

### 5.3 配置文件

默认没有 `forge.toml`。只有以下差异无法可靠从仓库推导时才建议创建：

- 覆盖项目命令；
- 声明多模块边界；
- 声明高风险或受保护路径；
- 调整超时、证据要求或输出限制；
- 显式启用宿主适配；
- 引用已有但无法自动定位的工程文档。

配置使用 `schema = 1`，未知字段报错；命令使用 `program + args`，不接受 shell 字符串。

---

## 6. Rust 工作区与 crate 边界

### 6.1 工作区

```text
forge/
├── Cargo.toml
├── rust-toolchain.toml
├── crates/
│   ├── forge-schema/
│   ├── forge-core/
│   ├── forge-runtime/
│   ├── forge-detect/
│   ├── forge-render/
│   └── forge-cli/
├── xtask/
├── fixtures/
├── tests/
└── docs/
    ├── design-proposal.md
    ├── adr/
    └── schemas/
```

### 6.2 crate 职责

| crate | 职责 | 禁止 |
|---|---|---|
| `forge-schema` | Wire 类型、Schema 版本、JSON Schema 导出 | OS I/O、业务状态机 |
| `forge-core` | 纯领域模型、策略、风险、状态机、证据规则、ports | 文件、Git、进程、时间、网络副作用 |
| `forge-runtime` | Git CLI、文件、同步进程、时钟、哈希、状态与缓存实现 | 业务策略与渲染决策 |
| `forge-detect` | 仓库、runner、Rust/Go Provider、工具探测、ProjectModel 构造 | 写工作树、决定最终授权 |
| `forge-render` | 受管块、ChangePlan、diff、原子 apply、宿主适配渲染 | 自行重新探测仓库 |
| `forge-cli` | 参数、依赖装配、输出、诊断、退出码、信号 | 隐藏业务规则或直接散布 `Command::new` |
| `xtask` | Schema 导出、fixture 生成、N−1 plan diff、发布辅助 | 运行时产品逻辑 |

### 6.3 依赖方向

```text
forge-schema
     ▲
forge-core
  ▲    ▲      ▲
runtime detect render
     \   |   /
      forge-cli

xtask 可读取 schema 与仓库文件，但不被产品 crate 依赖。
```

具体约束：

- `forge-core` 只依赖 `forge-schema` 与纯算法依赖；
- `forge-runtime`、`forge-detect`、`forge-render` 依赖 `forge-core`；
- `forge-cli` 负责组合所有实现；
- 任何环依赖阻断 CI；
- 所有外部进程必须经 runtime 单点封装；
- 业务代码中直接使用 `std::process::Command::new` 由架构 lint 阻断。

### 6.4 Rust 基线

```toml
edition = "2024"
rust-version = "1.85"
```

默认策略：

- `unsafe_code = "deny"`；
- Windows Job Object 若必须使用 FFI，只在单一平台模块局部允许，并为每个 `unsafe` 块写 `SAFETY:` 说明与平台测试；
- 库层使用结构化错误；CLI 边界负责诊断渲染；
- 业务路径不得 `unwrap()`、`expect()`、`panic!()`；
- `Cargo.lock` 提交；
- 依赖 patch 版本在 M0 兼容性 spike 后锁定，不在设计文档伪精确固定。

### 6.5 计划依赖类别

M0 兼容性验证后采用：

| 类别 | 候选 |
|---|---|
| CLI | `clap` |
| 序列化与配置 | `serde`、`serde_json`、`toml`、`schemars` |
| 错误与输出 | `thiserror`、`miette`、`tracing`、`anstream`、`anstyle` |
| 路径与遍历 | `bstr`、`ignore`、`globset`、`regex` |
| 哈希与 ID | `blake3`、`base64`、`ulid` |
| 文件与状态 | `tempfile`、`fs2` |
| diff | `similar` |
| 时间 | `time` |
| 进程 | `wait-timeout`、Unix `nix`、Windows `windows-sys` |
| 测试 | `insta`、`assert_cmd`、`predicates`、`proptest`、fuzz、mutation 工具 |

v0 不引入：`tokio`、`async-trait`、`libgit2`、`gix`、`tree-sitter`、LSP、HTTP 客户端、数据库、LLM SDK、动态库插件。

---

## 7. 版本路线与 CLI 命令面

### 7.1 v0 命令

```text
forge init
forge doctor
forge next

forge evidence run <intent>
forge evidence show
forge evidence verify
forge evidence export

forge adapters sync
forge adapters check

forge explain
forge schema [kind]
forge version
forge completions <shell>
```

命令职责：

| 命令 | 职责 | 不做什么 |
|---|---|---|
| `init` | 探测仓库，形成最小可审查 ChangePlan | 不复制模板树，不替团队编造组织资产 |
| `doctor` | 诊断环境、命令、配置、状态与适配漂移 | 不修业务代码，不批准变更 |
| `next` | 根据当前事实给出唯一主要动作 | 不做任务级 Agent 规划，不自动执行 |
| `evidence run` | 透明运行已解析的项目意图并记录 Receipt | 不成为项目长期入口 |
| `evidence show` | 展示有效、失效和失败的回执 | 不重新运行命令 |
| `evidence verify` | 判断当前风险所需本地证据是否充分 | 不批准合并、发布或生产操作 |
| `evidence export` | 输出 Evidence Bundle | 不保存聊天或私有思维过程 |
| `adapters sync` | 从权威资产重生成宿主适配 | 不维护多份正文 |
| `adapters check` | 只读检查漂移 | 不自动覆盖 |
| `explain` | 输出 ProjectModel 与来源 | 不修改仓库 |
| `schema` | 输出或列出版本化 Schema | 不修改协议 |
| `version` | 输出构建与支持能力 | 不联网检查更新 |
| `completions` | 生成 shell 补全 | 不成为运行时依赖 |

### 7.2 明确没有的顶层命令

```text
forge check
forge fix
forge test
forge build
forge context
forge task
forge improve   # v0 不实现
```

`evidence run check` 可以为 `check` 意图记录回执，但项目真正接口仍是 `cargo check`、`go test`、`make check` 等项目命令。

### 7.3 后续版本

| 版本 | 能力 |
|---|---|
| v0 | 最小可信闭环 |
| v0.1 | CI 外部证明导入、兼容升级、更多诊断解析、可选任务引用 |
| v0.2 | 基线棘轮、声明式 Language Pack、受控改进候选 |
| v0.3 | 保留测试、N−1、自托管权威边界、签名与灰度 |

后续版本不得要求 v0 项目把正常工程事实迁入 Forge 私有目录。

### 7.4 全局参数

```text
-C, --dir <PATH>             起始目录；向上定位 Git 根
--format human|json          TTY 默认 human，非 TTY 仍以命令约定为准
--json                       --format=json 的别名
--color auto|always|never
-q, --quiet
-v, --verbose                可叠加
--timeout <DURATION>          整条 Forge 命令共享的 wall-clock 总预算
--config <PATH>
--no-cache
```

写命令显式区分 `--dry-run` 与 `--apply`。网络相关能力若后续出现，必须用明确 `--network` 或命令专属 flag 启用；不得用“默认无网络”暗示 OS 沙箱。

---

## 8. 统一输出、诊断和退出码

### 8.1 stdout / stderr

- stdout 只放最终结果、diff 或单个 JSON 文档；
- stderr 放进度、警告和面向人的诊断；
- `--json` 时 stdout 不得混入日志、颜色、进度或子进程噪声；
- 成功的只读命令尽量安静；
- 子进程输出有界，完整日志外置并返回引用；
- human 与 JSON 由同一份结构化 `Diagnostic` 渲染，语义一致。

### 8.2 JSON 信封

所有机器输出包含：

```json
{
  "schema": "forge.next/v1",
  "tool_version": "0.1.0",
  "ok": true,
  "data": {},
  "diagnostics": [],
  "truncated": false,
  "artifacts": []
}
```

规则：

- Schema 版本与二进制 SemVer 解耦；
- 新增可选字段兼容；
- 删除、改名、类型或语义变化必须升主版本；
- 消费者必须忽略未知字段和未知枚举值；
- 旧 Schema 至少保留一个 minor 的读取/输出兼容期；
- TOML 配置相反：未知字段报错，防止拼写被静默忽略。

### 8.3 诊断格式

每条诊断必须包含：

```text
what   发生了什么
where  文件、字段、命令或阶段
why    为什么是问题、依据什么事实
next   下一步具体命令或动作
```

可选包含权威资料指针和来源链。示例：

```text
error[FGE2103]: required tool `cargo` was not found
  --> required by: rust.check
  why: Cargo.toml defines a Rust workspace at the repository root
  next: install the project-declared Rust toolchain, then run `forge doctor`
```

诊断码前缀固定为 `FGE`，分段：

| 范围 | 含义 |
|---|---|
| `FGE0xxx` | 用法、内部不变量 |
| `FGE1xxx` | 探测、配置、适配 |
| `FGE2xxx` | 环境、工具链、进程 |
| `FGE3xxx` | 状态、Receipt、Evidence |
| `FGE4xxx` | 风险、权限、权威边界 |
| `FGE5xxx` | 改进生命周期与兼容 |

### 8.4 退出码

| 码 | 名称 | 语义 |
|---:|---|---|
| 0 | `OK` | 操作成功或业务判定为通过 |
| 1 | `NEGATIVE` | 输入和环境合法，但检查失败、漂移或证据不足 |
| 2 | `ENV_UNMET` | 非 Git 仓库、缺工具、状态不兼容等前置不满足 |
| 64 | `USAGE` | 参数或命令用法错误 |
| 65 | `DATA_ERROR` | 配置、状态、Schema 或受管块数据非法 |
| 70 | `INTERNAL` | 内部不变量被破坏；实现缺陷 |
| 75 | `TEMPORARY` | 锁冲突、可重试 I/O 等临时失败 |
| 124 | `TIMEOUT` | 子进程或整体预算超时 |
| 130 | `INTERRUPTED` | 用户中断 |

项目工具的原始退出码保存在 Receipt 中，但 Forge 顶层命令映射到上述稳定语义。`evidence run` 可把被执行命令的原始结论映射为 0/1/2，同时保留 raw exit code。

---

## 9. 核心领域模型

以下类型名、字段语义和依赖方向已冻结；实现可调整内部表示，但不得改变公开语义而不更新 Schema/ADR。

### 9.1 标识与路径

```rust
pub struct RepoId(String);
pub struct UnitId(String);
pub struct CommandId(String);
pub struct ReceiptId(String);
pub struct EvidenceId(String);
pub struct Digest(String);
```

关键标识不得在业务代码中以裸 `String` 混用。

内部路径使用 `PathBuf`、`OsString` 或平台原生字节/宽字符，不能把整个真实仓库强制为 UTF-8。Wire 层：

```rust
pub struct WirePath {
    pub display: String,
    pub encoding: PathEncoding,  // utf8 | unix-bytes | windows-wide
    pub raw_base64: Option<String>,
}
```

只有 Forge 要写入 TOML 或自身管理的目标路径必须为 UTF-8；其他 Git 路径仍参与状态、风险和摘要。

### 9.2 Intent

```rust
pub enum Intent {
    Setup,
    FormatCheck,
    Format,
    Check,
    Fix,
    Test,
    Verify,
    Build,
}
```

Intent 是跨 runner 的语义，不表示 Forge 拥有对应命令。

### 9.3 CommandSpec

```rust
pub struct CommandSpec {
    pub id: CommandId,
    pub intent: Intent,
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: RepoRelativePath,
    pub env: BTreeMap<OsString, OsString>,
    pub timeout: Duration,
    pub mutability: Mutability,
    pub network: NetworkIntent,
    pub success: SuccessPredicate,
    pub source: CommandSource,
    pub confidence: Confidence,
    pub coverage: BTreeSet<CoverageDimension>,
}
```

```rust
pub enum SuccessPredicate {
    ExitZero,
    ExitZeroAndStdoutEmpty,
    JsonHasNoErrors,
    All(Vec<SuccessPredicate>),
}
```

`gofmt -l` 需要 `ExitZeroAndStdoutEmpty`，不能只看退出码。

### 9.4 ProjectUnit

```rust
pub struct ProjectUnit {
    pub id: UnitId,
    pub display_name: String,
    pub language: LanguageId,
    pub kind: ProjectKind,
    pub root: RepoRelativePath,
    pub manifest: RepoRelativePath,
    pub workspace_root: Option<RepoRelativePath>,
    pub members: Vec<UnitId>,
    pub dependencies: Vec<UnitEdge>,
    pub toolchain: ToolchainInfo,
}
```

```rust
pub enum ProjectKind {
    RustPackage,
    CargoWorkspace,
    GoModule,
    GoWorkspace,
    External(String),
}
```

### 9.5 ProjectModel

```rust
pub struct ProjectModel {
    pub schema: SchemaVersion,
    pub repository: RepoFacts,
    pub units: Vec<ProjectUnit>,
    pub commands: BTreeMap<Intent, ResolvedCommandSet>,
    pub assets: AssetInventory,
    pub adapters: AdapterInventory,
    pub policy: EffectivePolicy,
    pub assumptions: Vec<Assumption>,
    pub diagnostics: Vec<Diagnostic>,
}
```

`ProjectModel` 是渲染器的唯一输入。模板不得自行再次扫描仓库；`forge explain --json` 必须足以解释任何生成结果。

### 9.6 Ports

`forge-core` 定义，`forge-runtime` 实现：

```rust
pub trait GitPort { /* typed git operations */ }
pub trait FileSystemPort { /* read, inventory, atomic write */ }
pub trait ProcessPort { /* argv run, timeout, cancel, kill tree */ }
pub trait StateStore { /* load, save, lock, gc */ }
pub trait Clock { fn now(&self) -> SystemTime; }
pub trait Hasher { /* streaming digest */ }
pub trait OperationControl { /* one fixed command deadline, remaining budget, cancellation */ }
```

测试只替换这些外部端口，不 mock 风险、状态机和证据充分性等业务逻辑。
`--timeout` 在命令入口只构造一次 `OperationControl`；后续 Git、inventory、Provider、scope、状态和
子进程只能消费 remaining budget，不能用剩余 duration 创建新 deadline。

---

## 10. Git 与工作树模型

### 10.1 Git 访问方式

Forge 调用用户已安装的 Git CLI，不链接 libgit2/gix。核心命令：

```text
git rev-parse --show-toplevel
git rev-parse --path-format=absolute --git-dir
git rev-parse --path-format=absolute --git-common-dir
git status --porcelain=v2 -z --branch --untracked-files=all
git diff --binary --no-ext-diff --no-textconv <base> --
git diff --name-status -z <base> --
git ls-files -s -z
git check-ignore -z --stdin
git merge-base <base> HEAD
```

理由：

- porcelain v2 是面向脚本的稳定机器接口；
- `-z` 正确处理空格、换行和特殊文件名；
- 行为与用户实际 Git、attributes、sparse checkout、worktree、submodule 一致；
- 无 C 依赖和嵌入实现语义差异；
- 更易交叉编译。

所有调用通过 `GitPort`，业务代码不拼 Git shell 命令。

### 10.2 RepoFacts

```rust
pub struct RepoFacts {
    pub root: PathBuf,
    pub git_dir: PathBuf,
    pub git_common_dir: PathBuf,
    pub is_linked_worktree: bool,
    pub head: Option<CommitId>,
    pub branch: Option<String>,
    pub upstream: Option<UpstreamState>,
    pub work_state: WorkState,
}
```

`WorkState` 至少区分 clean、dirty、conflicted、merging、rebasing、unborn、corrupt/unknown。

### 10.3 工作树隔离

每个 linked worktree 使用自己的：

```text
<worktree-git-dir>/forge/
```

以下内容不得跨 worktree 共享：

- dirty snapshot / scope digest；
- Receipt；
- Evidence 草稿；
- 适配漂移状态；
- 运行日志；
- 临时任务引用；
- 锁。

只有由 commit、内容摘要、命令规格、工具链和环境完整寻址的不可变缓存，才可进入：

```text
<git-common-dir>/forge/cache/
```

### 10.4 子模块与 symlink

- v0 把 submodule 视为 Gitlink 边界，不递归初始化；
- 状态摘要记录 Gitlink OID 与脏状态；
- 遍历不跟随 symlink；
- 写操作拒绝目标本身是 symlink，或 canonicalize 后逃出仓库根；
- 路径检查在计划阶段和 apply 前各执行一次，以防 TOCTOU。

---

## 11. 配置、状态、缓存与并发

### 11.1 `forge.toml` v1

配置只在有实际差异时存在。完整形态：

```toml
schema = 1

[project]
include = []
exclude = []

[adapters]
agents = true
claude = true

[policy]
default_timeout_seconds = 300
max_log_file_bytes = 10485760
max_in_memory_stream_bytes = 262144

[commands.verify]
program = "make"
args = ["verify"]
cwd = "."
inputs = ["**"]

[evidence.require]
low = ["check"]
medium = ["check", "test"]
high = ["verify"]
critical = ["verify", "protected-ci", "owner-review"]

[[risk]]
id = "risk/migration"
level = "critical"
paths = ["migrations/**"]
external = ["owner-review", "protected-ci"]
```

规则：

- `schema` 必填；
- 未知字段报数据错误 65；
- `program + args`，不允许 `command = "..."`；
- `cwd` 必须是仓库内 UTF-8 相对路径；
- 配置优先于自动发现；
- 配置只覆盖和增补，不复制自动探测结果；
- 配置变化使相关 ProjectModel、Receipt 和 Evidence 失效；
- 配置本身属于高风险路径，因为它能影响评价策略。

### 11.2 私有状态布局

```text
<git-dir>/forge/
├── lock
├── model-v1.json
├── generated-v1.json
├── doctor-v1.json
├── receipts/
│   └── <ulid>.json
├── evidence/
│   └── <evidence-id>.json
└── logs/
    └── <run-id>/

<git-common-dir>/forge/cache/
├── inventory/
├── cargo-metadata/
├── go-metadata/
└── immutable-command-results/
```

状态要求：

- 全部带 Schema；
- 使用独占文件锁；
- 临时文件 + fsync + 原子 rename；
- 读取未来 Schema 时返回 65 或 2，并给出升级/删除可再生状态的指引；
- 损坏状态可以安全删除重建，不影响项目；
- state 不进入 Git，不成为权威资产；
- 日志和 Receipt 有数量、时间和总字节 GC 策略；
- GC 不删除仍被 Evidence 引用的对象。

### 11.3 缓存键

缓存复用需要全部相同：

```text
repository identity
+ worktree/scope digest
+ canonical command spec
+ tool versions
+ relevant environment digest
+ effective policy digest
+ Forge behavior version
```

不得缓存：

- mutating 命令；
- network required 命令；
- timeout/cancel 结果；
- 判断所需输出已被截断的结果；
- source/confidence 为 unknown 的命令；
- 用户要求 `--fresh` / `--no-cache`；
- 未能获得可靠作用域摘要的结果。

v0 的 shared inventory cache 采用更窄的专用键：repository identity、HEAD、inventory
边界、effective policy、平台、Forge behavior，加上当前普通 Git index 的语义投影
`(mode, blob object id, native relative path)`。raw index bytes 只用于在 status/index 读取前后
检测竞态，不进入跨 linked-worktree 的共享键，因为其中含 checkout 本地 stat 数据。缓存值只含
固定形状的资格证明（Schema、包含 behavior 的 key、平台、规则、index 语义投影、条目数和 payload digest），
不含路径或 worktree 本地 size；命中时 inventory 与 file set 必须完全由当前 typed stage-zero index
在同一趟校验中重建，并再次确认 raw index 未变化。旧 Schema/behavior 的缓存自然 miss。split index、
`index.lock`、symlink/reparse、未严格排序或重复路径的 typed index、非普通 index、
Gitlink、unmerged、sparse/skip-worktree、assume-unchanged、untracked，或 bounded Git 读取所暴露的
状态不在明确允许的普通 stage-zero 子集内，均回退到权威 inventory。只读命令的 miss 不发布；
只有已成功的授权状态写入才能顺带发布不可变条目。

### 11.4 并发

Forge v0 是同步单进程 CLI，不引入异步运行时。实现可以：

- 串行执行主控制流；
- 对彼此独立、可取消且输出有界的纯探测使用受限线程池；
- 同一 Cargo workspace 的 Cargo 命令使用相同 concurrency key 并串行；
- 同一 go.work 或 Go module 的相关命令默认串行；
- 不同语言/工作区是否并行由后续实测决定，不改变同步 API；
- 输出按计划顺序稳定汇总，不按完成先后排序。

v0 的正确性和可取消性优先于并发吞吐。没有真实瓶颈数据前，不建立 DAG 调度平台。

---

## 12. 仓库探测管线

### 12.1 总流程

```text
P0 locate repository
P1 read Git/worktree facts
P2 inventory manifests and standard assets
P3 build language units
P4 detect existing project command surfaces
P5 resolve project intents
P6 probe required tools and safe metadata
P7 inventory host adapters and CI
P8 load and merge policy
P9 emit ProjectModel with provenance/confidence/assumptions
```

探测器只读；不能确认的事实标记 unknown，而不是猜测。

### 12.2 Inventory

遍历要求：

- 尊重 `.gitignore`、`.ignore` 和 Git 全局 ignore；
- 不进入 `.git`、`target`、`vendor`、`node_modules` 等大型生成目录；
- 不跟随 symlink；
- 稳定路径顺序；
- 单文件读取上限；
- 二进制文件不作为文本解析；
- 记录跳过项及原因；
- 非 UTF-8 路径保留原始表示；
- 对 manifest 采用精确路径搜索，不全仓读取正文。

### 12.3 Provenance 与 Confidence

任何推导值必须带来源：

```rust
pub struct Provenance {
    pub rule_id: String,
    pub source_path: Option<WirePath>,
    pub source_range: Option<TextRange>,
    pub detail: String,
}
```

Confidence：

| 级别 | 含义 |
|---|---|
| high | 官方元数据命令或显式配置直接给出 |
| medium | 标准文件、runner 目标和一致的多信号推导 |
| low | 命名启发式或不完整文本解析 |
| unknown | 输入不足、互相矛盾或命令未验证 |

AGENTS.md 只渲染 high/medium 且不会造成虚假承诺的事实。低置信度信息进入 `uncertain_assumptions` 或 doctor 建议。

### 12.4 探测失败语义

- 非 Git 仓库：环境前置失败 2；
- manifest 非法：对应 Unit 失败并返回位置；若无可用 Unit 则 2/65；
- 官方元数据工具缺失：Unit 可静态识别，但命令/图标记 unknown；
- 单个 Provider 失败不应使其他 Provider 信息丢失；
- 总预算超时：已完成结果返回，未完成项标记 unknown，并以 124 表示计划不完整；
- 仓库正在 merge/rebase/conflict：探测可完成，但 `next` 优先 blocked。

---

## 13. 项目命令发现与验证

### 13.1 解析优先级

```text
显式 forge.toml
> 已有项目入口
> 语言原生默认
```

已有入口包括：

```text
Makefile
justfile
Taskfile.yml / Taskfile.yaml
项目已有标准脚本
```

v0 对“标准脚本”采用可审计的窄边界，不按相似名称猜测：只识别仓库根
`scripts/`、`tools/`、`hack/` 的直接子项；可选扩展名为
`sh/bash/zsh/fish/py/rb/pl/js/ps1/cmd/bat`；文件 stem 到 intent 的映射为：

| intent | 精确 stem |
|---|---|
| setup | `setup`、`bootstrap` |
| format-check | `format-check`、`fmt-check` |
| format | `format`、`fmt` |
| check | `check`、`lint` |
| fix | `fix` |
| test | `test` |
| verify | `verify`、`ci` |
| build | `build` |

名称只定位 intent，不决定解释器。v0 只有在文本首行精确为
`#!/usr/bin/env <portable-program-name>` 时才把它规范化成等价的
`<portable-program-name> <repo-relative-script-path>` argv；缺失、截断、二进制、控制参数、
绝对解释器或其它不可移植 shebang 只令该脚本对应的 intent 为 unknown，不污染其它 intent，
也不执行脚本。显式配置仍可覆盖同一 intent 的 unknown。

v0 不解析任意 CI shell 以反推命令；CI 仅作为“项目是否已经使用某入口”的补充证据。

### 13.2 ExistingProjectTarget 是不透明接口

发现 `make verify` 并不等于 Forge知道其覆盖格式、测试、构建和安全扫描。模型中必须区分：

```text
命令存在
命令是否实际运行过
命令声明/观察到的 coverage
无法确认的 coverage
```

只有结构化工具输出、显式配置或项目权威文档能提高 coverage 置信度。名称本身不能证明语义。

### 13.3 默认不运行项目目标

`init` 和普通 `doctor` 默认不运行 `make check`、`go test`、`cargo test` 等项目目标。理由：仓库命令可能耗时、写文件、访问网络或执行任意代码。

安全探针仅包括：

- 工具在 PATH 中；
- `--version`；
- Rust/Go 官方元数据命令；
- 可静态解析的 runner 目标；
- 用户显式启用的命令验证。

`make -n` 也不能称为无副作用，因为展开阶段可能执行 `$(shell ...)`。若作为显式增强探针，必须：

- 明确标为 best-effort；
- 有严格超时；
- 清洁化环境；
- 不把成功等同于实际验证；
- 失败回退到静态解析。

### 13.4 Runner 默认策略

| 仓库形态 | 无已有 runner 时的默认行为 |
|---|---|
| 单一 Rust | 不生成；Cargo 原生命令足够 |
| 单一 Go | 不生成；Go 原生命令足够 |
| Rust + Go 混合 | 默认仍只建议；用户显式选择统一 runner 后才生成 |
| 现有 runner | 使用现有入口；不覆盖同名目标 |
| 显式 `init --with-runner make|just|task` | 生成或补齐受管块 |

v0 `init` **不默认生成 runner**。避免把工具偏好强加给存量仓库，也避免为单语言项目增加同义维护层。

### 13.5 命令是否可用于 Evidence

只有满足以下条件才可生成 authoritative local Receipt：

- CommandSpec 来源和 argv 明确；
- cwd 在仓库内；
- 工具版本可记录；
- 执行前 scope digest 成功；
- 运行未超时/取消；
- 执行后 scope digest 成功；
- success predicate 可确定；
- 输出截断不影响判定；
- 网络和副作用状态如实记录。

否则只能形成 observation，不满足证据要求。

---

## 14. Rust LanguageProvider

### 14.1 检测

对每个候选 `Cargo.toml` 调用：

```bash
cargo metadata \
  --format-version=1 \
  --no-deps \
  --manifest-path <Cargo.toml>
```

读取：

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
rust-toolchain
.cargo/config.toml
.cargo/config
```

去重规则：

- 相同 `workspace_root` 的 package 归为一个 Cargo workspace Unit；
- 被 workspace 覆盖的 member 不重复成为顶层 Unit；
- workspace 外的 package 保持独立；
- 多个互不相属的 workspace 分别建 Unit；
- metadata 失败时可静态识别 manifest，但依赖图与命令范围标 unknown。

不得：

- 修改 `Cargo.lock`；
- 自动 `cargo update`；
- 自动安装 rustfmt/clippy；
- 假定所有 features 应开启；
- 假定项目使用 edition 2024；
- 绕过项目自己的 toolchain override。

### 14.2 默认命令

Fast/Check：

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
```

Full/Test：

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --no-fail-fast
```

按模型去掉不适用的 `--workspace`。

Clippy：

- 现有项目命令、CI、`[lints]`、clippy 配置明确要求时，作为 required；
- 否则 `cargo clippy --workspace --all-targets` 只作为 advisory；
- 不默认增加 `-D warnings`；
- 不默认增加 `--all-features`、`--locked`、nextest、cargo-deny、cargo-audit。

Format/Fix：

```text
cargo fmt --all
```

`cargo fix`、`cargo clippy --fix` 不属于 v0 默认自动修复。

### 14.3 Toolchain 与 features

- 默认使用项目默认 features；
- 已有项目入口若使用 `--all-features`，尊重项目；
- 显式配置可以覆盖；
- Forge 不穷举 feature 笛卡尔积；
- rust-toolchain 变化使相关 Receipt 失效；
- Cargo version、rustc version、target triple 和关键配置摘要进入 toolchain/environment digest。

### 14.4 Changed 影响范围

| 变化 | 最小安全范围 |
|---|---|
| 根 `Cargo.toml`、`Cargo.lock`、toolchain、`.cargo/**` | 整个 workspace |
| member `Cargo.toml`、`build.rs`、proc-macro | package + 反向 path 依赖；不确定时整个 workspace |
| 普通 `src/**` | 所属 package |
| `tests/**`、`examples/**`、`benches/**` | 所属 package |
| workspace 共享配置 | 整个 workspace |
| 无法映射、宏/生成影响未知 | 整个 workspace |

v0 不做 AST 公共 API 指纹。无法确认公共面是否变化时，不乐观排除反向依赖；根据风险和仓库规模扩大到 workspace。

### 14.5 Coverage 维度

Rust Provider 至少声明：

```text
format
compile
lint (required/advisory/unknown)
unit-test
integration-test (如果 cargo test 覆盖但外部依赖未知，标明边界)
build
examples/benches (是否覆盖由实际命令决定)
cross-target (默认 not-verified)
performance (默认 not-verified)
```

Evidence v2 保留上述通用维度，并用现有 custom 维度声明
`rust-format`、`rust-compile`、`rust-lint`、`rust-unit-test`、
`rust-integration-test-local`、`rust-build`、`rust-examples-compile`、
`rust-benches-compile`、`rust-cross-target` 和 `rust-performance`。这样 mixed repository 中
Go 的通用 coverage 不会遮蔽 Rust 缺口。`cargo check --all-targets` 只声明通用 compile 与
`rust-compile`；Cargo 会跳过当前 feature set 未满足 `required-features` 的 target，因此默认命令不
声明 examples/benches compile、performance 或 cross-target coverage。无 Receipt 或部分 Receipt 时，
Provider expectation 中尚未出现在 verified/advisory/显式 not-verified 的维度进入 not-verified；
四分优先级为 external-required > not-verified > advisory > verified。该展示不改变本地充分性。

---

## 15. Go LanguageProvider

### 15.1 检测

顺序：

1. 查找仓库内 `go.work`；
2. 静态解析或显式元数据模式运行 `go work edit -json`；
3. 识别 `use` 中 module；
4. 未被任何 go.work 包含的 `go.mod` 作为独立 module；
5. 独立 module 的命令显式设置 `GOWORK=off`；
6. go.work Unit 的命令显式设置 `GOWORK=<absolute path>`；
7. 需要依赖图时运行 `go list -json -deps -test ./...`，但不能在普通 init 中因依赖下载而隐式联网。

额外读取：

```text
go.mod
go.sum
go.work
go.work.sum
vendor/modules.txt
```

不得：

- 自动 `go mod tidy`；
- 自动 `go get`；
- 自动修改 `go.sum` / `go.work.sum`；
- 自动切换 vendor 模式；
- 自动安装 goimports、staticcheck、golangci-lint、govulncheck。

### 15.2 默认命令

Format check：

```text
gofmt -l <Git tracked .go files in scope>
```

成功条件是退出码 0 且 stdout 为空。文件参数按平台 argv 限制分批。

Fast/Check：

```text
gofmt -l <affected files>
go test -json <affected packages>
go vet -json <affected packages>
```

Full：

```text
gofmt -l <all tracked .go files>
go test -json ./...
go vet -json ./...
```

`go vet` 是启发式分析，不等于程序正确性。若项目现有入口没有把 vet 设为门禁，Forge 应把其结果标为 advisory，而不是擅自改变项目准入语义。

默认不启用：

```text
-race
-count=1
coverage threshold
staticcheck
golangci-lint
govulncheck
```

项目已有入口使用这些参数时尊重项目；显式 fresh 模式可以给 `go test` 增加 `-count=1`。

Fix：

```text
gofmt -w <changed non-generated .go files>
```

带标准 `Code generated ... DO NOT EDIT.` 标记的文件不自动修改。

### 15.3 Changed 影响范围

| 变化 | 最小安全范围 |
|---|---|
| `go.work`、`go.work.sum` | workspace 全部 module |
| `go.mod`、`go.sum` | 当前 module；必要时 workspace 依赖 module |
| 普通 `.go` | 所属 package |
| `_test.go` | 所属 package与相关外部测试 package |
| `//go:embed` 资源 | 声明该 pattern 的 package |
| cgo、assembly、生成器 | 当前 module |
| 无法映射 | 当前 module或整个 workspace |

v0 不做 AST exported API fingerprint。无法确认时扩大范围。

### 15.4 Go 特殊边界

- 避免父目录或用户环境中的外部 `GOWORK` 污染；
- 记录 GOFLAGS/GOWORK 等相关变量摘要但不保存 secret 值；
- build tags 变化扩大 package 范围；
- vendored 仓库尊重项目已有模式，不自行决定 `-mod=vendor`；
- `gofmt` 文件列表只来自 Git/Provider 作用域，不递归把 vendor/generated 全部写入；
- 命令行超长时分批，所有批次结果聚合为一个 intent observation。

---

## 16. `forge init`

### 16.1 定位

`init` 是一台仓库编译器，不是模板复制器：

```text
RepoFacts      仓库事实
    ↓
ProjectModel   中间表示
    ↓
ChangePlan     可审查编译产物
```

### 16.2 用法

```text
forge init
forge init --apply
forge init --with-runner make|just|task
forge init --with-ci github
forge init --adapter claude
forge init --adapter cursor
forge init --allow-dirty   # 非默认，仍不绕过 preimage
forge init --json
```

默认行为：

- dry-run；
- 允许在 dirty worktree 中预览；
- `--apply` 要求 clean worktree，除非显式 `--allow-dirty`；
- 只做元数据探测，不运行完整检查；
- 不自动 commit、branch、stage 或修改 Git 配置；
- 不默认联网；
- 不默认生成 runner、CI、配置或组织文档。

### 16.3 流水线

```text
1 locate
2 inventory
3 detect units and assets
4 resolve project commands
5 inspect safe metadata and tools
6 classify gaps
7 choose native destinations
8 render ChangePlan
9 validate all preimages, paths, blocks and invariants
10 preview diff, assumptions and rollback
11 apply transactionally when --apply
12 re-detect and run post-doctor against generated state
```

每阶段输入输出都应是显式类型；探测、推导、渲染和写入不得混成一个函数。

### 16.4 Gap 分类

```rust
pub enum GapKind {
    MissingProjectCommand,
    MissingHostIndex,
    MissingHostPointer,
    AmbiguousCommand,
    AdapterDrift,
    OptionalRunner,
    OptionalCiDraft,
    ConfigurationRequired,
}
```

v0 默认可生成的 gap 只有：

- `MissingHostIndex` → `AGENTS.md`；
- 已探测/显式请求宿主的 `MissingHostPointer`；
- 确实无法推导的 `ConfigurationRequired`。

其他 gap 默认只诊断或需要显式 flag。

`CONTRIBUTING.md`、ADR、Runbook、CODEOWNERS 缺失不直接成为自动生成动作，因为它们包含团队意图、责任和历史，不可从语言 manifest 唯一推出。

### 16.5 默认产物

正常单语言仓库中，init 最多创建/更新：

```text
AGENTS.md
CLAUDE.md / 其他已请求宿主指针
forge.toml   # 只有存在无法推导的必要差异
```

默认不创建：

```text
Makefile
justfile
Taskfile
.github/workflows/*
CONTRIBUTING.md
docs/adr/
docs/runbooks/
CODEOWNERS
质量基线
示例代码
README 正文
.gitignore 条目
```

Forge 自身起始仓库中的设计文档、ADR、CONTRIBUTING 和 CI 是本项目的正常人工工程资产，不代表 `forge init` 默认会为其他项目生成它们。

### 16.6 空仓库

若无 `Cargo.toml`、`go.mod`、可识别项目命令或其他足够项目事实：

```text
error[FGE2010]: no project facts found
  why: forge compiles an existing repository; it does not choose a language or framework
  next:
    Rust: cargo new / cargo init
    Go:   go mod init <module-path>
    then run: forge init
```

退出 2。不提供 `forge new --lang`。

### 16.7 不支持语言

- 若已有明确项目命令，Forge 可以生成语言无关薄适配并把语言标为 external/unsupported；
- 若命令也不明确，只输出诊断和扩展方式，不猜测；
- 不为不支持语言生成注释占位 runner；
- 后续声明式 Language Pack 或进程协议加入，不要求改核心领域模型。

### 16.8 ChangePlan

```rust
pub struct ChangePlan {
    pub schema: SchemaVersion,
    pub repository: RepoIdentity,
    pub model_digest: Digest,
    pub edits: Vec<FileEdit>,
    pub assumptions: Vec<Assumption>,
    pub skipped: Vec<SkippedChange>,
    pub rollback: RollbackPlan,
}
```

```rust
pub enum FileEdit {
    Create {
        path: RepoRelativePath,
        content: Vec<u8>,
    },
    ReplaceManagedBlock {
        path: RepoRelativePath,
        block_id: ManagedBlockId,
        expected_preimage: Digest,
        content: Vec<u8>,
    },
}
```

不提供任意全文覆盖现有文件的 edit 变体。

### 16.9 应用事务

应用前：

1. 重新读取所有 preimage；
2. 验证目标位于仓库根；
3. 拒绝 symlink 写入和逃逸；
4. 验证所有受管块无冲突；
5. 验证计划中无重复目标和交叠块；
6. 验证输出确定、无绝对路径、用户名、随机数、当前时间；
7. 若任一失败，整体不写。

应用：

```text
同目录临时文件
→ 写入完整 postimage
→ flush/fsync
→ 保留原权限
→ 原子 rename
→ 重新读取并核对摘要
```

多个文件无法提供跨文件 OS 原子事务。实现必须在失败时返回已写/未写列表和每个 preimage，允许 Git 完整回滚；不得声称真正的全仓原子性。

### 16.10 回滚

`--apply` 默认要求 clean worktree，因此回滚使用 Git：

```text
git restore -- <modified paths>
git clean -f -- <created paths>
```

Forge 不建立长期 backup/undo 目录，避免与 Git 重复并误覆盖应用后的人工编辑。

### 16.11 幂等与确定性

- 幂等键 = 目标路径 + managed block id；
- 同输入和模板版本得到相同内容；
- 生成物不含生成时间、绝对路径、用户名、随机 ID；
- 第二次 init 发现目标已满足，ChangePlan 为空；
- 时间只可进入运行报告和 Receipt，不进入生成文件；
- 排序统一使用稳定规则，而不是 HashMap 迭代顺序。

---

## 17. 受管块与宿主适配

### 17.1 受管块格式

Markdown：

```markdown
<!-- forge:begin block=project-index schema=1 hash=blake3:... -->
生成正文
<!-- forge:end block=project-index -->
```

Make/TOML/YAML/shell（未来显式生成时）：

```text
# forge:begin block=<id> schema=1 hash=blake3:...
...
# forge:end block=<id>
```

hash 计算正文的规范字节，不含 marker。Marker Schema 与文件内容 Schema 独立演进。

### 17.2 合并算法

| 状态 | 动作 |
|---|---|
| 文件不存在 | 创建只含受管块的文件 |
| 文件存在、无同 ID 块 | 按该文件类型的标准位置追加 |
| 块存在、声明 hash 等于实际正文、内容相同 | NoOp |
| 块存在、声明 hash 等于实际正文、规范内容变化 | 安全替换块正文 |
| 声明 hash 不等于实际正文 | `user-edited` 冲突，默认中止 |
| 同 ID 块出现多次 | 数据错误，人工修复 |
| 遇到未知未来 Schema | 拒绝写入，要求升级 |

`--force-block <id>` 只覆盖指定块；块外字节保持。不得自动三方合并受管块内的人工内容。正确做法是把需求移动到权威资产，再重新生成。

### 17.3 `AGENTS.md`

只允许四类内容：

1. 权威资料在哪里；
2. 项目原生命令是什么；
3. 什么本地证据状态算完成；
4. 哪些区域必须停止并交给授权者。

每条通过删除测试：

> 删除这一条后，执行者是否更可能造成一个具体错误，而不仅是做得没那么漂亮？

模板不能：

- 复制 README/CONTRIBUTING 正文；
- 列出可由 manifest 轻易发现的全部依赖；
- 记录架构历史；
- 重复格式规范；
- 承诺不存在的 CI 或权限；
- 固化当前模型的微小弱点；
- 要求保存私有思维过程。

初始护栏：受管块不超过 120 行和 8 KiB；这是防失控断路器，不是普遍最优行数。

### 17.4 `CLAUDE.md`

Claude 适配使用导入而非 symlink：

```markdown
<!-- forge:begin block=claude-pointer schema=1 hash=blake3:... -->
@AGENTS.md
<!-- forge:end block=claude-pointer -->
```

Windows 无需管理员 symlink 权限。

### 17.5 Codex 与其他宿主

- Codex 使用 `AGENTS.md`，不生成 `CODEX.md`；
- Cursor 等不能直接导入时，只有在探测到或显式请求时生成最小投影；
- 最小重复可接受，前提是同一 `RenderContext` 生成且可漂移检测；
- 宿主适配注册表数据驱动；
- 新宿主不得修改核心状态机和证据语义；
- 宿主能力变化通过消费者契约测试发现，适配可负发布删除。

### 17.6 `adapters sync` 与 `adapters check`

`sync`：

- 默认生成 diff；写盘需要 `--apply`，与 init 保持一致；
- 只处理 Forge 拥有的块/文件；
- 遇到 user-edited 默认退出 1；
- 更新 manifest 和 source asset digests；
- 连续两次 apply 第二次 NoOp。

`check`：

- 永远只读工作树；
- 0 = 无漂移；1 = 漂移；2/65 = 环境或状态不可用；
- 可作为独立 CI job；
- 主 build/test/verify job 不依赖该 job 或 Forge。

漂移分类：

| 分类 | 含义 |
|---|---|
| `asset-changed` | 权威资产变了，生成物未被手改，可安全重生成 |
| `user-edited` | 生成物/块被手改，默认冲突 |
| `generated-missing` | manifest 有记录但目标缺失 |
| `manifest-stale` | manifest Schema/生成器版本不兼容，可重建或需升级 |
| `no-drift` | 资产与生成物均匹配 |

---

## 18. `forge doctor`

### 18.1 定位

`doctor` 是只读诊断器，回答：环境、项目操作协议、Forge 状态、适配与权限前置是否足以继续。它不修业务代码，不安装工具，不批准变更。

### 18.2 检查项

| ID | 检查 |
|---|---|
| `git.repository` | Git 根、git dir/common dir、HEAD、worktree 状态 |
| `git.operation` | merge/rebase/conflict/unborn |
| `state.layout` | 私有状态可读写、锁和 Schema |
| `config.schema` | `forge.toml` 解析、未知字段、路径和命令安全 |
| `project.units` | Rust/Go manifests、workspace/module 边界 |
| `project.commands` | 各 intent 是否可解析、来源与置信度 |
| `toolchain.required` | 项目命令要求的工具是否存在和版本可读取 |
| `adapters.drift` | AGENTS/CLAUDE 等受管块和 manifest |
| `ci.visible` | 仓库内可见 CI 是否调用项目原生入口；服务端设置未知时标 unknown |
| `ownership.visible` | 高风险路径是否有可见 CODEOWNERS；不可见权限不推断 |
| `path.safety` | symlink 逃逸、管理路径编码、目标冲突 |
| `process.capability` | 超时/进程树终止能力是否可用 |

### 18.3 状态

每项：

```text
pass
fail
unknown
skipped
```

- unknown 不是 pass；
- skipped 必须给出用户 flag、平台限制或预算原因；
- `overall` 可为 pass/fail/unknown；
- fail 退出 1；环境不能运行核心诊断退出 2；配置/状态损坏退出 65；
- `doctor` 不默认运行项目 test/verify；显式深度模式也只根据用户授权运行。

### 18.4 输出

```json
{
  "schema": "forge.doctor/v1",
  "overall": "unknown",
  "checks": [
    {
      "id": "ci.visible",
      "status": "unknown",
      "detail": "server-side branch protection is not observable from this clone",
      "next": "verify repository protection settings in the hosting platform"
    }
  ],
  "tool_versions": {},
  "assumptions": [],
  "artifacts": []
}
```

### 18.5 修复边界

v0 不提供通用 `doctor --fix`。适配漂移由显式 `forge adapters sync --apply` 修复。把诊断与写入分开，避免 flag 改变命令的副作用性质。

---

## 19. `forge next`

### 19.1 定位

`next` 是确定性导航器，不是任务规划器。它读取 Git、ProjectModel、doctor、适配漂移、风险、Receipt 有效性，给出当前唯一主要动作；不修改工作树，不执行命令。

### 19.2 状态优先级

首个匹配即返回：

| 序 | 条件 | 状态 | 主要动作 |
|---:|---|---|---|
| 1 | 输入损坏或不足 | `unknown` | `run-doctor` |
| 2 | merge/rebase/conflict、环境 blocker、受保护动作待授权 | `blocked` | `resolve-blocker` / `stop-and-escalate` |
| 3 | 宿主适配漂移且当前任务需要适配 | `adapters-drifted` | `sync-adapters` |
| 4 | 无工作树/分支变更 | `idle` | `none` |
| 5 | 当前作用域最近 required Receipt 失败 | `checks-failing` | `fix-failures` |
| 6 | 有变更且无有效 check Receipt | `changed-unverified` | `run-intent(check)` |
| 7 | check 有效但风险要求 test/verify 且缺失 | `partially-verified` | `run-intent(test|verify)` |
| 8 | 本地证据充分 | `local-verified` | `collect-evidence` 或 `none` |

失败 Receipt 只有在其 scope/command/toolchain/environment/policy 仍匹配时才决定当前状态；输入变化后它保留历史但不再约束当前作用域。

### 19.3 输出契约

```json
{
  "schema": "forge.next/v1",
  "state": "changed-unverified",
  "required_action": "run-intent",
  "intent": "check",
  "project_commands": [
    {"program": "cargo", "args": ["check", "--workspace"], "cwd": "."}
  ],
  "receipt_command": "forge evidence run check",
  "context_paths": [
    {"path": "Cargo.toml", "why": "workspace manifest"}
  ],
  "risk": {
    "level": "medium",
    "matched": ["risk/source-change"]
  },
  "blockers": [],
  "reason": "Rust source changed and no valid check receipt exists for the current scope",
  "provenance": ["state/current-scope", "provider/rust/default-check"],
  "uncertain_assumptions": []
}
```

`reason`、`provenance`、`uncertain_assumptions` 必须存在；没有来源的建议视为内部错误。

### 19.4 项目命令与 Receipt 命令同时给出

`project_commands` 是长期接口；`receipt_command` 是可选便利层：

```text
直接执行 cargo check --workspace        合法，但 Forge 不自动获得 Receipt
forge evidence run check                 执行同一 CommandSpec 并记录 Receipt
```

不得只返回 Forge 命令而隐藏项目实际命令。

### 19.5 `next` 不做的事

- 不分解任务；
- 不生成代码；
- 不读完整对话；
- 不自动运行项目命令；
- 不联网查 PR 状态；
- 不声称得到完整影响闭包；
- 不根据随机或模型输出改变结果；
- 不把不存在的测试写成 blocker；
- 不把本地 verified 叫作 ready-to-merge。

---

## 20. 风险与上下文选择

### 20.1 风险级别

```text
low
medium
high
critical
```

风险影响需要的证据和外部批准，不直接赋予 Forge 权限。

### 20.2 默认规则

| ID | 级别 | 典型匹配 |
|---|---|---|
| `risk/ci-policy` | critical | CI、CODEOWNERS、权威策略、发布/签名 |
| `risk/permission` | critical | 权限、密钥、认证配置 |
| `risk/migration` | critical | 数据迁移、schema migration、删除数据 |
| `risk/test-weakening` | high | 删除测试、弱化断言、ignore/skip、放宽 lint |
| `risk/unsafe-cgo` | high | Rust unsafe、Go cgo/unsafe |
| `risk/public-api` | high | 可可靠识别的公开接口变化；不确定时记录 unknown |
| `risk/dependency` | medium | manifests、lockfiles、toolchain |
| `risk/source-change` | medium | 普通源码 |
| `risk/docs-only` | low | 纯文档且不含策略/命令/安全语义 |

风险规则必须输出 provenance。多规则取最高等级，全部命中保留。

### 20.3 防止策略自我削弱

策略变更使用：

\[
P_{effective}=P_{base}\cup stricter(P_{candidate})
\]

即：

- 候选新增/收紧的要求可以立即评价当前候选；
- 候选删除/放宽的要求在当前评价中无效；
- 放宽经外部批准合入后，才成为下一次变更的 base；
- 不能通过先删风险规则、再使自己的变更变低风险。

### 20.4 v0 上下文信号

`next` 只返回路径和理由，不默认输出大段正文。排序信号：

1. 用户/变更精确路径；
2. 所属 manifest 和 ProjectUnit；
3. 同目录、命名相关测试；
4. Provider 已知依赖与反向依赖；
5. CODEOWNERS 命中；
6. 精确文本命中的 ADR、Runbook、CONTRIBUTING；
7. 无法确认的影响项。

v0 不使用 AST、LSP、PageRank、embedding 或模型摘要。需要这些能力时，先在真实任务上证明相对路径/元数据方案的边际收益。

### 20.5 预算与降级

- 默认预算用字节/行，而不是绑定某个 tokenizer；
- 超预算保留标题、路径、理由，正文退化为指针；
- 每项带 provenance、confidence；
- 无法确认闭包时写入 `uncertain_assumptions`；
- 同分稳定按类型和仓库相对路径排序；
- 不把低置信度内容自动注入 `AGENTS.md`。

---

## 21. 执行回执与证据协议

### 21.1 `evidence run`

```text
forge evidence run check
forge evidence run test
forge evidence run verify
```

流程：

1. 解析当前 ProjectModel 的 Intent；
2. 显示将执行的真实项目 CommandSpec；
3. 计算执行前作用域摘要；
4. 同步执行，流式/有界处理输出；
5. 按 SuccessPredicate 归一化结果；
6. 计算执行后作用域摘要；
7. 记录工具链、相关环境和策略摘要；
8. 写入 worktree 私有 Receipt；
9. 以稳定退出码返回。

如果命令会修改工作树（如 format/fix），执行前 Receipt 不能直接证明执行后的状态；只有 after digest 与后续只读检查匹配才可满足 evidence。

### 21.2 Scope Digest

\[
D_{scope}=H(
format\_version,
HEAD,
sorted(path,mode,content\_identity)
)
\]

- 未修改 tracked 文件使用 index blob OID；
- staged/unstaged/untracked 文件流式 BLAKE3 内容；
- symlink 使用 link 内容；
- ignored 文件不进入默认作用域；
- mtime 不进入摘要；
- 不用“大文件只取 size”的不安全降级；
- 若文件无法读取，摘要失败而不是乐观复用；
- Intent 的输入集合由 Provider/显式配置确定；无法可靠缩小时使用整个相关 Unit。

### 21.3 Command Digest

Canonical form：

```text
program raw representation
argv raw representations in order
cwd repository-relative representation
environment names and allowed values/digests
mutability
network intent
success predicate
coverage declaration
source/provenance
```

显示字符串不是摘要输入；避免 quoting 差异造成错误碰撞。

### 21.4 Receipt

```rust
pub struct Receipt {
    pub schema: SchemaVersion,        // forge.receipt/v1
    pub id: ReceiptId,
    pub intent: Intent,
    pub observations: Vec<CommandObservation>,

    pub head: Option<CommitId>,
    pub scope_digest_before: Digest,
    pub scope_digest_after: Digest,

    pub command_digest: Digest,
    pub toolchain_digest: Digest,
    pub environment_digest: Digest,
    pub policy_digest: Digest,

    pub started_at: OffsetDateTime,
    pub duration_ms: u64,
    pub outcome: Outcome,
    pub coverage: BTreeSet<CoverageDimension>,
    pub log_refs: Vec<LogRef>,
}
```

每个 observation 保存：

```text
program + argv
cwd
raw exit code / signal
normalized outcome
duration
timed_out / interrupted
stdout/stderr digest
有界摘要或 finding 计数
完整日志引用（若存在）
```

默认不保存完整 stdout、环境变量值、对话或模型输出。

### 21.5 Receipt 有效性

\[
valid(r)=
(r.scope=current.scope)
\land(r.command=current.command)
\land(r.toolchain=current.toolchain)
\land(r.environment=current.environment)
\land(r.policy=current.policy)
\]

TTL 只能作为额外保守限制，不能替代依赖比较。以下任一变化立即失效：

- 输入文件/HEAD；
- CommandSpec；
- 工具版本；
- 相关环境；
- effective policy；
- 比较 base；
- task acceptance（若 evidence 绑定任务）；
- Forge 行为版本发生不兼容变化。

### 21.6 Evidence Bundle

```rust
pub struct EvidenceBundle {
    pub schema: SchemaVersion,        // forge.evidence/v1
    pub id: EvidenceId,
    pub repository: RepositoryIdentity,
    pub task_reference: Option<String>,
    pub base_commit: Option<CommitId>,
    pub head_commit: Option<CommitId>,
    pub diff_digest: Digest,
    pub risk: RiskAssessment,

    pub valid_receipts: Vec<ReceiptRef>,
    pub stale_receipts: Vec<StaleReceipt>,
    pub coverage_and_gaps: CoverageStatement,

    pub local_state: LocalEvidenceState,
    pub external_requirements: Vec<ExternalRequirement>,
    pub external_attestations: Vec<ExternalAttestation>,
}
```

`coverage_and_gaps` 强制存在：

```json
{
  "verified": ["format", "compile", "unit-test"],
  "advisory": ["lint"],
  "not_verified": [
    "real-database-integration",
    "cross-platform-runtime",
    "performance-regression"
  ],
  "external_required": ["protected-ci", "owner-review"]
}
```

一次全绿只能说明列出的维度，不代表绝对正确。

### 21.7 信任层次

```text
local-observation       本地运行记录
external-attestation    独立 CI/测试系统的证明
approval                授权者批准
deployed-observation    灰度或生产观察
```

v0 生成第一层，并可在 Evidence 中声明后续要求；v0.1 才导入受验证的外部引用。不得用单个 `pass=true` 混淆这些层次。

### 21.8 Evidence 命令语义

`show`：展示当前工作树和分支相关的有效/失效 Receipt；只读。

`verify`：按风险策略检查 required local evidence；不足退出 1；仍不表示可以合并。

`export`：输出 JSON 或 Markdown 评审包；包含盲区；默认不提交到仓库。

后续 `import`：只接受可验证来源/签名/平台 API，不能仅凭用户传入“CI passed”文本升级信任层级。

---

## 22. 进程执行、安全与隐私

### 22.1 信任边界

以下全部视为不可信输入：

```text
仓库文件和文件名
Cargo.toml / go.mod / runner 文件
README/注释中的命令
Forge 配置中的命令覆盖
Git 配置和 hooks
tool/subprocess 输出
symlink
Language Pack
CI 引用
```

Rust/Go 官方工具和 Git 也必须通过版本、退出码和有界输出验证，不能假设永不异常。

### 22.2 同步进程执行器

唯一入口接收：

```rust
pub struct ExecSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: RepoRelativePath,
    pub env: EnvPolicy,
    pub timeout: Duration,
    pub stdin: StdinPolicy,
    pub stdout: OutputPolicy,
    pub stderr: OutputPolicy,
    pub mutability: Mutability,
    pub network: NetworkIntent,
    pub concurrency_key: Option<String>,
}
```

要求：

- 不经 shell；
- cwd canonicalize 且位于仓库内；
- stdin 默认关闭，交互命令必须显式；
- stdout/stderr 分开流式读取；
- 内存有界，完整日志按策略落盘；
- 记录 wall time、raw exit、signal、timeout、cancel；
- 子进程 timeout 取命令声明上限与 operation remaining budget 的较小值，不重置总预算；
- 捕获 SIGINT 并终止整个进程树；
- Unix 使用独立进程组；
- Windows 使用 Job Object；
- 子进程启动和终止竞态有集成测试；
- 不直接把子进程输出写进 JSON stdout。

### 22.3 环境策略

执行环境采取“继承最小必要项 + 显式覆盖”：

- PATH 需要继承以找到项目工具；
- HOME、CARGO_HOME、RUSTUP_HOME、GOMODCACHE 等可继承，但 Evidence 只记位置摘要；
- GOWORK 对每个 Go Unit 显式设置；
- secret 名称和值不进入 Receipt；
- 与结果相关的非秘密变量进入 canonical digest；
- 未列入 digest 但可能影响结果的变量进入 unknown/gap；
- 本地 shell alias/function 不参与 argv 执行。

Secret 名称至少匹配：

```text
*TOKEN*
*SECRET*
*PASSWORD*
*PRIVATE*
*KEY*
AWS_*
GITHUB_TOKEN
GOOGLE_*
AZURE_*
```

### 22.4 网络语义

v0 不提供 OS 级网络沙箱。必须诚实区分：

```text
Inherit             项目命令可能访问网络
OfflineRequested    设置生态离线参数，best-effort
Required            命令声明需要网络
Unknown             无法确认
```

Cargo `--offline`、`CARGO_NET_OFFLINE=true`、Go `GOPROXY=off` 等只能描述为“请求离线”，不能描述为安全隔离。

普通 `init`、`doctor`、`next`、`adapters`、`show/verify/export` 不需要 Forge 自身联网。更新检查、CI import 等后续网络能力必须显式、可禁用、有域名/来源约束。

### 22.5 路径与写入安全

- 所有目标先规范为仓库相对路径；
- 拒绝绝对路径、`..` 逃逸、NUL；
- 不跟随 symlink 写入；
- apply 前重新核对父目录和目标；
- 同目录临时文件避免跨文件系统 rename；
- 保留原文件权限、换行风格和尾部换行；
- 新 Markdown/TOML 默认 LF；
- 尊重可确定的 `.gitattributes` EOL；
- 非 UTF-8 现有路径可读取和汇报，但 Forge 管理的新路径必须 UTF-8。

### 22.6 仓库指令注入

Forge 不把仓库任意文本自动当作命令或策略：

- README/注释只作为上下文指针，不解析“请执行...”为命令；
- Project command 只来自显式配置、受支持 runner 结构或 LanguageProvider；
- runner 目标名必须通过严格语法；
- 模板不直接插值未转义仓库正文；
- context 输出带来源，不授予权限；
- Language Pack 中的命令需要用户级信任或显式仓库授权；
- 外部适配器将来使用子进程协议和权限/超时边界，不使用 Rust dylib。

### 22.7 隐私与日志

默认不保存：

```text
模型私有思维过程
全量聊天
全部环境变量
凭证
无限 stdout/stderr
可由 Git 重建的源码副本
主机名明文
```

日志引用应使用仓库相对/状态相对路径；导出前再次脱敏。v0 不发送遥测。未来遥测必须 opt-in、单独 ADR、可检查字段、可删除历史。

---

## 23. 受控改进与可信自托管

### 23.1 失败经验的沉淀顺序

真实失败优先按以下顺序处理：

```text
0 删除或简化，使错误条件消失
1 用类型、Schema、接口或权限使错误不可表达
2 用测试、静态检查或 CI 使错误不能通过
3 改进项目命令、默认值和错误反馈
4 更新 CONTRIBUTING、ADR 或 Runbook
5 前四项都无法表达时，才更新宿主适配
```

自然语言微规则是最后手段，不是第一反应。

### 23.2 改进候选的成本判定

长期机制必须满足：

\[
\mathbb E[\text{避免的损失}]
>
\text{维护}+
\text{运行}+
\text{误报}+
\text{上下文成本}
\]

候选至少包含：

```text
来源事件
失败机制
影响范围
预期收益
新增运行时间
误报风险
所有者
回滚方法
复审条件
删除条件
依赖失效条件
```

### 23.3 生命周期

v0.2 才实现：

```text
proposed → trial → enforced → retired
```

- proposed：只是一份可审查提案；
- trial：只告警，不阻断；有时间、成本和并发配额；
- enforced：进入项目原生类型、测试、lint、CI 或权限系统；
- retired：删除低收益或已被更好机制替代的规则。

规则“毕业”的终点是离开 Forge 私有配置。CLI 不应成为永久规则收容所。

### 23.4 依赖失效图

规则可依赖：

```text
框架/依赖版本
某条 ADR 的状态
模块/路径是否存在
部署方式
宿主能力
某种已知失败机制
```

事实变化时下游规则立即 stale，而不是只靠固定 TTL。安全类规则不能时间到自动过期，需要 owner + review condition + explicit retirement。

### 23.5 试运行配额

过严的准入也会冻结系统。应限制同时 active 的 trial 数量，并确保每条到期必须晋升或退役。启动默认值可设 5 条，但属于待实测参数，不是架构常数。

### 23.6 普通自托管与可信自托管

v0 普通 dogfooding：

- Forge 仓库由自身设计规则约束；
- 当 `init` 实现后，对自身执行 `forge init --dry-run` 必须零 diff；
- 自身 Cargo build/test/verify 不依赖已安装 Forge；
- 公开 fixtures 与不变量测试可由候选修改，但所有变化必须在 PR 中可见。

v0.3 可信自托管：

```text
已知良好的 N−1 Forge
→ 验证候选公开协议与生成计划
→ 候选不可见/不可改的外部保留测试
→ 外部权威边界检查
→ 所有者批准
→ 签名、灰度、生产观察
→ 候选成为新的已知良好版本
```

N−1 不是充分条件。如果上一版读取的测试、配置和评分逻辑仍由候选修改，仍是循环信任。

### 23.7 Authority Set 必须物理外置

以下最终权威不能只放在候选仓库里的一个 TOML 或 shell 文件中：

```text
保留测试与评分器
release/signing workflow
发布身份与密钥
branch protection
最终 required-check 来源
灰度晋升与回滚权限
批准风险策略放宽的系统
```

可选物理实现：

- 组织级 required workflow；
- 独立 GitHub App；
- 另一受保护仓库；
- 不向候选暴露内容的 CI 环境；
- 已签名旧版本和独立签名策略。

候选仓库内可以有公开自检，但不能把它称为最终裁判。

### 23.8 N−1 兼容

`xtask diff-plans` 对公开 fixtures 比较：

```text
N−1 init plan / schemas / diagnostics
vs
candidate init plan / schemas / diagnostics
```

任何行为差异必须：

- 属于兼容新增；或
- 提升对应 Schema/marker 版本；或
- 在 CHANGELOG 和 PR trailer 中显式声明 `plan-change:` / `breaking:`；
- 经外部审查。

### 23.9 负发布

删除功能与新增功能走同一正式流程。CHANGELOG 保留 `Removed` 段。每个 minor 发布评审：

> 本次是否有命令、规则、模板或生成文件因价值被项目原生机制吸收而删除？若长期没有，是否正在制造不可退出的遗留层？

---

## 24. 测试、fixture 与兼容性

### 24.1 测试层次

| 层 | 内容 |
|---|---|
| 单元 | 状态机、风险、命令解析、证据充分性、错误映射 |
| 表驱动 | 每条状态/风险/失效规则 |
| 属性 | 幂等、确定性、块外保持、路径不逃逸、稳定排序 |
| 快照 | human/JSON、Schema、适配、init diff |
| 集成 | 真实 Git、文件系统、同步进程、状态锁 |
| E2E | 真实 Rust/Go fixture 和缺失工具环境 |
| Fuzz | porcelain v2、受管块、配置、路径编码 |
| Mutation | 核心状态机、风险、Receipt validity、策略自我削弱 |
| 兼容 | N−1 Schema、init plan、diagnostic/exit behavior |
| 外部保留 | v0.3；候选不可见、不可改 |

### 24.2 必需 fixture 矩阵

| Fixture | 覆盖 |
|---|---|
| `rust-package` | 单 package、默认 features |
| `rust-workspace` | 多 member、path dependency |
| `rust-multi-workspace` | 一个仓库多个独立 workspace |
| `rust-no-lock` | library 无 lockfile |
| `go-module` | 单 module |
| `go-workspace` | go.work 多 module |
| `go-multi-module` | 无 go.work 的独立 modules |
| `go-generated` | generated marker 与 fix 跳过 |
| `go-embed` | embed 资源映射 |
| `mixed-rust-go` | 多语言仓库 |
| `brownfield-make` | 已有目标不得覆盖 |
| `brownfield-just` | 已有 justfile |
| `brownfield-task` | 已有 Taskfile |
| `brownfield-adapters` | AGENTS/CLAUDE 已有人工正文 |
| `managed-block-conflict` | 块内人工修改默认 abort |
| `empty-repo` | 引导官方生成器 |
| `non-git` | 环境前置失败 |
| `dirty-worktree` | dry-run 可预览，apply 默认拒绝 |
| `linked-worktrees` | state/receipt 隔离 |
| `submodule` | Gitlink 边界 |
| `non-utf8-path` | Unix 原始路径字节 |
| `crlf` | 行尾保持 |
| `symlink-escape` | 写入逃逸被阻止 |
| `missing-tools` | unknown/env-unmet 区分 |
| `timeout-tree` | 子孙进程全部终止 |
| `huge-output` | 内存/终端上限 |
| `malicious-runner` | 不自动执行、目标名与 shell 注入防护 |
| `large-repository` | 10万文件性能和缓存 |

### 24.3 不变量测试

至少逐项对应 §3。高优先级：

1. `init --apply` 后从 PATH 移除 Forge，删除 Forge 生成的薄适配与私有状态，项目原生命令仍通过；
2. 第二次 init 零 diff；
3. 相同 ProjectModel 重渲染字节完全一致；
4. 受管块外正文逐字节相同；
5. read-only 命令前后 Git snapshot 相同；
6. symlink 无法写出仓库；
7. timeout/cancel 无孤儿进程；
8. worktree A 的 Receipt 不能满足 worktree B；
9. 任一 Receipt 依赖变化后自动 stale；
10. 候选放宽策略不能评价自身；
11. `--json` stdout 永远是单个合法文档；
12. 所有 AppError 有固定退出码和 Diagnostic；
13. 未知外部 CI 不得显示 pass；
14. Forge 自身主 CI 不需要先运行 Forge。

### 24.4 输出即接口的回归

- human 输出用 snapshot；
- JSON 通过 checked-in Schema 校验；
- `xtask check-schemas` 检测漂移；
- 退出码有穷举矩阵；
- Agent 可见错误文案改动必须在 review diff 中可见；
- Schema consumer 测试验证未知字段/枚举不会崩溃；
- 配置 consumer 测试验证未知字段必报错；
- managed block marker 的版本升级有 fixture。

### 24.5 不依赖真实工具的测试

测试 PATH 可注入 fake executables，按 argv 输出稳定结果，用于：

- missing/old tool；
- timeout；
- malformed JSON；
- huge output；
- exit/signal；
- 命令是否经 shell；
- 环境变量传递；
- GOWORK 隔离；
- 输出解析降级。

业务逻辑本身不 mock；fake 只替换 ports。

### 24.6 CI

Forge 仓库主验证：

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

矩阵：

- Ubuntu Rust 1.85（MSRV）；
- Ubuntu stable；
- macOS stable；
- Windows stable；
- 后续加入真实 Go fixture 所需的受支持 Go 版本；
- fuzz/mutation 可定时运行，v0 是否阻断按关键模块确定；
- adapters、自托管、authority boundary 是独立 job，不成为项目命令的反向依赖。

---

## 25. 非功能要求与平台支持

### 25.1 平台等级

| 平台 | 级别 | 要求 |
|---|---|---|
| Linux x86_64/aarch64 | 一级 | 完整 CI、进程组、路径、fixture |
| macOS x86_64/aarch64 | 一级 | 完整 CI、路径和进程组 |
| Windows x86_64 | 二级 | 构建、基本 E2E、Job Object、CRLF/UNC/大小写 |

二级不表示“以后再管”，而是首版不承诺所有第三方 runner/TTY 组合与 Unix 完全等价。平台差异必须显式诊断，不静默丢失。

### 25.2 性能目标

性能数字是启动目标，不是不变量：

| 操作 | 目标 |
|---|---:|
| `forge version` | < 50 ms |
| warm `forge next` | p95 < 200 ms（大 fixture） |
| warm `adapters check` | p95 < 300 ms |
| `doctor` 不跑项目命令 | p95 < 3 s |
| 首次 inventory | p95 < 5 s（10万文件 fixture） |
| 额外内存 | < 150 MiB |
| 单流内存输出 | 默认 ≤ 256 KiB |

优化顺序：正确性 → 输出稳定 → 减少 Git/文件调用 → 精确缓存 → 有界并发 → 微优化。不得为性能绕过 snapshot、preimage 或路径检查。

### 25.3 可用性

- `--help` 与设计命令面同步；
- 错误给出具体下一步；
- 输出可复制执行但同时展示真实项目命令；
- JSON 中不放本地化字符串作为唯一机器判据；
- human 文案可本地化，但诊断码/枚举稳定；
- 颜色不是语义；
- non-TTY 输出可预测；
- `NO_COLOR` 生效；
- Ctrl-C 及时且无孤儿进程。

### 25.4 可分发性

ADR-0029 已冻结首个 v0 候选的可分发边界：

- 首个候选固定为 `0.1.0-rc.1`，只通过 GitHub Release 分发；v0 RC 不发布到 crates.io，
  也不承诺 Homebrew、Scoop 或自动更新通道；
- 本地候选包含五个冻结目标的原始二进制和 CycloneDX SBOM，以及
  `release-manifest.json` 与 `SHA256SUMS`；Linux 一级目标使用 musl 静态链接；
- 仓库内 `xtask` 只组装和核验 `local-review-candidate`，不得签名、上传、发布或授权；
- 最终 SLSA provenance、签名、审批、不可变发布和撤回权限属于候选仓库之外的 Authority Set。

完整目标矩阵、资产名、构建隔离、失败残留和回滚规则见 ADR-0029 与 `docs/release.md`。

### 25.5 无遥测默认

v0 不上传任何使用数据。实现退出条件所需的使用计数若加入，只能 opt-in 写本地 XDG state，且必须另有 ADR；不得偷偷网络上报。

---

## 26. 实现里程碑与任务依赖图

日历估值不冻结；冻结的是顺序和每阶段完成定义。

### M0：协议与骨架

交付：

```text
Cargo workspace
ProductIdentity
核心 newtypes 与原生路径表示
SchemaVersion 和首批 wire types
Diagnostic / AppError / ExitCode
JSON 信封
version / schema / completions
依赖兼容性 spike 和 Cargo.lock
```

门槛：

- 所有 crate 联合编译；
- schema golden 建立；
- 无业务 `unwrap/expect/panic`；
- crate 依赖方向测试；
- CLI stdout/stderr 基础契约测试。

### M1：Runtime

交付：

```text
Git CLI typed port
porcelain v2 -z parser
native path representation
inventory and ignore handling
atomic file/state writer
state layout and locks
synchronous process runner
bounded output
Unix process group / Windows Job Object
clock and BLAKE3 hasher
```

门槛：

- Linux/macOS/Windows 集成测试；
- worktree 隔离；
- 无孤儿进程；
- symlink 逃逸被阻止；
- Git parser fuzz seed 全绿。

### M2：ProjectModel 与通用探测

交付：

```text
RepoFacts
AssetInventory
runner detection
CommandSpec/Intent resolution
config loader
ProjectModel
explain
```

门槛：

- 相同仓库得到稳定模型；
- 所有推导含 provenance/confidence；
- 不运行任意项目目标；
- zero-config fixture 不生成配置。

### M3：Rust 与 Go Provider

交付：

```text
cargo metadata
Cargo workspace grouping
Rust default commands and conservative impact
Go work/module detection
GOWORK isolation
gofmt/test/vet command plans
Go conservative impact and generated/embed handling
mixed repository model
```

门槛：

- 单模块/workspace/多 workspace/混合 fixtures；
- 不自动修改依赖；
- 不默认强加 `-D warnings`、all-features、race、fresh；
- unknown 时扩大范围。

### M4：渲染、受管块与 init

交付：

```text
ManagedBlock parser/render
conflict detection
ChangePlan
preimage/path validation
atomic apply report
AGENTS renderer
host adapter registry
init dry-run/apply
adapters sync/check
```

门槛：

- 幂等、确定性、块外保持；
- brownfield 不覆盖；
- dirty apply 默认拒绝；
- future marker 版本拒绝；
- 默认不生成 runner/CI/组织文档。

### M5：doctor 与 next

交付：

```text
doctor check registry
pass/fail/unknown/skipped
risk engine
policy self-weakening protection
next reducer
context path ranking
reason/provenance/unknown contract
```

门槛：

- 每个状态和 blocker fixture；
- unknown 不冒充 pass；
- next 只读；
- same input → same output；
- v0 无 AST/向量/模型依赖。

### M6：Receipt 与 Evidence

交付：

```text
scope digest
command/toolchain/environment/policy digest
evidence run/show/verify/export
Receipt validity and stale reasons
coverage_and_gaps
GC and log references
```

门槛：

- 每项依赖变化使 Receipt stale；
- local evidence 与 external authority 分离；
- worktree 不串扰；
- mutating command after-digest 语义正确；
- full logs/secret 不进入默认 Evidence。

### M7：Hardening 与 v0 发布

交付：

```text
fixture full matrix
fuzz/mutation for critical modules
cross-platform process/path hardening
schemas checked in
SBOM/checksum/signing
install documentation
security review
N-1 public compatibility harness skeleton
```

门槛：v0 验收清单全部通过。

### M8：v0.1+

按版本门控实现外部 CI attestation、upgrade、Language Pack、baseline、improve、自托管等，不提前把死实现放进 v0。

### 26.1 首批 Issue

1. 建立依赖兼容性 spike，并锁定 M0 `Cargo.lock`。
2. 实现 `ProductIdentity`、SchemaVersion、typed IDs。
3. 实现 WirePath/native path round-trip。
4. 实现统一 AppError、Diagnostic、ExitCode。
5. 用 clap 替换 bootstrap 参数解析，保持命令面不扩大。
6. 实现 `forge version --json`。
7. 实现 `forge schema` 和 `xtask schema-export/check-schemas`。
8. 实现 Git CLI 封装与 `rev-parse`。
9. 实现 porcelain v2 `-z` parser。
10. 实现 worktree/common-dir 状态布局与锁。
11. 实现原子 JSON/文件写入。
12. 实现 native path / symlink 防逃逸。
13. 实现同步 ProcessPort、超时和 kill tree。
14. 实现有界输出、日志引用和脱敏。
15. 实现 config v1 与 unknown-field rejection。
16. 实现 RepoFacts、AssetInventory、ProjectModel。
17. 实现 runner 发现和 CommandSource/Confidence。
18. 实现 Cargo metadata Rust Provider。
19. 实现 Go work/module Provider 与 GOWORK 隔离。
20. 实现 conservative impact selection。
21. 实现 managed block parser/renderer。
22. 实现 ChangePlan dry-run/apply。
23. 实现 AGENTS/CLAUDE adapter。
24. 实现 adapters sync/check 与 manifest。
25. 实现 doctor registry。
26. 实现 risk/policy 和 next reducer。
27. 实现 scope digest。
28. 实现 evidence run 与 Receipt。
29. 实现 evidence show/verify/export。
30. 实现 fixture builder 与 fake tools。
31. 实现卸载、幂等、确定性、read-only 不变量测试。
32. 实现 linked-worktree、非 UTF-8、symlink、timeout、huge-output E2E。
33. 实现 dogfooding 不动点测试。
34. 实现打包、SBOM、checksum、签名。

依赖顺序：

```text
1–7
→ 8–14
→ 15–17
→ 18–20
→ 21–24
→ 25–26
→ 27–29
→ 30–33
→ 34
```

---

## 27. v0 发布验收清单

### 27.1 功能

- [ ] 识别 Rust package、workspace、多个 workspace。
- [ ] 识别 Go module、go.work、多个独立 module。
- [ ] 识别 Rust + Go 混合仓库。
- [ ] `init` 默认 dry-run。
- [ ] `init --apply` 幂等、低侵入、不覆盖人工正文。
- [ ] 默认不生成 runner、CI、配置、ADR、Runbook、CODEOWNERS。
- [ ] `doctor` 给出可执行的 pass/fail/unknown/skipped 诊断。
- [ ] `next` 返回唯一主要动作、项目命令、理由、来源和未知项。
- [ ] `evidence run` 执行真实项目命令并生成 Receipt。
- [ ] `evidence verify` 按风险判断本地充分性。
- [ ] Evidence 强制包含未验证维度。
- [ ] adapters 可检查和重建。
- [ ] explain 输出足以解释生成结果。

### 27.2 正确性

- [ ] Git 路径输出使用 porcelain `-z`。
- [ ] 外部命令全部 argv 执行。
- [ ] 所有写入使用 preimage + 同目录原子替换。
- [ ] 所有集合稳定排序。
- [ ] JSON stdout 无污染。
- [ ] 退出码符合规范。
- [ ] Receipt validity 包含 scope、command、toolchain、environment、policy。
- [ ] 不确定影响分析扩大范围。
- [ ] local observation、external attestation、approval 严格区分。
- [ ] policy 变更不能自我放宽。

### 27.3 安全

- [ ] symlink 逃逸测试。
- [ ] 非 UTF-8/特殊文件名测试。
- [ ] secret/env 脱敏测试。
- [ ] 子进程树终止测试。
- [ ] huge output 测试。
- [ ] 恶意 README/manifest 不变成 shell 执行。
- [ ] dirty worktree 默认不 apply。
- [ ] 不自动安装工具或修改依赖。
- [ ] 不把生态离线参数描述为 OS 沙箱。
- [ ] authority boundary 最终实现位于候选控制范围之外。

### 27.4 可维护性

- [ ] 核心业务无 `unwrap/expect/panic`。
- [ ] crate 依赖方向通过。
- [ ] Schema 有 golden 和兼容测试。
- [ ] 每个命令有失败案例。
- [ ] ProductIdentity 集中。
- [ ] managed marker 集中。
- [ ] 输出文案快照可审查。
- [ ] fixtures 可独立生成/运行。
- [ ] 没有未使用的“未来平台”死实现。

### 27.5 可退出性

对所有 fixture：

```text
删除 AGENTS/CLAUDE 的 Forge 受管块
删除 forge.toml（若存在）
删除 <git-dir>/forge/
从 PATH 移除 forge
```

项目仍能用自己的 Cargo/Go/runner 命令完成 build/test/verify。此项不通过不得发布。

---

## 28. 明确否决的设计

| 被否决方案 | 原因 |
|---|---|
| 另一个编码 Agent 或多 Agent 框架 | 与宿主能力重叠，扩大信任和维护面 |
| 首版内置 LLM/MCP/后台服务 | 不是最小闭环所需，绑定模型和宿主 |
| 顶层 `forge check/fix/test/build` | 取代项目接口，造成反向依赖 |
| 默认生成 Makefile/justfile/Taskfile | 单语言项目已有稳定原生命令；无法统一团队偏好 |
| 默认生成 CI | 版本、runner、secrets 和权限无法从 clone 唯一推出 |
| 默认生成 CONTRIBUTING/ADR/Runbook/CODEOWNERS | 工具不能编造团队意图、历史和责任 |
| 每仓库默认生成 `forge.toml` | 无差异配置是维护税 |
| 入库 `.forge/` 私有目录 | 按产品归档而非职责归档，污染工作树 |
| 生成 CODEX.md | 发明新惯例；Codex 使用 AGENTS.md |
| 本地哈希叫不可伪造证明 | 本地用户仍能修改状态；只能提供可核对性 |
| `make -n` 叫绝对无副作用 | Make 展开阶段可执行 shell |
| 首版 AST/tree-sitter/LSP/向量检索 | 没有证明相对简单信号的边际收益，增加复杂度 |
| Tokio/async-trait | 短命同步 CLI 无必要；取消和测试更复杂 |
| libgit2/gix | 与用户 Git 行为可能偏差，增加依赖和平台成本 |
| Rust 默认 `-D warnings --all-features` | 把工具偏好强加给存量项目 |
| Go 默认 `-race -count=1` | 显著改变成本与语义 |
| 自动 `cargo update` / `go mod tidy` | 修改依赖属于项目决策 |
| 固定强制 TDD | 验收应约束结果，不普遍强制过程仪式 |
| 自建长期 undo/backup | 与 Git 重复，可能覆盖后续人工编辑 |
| 保存完整聊天/思维过程 | 噪声、隐私和审计成本高，非证据所需 |
| 候选仓库里的脚本充当最终权威 | 候选仍能修改裁判，违反 authority separation |
| 统一 TTL 决定 Evidence/规则有效性 | 有效性取决于依赖变化，不只取决于时间 |
| 固定未经实测的精确成功率和阈值 | 伪精确，应通过真实历史回放校准 |

---

## 29. 待实测校准但不阻塞编码的参数

以下不改变架构，可以采用启动默认值并通过真实回放调整：

| 参数 | 启动默认 | 校准方法 |
|---|---:|---|
| AGENTS 受管块上限 | 120 行 / 8 KiB | 观察删除率、上下文占用、漏指引与人工撤销 |
| 单流内存输出 | 256 KiB | huge-output 和真实工具分布 |
| 单日志文件 | 10 MiB | 排障需求与磁盘成本 |
| doctor 元数据默认子阶段上限 | 30–60 s | p95、总预算余量与超时原因 |
| check/test 默认子进程上限 | 5/15 min | 仓库实际耗时分布；不得重置命令总预算 |
| Receipt GC | 最近 200 条或 14 天取宽 | Evidence 引用、磁盘占用、排障需要 |
| context 预算 | 16 KiB 路径/摘要 | 任务完成率与默认上下文成本 |
| 变更规模风险阈值 | 暂不硬编码或保守值 | 历史 PR 与人工风险标注 |
| trial 并发配额 | 5 | 告警噪声、晋升/退役吞吐 |
| next 性能目标 | p95 < 200 ms | 10万文件 fixture 与真实大型仓库 |
| Windows 支持等级 | 二级 | process/TTY/runner 矩阵 |
| 声明式 Language Pack 覆盖 | 未承诺比例 | 第三、四门语言的真实实现成本 |

数值调整走正常评审；只有语义或兼容契约变化才需要 Schema/ADR 升级。

---

## 30. ADR 索引

ADR 全部位于 `docs/adr/`：

| ADR | 决策 |
|---|---|
| 0001 | CLI 命名为 Forge，身份常量集中 |
| 0002 | 使用 Rust 2024，MSRV 1.85 |
| 0003 | 项目原生命令是稳定接口 |
| 0004 | 采用六 crate 分层工作区 |
| 0005 | 运行状态放 Git 私有目录 |
| 0006 | 宿主适配使用受管块 |
| 0007 | 调用 Git porcelain v2，不嵌入 Git 实现 |
| 0008 | 使用同步执行，不引入 Tokio |
| 0009 | 版本化所有机器接口 |
| 0010 | 本地证据与外部授权分离 |
| 0011 | 自托管受外部 Authority Set 约束 |
| 0012 | v0 只支持 Rust 与 Go |
| 0013 | 延后 AST、语义索引与模型集成 |
| 0014 | 默认零配置和最小 init |
| 0015 | worktree 状态隔离，只共享内容寻址缓存 |
| 0016 | Evidence 按依赖变化失效 |
| 0017 | 默认不生成 runner、CI 和组织文档 |
| 0018 | 从 Git common-dir 派生本地仓库身份 |
| 0019 | v0 使用 HEAD 作为工作树比较基线 |
| 0020 | 版本化完整的本地 Evidence 契约 |
| 0021 | Evidence 状态使用不可变对象和有界保留 |
| 0022 | 不可变证据身份对 JSON 数字做无浮点精确规范化 |
| 0023 | JSON Schema 文档不套 Forge 结果信封 |
| 0024 | 进程边界失败写入类型化非证明 Receipt |
| 0025 | 每条命令使用一个操作级总预算 |
| 0026 | 声明 Provider 命名空间覆盖与缺口 |
| 0027 | 显式生成只创建不覆盖的 GitHub CI 工作流 |
| 0028 | 仓库写入固定目录句柄 |
| 0029 | 发布可审查、可回滚的 v0 候选版本 |
| 0030 | 分离 release manifest 的兼容读取与候选验收 |
| 0031 | Windows 使用原生同目录句柄重命名（已由 0033 取代） |
| 0032 | 记录不含输出内容的命令诊断摘要 |
| 0033 | Windows 重命名显式使用固定目标目录句柄（已由 0034 取代） |
| 0034 | Windows 拒绝目录交换提交时安全失败 |
| 0035 | Evidence GC 固定类目录并使用同目录隔离名 |
| 0036 | 未发布的旧 Evidence GC 目录残留安全失败并原样保留 |

实现变更必须引用相应 ADR；新 ADR 不删除旧记录，而是通过 Supersedes/Superseded by 建立历史。

---

## 31. 实现者从哪里开始

起始仓库已经完成以下冻结：

```text
二进制名 forge
Rust edition/MSRV
六 crate 边界和单向依赖
v0 命令名保留
Schema 命名空间和首批 ID
ProjectModel / CommandSpec / Ports 骨架
Git porcelain v2 参数常量
同步 runtime、Rust/Go Provider 和 managed-block 骨架
主 CI 直接运行 Cargo，不依赖 Forge
设计提案与 ADR
```

接下来严格按 M0：

1. 安装 Rust 工具链并运行当前 workspace 的 `cargo fmt/clippy/test`；
2. 修复任何 bootstrap 语法或 lint 问题，不扩大架构；
3. 做依赖联合编译 spike，锁定 `Cargo.lock`；
4. 先实现 Schema、AppError/Diagnostic/ExitCode、ProductIdentity；
5. 再实现 runtime ports 与不变量测试；
6. 在 M1 结束前，不开始 `init/next/evidence` 高层功能；
7. 每完成一个 milestone，先让对应不变量测试存在，再继续下一层。

第一条实际代码原则：

> **如果从 PATH 删除 `forge`，项目原生构建、测试、验证或发布就不能运行，说明依赖方向已经错了。**
