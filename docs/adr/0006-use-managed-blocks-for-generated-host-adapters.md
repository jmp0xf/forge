# ADR-0006：宿主适配使用受管块

- Status: Accepted
- Date: 2026-07-26
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

Forge 要生成 `AGENTS.md`、`CLAUDE.md` 等宿主入口。全文覆盖会删除人工内容；只在文件不存在时生成会导致长期漂移；把生成正文复制到多个宿主文件会产生多个真相源。需要一个可幂等更新、可检测人工修改、并保留块外正文的机制。

## Decision

- Forge 只拥有带版本和正文哈希的受管块。
- 幂等键是 `path + block id`。
- 块外内容逐字节保持。
- 声明 hash 与实际正文不一致时视为 `user-edited`，默认中止并打印 diff。
- `--force-block <id>` 只能覆盖显式块。
- 未知未来 marker Schema 拒绝写入；重复 block id 视为数据错误。
- AGENTS 是薄索引；CLAUDE 默认只导入 `@AGENTS.md`。

## Consequences

### Positive

- 可安全重生成和检查漂移。
- 人工正文与生成正文有明确边界。
- 无需复杂三方合并，同一 RenderContext 可投影多个宿主。

### Negative / trade-offs

- 用户不能直接编辑受管块并期待自动保留。
- marker 是公开接口，需要版本和兼容策略。
- 某些格式需要独立生成文件或最小投影。

### Implementation constraints

- parser 需要 fuzz 和属性测试。
- 第二次渲染必须 NoOp。
- 块外文本保持覆盖任意 Unicode 和换行。
- 生成物不得含时间戳、绝对路径或随机内容。

## Rejected alternatives

### 全文生成并覆盖

会删除人工内容，brownfield 风险不可接受。

### 自动三方合并块内人工修改

把生成物升级为混合真相源，结果不可再生；需求应进入权威资产。

### symlink 所有宿主到 AGENTS

Windows 权限和宿主兼容性差；导入或最小投影更稳健。

## Validation and revisit conditions

若宿主提供可靠原生引用，可负发布删除对应投影，但仍保留同源和漂移测试。
