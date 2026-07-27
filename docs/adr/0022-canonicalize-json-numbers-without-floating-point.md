# ADR-0022：不可变证据身份对 JSON 数字做无浮点精确规范化

- Status: Accepted
- Date: 2026-07-27
- Deciders: Forge maintainers
- Supersedes: None
- Superseded by: None

## Context

ADR-0009 要求同 major 的 JSON consumer 忽略未知可选字段，ADR-0021 又要求 Receipt/Evidence 身份
覆盖这些未知字段。`serde_json::Value` 只能无损表示 `i64`/`u64` 范围内的整数；小数、指数形式和更
大的整数会经过有限精度浮点数，或者被拒绝。前者可能让两个不同值得到同一身份，后者则把合法的
同-major 扩展错误地当成损坏状态。

身份解析还必须有明确资源上限。特别是 `1e999999999999` 这样的短输入，不能按指数值展开并分配
内存。

## Decision

Receipt/Evidence identity 使用本地、有界、无浮点的 RFC 8259 JSON parser。它与 typed wire
projection 分离：

- Receipt 最大 4 MiB，Evidence 最大 8 MiB，JSON 容器嵌套最多 256 层；
- object key 先解码为 Unicode 字符串，再按 UTF-8 字节排序；转义形式不同但解码结果相同的重复
  key 拒绝；
- array 保留顺序，string 使用 `serde_json` 的最小合法 UTF-8 编码；
- identity 只删除根对象中的 `data.id`，其他同名字段仍参与 identity；
- number 解析为符号、去除首尾零后的十进制 coefficient 和任意长度十进制 exponent，不经过
  `f32`/`f64`；零统一为 `0`，包括 `-0`；
- exponent 只做与输入长度成比例的十进制加减。最多 20 位的非负整数形式输出为普通十进制，以
  保持既有 `i64`/`u64` 文档身份稳定；其他值输出为唯一的 `coefficient e exponent` 形式，不按
  exponent 数值展开；
- 因此 `1`、`1.0`、`1e0` identity 相同，`-0` 与 `0` 相同，任意大的相邻整数保持不同。

typed reader 从精确 AST 取得单独的语义投影。能精确落入 `i64`/`u64` 的整数仍投影为 JSON
number；其他 number 分别以 `0` 和 `1` 做两次 typed projection，并要求两个 typed 结果完全一致。
未知字段会在两次 projection 中被同样忽略；任何已知数值字段会产生不同结果或反序列化失败，因而
fail closed。原始字节和精确 identity AST 不丢失。这类同-major 未知对象继续标记为
non-proving，GC 使用 `RetainAll`，future major 继续 fail closed。

同一轮 v2 兼容性校准也冻结以下可选字段语义：

- Receipt 的 `resolution_confidence` 和 `coverage_confidence` 必须同时存在，且均为 `medium` 或
  `high`，才可支持当前 Evidence；缺失、`low` 或 `unknown` 的旧 v2 Receipt 可读但 non-proving，
  两个 confidence 同时进入 command-set dependency；
- observation 的 `stdout_truncated` 和 `stderr_truncated` 必须同时存在，且兼容字段
  `output_truncated` 必须等于二者的逻辑或，才可支持当前 Evidence；缺失两者的旧 v2 Receipt 可读
  但 non-proving，字段自相矛盾则视为 malformed；
- stdout 为空且 stdout 自身被截断时，不能从保留片段证明 `stdout-empty`。只有 stderr 被截断不
  改写 stdout predicate，但仍通过独立的 stderr flag 留下完整边界事实。

这些都是同-major 新增可选字段：旧文档不因缺失而变成损坏状态，新 writer 则不能省略它们或从
旧的合并 truncation flag 猜测证明力。

Receipt 和 Evidence canonical serialization component 分别升为
`forge.receipt-canonical-json/v3`、`forge.evidence-canonical-json/v3`，完整 behavior composition
升为 `forge.evidence-behavior/v3`。identity domain 保持 v1；普通既有整数的 canonical bytes 不变，
而 behavior dependency 会使新写 Receipt 与旧行为自然区分。

## Consequences

### Positive

- 合法同-major 数字扩展可以读取、保留和清理，不再因宿主浮点精度产生 identity collision。
- 已知数值字段的范围和类型错误仍然失败，不会因兼容投影被改写成另一个有效值。
- 时间、空间和递归上限明确，巨大 exponent 不造成指数级或按 exponent 数值分配。

### Negative / trade-offs

- identity parser 与 typed serde reader 是两条边界，需要固定向量和交叉测试共同维护。
- 非整数未知字段在 `original_json` 主语义投影中显示为 `0`；审计与再导出必须使用保留的原始字节，
  不能把该投影视为无损来源。
- canonical number 实现需要维护少量十进制字符串算术。

### Implementation constraints

- 不启用 `serde_json` 私有 arbitrary-precision marker，也不引入 big-number dependency。
- 测试必须覆盖等价小数/指数/负零、任意大相邻整数、escaped/literal 重复 key、嵌套与字节上限、
  malformed number，以及 unknown same-major 的原字节保留和 non-proving/`RetainAll`。
- canonical serialization 发生任何不兼容变化时，必须再次升级 component 和完整 behavior 版本。

## Rejected alternatives

### 使用 `f64`

大整数和高精度小数会舍入，无法作为内容身份的等价关系。

### 只接受 `i64`/`u64`

虽然不会碰撞，却违反同-major 可新增未知可选字段的兼容承诺。

### 按 exponent 展开普通十进制

短输入可要求近乎无限输出，是不必要的资源放大。

### 引入任意精度数字依赖

当前只需要规范化和比较，不需要通用算术；小型有界十进制实现更容易审计，也不会扩大依赖面。

## Validation and revisit conditions

固定 identity/behavior 向量、数值等价与区分、深度/大小边界、重复 decoded key、malformed token 和
same-major round-trip 测试必须通过。若未来 wire contract 增加非整数的已知数值字段，应先增加
精确 typed conversion，而不是通过浮点投影绕过该边界。
