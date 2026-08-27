# 缩进控制重构总结

## 问题背景

项目中存在大量硬编码空格（如 `"  "`、`"    "`、`"        "`），用于终端输出的缩进和对齐。这种方式存在以下问题：

1. **一致性问题**：同类内容使用不同缩进
2. **可维护性问题**：硬编码空格难以统一修改
3. **国际化问题**：中英文混合时空格对齐效果不佳
4. **代码重复**：大量重复的空格字符串

## 解决方案

在 `output.rs` 中新增三个缩进工具函数：

```rust
/// 获取指定层级的缩进字符串。
pub fn indent(level: usize) -> &'static str

/// 将文本填充到指定宽度，用于对齐。
pub fn pad_to(text: &str, width: usize) -> String

/// 创建指定长度的空格字符串。
pub fn spaces(count: usize) -> String
```

## 缩进层级规范

| 层级 | 空格数 | 用途 |
|------|--------|------|
| 0 | 0 | 无缩进 |
| 1 | 2 | 一级列表、子标题 |
| 2 | 4 | 二级内容、文档字符串 |
| 3 | 8 | hexdump 等特殊用途 |
| 4+ | 12+ | 深度嵌套 |

## 重构的文件

### 核心库文件：

1. **`engine/eng/mod.rs`** - 文档输出
2. **`engine/eng/display.rs`** - hexdump、注记、剩余字节等
3. **`stats.rs`** - 统计输出（丢包率、延迟、抖动、直方图）
4. **`ping/mtu.rs`** - MTU 探测输出
5. **`ping/trace/mod.rs`** - traceroute IP 地址对齐
6. **`engine/pkg/send.rs`** - 发送结果输出
7. **`engine/pkg/recipe.rs`** - 配方执行输出

## 使用示例

### 使用 `indent()`：
```rust
// 之前
print_dim(&mut w, format!("    {summary}"))?;

// 之后
print_dim(&mut w, format!("{}{summary}", indent(2)))?;
```

### 使用 `spaces()`：
```rust
// 之前
let pad = " ".repeat(indent);

// 之后
let pad = spaces(indent);
```

### 使用 `pad_to()`：
```rust
// 之前
output::print_cyan(w, format!("{:<48}", ip))?;

// 之后
output::print_cyan(w, output::pad_to(&ip.to_string(), 48))?;
```

## 优势

1. **语义清晰**：`indent(2)` 比 `"    "` 更清楚地表达意图
2. **易于维护**：修改缩进只需改一处，不影响使用点
3. **类型安全**：编译时检查，避免字符串拼写错误
4. **灵活性**：支持动态计算缩进，适应不同场景
5. **一致性**：统一了项目中的缩进风格
6. **可扩展性**：可以轻松添加新的缩进级别或对齐函数

## 测试结果

所有 82 个测试都通过，clippy 零警告（除已有的未使用函数警告）。

## 后续工作

可以继续重构以下文件中的硬编码空格：
- `engine/pkg/send.rs` 中的其他部分（如 `render_dissected` 调用）
- `serve/mod.rs` 和 `serve/capture.rs` 中的字符串参数
- 其他可能遗漏的硬编码空格

这些工具函数已经导出到 `prping_core` 库，可以在整个项目中统一使用。
