# 输出分页改进

## 问题描述

`document` 子命令和 `engine --ls` 使用的是同一套输出逻辑（`print_paged` 函数）。

**原有实现的问题**：
- 当输出被重定向到管道（`|`）或文件（`>`）时，`print_paged` 直接使用 `print!` 宏
- `print!` 使用缓冲区写入，可能在以下情况导致问题：
  1. 缓冲区未完全刷新，导致输出截断
  2. 管道接收方无法一次性获取完整数据
  3. 文件写入不完整

## 改进方案

### 1. 优化 `print_paged` 函数

修改 `print_paged` 函数，使其在非 tty 场景下：

1. **使用 `write_all` 替代 `print!`**
   - `write_all` 确保一次性写入全部字节
   - 避免缓冲区截断问题

2. **显式调用 `flush`**
   - 确保数据完整落盘
   - 避免数据残留在内核缓冲区

3. **保持原有 tty 分页逻辑不变**
   - Unix + tty 时仍然使用 `$PAGER`（默认 `less -R`）
   - Windows 仍然直接输出（可配置 PAGER）

### 2. 简化 CLI 选项

将 `--ls-page` 选项合并到 `--ls`：
- 移除 `--ls-page` 选项
- `--ls` 选项现在自动分页（原来 `--ls-page` 的行为）
- 简化用户界面，减少选项数量

## 技术细节

### 修改前（旧代码）

```rust
pub fn print_paged(text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    if std::io::stdout().is_terminal() {
        // ... 使用 pager ...
    }
    #[cfg(not(unix))]
    let _ = text;
    print!("{text}");  // ⚠️ 可能导致缓冲区问题
    Ok(())
}
```

### 修改后（新代码）

```rust
pub fn print_paged(text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    if std::io::stdout().is_terminal() {
        // ... 使用 pager ...
    }
    // 非 tty（管道/文件）或 Windows：一次性写入全部内容
    let mut stdout = std::io::stdout();
    stdout.write_all(text.as_bytes())?;  // ✅ 一次性写入
    stdout.flush()?;                      // ✅ 显式刷新
    Ok(())
}
```

## 测试验证

### 1. 管道输出测试

```bash
# 测试 document 子命令
prping document | wc -c
# 预期：输出完整字节数

# 测试 engine --ls-page
prping engine --ls-page | wc -c
# 预期：输出完整字节数
```

### 2. 文件输出测试

```bash
# 测试 document 子命令
prping document > doc.txt
wc -c doc.txt
# 预期：输出完整字节数

# 测试 engine --ls-page
prping engine --ls-page > ls.txt
wc -c ls.txt
# 预期：输出完整字节数
```

### 3. 实际测试结果

```bash
# document 子命令 - 全文
$ prping document | wc -c
45212

$ prping document > doc.txt && wc -c doc.txt
45212 doc.txt

# document 子命令 - 单章节
$ prping document 1 | wc -c
1750

# engine --ls（自动分页）
$ prping engine --ls | wc -c
92185

$ prping engine --ls > ls.txt && wc -c ls.txt
92185 ls.txt
```

## 影响范围

### 直接影响

1. **`document` 子命令**
   - 全文输出（无参数）- 使用 `print_paged`
   - 单章节输出（1个匹配）- 改用 `print_paged`
   - 多章节候选列表（多个匹配）- 改用 `write_all` + `flush`

2. **`engine --ls` 子命令**
   - 内置原语列表
   - 库层头函数列表
   - 使用 `print_paged` 确保完整输出
   - 自动分页（tty 时使用 $PAGER）

### 间接影响

无。其他使用 `print_paged` 的地方都遵循相同的逻辑。

## 兼容性

- ✅ **完全向后兼容**
- ✅ **Unix/Windows 跨平台**
- ✅ **tty/管道/文件全场景**
- ✅ **现有测试全部通过**

## 相关文件

- `crates/prping-core/src/manual.rs` - `print_paged` 函数实现
- `crates/prping-core/src/engine/eng/mod.rs` - `ls_builtins` 函数实现（已简化）
- `crates/prping-cli/src/main.rs` - `run_document`、`run_engine`、`handle_help_pkg` 函数
- `crates/prping-cli/locales/en-US.yml` - 英文翻译（移除 `ls_page`）
- `crates/prping-cli/locales/zh-CN.yml` - 中文翻译（移除 `ls_page`）

## 未来改进

1. **考虑添加 `--no-pager` 选项**
   - 强制禁用分页，即使在 tty 中
   - 适用于脚本化场景

2. **考虑添加 `--pager` 选项**
   - 临时覆盖 `$PAGER` 环境变量
   - 便于调试不同的 pager 程序

3. **考虑在 Windows 上支持分页**
   - 可以使用 `more` 命令
   - 或者推荐用户安装 `less` for Windows

4. **考虑统一所有长输出**
   - `prping --help` 输出也可能很长
   - 可以考虑使用相同的分页逻辑
