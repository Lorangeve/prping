# Contributing

欢迎贡献。本项目为个人工具，但流程从第一天就保持简单明确。

## 开发环境

- Rust edition 2024（stable toolchain）
- 版本控制：本仓库用 [jujutsu](https://github.com/jj-vcs/jj)（jj），git 后端

## 提交前必须通过

```bash
cargo fmt --check     # 格式
cargo clippy --all-targets -- -D warnings   # 零警告
cargo test --all-targets                     # 单元 34 + 协议 9 + CLI 5 + doc
```

可选（改动涉及 Windows 路径时）：
```bash
cargo check --target x86_64-pc-windows-msvc  # 需可写 CARGO_HOME 下载 Windows 依赖
```

## 测试结构

| 位置 | 内容 |
|------|------|
| `src/*.rs` 内 `#[cfg(test)]` | 纯函数单元测试（协议解析、统计、Run 循环） |
| `tests/protocol.rs` | 进程内协议测试：直接调 lib 的 `serve`/`run`，`set_interrupted` 注入优雅退出 |
| `tests/integration.rs` | 子进程 CLI 行为测试：退出码、`--json`、`--version`、参数错误 |

## 代码约定

- 用户可见输出走 i18n（`locales/*.yml`），注释用中文
- 颜色统一走 `output.rs`（termcolor），服务端与客户端一致
- 共享逻辑（DNS/运行循环/UDP socket/测试参数）收敛在 `util.rs`，不重复实现
- 不引入不必要的抽象
- 改动按逻辑主题分批提交（`jj split` 可用），迁移类改动不夹带行为变更

## 架构速览

```
prping crate
├── src/lib.rs       pub: run / serve / PingConfig / Stats / 报告 / PrpingError / PrpingWarning
├── src/main.rs      bpaf 解析 → run()/serve() → t! 渲染 → 退出码；信号安装
└── src/{util,stats,output,icmp,tcp,udp,latency,bandwidth}.rs   lib 内部实现
```

协议细节（TCP 0xFF 触发、UDP 触发包、回显语义）见 `src/lib.rs` 的 rustdoc。

## 提交

```bash
jj commit            # 提交工作副本
jj split -m "msg" <paths>   # 按文件拆分
jj git push          # 推送到远端 git
```
