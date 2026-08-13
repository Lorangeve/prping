# prping

跨平台 psping 复刻，使用 Rust 实现。支持 ICMP ping、TCP ping、UDP ping、延迟测试和带宽测试。

## 特性

- **四种 ping 模式**：ICMP / TCP / UDP，自动识别（有端口=TCP，`-u`=UDP，无端口=ICMP）
- **延迟测试**：client/server 架构，TCP/UDP 双模式，`-r` 接收模式测反向
- **带宽测试**：多连接并发（`-P`），直方图，`-r` 测下载方向
- **IPv4/IPv6 双栈**：`[::1]:80` 括号格式自动识别
- **统计输出**：min/max/avg/stddev + P50/P95/P99 + 丢包率
- **可视化**：直方图（`-H`）、延迟时间线、Unicode 渲染（`-p`）
- **i18n**：英文/中文自动检测（`--lang` 切换）
- **彩色输出**：语义化配色（IP 青、端口品红、延迟黄、错误红）

## 安装

```bash
cargo build --release
sudo setcap cap_net_raw+ep target/release/prping  # ICMP 需要（Linux）
```

## 用法

```
prping HOST                    # ICMP ping（无限，Ctrl+C 停止）
prping HOST:PORT               # TCP ping
prping -u HOST:PORT            # UDP ping
prping -l SIZE HOST:PORT       # 延迟测试（触发条件：-l + 端口）
prping -b -l SIZE HOST:PORT    # 带宽测试
prping -s ADDR:PORT            # 服务端（同时支持延迟/带宽/接收模式）
```

### 常用选项

| 选项 | 说明 |
|------|------|
| `-n N` / `-n 10s` | 次数（默认无限）或时长 |
| `-i S` | 间隔秒数（0=快速） |
| `-l SIZE` | 请求大小，`k`/`m` 后缀 |
| `-H N` | 直方图桶数 |
| `-w N` | 预热次数（默认 4） |
| `-q` | 静默模式 |
| `-r` | 接收模式（测下载） |
| `-u` | UDP 模式 |
| `-P N` | 并发连接数 |
| `-p` | Unicode 渲染 |
| `-4` / `-6` | 强制 IPv4/IPv6 |
| `--lang en\|zh-CN` | 语言 |
| `--help-icmp` 等 | 各模式详细帮助 |

## 示例

```bash
# TCP ping，30 次，0.1s 间隔，直方图 + Unicode 渲染
prping -n 30 -i 0.1 -H 10 -p 192.168.1.1:80

# 延迟测试（客户端发送 64B）
prping -l 64 -n 100 server:8080

# 接收模式延迟测试（客户端接收，测下载方向）
prping -l 64 -n 100 -r server:8080

# 带宽测试，8KB 包，4 并发
prping -b -l 8k -n 10000 -P 4 server:8080

# 服务端
prping -s 0.0.0.0:8080
```

## 输出示例

```
TCP 连接到 127.0.0.1:22:
7 次迭代 (预热 4) ping 测试:
连接到 127.0.0.1:22 (预热): 从 127.0.0.1:55940: 0.32ms
连接到 127.0.0.1:22: 从 127.0.0.1:55944: 0.17ms

  发送 = 3，接收 = 3，丢失 = 0 (0% 丢失),
  最小 = 0.12ms，最大 = 0.17ms，平均 = 0.15ms，标准差 = 0.02ms
  P50 = 0.15ms, P95 = 0.17ms, P99 = 0.17ms

延迟分布:
     0.12 -    0.15 ms ████████████████████ (2)
     0.15 -    0.17 ms ██████ (1)

Latency timeline (Y: 0.12~0.17ms, X: 0~2.0s):
     0.2 │
        │ #
     0.1 │  #
        └───
       0s2.0s
```

## 与 psping 对比

| 功能 | psping | prping | 说明 |
|------|--------|--------|------|
| ICMP ping | ✓ | ✓ | raw socket，需 root/cap_net_raw |
| TCP ping | ✓ | ✓ | |
| UDP ping | ✓ | ✓ | psping 无独立 UDP ping，prping 有 |
| 延迟测试 | ✓ | ✓ | TCP/UDP |
| 带宽测试 | ✓ | ✓ | TCP/UDP |
| 接收模式 `-r` | ✓ | ✓ | 0xFF 触发协议 |
| 直方图 | `-h` | `-H` | psping 支持自定义阈值，prping 仅桶数 |
| 0.01ms 精度 | ✓ | ✓ | |
| IPv4/IPv6 | ✓ | ✓ | |
| `-n 10s` 时长模式 | ✓ | 部分 | 解析了但未实现 |
| Ctrl+C 优雅退出 | ✓ | ✗ | 打印中间统计待实现 |
| `-t` 持续 ping | ✓ | 默认 | prping 默认即无限 |
| 默认次数 | 4 | 无限 | |
| 预热默认 | ICMP/TCP=1, 延迟=5, 带宽=2×CPU | 全部=4 | |
| 并发 IO `-i`（带宽） | ✓ | `-P` | 参数名不同 |
| 防火墙 `-f` | ✓ | — | Windows only，跨平台不需要 |
| i18n | ✗ | ✓ | 中英文自动切换 |
| 时间线图 | ✗ | ✓ | prping 独有 |
| P50/P95/P99 | ✗ | ✓ | prping 独有 |
| 跨平台 | Windows | Linux/macOS/Windows | |
| 二进制体积 | ~500KB | ~1.4MB | |

## 技术栈

- [smol](https://github.com/smol-rs/smol) — 轻量异步运行时
- [bpaf](https://github.com/pacak/bpaf) — CLI 解析
- [rust-i18n](https://github.com/longfangsong/rust-i18n) — 国际化
- [termcolor](https://github.com/BurntSushi/termcolor) — 跨平台终端颜色
- [socket2](https://github.com/rust-lang/socket2) — raw socket

## 开发

```bash
cargo test        # 24 tests
cargo clippy      # 零警告
```

## License

MIT
