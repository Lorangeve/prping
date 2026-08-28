# ICMP Ping 配方（基于 pktlang）

本目录包含 ICMP Ping 的配方，使用 pktlang 配方实现真正的 ping 功能。

## 文件说明

### 学习用配方（原始）
- **icmp_ping.pktl** - ICMP Echo Request/Reply 流程（学习用，发送请求和模拟应答）
- **icmp_request.pkt** - ICMP Echo Request 包结构
- **icmp_reply.pkt** - ICMP Echo Reply 包结构（模拟应答）

### 真实 Ping 配方（基于 pktlang）
- **icmp_ping_step.pkt** - ICMP Echo Request 步骤（用于多步配方）
- **icmp_ping_real_1.pktl** - 1 次 ICMP Echo Request 配方
- **icmp_ping_real_2.pktl** - 2 次 ICMP Echo Request 配方
- **icmp_ping_real_3.pktl** - 3 次 ICMP Echo Request 配方
- **icmp_ping_real_4.pktl** - 4 次 ICMP Echo Request 配方
- **icmp_ping_real_5.pktl** - 5 次 ICMP Echo Request 配方
- **icmp_ping_real_6.pktl** - 6 次 ICMP Echo Request 配方
- **icmp_ping_real_7.pktl** - 7 次 ICMP Echo Request 配方
- **icmp_ping_real_8.pktl** - 8 次 ICMP Echo Request 配方
- **icmp_ping_real_9.pktl** - 9 次 ICMP Echo Request 配方
- **icmp_ping_real_10.pktl** - 10 次 ICMP Echo Request 配方

### 工具脚本
- **generate_recipes.sh** - 生成不同次数的配方文件

## 使用方法

### 使用 pktlang 配方（推荐）

pktlang 配方实现了真正的 ping 功能，每个步骤发送一个 ICMP Echo Request 并等待真实应答。

**注意：** 需要在 prping 项目根目录下运行命令，或者使用完整路径。

```bash
# 查看配方结构
./target/release/prping engine examples/icmp_ping/icmp_ping_real_4.pktl

# 发送 4 次 ICMP Echo Request（需要 root 权限）
sudo ./target/release/prping packet examples/icmp_ping/icmp_ping_real_4.pktl --raw --wait 1 -p ip=127.0.0.1

# 注入目标地址
sudo ./target/release/prping packet examples/icmp_ping/icmp_ping_real_4.pktl --raw --wait 1 -p ip=8.8.8.8

# 发送 10 次 ICMP Echo Request
sudo ./target/release/prping packet examples/icmp_ping/icmp_ping_real_10.pktl --raw --wait 1 -p ip=127.0.0.1
```

## 权限说明

- **ICMP ping**：需要 root 权限或 `cap_net_raw`（raw socket）

## 学习要点

1. **ICMP 协议结构**：Type(1B) + Code(1B) + Checksum(2B) + ID(2B) + Seq(2B)
2. **Echo Request/Reply 匹配机制**：相同 id 和 seq
3. **ICMP 是网络层协议**：封装在 IPv4 中（proto=1）
4. **pktlang 配方**：使用多步配方实现多次发送，sniffer 匹配真实应答
5. **参数注入**：使用 params 注入目标地址和序号
6. **extract 机制**：从应答中提取值，用于后续步骤

## 相关资源

- **prping ping 命令**：完整的 ICMP/TCP/UDP ping 功能
- **examples/network_icmp_bare/**：裸 IP 版 ICMP echo 流程（代理/Clash fake-ip 环境可用）
- **eng_lib/headers.pkt**：ICMP 协议头定义
- **docs/protocol-learning.md**：详细的协议学习指南
- **docs/claude-rules/engine.md**：pktlang 配方详细文档