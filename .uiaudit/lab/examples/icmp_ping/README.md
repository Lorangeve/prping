# ICMP Ping 真实探测配方（基于 pktlang）

本目录是**对真实目标发 ICMP ping** 的实用配方集：每个步骤发送一个 ICMP Echo
Request 并等待真实应答（内核/远端主机回包，非 mock）。

> 「请求 + 模拟应答」的学习流程已移除——那正是 `../icmp_mock/` 的形态：
> server.pktl（链路层监听触发发包）+ client.pktl（发包 + wait 校验）双配方
> 模拟一次 ICMP echo 会话，回环可验证。要看 ICMP 协议结构/回包构造，去那里。

## 文件说明

- **icmp_ping_step.pkt** - ICMP Echo Request 步骤（id=rand16() 随机，seq 可注入）
- **icmp_ping_real_1.pktl** ～ **icmp_ping_real_10.pktl** - 1～10 次真实 ping 配方
- **generate_recipes.sh** - 生成不同次数的配方文件（键名已更新为 `packet:`）

## 使用方法

需要在 prping 项目根目录下运行命令，或使用完整路径。

```bash
# 查看配方结构
prping engine examples/icmp_ping/icmp_ping_real_4.pktl

# 发送 4 次 ICMP Echo Request（需要 root 权限；ICMP 无端口，--raw 用裸 HOST）
sudo prping packet examples/icmp_ping/icmp_ping_real_4.pktl --raw --wait 1 -p ip=127.0.0.1

# 注入目标地址
sudo prping packet examples/icmp_ping/icmp_ping_real_4.pktl --raw --wait 1 -p ip=8.8.8.8

# 发送 10 次 ICMP Echo Request
sudo prping packet examples/icmp_ping/icmp_ping_real_10.pktl --raw --wait 1 -p ip=127.0.0.1
```

## 权限说明

- **ICMP ping**：需要 root 权限或 `cap_net_raw`（raw socket）

## 学习要点

1. **ICMP 协议结构**：Type(1B) + Code(1B) + Checksum(2B) + ID(2B) + Seq(2B)
2. **Echo Request/Reply 匹配机制**：相同 id 和 seq（sniffer `id=id`/`seq=seq` 引用发包字段）
3. **ICMP 是网络层协议**：封装在 IPv4 中（proto=1）
4. **pktlang 配方**：使用多步配方实现多次发送，sniffer 匹配真实应答，extract 提取 id/seq
5. **参数注入**：使用 params 注入目标地址和序号

## 相关资源

- **../icmp_mock/**：ICMP echo 的 mock server/client 双配方（回环可验证，学习首选）
- **../network_icmp_bare/**：裸 IP 版 ICMP echo 流程（代理/Clash fake-ip 环境可用）
- **eng_lib/headers.pkt**：ICMP 协议头定义
- **docs/protocol-learning.md**：详细的协议学习指南
- **docs/claude-rules/engine.md**：pktlang 配方详细文档
