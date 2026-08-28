# 协议学习用 Examples

本目录包含用于学习网络协议的 `.pktl` 配方文件，每个目录演示一个协议的完整流程。**每个 `.pktl` 和 `.pkt` 文件都包含详细的中文注释**，解释协议结构、字段含义和工作原理。

## 目录结构

### 1. `icmp_ping/` - ICMP Ping 协议
- **icmp_ping.pktl** - ICMP Echo Request/Reply 流程（学习用）
- **icmp_request.pkt** - ICMP Echo Request（ping 请求）
- **icmp_reply.pkt** - ICMP Echo Reply（ping 应答）
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
- **generate_recipes.sh** - 生成不同次数的配方文件
- **学习要点**：ICMP 协议结构、Type/Code 字段、Echo Request/Reply 匹配机制、pktlang 多步配方

### 2. `http_flow/` - HTTP 协议
- **http_flow.pktl** - HTTP 请求/响应流程
- **http_request.pkt** - HTTP GET 请求
- **http_response.pkt** - HTTP 200 OK 响应
- **学习要点**：HTTP 协议结构、请求/响应格式、常见方法和状态码

### 3. `dhcp_flow/` - DHCP 协议
- **dhcp_flow.pktl** - DHCP 四步流程（DORA）
- **dhcp_discover.pkt** - DHCP Discover（客户端广播发现）
- **dhcp_offer.pkt** - DHCP Offer（服务端提供 IP）
- **dhcp_request.pkt** - DHCP Request（客户端确认请求）
- **dhcp_ack.pkt** - DHCP Ack（服务端确认分配）
- **学习要点**：DHCP 协议结构、四步流程、地址分配机制

### 4. `dns_flow/` - DNS 协议
- **dns_flow.pktl** - DNS 查询/响应流程
- **dns_query.pkt** - DNS 查询请求
- **dns_response.pkt** - DNS 查询响应
- **学习要点**：DNS 协议结构、域名解析机制、记录类型

### 5. `tcp_data_flow/` - TCP 数据传输
- **tcp_data_flow.pktl** - TCP 数据传输流程
- **tcp_data.pkt** - TCP 数据发送（PSH|ACK）
- **tcp_ack.pkt** - TCP 数据确认（ACK）
- **学习要点**：TCP 数据传输机制、序列号/确认号、滑动窗口

## 使用方法

### 查看协议结构
```bash
# 查看 ICMP Ping 协议结构
prping engine icmp_ping

# 查看 HTTP 流程协议结构
prping engine http_flow

# 查看 DHCP 流程协议结构
prping engine dhcp_flow

# 查看 DNS 流程协议结构
prping engine dns_flow

# 查看 TCP 数据传输协议结构
prping engine tcp_data_flow
```

### 查看单个协议包结构
```bash
# 查看 ICMP Request 包结构
prping engine examples/icmp_ping/icmp_request.pkt

# 查看 HTTP Request 包结构
prping engine examples/http_flow/http_request.pkt

# 查看 DNS Query 包结构
prping engine examples/dns_flow/dns_query.pkt
```

### 发送协议包
```bash
# 发送 ICMP Ping（需要 root 权限；ICMP 无端口，--raw 用裸 HOST）
sudo prping packet icmp_ping 127.0.0.1 --raw --wait 1

# 发送 4 次 ICMP Echo Request（使用 pktlang 配方）
sudo prping packet examples/icmp_ping/icmp_ping_real_4.pktl --raw --wait 1 -p ip=127.0.0.1

# 发送 HTTP 请求（需要 HTTP 服务监听）
prping packet http_flow 127.0.0.1:80 --wait 1

# 发送 DHCP 流程（需要 root 权限；UDP 广播无目标端口）
sudo prping packet dhcp_flow --raw --wait 2

# 发送 DNS 查询（需要 DNS 服务监听）
prping packet dns_flow 127.0.0.1:53 --wait 1

# 发送 TCP 数据传输（需要 TCP 服务监听）
prping packet tcp_data_flow 127.0.0.1:80 --wait 1

# 发送 ARP 请求（需要 root 权限；链路层帧，--raw 用裸 IP）
sudo prping packet link_arp 127.0.0.1 --raw --wait 1
```

### 参数注入
```bash
# 注入目标 IP（ICMP 无端口，--raw 用裸 HOST）
sudo prping packet icmp_ping 127.0.0.1 --raw -p ip=192.168.1.1

# 注入目标 IP 和端口
prping packet http_flow 127.0.0.1:80 -p ip=192.168.1.1,port=8080

# 注入 MAC 地址（ARP 链路层帧）
sudo prping packet icmp_ping 127.0.0.1 --raw -p mac=00:11:22:33:44:55
```

## 协议学习建议

1. **从简单开始**：先学习 ICMP Ping，了解网络协议的基本结构
2. **理解分层**：学习 HTTP、DNS 等应用层协议，理解协议栈的分层设计
3. **掌握状态机**：学习 TCP 数据传输，理解序列号和确认号机制
4. **实践验证**：使用 `prping engine` 查看协议结构，使用 `prping packet` 发送协议包

## 相关资源

- **eng_lib/headers.pkt** - OSI 模型各层协议头定义（包含详细学习注释）
- **eng_lib/quic.pkt** - QUIC 协议实现
- **eng_lib/tls.pkt** - TLS/SSL 安全传输层协议
- **docs/protocol-learning.md** - 详细的协议学习指南
- **PROTOCOL_SUPPORT.md** - 完整的协议支持清单
