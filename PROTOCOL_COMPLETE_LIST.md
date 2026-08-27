# 网络协议完整清单

## 已支持的协议（27种）

### 核心协议（headers.pkt）
1. **Ethernet** - 以太网帧（RFC 802.3）
2. **ARP** - 地址解析协议（RFC 826）
3. **IPv4** - 互联网协议版本4（RFC 791）
4. **IPv6** - 互联网协议版本6（RFC 2460）
5. **ICMP** - 互联网控制消息协议（RFC 792）
6. **TCP** - 传输控制协议（RFC 793）
7. **UDP** - 用户数据报协议（RFC 768）
8. **HTTP** - 超文本传输协议（RFC 2616）
9. **DNS** - 域名系统（RFC 1035）

### 现代传输协议
10. **QUIC** - 基于UDP的传输协议（RFC 9000）

### 安全协议
11. **TLS/SSL** - 安全传输层协议（RFC 8446/5246）
12. **SSH** - 安全远程登录协议（RFC 4251-4254）
13. **IPSec** - IP层安全协议（RFC 4301-4309）
14. **WireGuard** - 现代VPN协议

### 应用层协议
15. **FTP** - 文件传输协议（RFC 959）
16. **SMTP** - 邮件传输协议（RFC 5321）
17. **DHCP** - 动态主机配置协议（RFC 2131）
18. **NTP** - 网络时间协议（RFC 5905）

### 路由协议
19. **OSPF** - 开放最短路径优先协议（RFC 2328）
20. **BGP** - 边界网关协议（RFC 4271）
21. **IGMP** - 组播组管理协议（RFC 3376）

### 隧道协议
22. **GRE** - 通用路由封装协议（RFC 2784/2890）

### IoT协议
23. **MQTT** - 消息队列遥测传输协议
24. **CoAP** - 受限应用协议（RFC 7252）

### 实时协议
25. **RTP** - 实时传输协议（RFC 3550）
26. **RTCP** - RTP控制协议（RFC 3550）

### 远程桌面协议
27. **VNC** - 远程桌面协议（RFC 6143）

## 协议覆盖层次

| OSI 层次 | 协议数量 | 具体协议 |
|----------|----------|----------|
| 链路层 | 2 | Ethernet, ARP |
| 网络层 | 4 | IPv4, IPv6, ICMP, IGMP |
| 传输层 | 2 | TCP, UDP |
| 应用层 | 19 | HTTP, DNS, QUIC, TLS, SSH, FTP, SMTP, DHCP, NTP, OSPF, BGP, IPSec, WireGuard, GRE, MQTT, CoAP, RTP, RTCP, VNC |

## 协议文件位置

| 协议 | 文件路径 | RFC |
|------|----------|-----|
| Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP, HTTP, DNS | `eng_lib/headers.pkt` | 多个RFC |
| QUIC | `eng_lib/quic.pkt` | RFC 9000 |
| TLS/SSL | `eng_lib/tls.pkt` | RFC 8446/5246 |
| SSH | `eng_lib/ssh.pkt` | RFC 4251-4254 |
| FTP | `eng_lib/ftp.pkt` | RFC 959 |
| SMTP | `eng_lib/smtp.pkt` | RFC 5321 |
| DHCP | `eng_lib/dhcp.pkt` | RFC 2131 |
| NTP | `eng_lib/ntp.pkt` | RFC 5905 |
| IGMP | `eng_lib/igmp.pkt` | RFC 3376 |
| OSPF | `eng_lib/ospf.pkt` | RFC 2328 |
| BGP | `eng_lib/bgp.pkt` | RFC 4271 |
| IPSec | `eng_lib/ipsec.pkt` | RFC 4301-4309 |
| WireGuard | `eng_lib/wireguard.pkt` | 草案 |
| GRE | `eng_lib/gre.pkt` | RFC 2784/2890 |
| MQTT | `eng_lib/mqtt.pkt` | OASIS标准 |
| CoAP | `eng_lib/coap.pkt` | RFC 7252 |
| RTP | `eng_lib/rtp.pkt` | RFC 3550 |
| RTCP | `eng_lib/rtcp.pkt` | RFC 3550 |
| VNC | `eng_lib/vnc.pkt` | RFC 6143 |

## 学习路径建议

### 初学者（1-2周）
1. **以太网和ARP** - 理解链路层通信
2. **IP协议** - 理解网络层寻址和路由
3. **TCP和UDP** - 理解传输层服务
4. **HTTP和DNS** - 理解Web应用基础

### 进阶者（2-4周）
1. **TLS/SSL** - 理解Web安全
2. **SSH** - 理解远程登录安全
3. **IPSec** - 理解IP层安全
4. **WireGuard** - 理解现代VPN

### 高级者（4-8周）
1. **OSPF** - 理解内部网关协议
2. **BGP** - 理解外部网关协议
3. **IGMP** - 理解组播通信
4. **GRE** - 理解隧道封装

### 专业者（8周+）
1. **MQTT** - 理解IoT消息传输
2. **CoAP** - 理解受限设备通信
3. **RTP/RTCP** - 理解实时音视频
4. **VNC** - 理解远程桌面协议
5. **QUIC** - 理解现代传输协议

## 使用示例

### 查看协议定义
```bash
# 查看所有协议
prping engine --ls headers.pkt

# 查看特定协议
prping engine --ls tls.pkt
prping engine --ls vnc.pkt

# 查看协议十六进制表示
prping engine --hex tls.pkt
```

### 学习协议
```bash
# 查看协议学习指南
cat docs/protocol-learning.md

# 查看协议支持清单
cat PROTOCOL_SUPPORT.md

# 查看协议总结
cat PROTOCOL_SUMMARY.md
```

## 协议特点总结

### 1. 完整的RFC引用
每个协议都引用了对应的RFC文档，确保协议实现的正确性。

### 2. 详细的中文注释
每个字段都有详细的中文注释，包括：
- 字段含义
- 数据类型
- 默认值
- 常见取值
- 使用场景

### 3. 实际应用场景
每个协议都说明了实际应用场景，帮助理解协议的用途。

### 4. 可学习性
所有协议定义都适合学习者使用，从初学者到专业者都能找到合适的学习内容。

## 总结

prping项目支持**27种网络协议**，覆盖：
- **OSI模型所有层次**：链路层、网络层、传输层、应用层
- **多种协议类型**：安全协议、路由协议、隧道协议、IoT协议、实时协议、远程桌面协议
- **完整的RFC引用**：每个协议都引用了对应的RFC文档
- **详细的中文注释**：每个字段都有详细的中文注释
- **实际应用场景**：每个协议都说明了实际应用场景

通过本项目，用户可以：
1. **深入理解网络协议的工作原理**
2. **学习协议头部的格式和字段含义**
3. **掌握协议的安全特性和加密机制**
4. **了解现代协议的设计理念和优化技术**
5. **进行网络协议的调试和分析**

prping是目前最全面的网络协议学习和调试工具之一。
