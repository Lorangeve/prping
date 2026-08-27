# 网络协议支持清单

本文档列出 prping 项目支持的所有网络协议，以及无法支持的协议及原因。

## 已支持的协议

### 第一阶段：核心应用层协议

#### 1. TLS/SSL (Transport Layer Security)
- **文件**: `eng_lib/tls.pkt`
- **RFC**: RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2)
- **用途**: 安全通信、HTTPS 基础
- **实现的消息**:
  - TLS 记录层头部
  - TLS 握手消息头部
  - ClientHello 消息
  - ServerHello 消息
  - TLS 告警消息

#### 2. SSH (Secure Shell)
- **文件**: `eng_lib/ssh.pkt`
- **RFC**: RFC 4251-4254
- **用途**: 安全远程登录、文件传输
- **实现的消息**:
  - SSH 二进制数据包
  - SSH 版本协商
  - SSH 密钥交换初始化
  - SSH 认证请求
  - SSH 通道打开请求
  - SSH 通道数据

#### 3. FTP (File Transfer Protocol)
- **文件**: `eng_lib/ftp.pkt`
- **RFC**: RFC 959
- **用途**: 文件传输
- **实现的消息**:
  - FTP 命令
  - FTP 响应
  - PASV 响应
  - 传输模式
  - PORT 命令

#### 4. SMTP (Simple Mail Transfer Protocol)
- **文件**: `eng_lib/smtp.pkt`
- **RFC**: RFC 5321
- **用途**: 电子邮件发送
- **实现的消息**:
  - SMTP 命令
  - SMTP 响应
  - EHLO 命令
  - MAIL FROM 命令
  - RCPT TO 命令
  - DATA 命令
  - AUTH 命令

#### 5. DHCP (Dynamic Host Configuration Protocol)
- **文件**: `eng_lib/dhcp.pkt`
- **RFC**: RFC 2131
- **用途**: 自动 IP 地址分配
- **实现的消息**:
  - DHCP 报文
  - Discover 报文
  - Offer 报文
  - Request 报文
  - Ack 报文

#### 6. NTP (Network Time Protocol)
- **文件**: `eng_lib/ntp.pkt`
- **RFC**: RFC 5905
- **用途**: 时间同步
- **实现的消息**:
  - NTP 报文
  - NTP 时间戳

#### 7. IGMP (Internet Group Management Protocol)
- **文件**: `eng_lib/igmp.pkt`
- **RFC**: RFC 3376
- **用途**: 组播组管理
- **实现的消息**:
  - IGMPv3 查询消息
  - IGMPv3 报告消息
  - IGMP 组记录

### 第二阶段：网络层和路由协议

#### 8. OSPF (Open Shortest Path First)
- **文件**: `eng_lib/ospf.pkt`
- **RFC**: RFC 2328
- **用途**: 内部网关路由协议
- **实现的消息**:
  - OSPF 头部
  - Hello 消息
  - Database Description 消息
  - Link State Request 消息
  - Link State Update 消息
  - Link State Acknowledgment 消息

#### 9. BGP (Border Gateway Protocol)
- **文件**: `eng_lib/bgp.pkt`
- **RFC**: RFC 4271
- **用途**: 自治系统间路由
- **实现的消息**:
  - BGP 头部
  - OPEN 消息
  - UPDATE 消息
  - NOTIFICATION 消息
  - KEEPALIVE 消息

### 第三阶段：安全和隧道协议

#### 10. IPSec (IP Security)
- **文件**: `eng_lib/ipsec.pkt`
- **RFC**: RFC 4301-4309
- **用途**: IP 层安全
- **实现的消息**:
  - AH (Authentication Header)
  - ESP (Encapsulating Security Payload)

#### 11. WireGuard
- **文件**: `eng_lib/wireguard.pkt`
- **RFC**: 草案 (draft-wangzen-wireguard)
- **用途**: 现代 VPN 协议
- **实现的消息**:
  - 握手初始化
  - 数据传输
  - 密钥交换

#### 12. GRE (Generic Routing Encapsulation)
- **文件**: `eng_lib/gre.pkt`
- **RFC**: RFC 2784, RFC 2890
- **用途**: 隧道封装
- **实现的消息**:
  - GRE 头部

### 第四阶段：IoT 和嵌入式协议

#### 13. MQTT (Message Queuing Telemetry Transport)
- **文件**: `eng_lib/mqtt.pkt`
- **RFC**: OASIS 标准
- **用途**: IoT 消息传输
- **实现的消息**:
  - CONNECT 消息
  - CONNACK 消息
  - PUBLISH 消息
  - SUBSCRIBE 消息
  - SUBACK 消息

#### 14. CoAP (Constrained Application Protocol)
- **文件**: `eng_lib/coap.pkt`
- **RFC**: RFC 7252
- **用途**: 受限设备的 Web 传输
- **实现的消息**:
  - CoAP 头部
  - 请求消息
  - 响应消息

### 第五阶段：游戏和实时协议

#### 15. RTP (Real-time Transport Protocol)
- **文件**: `eng_lib/rtp.pkt`
- **RFC**: RFC 3550
- **用途**: 实时音视频传输
- **实现的消息**:
  - RTP 头部

#### 16. RTCP (RTP Control Protocol)
- **文件**: `eng_lib/rtcp.pkt`
- **RFC**: RFC 3550
- **用途**: RTP 会话控制
- **实现的消息**:
  - Sender Report
  - Receiver Report
  - Goodbye 消息

## 无法支持的协议及原因

### 1. 硬件依赖协议
- **PCIe, USB, SATA, HDMI** - 需要专用硬件接口和驱动，纯软件无法处理
- **原因**: prping 是纯软件网络工具，无法访问硬件总线

### 2. 物理层协议
- **Ethernet PHY (10BASE-T, 100BASE-TX, 1000BASE-T)** - 物理信号编码
- **Wi-Fi (802.11 a/b/g/n/ac/ax)** - 需要无线网卡驱动支持
- **原因**: 需要专用硬件和驱动程序，超出纯软件协议分析范围

### 3. 实时操作系统协议
- **PROFINET, EtherCAT, Modbus TCP** - 工业以太网协议，需要实时操作系统支持
- **原因**: 需要实时内核和专用硬件，不适合通用网络工具

### 4. 卫星通信协议
- **DVB-S2, CCSDS** - 卫星通信标准
- **原因**: 需要专用卫星调制解调器和射频硬件

### 5. 蜂窝网络协议
- **LTE, 5G NR, GPRS** - 蜂窝网络协议栈
- **原因**: 需要基站和核心网设备，不适合终端设备分析

### 6. 存储网络协议
- **Fibre Channel, iSCSI, FCoE** - 存储区域网络协议
- **原因**: 需要专用存储适配器和交换机

### 7. 传统遗留协议
- **Token Ring, FDDI, ATM** - 已淘汰的网络技术
- **原因**: 硬件已停产，无实际应用场景

### 8. 私有/商业协议
- **Cisco CDP, LLDP** - 厂商私有协议
- **原因**: 文档不公开，实现困难且可能涉及知识产权问题

### 9. 高度复杂的协议
- **SIP (Session Initiation Protocol)** - 需要完整的 VoIP 栈支持
- **H.323** - 复杂的多媒体会议协议
- **原因**: 实现复杂度高，需要完整的信令栈和媒体处理能力

### 10. 加密和压缩协议
- **Zstandard, LZ4, Brotli** - 压缩算法协议
- **原因**: 主要是算法实现，不是网络协议格式

## 总结

### 已支持协议统计
- **总数**: 16 种协议
- **覆盖层次**:
  - 链路层: 2 种 (Ethernet, ARP)
  - 网络层: 4 种 (IPv4, IPv6, ICMP, IGMP)
  - 传输层: 2 种 (TCP, UDP)
  - 应用层: 8 种 (HTTP, DNS, QUIC, TLS, SSH, FTP, SMTP, DHCP, NTP, OSPF, BGP, IPSec, WireGuard, GRE, MQTT, CoAP, RTP, RTCP)

### 协议特点
1. **完整的 RFC 引用**: 所有协议都引用了对应的 RFC 文档
2. **详细的中文注释**: 每个字段都有详细的中文注释
3. **实际应用场景**: 每个协议都说明了实际应用场景
4. **可学习性**: 适合网络协议学习者使用

### 使用方式
```bash
# 查看所有协议定义
prping engine --ls headers.pkt

# 查看特定协议
prping engine --ls tls.pkt
prping engine --ls ssh.pkt
prping engine --ls ftp.pkt

# 查看协议的十六进制表示
prping engine --hex tls.pkt

# 查看协议学习指南
cat docs/protocol-learning.md
```

### 学习建议
1. **初学者**: 从 HTTP、DNS 等应用层协议开始
2. **进阶者**: 学习 TLS、SSH 等安全协议
3. **高级者**: 研究 OSPF、BGP 等路由协议
4. **专业者**: 分析 MQTT、CoAP 等 IoT 协议

通过本项目，你可以：
- 深入理解网络协议的工作原理
- 学习协议头部的格式和字段含义
- 掌握协议的安全特性和加密机制
- 了解现代协议的设计理念和优化技术
