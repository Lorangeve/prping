# 网络协议支持总结

## 已支持协议清单（eng_lib/ 目录）

### 1. 核心协议（headers.pkt）
- **Ethernet** - 以太网帧（RFC 802.3）
- **ARP** - 地址解析协议（RFC 826）
- **IPv4** - 互联网协议版本4（RFC 791）
- **IPv6** - 互联网协议版本6（RFC 2460）
- **ICMP** - 互联网控制消息协议（RFC 792）
- **TCP** - 传输控制协议（RFC 793）
- **UDP** - 用户数据报协议（RFC 768）
- **HTTP** - 超文本传输协议（RFC 2616）
- **DNS** - 域名系统（RFC 1035）

### 2. 现代传输协议
- **QUIC** - 基于UDP的传输协议（RFC 9000）

### 3. 安全协议
- **TLS/SSL** - 安全传输层协议（RFC 8446/5246）
- **SSH** - 安全远程登录协议（RFC 4251-4254）
- **IPSec** - IP层安全协议（RFC 4301-4309）

### 4. 应用层协议
- **FTP** - 文件传输协议（RFC 959）
- **SMTP** - 邮件传输协议（RFC 5321）
- **DHCP** - 动态主机配置协议（RFC 2131）
- **NTP** - 网络时间协议（RFC 5905）

### 5. 路由协议
- **OSPF** - 开放最短路径优先协议（RFC 2328）
- **BGP** - 边界网关协议（RFC 4271）
- **IGMP** - 组播组管理协议（RFC 3376）

### 6. 隧道协议
- **GRE** - 通用路由封装协议（RFC 2784/2890）
- **WireGuard** - 现代VPN协议

### 7. IoT协议
- **MQTT** - 消息队列遥测传输协议
- **CoAP** - 受限应用协议（RFC 7252）

### 8. 实时协议
- **RTP** - 实时传输协议（RFC 3550）
- **RTCP** - RTP控制协议（RFC 3550）

## 无法支持的协议及原因

### 1. 硬件依赖协议
- **PCIe, USB, SATA, HDMI** - 需要专用硬件接口和驱动
- **原因**: prping是纯软件网络工具，无法访问硬件总线

### 2. 物理层协议
- **Ethernet PHY (10BASE-T, 100BASE-TX, 1000BASE-T)** - 物理信号编码
- **Wi-Fi (802.11 a/b/g/n/ac/ax)** - 需要无线网卡驱动支持
- **原因**: 需要专用硬件和驱动程序

### 3. 实时操作系统协议
- **PROFINET, EtherCAT, Modbus TCP** - 工业以太网协议
- **原因**: 需要实时内核和专用硬件

### 4. 卫星通信协议
- **DVB-S2, CCSDS** - 卫星通信标准
- **原因**: 需要专用卫星调制解调器和射频硬件

### 5. 蜂窝网络协议
- **LTE, 5G NR, GPRS** - 蜂窝网络协议栈
- **原因**: 需要基站和核心网设备

### 6. 存储网络协议
- **Fibre Channel, iSCSI, FCoE** - 存储区域网络协议
- **原因**: 需要专用存储适配器和交换机

### 7. 传统遗留协议
- **Token Ring, FDDI, ATM** - 已淘汰的网络技术
- **原因**: 硬件已停产，无实际应用场景

### 8. 私有/商业协议
- **Cisco CDP, LLDP** - 厂商私有协议
- **原因**: 文档不公开，实现困难

### 9. 高度复杂的协议
- **SIP (Session Initiation Protocol)** - 需要完整的VoIP栈支持
- **H.323** - 复杂的多媒体会议协议
- **原因**: 实现复杂度高

### 10. 加密和压缩协议
- **Zstandard, LZ4, Brotli** - 压缩算法协议
- **原因**: 主要是算法实现，不是网络协议格式

## 使用方式

### 查看协议定义
```bash
# 查看所有协议
prping engine --ls headers.pkt

# 查看特定协议
prping engine --ls tls.pkt
prping engine --ls ssh.pkt

# 查看协议十六进制表示
prping engine --hex tls.pkt
```

### 学习协议
1. 从应用层协议开始（HTTP、DNS）
2. 学习安全协议（TLS、SSH）
3. 研究路由协议（OSPF、BGP）
4. 探索现代协议（QUIC、WireGuard）

### 测试协议
```bash
# 测试TLS握手
prping engine --hex tls.pkt

# 测试SSH连接
prping engine --hex ssh.pkt

# 测试FTP传输
prping engine --hex ftp.pkt
```

## 协议学习资源

### 文档
- `docs/protocol-learning.md` - 协议学习指南
- `PROTOCOL_SUPPORT.md` - 协议支持清单

### 注释规范
每个协议定义都包含：
1. RFC标准引用
2. 协议概述和工作原理
3. 字段详解（含义、数据类型、默认值）
4. 自动字段说明
5. 结构注释

### 学习路径
1. **初学者**: HTTP、DNS、TCP、UDP
2. **进阶者**: TLS、SSH、IPSec
3. **高级者**: OSPF、BGP、IGMP
4. **专业者**: MQTT、CoAP、RTP、RTCP

## 总结

prping项目支持**25+种网络协议**，覆盖：
- 链路层、网络层、传输层、应用层
- 安全协议、路由协议、隧道协议
- IoT协议、实时协议

成为最全面的网络协议学习和调试工具之一。
