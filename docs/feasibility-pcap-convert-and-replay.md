# pcap → pkt/pktl 转码 与 pcap 包重放器 —— 可行性调研

> 调研背景：`prping engine --pcap=1.pcap`（pcap 读取 + 逐条反解展示）已有；本调研评估
> 两个方向的可行性：(A) 把 pcap 转成 `.pkt` + `.pktl` 文件（`--out` 的逆操作）；
> (B) 做一个 pcap 包重放器。所有结论均对照源码并做实证验证（见「实证记录」）。
>
> 日期：2025-08；涉及代码：`crates/prping-core/src/engine/{pcap,pkg,eng,recipe}.rs`、
> `crates/packet-dsl/src/{dissect,serialize,ir}.rs`、`crates/prping-cli/src/main.rs`。

## 1. 现状盘点（已有的积木）

| 能力 | 位置 | 说明 |
|---|---|---|
| pcap 读取 | `engine/pcap.rs::read_pcap` | classic pcap（非 pcapng）：大小端 magic、微秒/纳秒时间戳；记录 = 原始字节 + ts；返回 `(linktype u16, nano, Vec<PcapRecord>)` |
| pcap 写入 | `engine/pcap.rs::write_pcap` | 微秒、LE；`LinkType{Ethernet=1, Raw=101}` |
| 字节 → 层栈 | `packet-dsl/dissect.rs::dissect` | eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns + raw 兜底；checksum 错/截断进 `notes` 不报错；DNS 压缩指针可解 |
| 层栈 → 字节 | `packet-dsl/serialize.rs` | 每层 `raw` 字段直喂（`bytes=`），自动补 length/checksum/伪头部 |
| 原始发送 | `engine/pkg.rs::send_raw_bytes` | Linux：eth→AF_PACKET、ipv4→IPPROTO_RAW+IP_HDRINCL、ipv6→raw socket；Windows：Npcap 链路层注入（`rawwin.rs`，含回环适配 + GetBestRoute/ARP 下一跳） |
| 载荷发送 | `engine/pkg.rs::send_payload` | TCP connect / UDP 数据报，回显等待 |
| 配方 | `engine/recipe.rs` + `pkg.rs::send_recipe` | `.pktl`：global 存储 + 步骤顺序执行 + wait/params/extract/on_error |
| DSL 字节表达 | hex/raw 原语、`bytes=` 直喂、`layer(kind, bytes)` | 任意字节序列可无损表达 |
| 已存在的逆方向 | `packet --out FILE.pcap` | pkt → pcap 已实现（配方模式合并写一个 pcap） |

即：**「pkt → pcap → 反解展示」链路今天已通**（实证：`packet examples/transport_udp --out=x.pcap` 后 `engine --pcap=x.pcap` 逐条展示）。缺的是反过来的「pcap → pkt/pktl」与「pcap → 重放」。

## 2. A：pcap → pkt+pktl 转码

### 2.1 结论：完全可行，分「无损字节级」与「语义结构化」两条路线

**路线 A1（无损字节级）—— 推荐先做，工作量最小**

每条记录生成一个 `.pkt`，包体用单层 `raw(bytes=hex("..."))`（或按 linktype 包一层
`layer("eth", hex(...))` 标注便于阅读）：

```text
# record_0001.pkt（链路层 Ethernet，58 B）
p = layer("eth", hex("66 77 88 99 aa bb 00 11 22 33 44 55 08 00 45 00 ..."))
export:
- p
```

- 字节 100% 保真：不经语义字段层，checksum/length 不会被引擎重算；截断捕获、坏 checksum 都原样保留。
- 生成器极简：`read_pcap` + 逐记录 `hex` 格式化 + 模板拼文件（约 100~150 行，无新依赖）。
- `.pktl` 配方：一个 recipe 引用全部 `.pkt` 步骤即可顺序执行；或单 `.pkt` 内多个 `export:` 一次发完。
- 局限：不可编辑语义字段（要改源/目的地址只能改 hex），仅适合「原样回放/存档/审计」。

**路线 A2（语义结构化）—— 可读可编辑，需修 3 个 fidelity 缺口**

`dissect` 每层已填好 `Field::Value`（src/dst/ttl/id/端口/seq...），生成器把它渲染成
DSL 源码（复用 `eng_lib/headers.pkt` 层函数 + 位常量）：

```text
# record_0001.pkt
p = raw(bytes="ping")
full = use(p) |> icmp(type=8, id=0x0007, seq=3)
               |> ipv4(src="192.168.1.1", dst="8.8.8.8", ttl=64, proto=1)
export:
- full
```

保真度矩阵（实证 + 代码分析）：

| 层 | 结构化 roundtrip 字节保真 | 说明 |
|---|---|---|
| eth / arp / ipv4 / ipv6 / tcp / udp | ✅（合法包） | 每层 `raw` 保留头字节；长度/checksum 确定性重算 = 原值 |
| icmp | ⚠️ **有 bug** | body 存 `f.payload`，但 `serialize_icmp` raw 分支只拼 `raw + 内层`，icmp 在最内层时 body 丢失（实证失败） |
| dns | ❌ 不保真 | `dissect` 的 dns `raw=None`；重序列化丢 nscount/arcount、压缩指针、附加段（`serialize_dns` 只编 questions/answers） |
| http | ❌ 不保真 | `dissect` 的 http `raw=None`；重序列化规范化头部格式 |
| 未知协议 / 未知 ethertype | ✅（raw 兜底） | 载荷进 Raw 层，字节原样 |
| 坏 checksum 的捕获 | ❌ 被"修复" | ipv4/icmp/tcp/udp raw 分支总是重算校验和 |
| snaplen 截断捕获 | ✅ | raw 保真 |

修复成本都很小（各 1~3 行 + 测试）：
1. **层序反转**：`dissect` 产出显示序（外→内），`serialize` 期望内→外 —— 转码器 `layers.rev()` 即可（现有 roundtrip 测试只比字段不比字节，未暴露）。
2. **icmp body 丢失**：`serialize_icmp` raw 分支补 `f.payload`。
3. **dns/http raw 缺失**：`parse_dns`/`parse_http` 填 `raw: Some(整段报文字节)`。
修完 A2 对 eth/arp/ipv4/ipv6/icmp/tcp/udp 字节级一致；dns/http 仍建议 `bytes=` 直喂兜底。

### 2.2 pktl 的时序缺口

- 配方步骤现在只有 `wait:`（等回包秒数），**没有「间隔延迟」选项**；pcap 时间戳（ts_sec/ts_frac）
  无法直接写进 pktl。
- 若要转码携带时序：给 recipe 加 `delay:`（步骤间 sleep）步骤选项即可（`recipe.rs` 解析 +
  `send_recipe` 循环里 sleep，改动 ~20 行）。
- 但注意语义错配：捕获间隔 ≠ 回包等待，混用会误导。**若目标是重放，直接走 B 方案读 pcap
  时间戳；pktl 更适合承载「可编辑的会话脚本」**（转码产出结构、global/extract 逻辑）。

### 2.3 A 方案建议形态

- CLI：`engine --pcap FILE.pcap --to-pkt DIR`（或新 flag），`--structured` 切 A2、缺省 A1。
- 大 pcap 防护：`--limit N` / `--skip N` / 每记录一个文件或单文件多 export 二选一；
  万级记录时文件爆炸，建议默认单文件多 export + 可选拆分。
- 产物自述头注释：来源文件、记录号、时间戳、linktype、notes（如 checksum 错）。

## 3. B：pcap 包重放器

### 3.1 结论：高度可行 —— 现有代码已覆盖约 70% 积木，本质是「组装 + 节奏引擎 + L2 适配」

复用（无需新依赖）：

- `read_pcap`：读取 + 时间戳；
- `send_raw_bytes` 全套发送路径：Linux AF_PACKET（eth 帧）、IPPROTO_RAW（裸 IPv4）、raw IPv6；
  Windows Npcap 注入（`rawwin.rs` 已含回环适配、GetBestRoute/ARP 下一跳解析、`--wait` 先开抓包句柄）；
- `--iface`、`--wait`、`--out`、`--raw` 语义；
- 节奏/统计模式参考 `drive.rs`（间隔循环、Ctrl+C 优雅退出、汇总统计、退出码、`--json` 均可复用模式）。

### 3.2 必须新写的缺口

1. **节奏引擎**：按 ts 差计算帧间隔；`实时`（默认，按原间隔）、`--speed N`（倍速）、
   `--topspeed`（尽发）、`--loop N`、`--skip/--limit` 范围选择；首包可选立即发。
2. **L2 适配（重放的核心难点）**：
   - 原始以太网帧：原 dst/src MAC 在新网段通常无效 → `--fix-mac`（dst=广播/网关、src=本机接口 MAC）
     或至少黄色警告；Linux 需 `--iface` 接口名，Windows 侧已有 GetBestRoute+ARP 可复用。
   - 裸 IP：IPPROTO_RAW 走内核路由（与 iface 无关），src IP 非本机 → `--rewrite-src` 或警告；
     dst 保持原样（重放「到原目标」语义）。
   - 高频性能：现有 `send_af_packet` 每包 socket+close（`pkg.rs:2031-2056`）→ 重放需缓存 fd
     （小重构，把发送原语抽成可复用的函数或对象）。
3. **linktype 处理**：目前只认 Ethernet/Raw；Linux `tcpdump` 非 root 默认 SLL(cooked, 113)、
   802.11 等 → 未知 linktype 按 opaque raw 整帧直发（不重组）或明确报错。
4. **pcapng 读取**：Wireshark/新版 tcpdump 默认 pcapng —— 建议补（或先支持 classic 并明确提示）。
5. **统计**：发送/失败计数、速率、耗时、Ctrl+C 汇总（模式在 `drive.rs`/`stats.rs`，照搬）。

### 3.3 架构建议

- 新子命令 `prping replay FILE.pcap`（与 engine/packet/server 并列，子命令前缀缩写机制自动生效），
  而非塞进 packet —— 语义独立（读 pcap 重放 vs 构建 DSL 发送），选项集互斥干净。
- 发送复用方式二选一：
  - (a) 构造合成 `PacketSpec`（最外层按 linktype 包 `Layer::Ethernet(raw: 整帧)` / `Ipv4(raw:)`），
    直接喂现有 `send_raw_bytes` —— 零重构但绕；
  - (b) 把 `send_af_packet`/`send_raw_ip4`/`send_raw_ip6` 提为 `pub(crate)` 公共函数，
    重放器直接调 —— 更直，顺手解决 fd 缓存。推荐 (b)。
- 工作量：核心模块 ~300-500 行 + CLI 接线 + 测试（节奏用 mock 时间戳单测；L2 适配用 lo 回环实测）。

### 3.4 必须写清的语义边界

- **TCP 字节级重放不产生有效连接**（seq/ack 陈旧、无握手状态机）——用途是防火墙/IDS/
  协议解析测试（tcpreplay 同款语义），文档明示；UDP/DNS/ICMP/ARP 重放是可靠场景。
- 重放 ≠ 转码：重放器直接读 pcap（时间戳即节奏），不需要也不建议经 pktl 中转。

## 4. 建议实施路线

| 阶段 | 内容 | 依赖 | 量级 |
|---|---|---|---|
| P0 | 顺手修 3 个 fidelity 缺口（层序 rev 约定、icmp raw body、dns/http raw）+ 字节级 roundtrip 测试 | 无 | 半天 |
| P1 | A1 无损转码：`engine --pcap --to-pkt`（+ `--limit/--skip`） | P0 可选 | 半天 |
| P2 | B 重放器：`replay` 子命令（节奏 + 复用发送路径 + `--fix-mac/--speed/--loop` + 统计） | P0 | 1-2 天 |
| P3 | pcapng 读取、linktype 白名单、A2 结构化转码（含 dns/http bytes= 兜底） | P1/P2 | 各半天 |

P1 与 P2 互不依赖，可并行；P2 是用户主目标，P0 的三个小修是两边的公共地基。

## 5. 实证记录（本调研实测）

1. `packet examples/transport_udp --out=/tmp/test1.pcap` → `engine --pcap=/tmp/test1.pcap`
   正常逐条反解展示（2 条记录，linktype=1）。
2. 临时测试（已删）验证结构化 roundtrip：dns/udp/ipv4/eth、arp/eth、tcp/载荷/ipv4/eth、
   udp/ipv6 四例在 `dissect(...).layers.rev()` 后重序列化 **字节一致**；icmp 裸包一例失败
   （body 丢失，定位 `serialize.rs::serialize_icmp` raw 分支）；未反转层序时全部失败
   （`dissect` 外→内 vs `serialize` 内→外）。
3. 现存 `dissect.rs` roundtrip 测试只校验字段相等（`tests/dissect.rs`），未覆盖字节级
   与 icmp body，故上述问题此前未被发现。
