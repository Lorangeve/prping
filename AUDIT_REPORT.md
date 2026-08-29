# prping 多 agent 审计报告：逻辑漏洞与可重构项

> 生成方式：7 个并行审计 agent（测量核心 / traceroute / serve+抓包 / engine / packet-dsl / pkg+CLI / 横切面共享层）
> 各自独立通读范围代码并产出带 file:line 证据的发现；主控对全部高严重度与主要中危项逐条 read/grep 交叉复核，
> 并独立通读约 3.5 万行核心文件，提出独立发现（其中 4 条与其他 agent 互为独立确认）。
> 本次刻意避开 REFACTOR_REPORT.md §4 已覆盖的「复制粘贴级重复」清单，聚焦逻辑漏洞与重复之外的改进项。
>
> 约 85 条原始发现，合并跨 agent 重复后约 70 条独立项（高 7 / 中 28 / 低 ~40 / 可重构 12）。

---

## 一、高严重度（7 条，全部经主控代码复核确认）

| # | 问题 | 位置 | 复现/影响 |
|---|------|------|-----------|
| H1 | `decode_hex` 奇数长度 hex 直接切片越界 panic | engine/eng/mod.rs:492-494 | `prping engine --hex "123"` 崩溃（切片先于 from_str_radix 校验） |
| H2 | 值函数自递归/互递归无深度限制 → 栈溢出崩溃（eval_component 有循环检测，eval_user_value_func 没有） | packet-dsl/src/eval.rs:2028-2085 | .pkt 里 `func f() -> bytes { f() }` 即可 abort |
| H3 | 词法器超长 hex 字面量 u64::from_str_radix(...).expect() panic（十进制分支有优雅报错，hex 分支漏了） | packet-dsl/src/lexer.rs:203 | 0x + 17 位以上 hex → release 也 panic |
| H4 | sniffer contains("") → b.windows(0) panic（#[rule] 路径拒绝空模式，sniffer 路径不对称） | packet-dsl/src/matchpred.rs:562,787 | - match raw(contains("")) 收到首包即崩 |
| H5 | tcp_frame_v6 先 &buf[8..24] 越界切片、后查长度 → IPv6 TCP trace 收 <24B 无头 TCP 段（回环自读 20B SYN / 20B RST）panic | ping/trace/tcp.rs:345 | trace ::1:PORT 或目标端口关闭时崩溃 |
| H6 | wait:/delay:/--wait/-i/-n Ns 的 f64 无有限性校验，inf/nan/超大值直达 Duration::from_secs_f64 panic（3 个 agent 独立发现同源问题） | engine/recipe.rs:443-462、pkg/raw.rs:179、pkg/send.rs:915-956、drive.rs:109、util/interrupt.rs:46、lib.rs:201（NaN 比较为 false 躲过 clamp） | ping H -i nan、engine --wait inf、配方 delay: 1e300 均崩溃 |
| H7 | --out pcap 记录字节 ≠ 实际发送字节：--out 块与 send_module 各建一个状态化序列化器（随机 IP ID / TCP/UDP sport 两次消费不同 RNG）；连带 extract from: sent.* 与 --summary 取到「从未发送」的随机值 | engine/pkg/send.rs:47-76 vs 259-263、448-471；packet-dsl/serialize.rs:393,549,619 | 存档 pcap 与实发不一致，配方 extract 拿到假字段值 |

## 二、中严重度（逻辑漏洞，按主题分组）

### 崩溃/挂死类
- M1 latency 客户端 addrs[0] 裸下标：resolve_vec 对主机名在 -4/-6 过滤后返回空 Vec 不报错，latency 是唯一无 is_empty 兜底的模式 → panic（icmp/tcp 都有兜底）— ping/latency.rs:17,23 + util/dns.rs:114-118
- M2 rest(子proto) 指向零消费 proto（bytes(0) 字段）→ parse_sub_sequence 死循环挂死 — packet-dsl/src/proto.rs:641-651,783-789
- M3 算术溢出无守卫：+/mul/sub/宽度表达式移位裸运算（debug panic、release 静默回绕）；div 用 i64::MAX 作除零哨兵导致误报+漏报 — eval.rs:1550,1860-1868、proto.rs:920-944

### serve 触发协议 DoS 面（4 个 agent 从不同角度命中同一协议）
- M4 UDP 触发包服务端无校验：8 字节 [FF FF size count] 可驱动最多 4.29e9×64KB 反射流量；size 不 clamp（>65507 → EMSGSIZE 首包即断）、count 无上限、无来源/并发限制 — serve/mod.rs:257-298,278（主控独立确认 size 未 clamp）
- M5 UDP 触发发送任务无终止条件：客户端消失后以 1ms 周期自旋到服务端退出（duration 模式 count=u32::MAX 必触发）— serve/mod.rs:280-299 + bandwidth.rs:525
- M6 TCP 触发写循环无 interrupted()/无写超时：客户端不读即永久挂起，每个挂死任务占 1 个信号量许可，1024 连接耗尽后新连接被静默拒绝；另连接读侧无空闲超时（slowloris）— serve/mod.rs:378-387,363-403,348-351
- M7 UDP 会话表 HashMap<SocketAddr, UdpSession> 无容量上限 + 每新源打日志 + 每 50ms 全表扫描 — serve/mod.rs:232-233,313-319,243

### 统计/汇总失真
- M8 -r 接收模式服务端汇总 Mbps 恒为 0：UDP 下 secs 也恒为 0（触发任务只加 agg.sent 不加 micros，会话被 remove 后不再结算）— serve/mod.rs:419-428,88,295（主控独立确认）
- M9 TCP --wait 的 RTT 在 read_all 之前采样，不含回显接收耗时（UDP/raw 路径都在收到回包时计时）— engine/pkg/send.rs:924-937
- M10 UDP 会话计时含 2s 空闲尾巴 + float→u64 截断，聚合 secs 虚增 — serve/mod.rs:86-92,233

### 行为错误 / 跨模式不一致
- M11 UDP latency 回包无任何校验（无 seq、不查源地址）：陈旧回包/杂包被当成功，超时后迟到的回显被下一轮消费成虚假极小 RTT（UDP ping 同文件有 4 字节 seq 校验）— ping/latency.rs:198-213
- M12 latency 缺省只测 1 次有效探测（count=0 被 max(1) 吞掉，-n 0 也进不了无限模式）— main.rs:836-839 + lib.rs:250
- M13 双栈主机无 IPv4 优先：v6 不通时 TCP/UDP ping 每次探测先等满 5s 才回退（eng/mod.rs:261 注释声称 v4 优先但未实现）— util/dns.rs:113 + util/net.rs:95-109
- M14 packet --json --summary 混合输出人读文本，破坏 JSONL 契约（validate_packet 未互斥）— send.rs:144-168,460-474、recipe.rs:763-779
- M15 TCP 分支 --wait 0 仍阻塞 2s 读回显（与 UDP 分支及 listen 注释「立即超时」相悖），且逐包刷红字「no reply within 0s」— send.rs:915-931,631-641
- M16 Unix TCP trace 静默忽略 -s 源绑定（Windows Npcap 路径尊重它）— trace/tcp.rs:48-50 vs tcpwin.rs:63-73
- M17 reverse DNS getnameinfo flags=0 缺 NI_NAMEREQD：无 PTR 的 IP 返回数字串而非 None → 输出地址重复、JSON hostname 恒非 null（与 mod.rs:245 文档矛盾）— trace/dns.rs:54,104
- M18 Linux/macOS 非 pcap 路径 IPv6 raw --wait 永远超时：回包 socket 恒为 IPv4 ICMP，v6 回包收不到且无提示 — engine/pkg/raw.rs:89-94,148-161

### 解析/序列化正确性
- M19 pcap 全局头 network 按 u16 只读低 2 字节：大端文件 linktype 恒为 0（_linktype 正确读了 4 字节却丢弃）— engine/pcap.rs:66-68（主控独立确认）
- M20 read_pcap 的 incl_len 无上限校验：伪造 24 字节文件可触发 4GiB 分配 OOM — engine/pcap.rs:79-81（主控独立确认）
- M21 结构化转码 ARP opcode 非 1/2（RARP）被静默改写为 request()，roundtrip 失真且 sha="" 生成坏 .pkt — engine/convert.rs:405-410 + packet-dsl/dissect.rs:646-650
- M22 序列化长度字段 u16 截断（包长 >65535 静默回绕成 4）与 TCP data_offset 截断（options>40B 头部损坏），均无错误返回 — packet-dsl/serialize.rs:346,399,471,625,567-576
- M23 tpl {n:} 零填充压缩用绝对 input[0]/input[1] 而非当前游标：重复组前有字面项时 :: 压缩失效或误触发 — packet-dsl/src/tpl.rs:323-334
- M24 sniffer 匹配 proto 分支与 IR 分支字段字节形态不一致（最小宽度 vs 固定宽度），同一规则跨分支假阴性 — matchpred.rs:895-914 vs 221-319
- M25 错误分类按硬编码中文字符串 contains 匹配（"只能在配方 extract"）：改文案即静默漂移，且违背 i18n — engine/eng/mod.rs:538 + eval.rs:1650-1653
- M26 LSP Content-Length 无上限直接分配（4GiB 头即 OOM）— engine/eng/lsp.rs:66-72
- M27 IPv4 IHL<5 未校验 + total_length 未交叉校验：畸形帧端口读取位置错误、--filter port 误命中；patch_zero_src 校验和只算 20B 头（IHL>5 时错误）— serve/capture.rs:176-184、engine/pkg/send.rs:1091-1103
- M28 Windows 抓包路径恒设 direction(In)：-a 全帧/--filter 在 Windows 上看不到本机出向帧（三平台不一致，与文档矛盾）— engine/rawpcap/mod.rs:308-312 + serve/capture.rs:1036

## 三、低严重度（主控确认的精选；完整约 40 条）

- L1 drain_after_send 无超时、不响应 Ctrl+C：对不随 EOF 关闭的对端（nc -l -k、keep-alive 服务器）无限挂起 — util/net.rs:213-223（主控独立确认）
- L2 手写 JSON 只转义 "，未转义 \\/换行/控制字符（hostname/错误串含这些字符时产出非法 JSON）— stats.rs:290-324（主控独立确认，建议换 serde）
- L3 Stats::record 窗口满后 times.remove(0)/timeline.remove(0) 每次 O(n) 搬移（100k 窗口），无限 ping 长跑 O(n²) memmove — stats.rs:170-173（主控独立确认，建议 VecDeque/环形缓冲）
- L4 stats.avg() 用 received as u32 作除数（>4G 样本理论截断）；percentile(p) 无 0..=100 校验（p>100 越界 panic）— stats.rs:198,228-236
- L5 ICMP send 失败被静默转成 Timeout（EACCES/EMSGSIZE 显示为「超时」计丢包）；UDP ping send 失败返回 Skip 不计丢包——同仓两口径 — ping/icmp.rs:234-237、udp.rs:88-93
- L6 bandwidth UDP 发送循环 udp_send().await? 瞬态错误（如端口不可达后 ECONNREFUSED）中止整个测试；并行 TCP 任一连接失败也 ? 中止并遗留任务 — bandwidth.rs:349,393,613
- L7 --parallel > 65535 报告截断成 u16；-r count×size 无 checked_mul；UDP receive 漏调 sampler.finish — bandwidth.rs:483,287,561
- L8 ICMP ident 全程固定 + seq u16 回绕：-i 0.1 约 1.8h 后 (ident,seq) 复用，迟到回包可污染统计 — ping/icmp.rs:103,133
- L9 -4/-6 对 IP 字面量目标不生效（字面量在过滤前直接 return）— util/dns.rs:107-109
- L10 Windows ICMP 路径 payload.len() as u16 截断（-l > 65535 静默错尺寸）— icmpwin.rs:193,264
- L11 echo_ok 一次性闩锁：一次 100ms 写超时后该连接回显永久关闭 — serve/mod.rs:390-398
- L12 IPv6 扩展头/分片头不追跳：带扩展头的本服务流量默认 verbose 不可见；VLAN(0x8100) tag 不剥 — serve/capture.rs:163-171,148-152
- L13 print_paged 的 write_all? 把 pager 提前退出的 EPIPE 当错误传播，且错误路径跳过 child.wait() — manual.rs:116-126
- L14 bind_udp 4MB 缓冲被 Linux rmem_max(212KB) 静默截断，注释声称的收益在默认系统不成立 — util/net.rs:22
- L15 UDP 触发协议幻数无逃逸：-l 8 的 UDP ping 每 2^32 次迭代恰有一次 seq 构成 [FF FF ...] 被误判为触发包 — util/format.rs:72-80
- L16 LANG=""（已设置但为空）不落入 macOS 系统 UI 语言兜底，与注释矛盾 — main.rs:1326-1340
- L17 listen_raw 8 帧去重窗口会静默丢弃合法重复帧，且 total/matched 统计口径不一致；--summary 在 listen_raw 不生效 — listen_raw.rs:542-604
- L18 pcap 多设备监听线程运行期出错后主线程静默挂起（仅打开期失败有兜底）— listen_raw.rs:480-523
- L19 全局 --lang 剥离误吞相邻参数（engine --lang 忘带值会把文件名当 lang 吞掉）— main.rs:1420-1426
- L20 trace ICMP Time Exceeded 截断兜底按「首个探测」归属可误配他人报文；parse_udp_icmp_v4 缺内嵌 version==4 校验（与 TCP 路径不一致）— trace/icmp.rs:142-143、trace/udp.rs:119-121

## 四、可重构项（非重复，区别于 REFACTOR_REPORT §4）

1. CLI 数值参数校验统一收口：interval/duration/wait/delay 的 is_finite() && >= 0 校验应在 bpaf 或 run() 一层做，根治 H6 系列 panic（warmup + count、8 + payload_size 改 saturating_*）。
2. --out 序列化器单实例化：修复 H7 的正确做法是发送流程只建一个序列化器、每包只序列化一次，--out/sent_full/summary 复用同一份字节。
3. lib.rs 公开面与 CLAUDE.md「公开面最小化」声明不符：整个 engine 约 45 个符号被全量 re-export（根因 pub(crate) mod engine 迫使 CLI 经 re-export 访问）——要么正式承认 engine 为稳定 API，要么收敛成 analyze/send 两级高层入口 — lib.rs:86-115。
4. justfile check-all 恒 exit 0：每个交叉目标 || echo "[跳过]" 把编译错误与工具链缺失混为一谈，门禁不可靠 — justfile:204-232（主控复核确认）。
5. build.rs 构建期改写仓库状态（.cargo/run-with-cap.sh + runner 配置），CI/只读 checkout 有副作用 — crates/prping-cli/build.rs:16-34。
6. TraceSocket/trace_loop 抽象被 TCP 双路径绕过：Unix TCP 与 tcpwin 各自复制约 40 行 hop 循环骨架，trait 形同虚设（与 REFACTOR_REPORT 的复制重复正交，属抽象失效）— trace/tcp.rs:63-235、tcpwin.rs:86-162。
7. 三处手写 from_raw_parts unsafe 切片应统一复用 util::init_slice（net.rs:50 已有带 SAFETY 注释的实现）— trace/mod.rs:136、trace/tcp.rs:138,190。
8. tcp.rs:171 丢弃共享匹配函数已算好的 is_dest 后重解析取 flags；dns.rs 双平台 getnameinfo 骨架重复。
9. all_exports_raw_only 对同一文件重复解析求值 3 次（且显式 --raw 时无需预检）— main.rs:1145,1159,1168。
10. 同一算术语义两套实现漂移：proto.rs::eval_width（宽度表达式，无守卫）vs eval.rs（值表达式，有守卫），应复用单一路径 — proto.rs:910-950。
11. 服务端 keep 过滤逻辑 4 个抓包循环复制粘贴（linux/windows/pcap×2），可提取 frame_keep(data, &filter, &expr) 单点（同时是修复 M28 的落点）。
12. stats.rs 采样窗口换 VecDeque（L3）、手写 JSON 换 serde 或完整转义（L2）、服务端 micros 累计提取共享辅助函数消除重复与截断差异。

## 五、与 REFACTOR_REPORT.md 的关系（报告需刷新）

- 重复清单大体仍有效，但 S-3 已部分修复：capture.rs 的 ip_meta/ip_summary 现已共享 parse_ip_base（capture.rs:162-186），报告描述的双份解析已收敛。
- 其余（C-1~C-6、M-1~M-18、E-1~E-13）经抽查仍在，其中 E-1/S-6（layer_name/layer_kind 双份映射）本次确认仍存在（display.rs:395-408 vs sniffer.rs:634-647）。

## 六、已验证无问题的区域（增加可信度）

信号处理（原子标志 + _exit 信号安全）、win_connect_select Win7 workaround、bandwidth parallel 全局配额（fetch_update + checked_sub 精确等于 count）、trace 的 TCP 伪头校验和与内嵌 IP 头偏移（16..20 / 24..40）、parse_histogram 阈值排序去重、meta_bits 1..=8 与 vint codec 宽度校验（杜绝 pack_fields 移位下溢）、matchpred 层名校验先于 build_value、capture 帧解析长度守卫完备、MTU 二分不变式、resolve_vec 无嵌套 block_on、locale 归一化。

---

## 附：本次已随报告落地的修复（见 git diff）

| 编号 | 修复内容 | 文件 |
|------|----------|------|
| H1 | decode_hex 奇数长度防护 | engine/eng/mod.rs |
| H4 | sniffer 空模式防护（contains/starts_with/ends_with） | packet-dsl/src/matchpred.rs |
| H5 | tcp_frame_v6 越界切片防护 | ping/trace/tcp.rs |
| H6 | interval/duration/wait/delay 有限性校验（含 MAX_DURATION_SECS=1e12 上限与负值拒绝；lib 层 + 配方层 + CLI --wait） | lib.rs、engine/recipe.rs、prping-cli/src/main.rs、locales |
| M4 | serve UDP 触发 size 服务端 clamp（与客户端协议对称） | serve/mod.rs |
| H2 | 值函数自递归/互递归深度限制（MAX_VALUE_FUNC_DEPTH=64，栈溢出 → 诊断错误） | packet-dsl/src/eval.rs |
| H3 | lexer 超长 hex 字面量优雅报错（替代 expect panic） | packet-dsl/src/lexer.rs |
| M8 | serve 接收模式汇总修复：触发任务记 micros + 报告 Mbps 按 bytes+sent 计算 | serve/mod.rs |
| M14 | packet --json --summary 互斥（保护 JSONL 契约） | prping-cli/src/main.rs + locales |
| M17 | reverse DNS 加 NI_NAMEREQD（无 PTR → None，不再返回数字串） | ping/trace/dns.rs |
| M19 | pcap 全局头 network 按 u32 读取（修复大端文件 linktype 恒 0） | engine/pcap.rs |
| M20 | pcap incl_len 上限（snaplen∩64MiB，畸形文件不再 4GB 分配） | engine/pcap.rs |
| M23 | tpl `{n:}` 零填充压缩改用当前游标（字面项后的 `::` 压缩生效） | packet-dsl/src/tpl.rs |
| M26 | LSP Content-Length 上限（16 MiB，恶意客户端不再 OOM） | engine/eng/lsp.rs |
| H7 | `--out` 存档与发送共用同一序列化器 + 每包单次序列化（存档字节==实发字节；sent.extract/摘要不再取到二次序列化的随机值） | engine/pkg/send.rs、engine/pkg/recipe.rs |
| M4 加固 | serve UDP 触发：同源并发任务上限（每源一个活跃发送任务）+ 30s 无进展超时（防任务堆叠/自旋） | serve/mod.rs |
| M9 | TCP `--wait` RTT 计入回显接收耗时（与 UDP/raw 路径口径一致） | engine/pkg/send.rs |
| M15 | TCP `--wait 0` 不再阻塞 2s 读回显、不打印误导性「no reply within 0s」 | engine/pkg/send.rs |
| M1 | latency `addrs[0]` 空列表防护（-4/-6 过滤后返回空 Vec 时报错而非 panic） | ping/latency.rs |
| M13 | `resolve_vec` v4 优先稳定排序（双栈主机不再每次先等满 5s v6 超时） | util/dns.rs |
| M6a | TCP 触发写循环加 interrupted() + 100ms 写超时（客户端停止读取即断开，不再占满连接配额） | serve/mod.rs |
| M6b | TCP 连接读侧 30s 空闲超时（slowloris 收口） | serve/mod.rs |
| M7 | UDP 会话表容量上限（10k，超限只回显不跟踪，防伪造源洪泛） | serve/mod.rs |
| M2 | packet-dsl `rest(子proto)` 零消费匹配防死循环（`bytes=0` 字段不再挂死） | packet-dsl/src/proto.rs |
| M3 | 算术溢出守卫：`+`/mul/sub/div/shl/shr 全走 checked 运算（debug/release 均不 panic/回绕，溢出报诊断）；div 除零改显式检查，废除 i64::MAX 哨兵（误报/漏报双修） | packet-dsl/src/eval.rs、packet-dsl/src/proto.rs |
| M16 | Unix TCP trace 尊重 `-s` 源绑定（与 Windows Npcap 路径一致） | ping/trace/tcp.rs |
| M18 | IPv6 raw `--wait` 开 ICMPv6 socket + 裸 ICMPv6 回包手工匹配（此前恒开 v4 socket 永远收不到） | engine/pkg/raw.rs |
| M21 | ARP opcode 保真：ArpOp 加 `Other(u16)` 变体，RARP(3) 等未知 opcode 不再静默改写成 request() | packet-dsl ir/dissect/eval/serialize/matchpred + engine/convert.rs |
| M22 | 序列化长度字段 u16 截断防护：IPv4 total_length / IPv6 payload_length / UDP len / TCP 伪头与 data_offset 超限均报 `PacketTooLong`（raw 直喂与非 raw 两条路径都覆盖） | packet-dsl/src/serialize.rs |
| L9 | `-4`/`-6` 对 IP 字面量生效（`ping -4 ::1` 报错而非静默走 v6） | util/dns.rs |
| L13 | `print_paged` 容忍 pager 提前退出的 EPIPE + 子进程回收 | manual.rs |
| L16 | `LANG=""`（空串）落入 macOS 系统 UI 语言兜底 | prping-cli/src/main.rs |
| L2 | 手写 JSON 转义补全：新增共享 `json_escape`（`\\`、`"`、换行/控制字符），替换 stats/bandwidth/mtu 全部手写只转 `"` 的站点 | util/format.rs、stats.rs、bandwidth.rs、mtu.rs |
| L3 | stats 采样窗口 `remove(0)` O(n²) → VecDeque `pop_front` O(1)（无限 ping 高频率长跑不再被 memmove 拖垮） | stats.rs、drive.rs |
| 重构 | `all_exports_raw_only` 同文件重复解析 3 次 → 缓存一次（显式 `--raw` 时跳过预检） | prping-cli/src/main.rs |
| 重构 | justfile `check-all` 不再 `|| echo` 吞编译错误：工具链缺失跳过、编译错误汇总后 exit 1（门禁恢复可靠） | justfile |
| M25 | 错误分类去字符串耦合：Diagnostic 加 `DiagnosticKind` 判别字段（ReplyOutsideRecipe），engine 分析按类别分支（改文案不再静默漂移） | packet-dsl diag/eval/parser + engine/eng/mod.rs |
| L5 | ICMP send 错误不再伪装成 Timeout：`IcmpErr::Send(msg)` 变体 + 人读显示真实原因、JSON `send failed` | ping/icmp.rs + locales |
| M28 | Windows 抓包 `direction(In)` 与 `-a` 全帧语义冲突：`open_capture` 加 `filter_self` 参数——serve 全帧模式关闭入向过滤（三平台语义对齐） | engine/rawpcap/mod.rs、serve/capture.rs、ping/trace/tcpwin.rs |
| M10 | UDP 会话计时去掉 2s 空闲尾巴（`last_activity - start`）+ 提取共用 `accumulate_micros` 辅助（TCP/UDP 一致） | serve/mod.rs |
| M11 | UDP latency 回包校验来源地址 == 目标（杂包忽略继续等；此前迟到的回显被消费成虚假 RTT） | ping/latency.rs |
| M12 | latency 缺省 10 次有效探测（此前 max(1) 吞成 1 次，单样本统计无意义）；`-n 0` = 无限 | prping-cli/main.rs、lib.rs |
| M27 | IPv4 IHL 合法域 [20,60] + total_length 交叉校验（畸形帧不再误读端口）；`patch_zero_src` 按实际 IHL 重算校验和（IHL>5 带选项包此前校验和错） | serve/capture.rs、engine/pkg/send.rs |
| M24 | sniffer proto 字段按声明类型定宽编码（u8→1B/u16→2B/...；此前按值最小宽度，`u8(1)` 与 u8 字段恒不匹配、`be16(1)` 反而误匹配） | packet-dsl/matchpred.rs |
| L4 | stats：avg 改 f64 除法（>4G 样本 u32 除数截断）；percentile 校验 p∈[0,100]（越界不再 panic） | stats.rs |
| L6 | bandwidth：UDP send 错误优雅结束并提示（不再 `?` 中止）；并行任一连接失败收集并提示部分结果（不再丢全部测量） | ping/bandwidth.rs |
| L7 | bandwidth：parallel 报告改 u32（>65535 不再截断）；count×size 改 saturating_mul；UDP receive 补 `sampler.finish` | ping/bandwidth.rs |
| L8 | ICMP seq 回绕（>65536 次迭代）时轮换 ident——固定 (ident,seq) 复用不再把迟到旧回包错配到当前迭代 | ping/icmp.rs |
| L10 | Windows ICMP 载荷按 MAX_UDP 钳制（IcmpSendEcho2 DataSize 是 u16，>65535 静默截断） | ping/icmp.rs |
| L11 | serve echo_ok 一次性闩锁改 1s 冷却重试（一次瞬时拥塞不再永久关闭该连接回显） | serve/mod.rs |
| L14 | bind_udp 读回实际缓冲并提示（Linux rmem_max 静默夹紧 4MB 请求） | util/net.rs |
| L17 | listen_raw 去重命中不再计 total（total - matched = 未命中数，口径一致） | engine/pkg/listen_raw.rs |
| L19 | `--lang` 忘带值不再吞掉相邻的文件名/子命令（仅合法 locale 形态才消费） | prping-cli/main.rs |
| L20 | trace UDP 内嵌报文补 version==4 校验（与 TCP/tcpwin 路径一致） | ping/trace/udp.rs |
| L1 | `drain_after_send` 响应 Ctrl+C + 100ms 分片超时（对不随 EOF 关闭的对端不再无限挂起） | util/net.rs |
| L6 补 | bandwidth TCP 单连接 send 错误优雅结束并提示（不再 `?` 中止） | ping/bandwidth.rs |
| L15 | UDP 触发包 parse 校验 size∈[1,MAX_UDP]（UDP ping 8B 载荷 seq=0xFFFF0000 的假触发被拒绝按普通回显处理） | util/format.rs |
| L18 | pcap 多设备监听线程运行期全部退出时主循环感知并结束（不再静默挂起） | engine/pkg/listen_raw.rs |
| L21 | `encode_dns_name` 补总长 ≤255 校验（RFC 1035；与 tpl %L 一致） | packet-dsl/serialize.rs |
| L22 | FieldNe 字段缺失语义统一：缺失 → ne 成立（回包/发包两侧一致，不再判定相反） | packet-dsl/matchpred.rs |
| L12 | IPv6 扩展头链式追跳（Hop-by-Hop/路由/分片/AH 等，有界 8 层）+ Fragment 偏移检测（带扩展头的本服务流量不再漏判） | serve/capture.rs |
| 重构 | lib.rs 公开面文档化：engine/pkg API 随 CLI 公开，确认为事实稳定面（注明收紧路径） | lib.rs |
| -l | ICMP 载荷按 MAX_UDP clamp（协议硬上限；Unix 超限 send 报错、Windows u16 截断，统一处理） | lib.rs |
| 重构 | trace 三处手写 `from_raw_parts` unsafe 切片统一收敛到 `util::init_slice` | ping/trace/mod.rs、tcp.rs |
| 重构 | `match_tcp_reply_v4` 直接透传共享函数的 is_dest（删除 tcp_flags 二次解析同一包） | ping/trace/tcp.rs |
| 重构 | build.rs 仅内容变化时重写 runner 脚本（不再每次覆盖用户自定义）；OUT_DIR 祖先扫描替代裸 unwrap | prping-cli/build.rs |
| 重构 | serve 抓包 keep 过滤 4 处复制收敛为 `frame_keep`/`bare_ip_keep` 共享函数 | serve/capture.rs |
| 重构 | LSP definitionProvider：`textDocument/definition` 跳转到元件/函数/proto/导出定义位置 | engine/eng/lsp.rs |
| A2 | TraceSocket 逐跳骨架收敛：`trace_loop_skeleton`（渲染上一跳/interrupted/PendingHop 收尾）三路径共用——ICMP/UDP 的 trace_loop、Unix TCP（tcp.rs）、Windows Npcap TCP（tcpwin.rs）各只保留发送/收集差异点（约 90 行复制消除） | ping/trace/mod.rs、tcp.rs、tcpwin.rs |
| D2 | UDP 触发协议 count 反射风险文档化（已做缓解：size clamp/同源并发/无进展超时/假触发校验；根治需来源认证，注明取舍） | serve/mod.rs |
