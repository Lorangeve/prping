# prping 全覆盖可复现单元测试计划

> 背景：现有 575 个测试中 ≈48% 集中在 packet-dsl 的 DSL 集成测试，运行面
> （ping/serve/stats/util/web/cli）覆盖稀疏。本计划把测试体系补齐为：
> **按模块清单化全覆盖 + 分层可复现（无外网、固定种子、显式特权分级）+ 一条命令复现**。
>
> 本文档定义「测什么、怎么分层、怎么复现」；用例落地按 M1/M2/M3 里程碑分批执行，
> 每批合并后本计划中的用例清单同步勾销（加 ✅）。

---

## 1. 现状基线（盘点于本计划编制时）

### 1.1 总量与分布

| crate | src 文件 | src LOC | 测试数 | 测试落点 |
|---|---|---|---|---|
| packet-dsl | 16 | 14 334 | 278 | `tests/` 9 个文件（eval 85 / semantic 43 / proto_func 41 / parse 31 / field_meta 20 / golden 18 / dissect 13 / proto_headers 9 / total_probe 1）+ 内联 17 |
| prping-core | 49 | 22 732 | 263 | `tests/` 5 个文件（pkg 64 / protocol 19 / engine 14 / convert 11 / pcap 3）+ 内联 159 |
| prping-cli | 1 | 2 183 | 34 | `tests/integration.rs` 23 + `main.rs` 内联 11 |
| **合计** | 66 | 39 249 | **575** | `#[ignore]` 0 个 |

### 1.2 零测试文件清单（计划的主要填补对象）

以下 src 文件**自身没有内联测试**（括号注明是否被外部集成测试覆盖及程度）：

| 区域 | 文件（LOC） | 现有外部覆盖 |
|---|---|---|
| packet-dsl | lexer(543) parser(1886) ast(478) ir(490) eval(2160) semantic(2215) serialize(886) dissect(831) matchpred(993) tpl(522) registry(1063) diag(103) | eval/semantic/parse/golden/dissect 集成覆盖主路径；**错误恢复、边界、matchpred/tpl/diag/registry 完整性是缺口** |
| 测量面 | ping/bandwidth(787) latency(263) tcp(111) udp(159) trace/{icmp,udp,dns}(520) | 均无；protocol.rs 只经 `run()` 间接触达 TCP ping |
| 服务端 | serve/mod.rs(521) | protocol.rs 覆盖回显/触发主路径，**错误路径与边界无** |
| 引擎 | pkg/send(1146) pkg/raw(471) pkg/listen(251) pkg/sniffer(13) pkg/mod(254) engine/recipe(918) pcap(127) rawpcap/device(110) eng/lsp(717) | pkg 系经 tests/pkg.rs 部分覆盖；lsp 经 tests/engine.rs；**raw/listen/pcap feature 门控路径无** |
| 基础设施 | util/config(85) util/mod(43) output(206) | 全无 |
| web | web/mod.rs(184) | http/ws/pipe/assets 各 3–5 个内联，信封协议与防御逻辑覆盖薄 |
| cli | main.rs(2183，内联 11) | validate_*/前缀展开/argv 解析矩阵大量缺失 |

### 1.3 已有可复用测试资产（约定来源，新测试必须沿用）

| 资产 | 位置 | 用途 |
|---|---|---|
| 端口分配 `alloc_port()`（AtomicU16 计数） | tests/protocol.rs(23000+)、tests/integration.rs(22000+) | 回环端口确定性；**计划收敛为统一 helper，避免两套计数器交叠** |
| `wait_port()` / `ServerGuard`（Drop 兜底杀进程） | tests/integration.rs | 子进程服务端生命周期 |
| 进程内 serve + `set_interrupted(true)` 注入退出 | tests/protocol.rs | 无信号依赖的优雅退出测试 |
| `DefaultSerializer::with_seed(1)` | tests/convert.rs 等 | DSL 随机字段固定种子 |
| `ensure_proto_registry()` | tests/pkg.rs | dissect 前注册 proto 函数 |
| `run_lsp_on`（内存读写对跑 LSP 会话） | tests/engine.rs | LSP 无进程测试 |
| 临时文件命名 `prping-*-{pid}.tmp` | tests/convert.rs、pcap.rs | 文件系统测试隔离 |
| Linux `cargo test` 自动 setcap cap_net_raw | `.cargo/config.toml` runner + `.cargo/run-with-cap.sh` | L2 特权层在本机/CI 可直接跑（依赖 passwordless sudo，无则降级跳过） |

---

## 2. 可复现性原则（硬规则，所有新测试必须遵守）

- **R1 禁真实外网**：一切对端为 `127.0.0.1`/`::1` 回环、内存管道或固定字节黄金文件。
  字符串如 `example.com` 只允许作为不解析的字面量 fixture。
- **R2 时间受控**：断言不依赖真实时钟精度；间隔/超时逻辑用「下限断言」（耗时 ≥ X）
  或注入时钟；单测总时长目标 < 30s，任何单测试 > 5s 需说明。
- **R3 端口确定性**：统一 `alloc_port()`（原子递增 + bind 冲突自动重试），
  禁止硬编码端口；UDP 与 TCP 计数段分离。
- **R4 随机固定**：一切随机（DSL seed、fuzz、端口回退）必须可注入固定种子；
  默认 seed=1。
- **R5 平台显式化**：`cfg(windows)` 路径（icmpwin/tcpwin/Npcap）只在 Windows 跑，
  其余平台 compile-check（`just check-all` 已有）；Unix 专属同理。
- **R6 特权分级**：依赖 cap_net_raw 的测试归 L2，运行时探测能力，无特权时
  `eprintln!` 说明并 return（不 fail），保证 L0/L1 在任何环境全绿。
- **R7 文件系统隔离**：tempdir + pid 命名（沿用现约定），测试内清理，
  不依赖 `$HOME`/cwd。
- **R8 黄金文件流程**：字节级黄金断言内联在测试里（hex 字面量），
  大文件放 `tests/golden/`；更新走 `PRPING_UPDATE_GOLDEN=1` 重生成 + diff 审查。
- **R9 locale 显式**：涉及 i18n 文案的断言先 `--lang en-US` / 设置 rust-i18n
  locale，不依赖环境 `$LANG`。
- **R10 异步确定性**：进程内异步测试沿用「smol 全局 executor + `smol::block_on` +
  std 阻塞 socket 对端」模式（protocol.rs 既有模式），不引入 tokio。

---

## 3. 测试分层与运行矩阵

| 层 | 定义 | 依赖 | 默认执行 | 数量目标（新增） |
|---|---|---|---|---|
| **L0 纯单元** | 纯函数：构造/解析/格式化/校验/统计 | 无 IO | `cargo test` 全环境 | ≈60% |
| **L1 回环** | 127.0.0.1 TCP/UDP 客户端×服务端配对 | 回环 socket | `cargo test` 全环境（CI 三平台） | ≈25% |
| **L2 特权** | raw ICMP / AF_PACKET / tcpdump 路径 | cap_net_raw（Linux runner 自动 setcap；无特权自动跳过） | Linux/macOS 本机 + CI Linux | ≈8% |
| **L3 子进程 CLI** | `CARGO_BIN_EXE_prping` 驱动 bin：argv/退出码/输出 | 编译产物 | `cargo test --all-targets` | ≈5% |
| **L4 黄金** | 字节/文本快照断言（内联 hex 或 tests/golden/） | 无 | `cargo test` | 分布于各层 |

feature 门控层（不占上述配额）：

| 门控 | 内容 | 执行点 |
|---|---|---|
| `--features pcap` | pkg/raw 发送、capture 多设备路径的**编译**+可跑单测（文件/mock 层） | CI ubuntu（libpcap-dev 已装）新增 `just test-pcap` |
| `--features web-embed` | assets 内嵌模式 lookup/503 | CI 已有 check，新增 1–2 个单测 |
| `cfg(windows)` | icmpwin/tcpwin 既有内联 + 补充解析类单测 | CI windows |

### 复现命令（落地后可用）

```bash
just test                 # 现有：cargo test --all-targets --workspace（L0/L1/L3/L4 + L2 尽力）
just test-unit            # 新增：cargo test --workspace --lib --bins（进程内单测，无子进程/无外部服务端）
just test-loopback        # 新增：cargo test --workspace --tests（集成测试文件；回环配对集中于此）
just test-privileged      # 新增：cargo test --workspace --lib --bins -- prping::icmp ping_loopback …
#                         按 L2 用例名过滤运行；无 cap_net_raw 时用例内探测并跳过（R6）
just test-golden          # 新增：cargo test -p packet-dsl --test golden
#                         + -p prping-core --test convert --test pcap（黄金/字节级集中地）
just test-pcap            # 新增：cargo test --workspace --features pcap（CI ubuntu，libpcap-dev）
just test-coverage        # 新增（可选跟踪）：cargo llvm-cov --workspace --all-targets --summary
```

> 配方按「测试文件/名称过滤」组织；新测试文件落地时同步把归属层写进对应配方
> （本计划 §5 各用例已标注层归属）。`just check-pcap` 同步追加
> `cargo test --workspace --features pcap`，使 pcap 门控从「仅编译」升级为「编译+测试」。

CI（`.github/workflows/ci.yml`）增量：`just test` 保持三平台门禁；
ubuntu 增设 `test-pcap`（非门禁）；llvm-cov 汇总上报（非门禁）。

---

## 4. 测试基础设施补齐（M0，先于用例落地）

1. **`crates/prping-core/tests/common/mod.rs`**（新）：
   统一 `alloc_port()`（TCP 23000+/UDP 24000+ 两段）、`wait_port`、
   `TempFile`（RAII 删除）、`golden_eq!`/`golden_hex!` 宏（`PRPING_UPDATE_GOLDEN` 支持）、
   `has_cap_net_raw()` 探测、smol block_on 包装 helper。
2. **`crates/packet-dsl/tests/common/mod.rs`**（已有，扩充）：错误断言宏
   （`assert_parse_err!` 校验错误类型+位置）。
3. **时钟注入点**（仅当 M2 落地 jitter/interval 逻辑重构时）：`drive.rs` 抽
   `Clock` trait，生产实现 `SystemClock`，测试用 `ManualClock`；不改默认行为。
4. **justfile**：新增 `test-unit/test-loopback/test-privileged/test-golden/test-pcap`
   配方（`cargo test --test <target>` 组合，见 §3）。

---

## 5. 模块测试矩阵

> 用例列法：`ID | 名称 | 层 | 断言要点 | 优先级`。P0=正确性回归防护（M1），
> P1=边界与错误路径（M2），P2=边缘与覆盖率收尾（M3）。

<!-- SECTION:UTIL -->

### 5.2 ping/ + serve/（测量面与服务端）

> 现状：ping/ 内联 31（icmp 12、mtu 5、trace/mod 6、trace/tcp 4、tcpwin 4），
> tcp/udp/latency/bandwidth/trace 的 icmp·udp·dns 零内联；serve/mod.rs（521 行）零内联。
> capture.rs 21 个内联测试但存在 cfg 盲区（`strip_null` BE 分支等在 Linux 默认构建不编译）。

#### 5.2.1 ping/icmp.rs（构造黄金 + 应答解析）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| ICMP-1 | build_v4_golden_hex / build_v6_golden_hex | L4 | `build_v4(0x1234,1,4)`→`0800e3c6 1234 0001 00010203`；`build_v6`→`80000000 abcd 0001 …`（落地跑一次固化，替换现有「非零即过」弱断言） | P0 |
| ICMP-2 | icmp_cksum_rfc1071_golden + odd_length | L4 | RFC1071 手算黄金；奇数长度折叠分支 | P0 |
| ICMP-3 | build_v4_corrupt_cksum_detected | L4 | 翻转载荷 1B → 重算 cksum ≠ 存值 | P0 |
| ICMP-4 | parse_reply_v6_unreach_and_ttl / with_header | L0 | v6 type1/type3＋内嵌 40B 匹配→Unreachable/TtlExceeded；48B 带头读 hop_limit | P0 |
| ICMP-5 | build_v4_varlen_payload_pattern | L4 | size=300：len=308、载荷 `i%256` 循环、id/seq 位置不变 | P1 |
| ICMP-6 | parse_reply_v4_err_truncated_inner / unknown_type | L0 | type3 内嵌头<8B → Timeout（杂包续等）；type13→Timeout | P1 |
| ICMP-7 | ping_loopback_end_to_end（v4+v6） | L2 | `run()` ICMP→127.0.0.1/::1 count=2：received=2、rtt>0（cap_net_raw runner） | P0 |
| ICMP-8 | send_recv_ignores_foreign_icmp | L2 | 杂包不误判（确定性弱，后置） | P2 |
| ICMP-9 | eff_ident_seq_rotation（**抽纯函数**） | L0 | seq>65535 的 ident 轮换决策（现内联不可测） | P2 |

> 行为决策点：`parse_reply` 全程不校验 ICMP cksum（坏校验和不检出）——
> 落地 M2 时要么补校验并加反例测试，要么在代码注释文档化现状。

#### 5.2.2 ping/tcp+udp+latency（回环配对）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| LP-1 | tcp_ping_connect_refused | L1 | 未监听端口 count=1：received=0、lost=1（退出码 1 语义） | P0 |
| LP-2 | tcp_ping_loopback_listener | L1 | 临时 listener：received=count、报告行含 peer | P0 |
| LP-3 | udp_ping_loopback_echo / udp_ping_timeout_unanswered | L1 | echo 线程配对 received=count；无 echo→received=0（count=1 控时） | P0 |
| LP-4 | latency 四方向闭环（tcp/udp × echo/receive_trigger） | L1 | lat-01..04：read_exact(size)、`[0xFF]` 触发读 1+size、UDP trigger 收 size 数据报（serve 配对，SERVER_LOCK） | P0 |
| LP-5 | udp_ping_stale_seq_ignored | L1 | 第 1 包回错 seq、第 2 包回对 seq → 按序号归属 | P1 |
| LP-6 | latency_udp_foreign_src_filtered | L1 | 服务端绑 127.0.0.2 回包被 src 过滤→Err（Linux 可绑 127/8） | P1 |
| LP-7 | latency_tcp_connect_refused | L1 | 无服务→Err、received=0 | P1 |
| LP-8 | tcp_ping_warmup_not_counted | L1 | warmup=1,count=2：成功 2 次且 warmup 不入统计（drive 契约） | P1 |
| LP-9 | tcp/udp duration 模式、多地址回退、min payload 钳制 | L1 | duration=Some(0.3) 收尾；size=0→载荷 4B | P2 |

#### 5.2.3 ping/bandwidth.rs

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| BW-1 | should_stop_branches | L0 | count 用尽/deadline 过期/set_interrupted→true（后 reset） | P0 |
| BW-2 | parallel_quota_total_exact | L1 | parallel=5,count=3：total_bytes==3×size（配额不丢不发超——注释自称修复过但无测试） | P0 |
| BW-3 | tcp_receive_target_truncation | L1 | count=1,size=1000（非 64KB 整块）：total_bytes==1000 而非 65536 | P0 |
| BW-4 | make_progress_kind_selection | L0 | duration→Time；receive→Bytes(count×size)；send→Packets；milestone=total/20.max(1) | P1 |
| BW-5 | sampler_window_samples | L0 | 100ms 窗口内不采样、过窗采 1 条、finish 补尾窗（~150ms） | P1 |
| BW-6 | bandwidth_duration_mode / tcp_warmup_extra_bytes | L1 | 0.3s 收尾；warmup=2,count=2 服务端累计收 4×size | P1 |
| BW-7 | udp_trigger_count_decision（抽纯函数）/ report_json_label_escape | L0 | duration→u32::MAX 饱和；label 含 `"`/`\` 仍合法 JSON | P2 |
| BW-8 | tcp_send_error_graceful_break | L1 | 对端 accept 即 drop：break 不 panic、报告已发字节 | P2 |

#### 5.2.4 ping/mtu.rs

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| MTU-1 | classify_ihl6_ip_options / classify_frag_needed_no_mtu_field | L0 | IHL=6 内嵌偏移正确；type3 code4 长度<14（缺 MTU 字段）→None | P1 |
| MTU-2 | bisect_step_decision（**抽 `bisect_step(lo,hi,fits)`**） | L0 | mid=lo+(hi-lo).div_ceil(2)；fits→lo=mid 否则 hi=mid-1；收敛表测 | P1 |
| MTU-3 | is_msg_too_big_platform | L0 | EMSGSIZE/10040→true；EINVAL→false（cfg 三平台） | P1 |
| MTU-4 | probe_mtu_loopback_baseline | L2 | 127.0.0.1 全可过：payload_max=65507、mtu=65535（~17 探测） | P1 |
| MTU-5 | classify_echo_wrong_ident / 死目标重试 | L0/L2 | id 不匹配→None；10.255.255.1 重试+notes 仅手工 | P2 |

#### 5.2.5 ping/trace/*

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| TRC-1 | v4_ttl_exceeded_matches_inner（mod+icmp 两文件矩阵） | L0 | type11 code0＋内嵌 IP＋eicmp id/seq→(seq,false)；inner dst≠target→None；**v4 Time Exceeded 现零覆盖** | P0 |
| TRC-2 | skeleton_reached_break_interrupt | L0 | trace_loop_skeleton：dest_hit→reached；rtts 空→break；中断中途退出 | P0 |
| TRC-3 | dns_hostname_channel_lifecycle / pending_hop_dns_gating | L0 | 发送端 drop→None；no_dns→rx=None | P0 |
| TRC-4 | tcp_checksum_v4_golden + v6_and_mixed_family | L4 | 黄金值落地固化；(V4,V6) 混族→0 | P0 |
| TRC-5 | build_tcp_syn_layout_csum / tcp_frame_v6_short_buffer_no_panic | L0 | offset=5/flags=0x02/cksum 自洽；**<24B 短帧不 panic（曾 index panic 回归）** | P0 |
| TRC-6 | parse_udp_icmp_v4/v6 矩阵（trace/udp 现零覆盖） | L0 | type11/0 与 type3/3（port unreachable）→Some；错 dst/端口∉want→None；v6 带头/无头两格式 | P0 |
| TRC-7 | is_port_unreachable_matrix | L0 | v4 3/3 true、11/0 false；v6 1/4 true；空 buf false | P0 |
| TRC-8 | parse_ttl_exceeded_v6_carries_syn | L0 | 内嵌 40B v6 头＋TCP 端口镜像→Some(sport) | P0 |
| TRC-9 | v4_ttl_exceeded_truncated_fallback / match_tcp_syn_reply_v4_edges | L0 | 内嵌<8B→归属 want[0]；ihl>5、len<ihl+20、仅 ACK | P1 |
| TRC-10 | fake_socket_hop_collect / trace_icmp_loopback_one_hop | L0/L2 | Fake TraceSocket 队列回包归属；L2 单跳：ICMP/UDP(关端口)/TCP(serve listener) 三技术 hop1 reached | P0 |
| TRC-11 | tcp_frame_v6_header_detection / parse_reply_frame_rejects_garbage（tcpwin，cfg any(windows,test) 全平台可测） | L0 | 带头跳 40B；ethertype≠0x0800、len<34→None；ttl=300→255 钳制、DF=0x4000 | P1 |
| TRC-12 | reverse_dns 通道生命周期 | L0 | recv_timeout 内必得 Some\|None（内容断言不可复现，豁免进 §7） | P2 |


#### 5.2.6 serve/mod.rs（回显/触发/聚合）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| SRV-1 | accumulate_micros_truncates_and_ignores_non_positive | L0 | 1.5s→+1_500_000µs；0/负忽略；1.0000009s→截断 | P0 |
| SRV-2 | flush_idle_udp_sessions_expires_and_accumulates | L0 | 回填 last_activity：到期移除+micros 累计 elapsed；未到期保留；bytes=0 过期静默 | P0 |
| SRV-3 | udp_trigger_size_zero_falls_back_to_echo | L1 | `[FF FF 00 00 +4B]` → 回显 8B、不触发 | P0 |
| SRV-4 | udp_trigger_truncated_and_oversized_echoed | L1 | 4B/9B 伪触发包（len≠8）→ 原样回显 | P0 |
| SRV-5 | tcp_echo_write_timeout_cooldown_and_drain | L1 | 客户端发 2MB 不读 → 写超时进 1s 冷却；连接不 RST、继续排空、恢复后可读；report.bytes==2MB | P0 |
| SRV-6 | tcp_0xff_boundary_cases | L1 | 非首包 0xFF 回显；单写 `[FF FF]`（n=2）不触发；发 0xFF 后半关闭仍进接收模式 | P0 |
| SRV-7 | tcp_receive_mode_64k_blocks | L1 | 读满 65536B 全 0x00；report.sent 为 65536 正整数倍 | P0 |
| SRV-8 | tcp_concurrent_clients_interleaved | L1 | ≥3 客户端交错 echo 各自正确；connections 计数正确 | P0 |
| SRV-9 | server_report_aggregation_semantics | L1 | echo bytes + 触发 sent + mbps==(bytes+sent)×8/secs 口径（**客户端读完再关**同步化，替代 80ms 收尾等待） | P0 |
| SRV-10 | udp_trigger_count_zero_sends_nothing | L1 | count=0 → sent==0、同源配额释放 | P1 |
| SRV-11 | udp_trigger_size_limits / same_source_dedup | L1 | size=65507 接受、65535（>MAX_UDP）拒→回显；大 count+不读延长任务寿命→同源第二触发被忽略 | P1 |
| SRV-12 | tcp_receive_mode_write_timeout_closes_conn | L1 | 接收模式写超时→EOF（与 SRV-5 排空语义相反，锁定差异） | P1 |
| SRV-13 | udp_session_elapsed_uses_last_activity / pure_udp_secs_via_drain | L0/L1 | 会话时长=last-start；中断 drain 路径使 pure UDP report.secs>0（不等 2s 空闲） | P1 |
| SRV-14 | tcp_client_disconnect_cleans_up | L1 | 半途 RST → 新连接仍可接受（配额未泄漏） | P1 |
| SRV-15 | serve_invalid_filter_is_hard_error | L1 | `Some("(")` → Err（bind 前返回，无特权可测） | P1 |
| SRV-16 | 长时/大规模分支（30s 空闲收割、1024 连接上限、10000 会话表溢出、触发 30s 无进展） | L2 | `#[ignore]` 标记，手动/夜间跑 | P2 |

#### 5.2.7 serve/capture.rs（抓包与 --filter）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| CAP-1 | parse_ip_base_v4_rejects_bad_ihl_and_total | L0 | IHL<5/>60→None；total<ihl、len<ihl+4→None（现零覆盖） | P0 |
| CAP-2 | parse_ip_base_v6_ext_header_chain | L0 | Hop-by-Hop/路由/目的头 (n+1)×8 推进、8 层上界、off>len→None、终点 proto/端口 | P0 |
| CAP-3 | parse_ip_base_v6_fragment_offset | L0 | 13 位偏移提取；offset>0 → meta None | P1 |
| CAP-4 | frame_keep_service_filter_overrides_expr | L0 | (Some(sf),Some(e))→只按 sf；三态收敛 | P1 |
| CAP-5 | filter_matches_ctx_without_dissect / filter_port_boundaries | L0 | noctx 下 port/host→false；0/65535 合法、65536 拒 | P1 |
| CAP-6 | filter_ip6_and_icmp6_host_chain | L0 | `ip6 host ::1`、`icmp6 host ::1` 展开与匹配 | P1 |
| CAP-7 | frame_summary_unknown_ethertype_none | L0 | VLAN 0x8100 等→None（锁定「--filter 仅 not/or 可命中」语义） | P1 |
| CAP-8 | local_addresses_contains_loopback | L0 | 127.0.0.1 在列（补 cfg(windows) 用例锁定现状） | P1 |
| CAP-9 | strip_null_accepts_be_and_le_family（**cfg 放宽至 test**） | L0 | DLT_LOOP 大端变体也剥头（现测试 Linux 默认构建不编译，回归盲区） | P1 |
| CAP-10 | print_summary_three_variants_rendering | L0 | 注入 `NoColor<Vec<u8>>` 断言 Transport/Ip/Arp 三分支文本 | P1 |
| CAP-11 | arp op∉{1,2}→None / proto_name 全表 / ip6 分片行为锁定 | L0 | 未知 op、0x8100、6/17/47/50/51/58/89/132/未知全表；v6 非首片仍出 Transport（与 v4 差异钉住） | P2 |
| CAP-12 | spawn 双态（有/无 cap_net_raw → Active/Unavailable）与平台抓包循环 | L2 | 接受双态不 panic；Linux AF_PACKET/Npcap/BPF 全部 feature+特权门控 | P2 |

**serve 区复现性约定**：serve 用例必须持 `SERVER_LOCK` 互斥（`set_interrupted` 全局）；
端口一律 `:0` 回读（并轨 22000/23000 两套计数器）；聚合断言用「客户端读到 EOF 再关」
同步，不依赖 80ms 收尾等待；慢客户端用例注意 smol 单线程 executor 让出（读侧用独立
线程）；依赖 dissect 注册表的用例沿用 `remaining.is_empty()` 守护防缺库机器误报；
「空注册表」类错误分支需独立进程验证（OnceLock 顺序不可复现）。

### 5.3 engine/（包构造引擎）

> 现状：tests/pkg.rs 64、tests/engine.rs 14（LSP）、tests/convert.rs 11、tests/pcap.rs 3；
> 内联散布在 eng/mod(6)、pkg/recipe(11)、listen_raw(4)、rawpcap(10)、convert(2)、display(2)。
> 零覆盖文件：pkg/send、pkg/raw、pkg/listen、pkg/sniffer、pkg/mod、engine/recipe（.pktl 解析）、
> engine/pcap、rawpcap/device（Linux 默认构建）、eng/lsp（仅集成覆盖）。

#### 5.3.1 eng/mod.rs + eng/display.rs（分析与渲染）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| ENG-1 | analyze_text_json_structure | L0 | `analyze_text_json` 产 JSON：tool/cmd/mode/total、packets[].hex 与手工序列化一致、layers[].raw、raw_only 布尔（web 与 CLI --json 同构契约） | P0 |
| ENG-2 | analyze_recipe_json_overview | L4 | tmp .pktl+.pkt → globals[].init / params[].required / steps[].wait/raw/extract.from/on_error 逐键断言 | P0 |
| ENG-3 | render_hexdump_golden | L4 | 固定 20B 输入 → 逐字符黄金（偏移 0000、pad、`|ASCII|`、16B/行） | P0 |
| ENG-4 | validate_expr_reply_leaves | L0 | 字面量未知层/字段报错；动态参数 `reply(g("l"),"f")` 跳过 | P1 |
| ENG-5 | analyze_recipe_rejects_bad_extract | L4 | 未知层/未知字段/`reply.peer.mac` → 报错含行号 | P1 |
| ENG-6 | describe_packet_layers_raw_feed | L0 | 字节直喂层 desc 含真实 len/chksum/proto（scapy 风格）、raw=true | P1 |
| ENG-7 | describe_raw_bytes_per_layer | L0 | eth/arp/icmp/tcp(FIN,SYN)/ipv6 traffic_class 字段串黄金 | P1 |
| ENG-8 | value_display_scalar_forms | L0 | `0x0800` 四位对齐、`0x00` 两位、Param 默认值、Call/BinOp | P2 |
| ENG-9 | decode_hex_rejects_bad_input | L0 | 奇数长度/非 hex 字符报错 | P2 |
| ENG-10 | dns_type_name_and_rdata / stack_warning_messages_kinds | L0 | A/AAAA/未知→"?"；六种 StackWarningKind 各产一条本地化 note | P2 |

#### 5.3.2 eng/lsp.rs（LSP 协议）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| LSP-1 | definition_jumps_to_def_and_func | L0 IO | `textDocument/definition`：defs/funcs 命中返回 range（1 基 span→0 基行列）；未命中→Null（现状完全未测） | P0 |
| LSP-2 | read_message_rejects_oversize_and_missing_len | L0 IO | Content-Length>16MiB、缺头 → -32700，不崩溃 | P1 |
| LSP-3 | did_change_takes_last_change | L0 IO | 多条 contentChanges 取末条 | P1 |
| LSP-4 | uri_info_and_percent_decode | L0 | `file:///a%20b/x.pkt`；非 file://→untitled | P2 |
| LSP-5 | hover_keyword_branches / completion_masks_lib_by_local_def | L0 IO | export/import/use/func 黄金 markdown；本地定义遮蔽库导出去重 | P2 |

#### 5.3.3 pkg/（send/recipe/listen/raw/mod）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| PKG-1 | match_reply_icmp_v4_v6_matrix | L0 | v4 echo type0 (id,seq) 命中；v6 请求 128→129；非 echo→None | P0 |
| PKG-2 | resolve_send_target_branches | L0 | 显式目标优先；eth 无 IP→放行+提示；裸 arp+raw→Err；payload 缺 dport→Err | P0 |
| PKG-3 | apply_extract_peer_field_matrix | L0 | peer.ip(str/bytes)/peer.port(hex/int)；无 peer→Err 行号 | P0 |
| PKG-4 | reply_field_value_proto_and_fallback | L0 | dns 层经注册表取 id；raw.bytes→remaining 兜底；icmp.payload 扩展 | P0 |
| PKG-5 | listen_addr_decision_matrix | L0 | 显式 target 优先；单 dport 推导；多 dport→Err；无端口→Err；IPv6→`[::]:port` | P0 |
| PKG-6 | send_payload_tcp_wait_zero_no_read | L1 | TCP wait=0 发送成功且不阻塞读（服务端不回显） | P1 |
| PKG-7 | listen_udp_once_deadline_returns_none | L1 | timeout 到期无包→Ok(None) | P1 |
| PKG-8 | recipe_listen_step_requires_sniffer | L4 | wait: 无值 + .pkt 无 sniffer → 步骤失败 stop | P1 |
| PKG-9 | step_params_override_cli_params | L1 | 步骤 params 同名覆盖 CLI `--params`（dport 参数化验证） | P1 |
| PKG-10 | match_reply_sniffer_requires_sent_report | L0 | sniffer+None report→Err("内部错误") | P1 |
| PKG-11 | reply_is_v6_packet_versions（需放宽 cfg 至 test） | L0 | eth\|ipv6(v6)→true；ipv4→false；无 IP→false | P1 |
| PKG-12 | send_raw_bytes_rejects_non_raw_outer | L0 | 最外层非 eth/ipv4/ipv6 → raw 提示错误（先于系统调用，跨平台可测） | P1 |
| PKG-13 | build_reply_bytes_template_eval_failure | L0 | 模板引用帧中不存在层/字段 → Err 不 panic | P1 |
| PKG-14 | stack_summary_raw_layer_identity / fmt_target_forms | L0 | http/dns 挂非标端口仍显 `<dns…|>`；port=0→仅 IP | P2 |
| PKG-15 | is_fake_ip_boundaries / wait_mode_one_shot_secs | L0 | 198.18–198.19 真、198.17/198.20/::1 假；OneShot/Off/Continuous 三态 | P2 |
| PKG-16 | recipe_retry_exhausted / recipe_delay_interrupted_stops | L1 | retry N 全超时计数正确；delay 期间 `set_interrupted` 提前返回 | P2 |
| PKG-17 | listen_survives_send_phase_failure | L1 | 发送段失败→警告后仍监听并回显 | P2 |
| PKG-18 | handle_frame_dedup_and_stats（需抽纯核小重构） | L0 | 同帧重复不增 total；注入帧回读跳过 | P2 |

#### 5.3.4 recipe.rs（.pktl 解析器，现零内联测试）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| RCP-1 | parse_comment_and_string_hash | L4 | `init: "a#b"` 值含 `#`；行尾 `#` 注释剥离 | P0 |
| RCP-2 | rewrite_reply_leaves_edge_cases | L0 | 字符串字面量内 `reply.` 保留；`reply(...)` 函数形态不二次改写；未配对引号不 panic | P1 |
| RCP-3 | parse_init_value_forms_and_errors | L0 | `0X` 大写；字节列表 [0x1,256] 越界/坏项/空列表 | P1 |
| RCP-4 | parse_step_raw_aliases | L0 | on/yes→On{None}；`"eth0"` 带引号→On{iface}；空引号→Err | P1 |
| RCP-5 | parse_wait_finite_guard | L4 | `wait: nan/inf/1e13` → finite 拒绝；`delay: -1` → Err | P1 |
| RCP-6 | parse_peer_field_validation | L4 | `from: reply.peer.mac` → Err（仅 ip/port） | P1 |
| RCP-7 | parse_indent_outside_section | L4 | 段外缩进行/段头后裸文本 → 行号化错误 | P2 |

#### 5.3.5 convert.rs + pcap.rs + rawpcap/

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| CVT-1 | lossless_layer_by_linktype | L0 | eth→layer；101+v6→ipv6；101+杂→raw；未知→raw+注释行 | P0 |
| CVT-2 | render_layer_bytes_feed_matrix | L0 | ipv4 选项/ipv6 flow_label/tcp urg/dns_bytes/http_bytes 各产 `*_bytes` 片段且 roundtrip | P0 |
| PCP-1 | read_pcap_magic_matrix | L4 | LE/BE × micro/nano 四组 magic 手写头全识别；非法 magic→Err | P0 |
| PCP-2 | read_pcap_incl_len_cap | L4 | incl_len>snaplen、>64MiB（snaplen=0）→Err 不分配（防 OOM 回归） | P0 |
| CVT-3 | fmt_delay_boundaries | L0 | <1μs→None；1.250000→"1.25" 尾零裁剪 | P1 |
| CVT-4 | convert_nano_and_bigendian_pcap | L4 | nano/大端 magic → 记录与时间戳正确 | P1 |
| PCP-3 | read_pcap_truncated_tail | L4 | 末记录截断→返回已有记录（行为固化后断言） | P1 |
| PCP-4 | write_pcap_header_golden | L4 | 前 24B 黄金（magic/版本/snaplen/network）；**ts=now() 不可全量黄金，仅 >0 冒烟** | P1 |
| RPC-1 | parse_mac_valid_invalid_on_linux | L0 | 门控放宽到 `test` 后 Linux 默认可跑（内容已有） | P1 |
| CVT-5 | skip_beyond_total_errors | L4 | skip≥记录数→报错文案 | P2 |
| RPC-2 | ethertype_of_direct / capture_devices_ipv6_addr_match / wrap_ip6_loopback（pcap 门控） | L0 | 0x45→0x0800、0x60→0x86DD、空→None；v6 绑定命中；::1 封装 | P2 |
| RPC-3 | unix_arp_lookup_parses_proc_line（需重构为路径注入） | L0 | 注入 /proc/net/arp 样例行→MAC 提取 | P2 |

**engine 区风险约定**（落地时遵守）：`write_pcap` 时间戳取 `now()` → 黄金只锁固定段；
`new_fuzz()` 时间种子 → 禁对 fuzz 字节黄金断言；`set_json`/`set_interrupted`/
`ensure_proto_registry` 为进程级全局 → 涉及用例集中放串行测试文件；ICMP 回环有内核
替答 → 沿用 icmp_mock 的 `seq+1000` 标记法；端口优先 `bind(0)`+`local_addr` 传递，
弃 probe-bind-drop（TOCTOU）；pcap 专属测试集中 `tests/raw_pcap.rs`（文件头
`#![cfg(feature = "pcap")]`，内部 `list_devices()` 空表则打印跳过）；
`just check-pcap` 追加 `cargo test --workspace --features pcap`。

### 5.4 web/ + prping-cli

> 现状：web 五文件仅 16 个内联测试（http 5 / ws 5 / pipe 3 / assets 3 / mod 0）；
> main.rs 内联 11 + tests/integration.rs 23，validate_* 与 bpaf argv 解析矩阵大量缺失。

#### 5.4.1 web/http.rs + mod.rs + assets.rs + pipe.rs

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| WEB-1 | respond_head_only_keeps_content_length | L1 | HEAD 无 body 但 `Content-Length` 仍为 body 长度（RFC 语义钉住） | P0 |
| WEB-2 | dispatch_config_json / dispatch_traversal_is_404 | L1 | /config.json 200+`wsPath`+no-cache；`/../etc/passwd` → 404（assets 层拒绝） | P0 |
| WEB-3 | sanitize_key_nested_and_mid_empty | L0 | `/a/b/c.js`→Ok；`/a//b`、`/a/b/../c`→None | P0 |
| WEB-4 | lookup_in_roundtrip_with_temp_root（**新增 `lookup_in(root,path)` 包装**） | L4 | 合法键读文件+MIME；缺失键 None（消除 current_exe/cwd 环境依赖） | P0 |
| WEB-5 | read_head_split_and_closed / read_head_rejects_oversize | L1 | 逐字节喂头→Ok(Some)；半头断开→Ok(None)；>64KiB→Err(InvalidData) | P1 |
| WEB-6 | parse_header_whitespace / parse_query_fragment_and_empty_path | L0 | `"Host : a"`→归一；`GET ?x`→path `""`（钉住现状） | P1 |
| WEB-7 | handle_conn_branches（405 / ws 错路径 404 / 缺 key 404 / keep-alive 连发 / Connection: close） | L1 | mod.rs `handle_conn` 全分支（现零测试），经统一回环拓扑 | P1 |
| WEB-8 | serve_web_bind_conflict_errors | L1 | 端口已占→Err（唯一不碰全局中断态的分支） | P1 |
| WEB-9 | mime_of_known_and_unknown | L0 | html/js/json/css/svg/wasm；`.xyz`→octet-stream | P1 |
| WEB-10 | chan_reader_eof_while_blocked / chan_writer_large_chunk_roundtrip | L0 | 阻塞读中发送端 drop→EOF；1MB 单次 write 保序 | P1 |
| WEB-11 | dispatch_assets_cache_headers（需 embed 或注入根） | L1 | `/assets/*` immutable vs 页面 no-cache | P2 |
| WEB-12 | embed_mode_missing_hint_smoke（`--features web-embed` 门控） | L1 | index_missing/missing_hint/source_label 不 panic 非空 | P2 |

#### 5.4.2 web/ws.rs（信封协议 + 防御）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| WS-1 | frame_decoder_bad_utf8_body_skipped | L0 | 非法 UTF-8 帧→静默丢弃不 panic，后续帧可解 | P0 |
| WS-2 | frame_decoder_bad_content_length_discards | L0 | `Content-Length: -5`/`abc`/小写头名→头丢弃不卡死；len==MAX_FRAME 恰好通过 | P0 |
| WS-3 | dispatch_invalid_json_and_unknown_type | L0 | error 信封文案；unknown type 回传 id | P0 |
| WS-4 | ws_loopback_lsp_passthrough | L1 | 真实握手→lsp initialize→收到 `{"type":"lsp"}` 信封（经 `handle_conn` 分派） | P0 |
| WS-5 | ws_loopback_analyze_ok_and_err | L1 | 合法 pkt→`ok:true,data` 与 CLI `--json` 同构；坏文本→`ok:false,error` | P0 |
| WS-6 | accept_handshake_rfc6455_vector | L1 | 已知 key→`s3pPLMBiTxaQ9kYGzzhZRbK+xO=`；101/Upgrade/Connection 头 | P1 |
| WS-7 | ws_loopback_list_and_read | L1 | **显式注入临时 `--lib` 目录**（不依赖烘焙库）；read 未命中→ok:false | P1 |
| WS-8 | read_lib_file_success_via_injected_dir / trailing_slash_rejected | L4 | 临时目录 `t.pkt` 命中；`x.pkt/`、`./x` 拒绝；`C:x` 平台差异只断言 is_err | P1 |
| WS-9 | frame_decoder_zero_len_and_mixed_stream / ws_loopback_binary_lossy | L0/L1 | 0 长度帧；整帧+残帧混块；Binary 帧 lossy 不崩 | P2 |

#### 5.4.3 prping-cli/src/main.rs（解析与校验）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| CLI-1 | parse_target_ipv6_bracket_forms + host_port_and_bad_port | L0 | `[::1]:80`/`[::1]`/`[::1`（拒）/`h:abc`、`h:`（invalid_port）/裸 `::1`→整串 host（现零测试） | P0 |
| CLI-2 | json_conflicts_matrix | L0 | json×pretty/graph/histogram 各报对应冲突；两两关闭→None | P0 |
| CLI-3 | mtu_conflicts_matrix（**抽 `mtu_conflicts()` 纯函数**） | L0 | `-m`×{u,l,g,p,H,n,i,w,q} 9 单项命中名单；无冲突→空（判定现内联在 process::exit 前） | P0 |
| CLI-4 | validate_bandwidth_zero_rejects | L0 | parallel=Some(0)/count=="0"→Err | P0 |
| CLI-5 | validate_engine_full_matrix | L0 | ls+hex/sub+lsp/json×sub/json×lsp/ls+file/lsp+file/to_pkt 无 pcap/structured 无 to_pkt/skip·limit·threads 无 to_pkt→全 Err；合法白名单→Ok | P0 |
| CLI-6 | validate_packet_json_conflicts | L0 | json×Continuous、json×summary→Err（补现测缺口） | P0 |
| CLI-7 | run_inner_ping_typical / run_inner_packet_wait_shapes | L0 | `["ping","-u","-n","5","127.0.0.1:53"]` 字段断言；裸 `--wait`→Continuous、`3.5`→OneShot、`-1`→Continuous、`nan/inf`→解析期 Err；`--count` 缺省 1 | P0 |
| CLI-8 | outcome_exit_nonzero_matrix（**抽 `outcome_exit_nonzero()`**） | L0 | Ping 有损 true/无损 false；Bandwidth/Mtu false；Traceroute !reached true（退出码 1 约定的可测化） | P0 |
| CLI-9 | parse_size_suffixes / parse_count_plain_and_duration | L0 | 64/8k/1m/1.5k/8K/负数；`10s`→duration、`abc`→Err | P1 |
| CLI-10 | validate_ping_latency_pass / bad_histogram_valid_and_invalid | L0 | 干净 args→None；`-H abc`→Some(msg) | P1 |
| CLI-11 | expand_prefix_more_unique_shorts / ambiguous_candidates_ordered | L0 | d→document、w→web、do/we/pin/trac；`p`→Err 含 `ping, packet`（顺序钉住） | P1 |
| CLI-12 | run_inner_latency_bandwidth / server_trace / engine_fields / document_web / exit_codes | L0 | 各子命令典型 argv→结构体（`run_inner` 捕获）；help exit 0、缺参数 exit≠0 | P1 |
| CLI-13 | cli_error_message_variants / render_warning_variants | L0 | 7 错误变体→Some、外变体→None；5 警告变体非空含参数 | P1 |
| CLI-14 | extract_global_lang_prescan（**抽纯函数**） | L0 | `--lang` 前置/子命令后/`--lang=x`/无值不吞 token；`--version`/`-V` | P1 |
| CLI-15 | parse_params_globals_errors / is_recipe_case_insensitive | L0 | `k=v,k2`→Err；空段跳过；globals `0x10`→数值；`.PKTL` 大小写 | P1 |
| CLI-16 | expand_prefix_colon_token_hits_legacy_hint | L0 | `a:b` → legacy 提示 | P2 |
| CLI-17 | resolve_libs_default_and_extra（抽 base 参数注入） | L4 | 临时 lib/ 目录→含默认项 | P2 |

#### 5.4.4 prping-cli/tests/integration.rs（子进程层增量）

| ID | 名称 | 层 | 断言要点 | P |
|---|---|---|---|---|
| INT-1 | version_flag_anywhere | L3 | `["ping","--version"]`、`["-V"]` 均打印版本 exit 0 | P1 |
| INT-2 | packet_json_listen_conflict_subprocess / engine_json_ls_conflict_subprocess | L3 | validate 冲突 exit 1、stderr 关键短语 | P1 |
| INT-3 | ambiguous_prefix_exit_code_two | L3 | `p x` exit 2（区别 validate 的 1，钉退出码约定） | P1 |
| INT-4 | lang_eq_form_accepted / web_bad_addr_errors_fast | L3 | `--lang=zh-CN`；`--addr nonsense` 绑定前报错 | P2 |

**web/cli 区拓扑与风险约定**：
- HTTP 回环统一：`TcpListener::bind("127.0.0.1:0")` → `smol::spawn(handle_conn(stream))`
  → 客户端手写请求字节断言状态行/头（**不引 reqwest**，遵守零新增依赖）；WS 回环用
  仓库既有 async-tungstenite `client_async`，读侧 `Timer+select` 超时防卡死；
  `serve_web` 整体不进常规测试（阻塞于全局 `interrupted()`），仅测绑定冲突。
- 端口策略全面改 `:0`+`local_addr`，弃固定基址递增（22000/23000 双计数器并轨）。
- locale 全局竞争：i18n 断言统一测试开头 `set_locale("en-US")` 且只断言英文关键短语。
- 不可复现豁免：`--open`、`$PAGER`、tty `^C` 回显、二连 Ctrl+C→130（显式列入 §7）。

### 5.5 packet-dsl（DSL 层）

> 现状：集成测试 278 个为全仓最密，但源码 16 文件中 12 个零内联测试；缺口集中在
> **错误路径与报错位置、编解码失败分支、往返幂等、注册表/文档门禁**。
> 盘点发现的真实缺陷（用例落地时先修再测，作为回归钉）：
> ① lexer `||`/`=>`/`==` 错误 span 先 bump 后 err，偏移 1–2 列（与 `!`/`<` 不一致）；
> ② 字符串内裸换行不推进行号，后续 token 行列失真；③ codec `Prefix{prefix_bits:0}`、
> `widths` 含 0 时位移溢出 panic（parser 挡住但绕过可触发）；④ `parse_ast` 设计上只报
> 首个错误（lex 短路 + `errs.first()`），无多错误恢复——需文档化。

#### 5.5.1 eval.rs / semantic.rs / ir.rs（求值/语义/IR 缺口）

> 三文件均 0 内联测试；集成侧 eval/semantic 已密，此处只收**集成未覆盖分支**。
> P0 崩溃级风险：值函数自递归（`func f(x)->bytes{f(x)}`）不走组件循环检测，
> 走 value_depth>=64 分支——超限前存在真实栈溢出风险，需 EV-1 钉住。

| ID | 名称 | 放哪 | 断言要点 | P |
|---|---|---|---|---|
| DSL-31 | value_func_self_recursion_depth_limit | tests/eval.rs | 自递归→"深度超过 64"，不栈溢出 | P0 |
| DSL-32 | 位宽/溢出错误矩阵 | tests/eval.rs | u8(-1)/u8(256)/be16(-1)/be32(2^32) 超范围文案；be64(2^63) 拒；`+` 溢出与非整数相加；div 0；mul 溢出；shl 负移位 | P1 |
| DSL-33 | 函数/proto 参数错误面补全 | tests/eval.rs | 用户函数与 proto 的「命名后位置」分支；proto 字段重复/位置过多；默认值表达式与跨层 deref；返回类型不匹配 | P1 |
| DSL-34 | 重复区/切片/global 元数据 | tests/eval.rs | list/rest 值非列表；item 指向不存在名；bytes 负宽度；global 3 参/非串名/默认值惰性（已设全局不求值默认） | P1 |
| DSL-35 | `#[rule]` 错误路径整簇 | tests/semantic.rs | not 拒绝；or 分支含 mask/startswith 拒绝；and()/or() 空参；mask 非数字/>255；非 k=v 原子；跨层原子拒绝；startswith/contains(at=/in=) 构造与错误；ne/eq 参数个数 | P1 |
| DSL-36 | proto 字段校验补全 | tests/semantic.rs | len 目标前序/缺失/位字段；bits 配非整型；bytes 缺宽度；list 缺 item；switch 互斥；cases 判别值重复；结尾位组不对齐；vint prefix/table 形状错误 | P1 |
| DSL-37 | IR 类型单元（**新建 tests/ir_units.rs**） | tests/ir_units.rs | MacAddr 宽松解析/低 48 位截断；TcpFlags 8 token（含 ece/cwr）与 to_byte/Display；10 个 Layer 变体 serde 往返 + tag 名；三手写 Default 的 auto_checksum=true | P1 |
| DSL-38 | 弃用注解与 import 链 | tests/semantic.rs | #[bind]/#[feature]/#[layer] 迁移报错；#[proto(kind=123)]；双 import 同名冲突；转出口断链；parse_source_at 未落盘 import 解析 | P2 |
| DSL-39 | 杂项边界 | tests/eval.rs | mac 字符串分隔符容忍与错误；ip 字节列表长度；"random" 关键字拒绝；typed_layer http 响应形态/arp Other 回填/ipv4 flags 掩码；reply 元数 | P2 |

#### 5.5.2 dissect.rs / stack.rs / matchpred.rs / tpl.rs / registry.rs / proto.rs

> 新增发现（先修再测/钉住）：① `dissect` 未知 ethertype 分支 payload 疑似不进
> remaining（丢字节）→ DSL-21 不变式测试暴露；② `build_cond` 数值溢出静默截断
> （dport=70000 回绕）→ DSL-22 钉语义；③ rest 子 proto 0 消费死循环护栏零测试。

| ID | 名称 | 放哪 | 断言要点 | P |
|---|---|---|---|---|
| DSL-20 | matcher 求值面（**整层零覆盖**） | tests/matcher.rs（新） | FieldEq 命中/值不符/层缺席；FieldNe「缺失=成立」双分支；`not(not(x))≡x`；空模式构建期拒绝（windows(0) panic 防线）；字节谓词 IR 按层 raw vs proto 按整包首字节；proto 定宽编码 vs 未注册回退；sniffer_match_with 端到端命中/不命中 | P0 |
| DSL-21 | dissect 字节不丢不变式组 | tests/dissect.rs | `dns_message_id` 四分支；未知 ethertype：layers+remaining 并集=全部 payload 字节；v6 plen 谎报双向；UDP length<8/双向谎报；裸 DNS/DoT/HTTP 识别与随机字节防误报 | P0 |
| DSL-22 | proto 溢出与死循环护栏 | tests/proto_func.rs | `build_cond` dport=70000 截断语义钉住；rest 子 proto if=0 立即停不死循环；DNS 指针自指环>32/目标越界/保留位 → 反解失败回退 raw | P0 |
| DSL-23 | **注册表/文档同步门禁进 cargo test** | tests/registry_docs_sync.rs（新） | `include_str!` 内嵌 registry.rs/eval.rs/GRAMMAR.md 复刻 primitive-docs-check.sh：分派集 ⊆ builtin_docs（--ls 完整性）、无 stale doc、每名在 GRAMMAR §4.6 整词出现——零 IO 零 shell，CI 可跑（与 just doc-sync-check 双保险） | P0 |
| DSL-24 | dissect 回退与边界 | tests/dissect.rs | 802.3（ethertype<0x0600）拒绝；层头反解失败→raw note；ICMP checksum note；tcp flags 8 位全开；ARP `Other(op)` re-serialize 不变；三路择优（0x45 裸 IP 优先） | P1 |
| DSL-25 | stack_warnings 补充 | 内联 | Raw 作外层永不告警；eth 承载 arp/ipv6/eth 静默；空/单层不 panic；ctx 树嵌套 and/or 载体收集；真实注册表 quic_initial\|>tcp WrongCarrier | P1 |
| DSL-26 | tpl 边界 | tests/eval.rs | %L 字节列表输入拒绝；%d1 贪心 "1234"→未消费；`{0}`/`{`/空字符类/非 ASCII 分隔模板错矩阵；缺参/类型不符 | P1 |
| DSL-27 | proto 防御分支 | tests/field_meta.rs、proto_func.rs | eval_width 移位溢出/除 0/下溢→None 非 panic；switch 无界窗半消费→None；windowed_rest 未注册子 proto→整窗不透明；`in=` 字段目标匹配；Line 无终止符截断 | P1 |
| DSL-28 | registry 其余 | tests/eval.rs、proto_func.rs | `layer()` 错误面（缺 kind/bytes、未知 kind、非 IP 层带 src）；raw_layer 9 kind 全覆盖；`deref_opt` 深度>32 | P1 |
| DSL-29 | DNS 解析器未注入路径 | tests/lib_surface.rs（新） | 不注入 resolver：域名回退报错、`dns_resolver_is_set()==false`（独立测试二进制防 OnceLock 污染） | P1 |
| DSL-30 | 行为固化类 | 内联/各测试文件 | arp op=3；rest list_count>0xFFFF→None；find_content_candidates 三类筛选；ProtoVal display 截断；doc Display 四分支；Span::union 倒挂语义 | P2 |

#### 5.5.3 lexer.rs / parser.rs / serialize.rs / codec.rs / diag.rs / ast.rs

| ID | 名称 | 放哪 | 断言要点 | P |
|---|---|---|---|---|
| DSL-1 | lex_int/hex_overflow_error_span | 内联 | Int 溢出、`0x` 17 位溢出、`0x` 空数字：message+span 恰盖 token | P0 |
| DSL-2 | lex_unknown_char_span_unicode | 内联 | 非 ASCII 字符错误、列按字符/offset 按字节双轨正确 | P0 |
| DSL-3 | unbalanced_parens_eof_span | tests/parse.rs | call/列表/函数体不闭合→"输入已结束"、span 终点=最后 token 之后 | P0 |
| DSL-4 | serialize_error_all_variants | tests/golden.rs | 5 类 SerializeError（超长 ipv4/tcp/udp、options>40、UnknownEthertype、DNS 标签/总长）比对枚举 | P0 |
| DSL-5 | codec_decode_failure_paths | 内联 | Le128 截断/超 9B→None；Prefix 索引越表/截断→None；Table 未知哨兵/截断→None（全不 panic） | P0 |
| DSL-6 | lex_illogical_token_span_accuracy | 内联 | `a \|\| b` 等 span 首列=运算符首列（**先修 lexer 再测**） | P1 |
| DSL-7 | lex_string_raw_newline_breaks_line | 内联 | 裸换行后 token 行号+1（**先修**）；未终止串 span 起点=开引号 | P1 |
| DSL-8 | parse_reports_only_first_error / lex_error_short_circuits | tests/parse.rs | 两处错只报第一处；lex 错误优先于语法错（固化现状） | P1 |
| DSL-9 | add_left_associativity_shape / dangling_pipeline_arrow | tests/parse.rs | `1+2+3` 左折叠嵌套；`\|>` 悬垂 span 指向箭头 | P1 |
| DSL-10 | fuzz_seed_determinism_and_diff / random_field_invariants_fixed_seed | tests/golden.rs | `with_seed_fuzz(7)` 两次逐字节相等且 ≠ 非 fuzz；固定种子下随机场不变式（mac 首字节 bit1=1、ip4 首字节 1..=223、ip6 2000::/12）；seed=0≡1（XorShift 钳制） | P1 |
| DSL-11 | checksum_pure_fn_edges | 内联 | `checksum(&[])==0xffff`；奇数长度补位；全 0xFF 收敛 | P1 |
| DSL-12 | fully_specified_roundtrip_idempotent / proto_layer_roundtrip_bits_switch_vint | tests/dissect.rs、proto_func.rs | 全字段显式 ser→dissect→ser 逐字节相等（真幂等）；bits/switch/vint proto 层幂等 | P1 |
| DSL-13 | raw_direct_feed_branches | tests/golden.rs | eth raw 0x0800 内层改写/<14B 跳过；ipv4 raw proto 推导；icmp raw payload 入 cksum；arp/http/dns 透传 | P1 |
| DSL-14 | codec_le128_non_canonical / table_endian_decode_direct | 内联 | `0x80 0x00`→0 非最小编码被接受（固化）；同字节喂 BE/LE 表解出不同值 | P1 |
| DSL-15 | old_proto_keyword_migration_span / parse_value_expr_deep_errors | tests/parse.rs | 迁移文案 span 恰盖 `proto`；空串/尾逗号/嵌套 hex("zz") 解析不报由求值报 | P1 |
| DSL-16 | codec_prefix_prefix_bits_zero_guard | 内联 | `prefix_bits:0` 位移溢出：`#[should_panic]` 固化或先加防御（风险钉） | P2 |
| DSL-17 | span_from_tokens_edge_cases / diagnostic_display_four_branches / span_union_inverted | 内联 | EOF/越界/跨行区间；Display 四分支精确输出；`union` 取 self.start+other.end（钉语义） | P2 |
| DSL-18 | escape_passthrough / hash_annotation_vs_comment / carriage_return | 内联 | `\q` 原样两字符；`#[` vs `# [`；孤立 `\r` 不分行 | P2 |
| DSL-19 | tcp_options_padding_and_dns_opcode / serialize_parts_layer_spans / transport_checksum_no_ip | tests/golden.rs | MSS 4B 对齐；DNS opcode 嵌 flags；层区间单调衔接；bare TCP/UDP 零伪头 | P2 |


---

## 6. 里程碑与验收

| 里程碑 | 范围 | 验收标准 |
|---|---|---|
| **M0 基础设施** | §4 全部 | `cargo test --workspace` 既有 575 全绿不回归；helper 可被后续用例引用 |
| **M1 P0 正确性** | §5 各表 P0 行 | 新增用例全绿；`cargo clippy --all-targets --workspace -- -D warnings` 零警告；`cargo fmt --check` 通过 |
| **M2 P1 边界/错误路径** | §5 各表 P1 行 | 同上；回环层在三平台 CI 稳定（连续 3 次 CI 无 flake） |
| **M3 P2 收尾** | §5 各表 P2 行 + 豁免清单复核 | llvm-cov 行覆盖报告归档；`just test` 单次 < 120s |

**总目标**：新增用例约 400–500 个（按 §5 明细表合计），使每个 src 文件
满足「有内联 cfg(test) 或有指名集成测试文件覆盖」；零测试文件清单（§1.2）清零。

---

## 7. 显式豁免清单（不写自动化测试，给出理由与替代）

| 项 | 理由 | 替代 |
|---|---|---|
| 真实外网连通（公网 ICMP/TCP/DNS 解析） | 不可复现 | 回环 + 黄金字节；真实网络留给 pktlang_tests/ 的 tcpdump 冒烟（已有） |
| Npcap/libpcap 真实设备抓包 | 依赖硬件与驱动 | pcap 文件读写纯单测 + `--features pcap` 编译检查 + tcpdump 冒烟 |
| Windows ICMP.DLL / WSAPoll 平台分支 | 仅 Windows 可执行 | cfg(windows) 内联测试在 CI windows 跑 + `just check-all` 交叉编译 |
| `--open` 打开浏览器、`$PAGER` 分页 | 外部程序副作用 | 仅测命令构造/参数传递的纯函数部分 |
| Ctrl+C 真实信号投递 | 平台 tty 行为不可复现 | `set_interrupted(true)` 注入（既有模式）+ Run 状态机单测 |
| 前端 SolidJS UI 行为 | 非 Rust 范围 | 前端自带构建检查；web 后端协议层全单测 |
