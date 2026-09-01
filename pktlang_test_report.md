# pktlang 全面测试报告

日期：2025-09-01 ｜ 环境：Linux x86_64 ｜ 产物：target/debug/prping（已编译）

## 一、总览：全部通过 ✅

| 测试层 | 套件 | 结果 |
|---|---|---|
| packet-dsl 单元+集成 | `cargo test -p packet-dsl`（lib 36 / comprehensive 54 / dissect 13 / eval 85 / field_meta 20 / golden 18 / parse 31 / proto_func 41 / proto_headers 9 / semantic 45 / total_probe 1 / doctest 1） | **354 通过，0 失败** |
| prping-core | unittests 162 / convert 11 / engine 15 / pcap 3 / pkg 63 / protocol 19 / doctest 2 | **275 通过，0 失败** |
| prping-cli | unittests 10 / integration 23 | **33 通过，0 失败** |
| pktlang_tests/engine | test_engine.py（E1–E10：分析/配方/--ls/--hex/--pcap/示例全量/params/sniffer/hexdump） | **10/10（40 断言）** |
| pktlang_tests/protocols | test_protocols.py（P1–P10：ARP/DNS/UDP/ICMP/ICMPv6/TCP/QUIC/载荷尺寸，tcpdump 地面真相） | **10/10（26 断言）** |
| pktlang_tests/recipe | test_recipe.py（R1–R10：配方执行/params/fuzz/pcap 往返） | **10/10（31 断言）** |
| pktlang_tests/smoke | test_smoke_tcpdump.py（S1–S9：ping/trace/latency/bandwidth/packet 全模式冒烟） | **9/9（30 断言）** |
| pktlang_tests/raw | test_raw_effectiveness.py（T1–T8：user+net namespace 内 raw 发包有效性/伪造源/零源填充） | **8/8（35 断言）** |

门禁复检：`cargo fmt --check` ✅ ／ `cargo clippy -p packet-dsl --all-targets` 零警告 ✅

## 二、本次新增/变更

- **新增** `crates/packet-dsl/tests/comprehensive.rs`（54 个测试）：语法解析（标识符/字符串转义/hex/管道/命名+位置参数/import-export/注释/续行）、类型系统（数值/字节/地址）、值原语（位运算 bor、rand16、pad）、九种协议层（eth/arp/ipv4/ipv6/tcp/udp/icmp/http/dns 层栈断言）、管道组合（单层/多层/多载荷/多导出 4 包展开）、params/sniffer 语法、语义与错误路径、性能（千次解析 <1s）、边界（空输入/纯空白/纯注释/超长字符串）。
- **修复** `pktlang_tests/test_engine.py` E6：此前只豁免「global 未设置」类配方上下文文件，漏掉「params 未提供」类步骤文件（wait_timeout/probe.pkt、fallback.pkt）——与测试自身注释的设计意图一致，补上豁免后 E1–E10 全过。
- **新增** 本报告与 `pktlang_comprehensive_test_plan.md`（测试计划）。

## 三、验证到的关键语义（探针确认）

- **导出语义**：`resolve()` 返回「顶层匿名流水线（默认导出）+ 全部具名导出」的包；未被 `export:` 的 def 不产生包。例如 `a = http(...)` + 匿名管道 + `export: - a` → 2 包（完整层栈 72B + 裸 http 18B）。
- **缺参诊断**：独立分析配方步骤文件时，引擎对缺失 params/global 给出可操作报错（提示 --params / global / 默认值三途径），退出码 1 —— 属设计行为，非缺陷。
- **raw 有效性**（T1–T8）：payload 模式走内核协议栈；`--raw` 伪造源可上线且服务端收不到（握手失败）；`src=0.0.0.0` 触发 `patch_zero_src` 填真实 IP；eth 帧按目的 MAC 直发。

## 四、遗留说明

- `tests/parse_bench.rs` 为 1 个 ignored 基准（按设计非默认执行）。
- examples 中 13 个 .pkt 为配方步骤文件（依赖 global/params 注入），独立分析报错属预期；E6/E7 已按配方上下文口径豁免。
- 真实外网连通性不在本套件范围（pktlang_tests 以回环 + tcpdump 为地面真相）。
