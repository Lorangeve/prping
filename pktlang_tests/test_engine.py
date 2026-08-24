#!/usr/bin/env python3
"""
pktlang_tests/test_engine.py

验证 prping engine 子命令：分析、--ls、--hex、--pcap、配方概览。
纯离线测试，不需要网络或 raw socket。

测试清单：
  E1. engine 分析单个 pkt → 层栈/字节正确
  E2. engine 分析 pktl 配方 → 步骤/参数/extract 展示
  E3. engine --ls → 列出内置原语
  E4. engine --hex → hex 解码正确
  E5. engine --pcap → 读取 pcap 文件
  E6. engine 分析所有示例 pkt → 无报错
  E7. engine 分析所有示例 pktl → 无报错
  E8. engine pkt 带 --params → 参数注入展示
  E9. engine pkt 带 sniffer → sniffer 展示
  E10. engine pkt 有 hexdump → 字节校验

运行：python3 pktlang_tests/test_engine.py
"""

import os
import re
import sys
import subprocess
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
PRPING = WORKSPACE / "target" / "debug" / "prping"
EXAMPLES = WORKSPACE / "examples"


def run_cmd(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1


class Result:
    def __init__(self, tid, name):
        self.tid = tid
        self.name = name
        self.checks = []

    def ok(self, cond, msg):
        self.checks.append((bool(cond), msg))

    @property
    def passed(self):
        return all(c[0] for c in self.checks)

    def summary_line(self):
        n = len(self.checks)
        m = sum(1 for c in self.checks if c[0])
        sym = "✅" if self.passed else "❌"
        return f"{sym} {self.tid} {self.name}  ({m}/{n})"


def test_E1():
    """E1: engine 分析单个 pkt"""
    r = Result("E1", "engine_analyze_single_pkt")
    out, err, rc = run_cmd(
        [str(PRPING), "engine", str(EXAMPLES / "app_http/http_get.pkt"),
         "-p", "ip=127.0.0.1"],
    )
    r.ok(rc == 0, f"exit={rc}")
    r.ok("http" in out, "包含 http 层")
    r.ok("tcp" in out, "包含 tcp 层")
    r.ok("ipv4" in out, "包含 ipv4 层")
    r.ok("eth" in out, "包含 eth 层")
    r.ok("GET / HTTP/1.1" in out, "HTTP start_line 正确")
    r.ok("bytes: 72 B" in out, "字节数 72 B")
    r.ok("0x" in out, "包含十六进制 dump")
    return r


def test_E2():
    """E2: engine 分析 pktl 配方"""
    r = Result("E2", "engine_analyze_recipe")
    out, err, rc = run_cmd(
        [str(PRPING), "engine", str(EXAMPLES / "app_http")],
    )
    r.ok(rc == 0, f"exit={rc}")
    r.ok("step 1" in out, "显示步骤 1")
    r.ok("step 2" in out, "显示步骤 2")
    r.ok("params" in out or "param" in out.lower(), "显示参数信息")
    return r


def test_E3():
    """E3: engine --ls 列出内置原语"""
    r = Result("E3", "engine_ls_builtins")
    out, err, rc = run_cmd([str(PRPING), "engine", "--ls"])
    r.ok(rc == 0, f"exit={rc}")
    r.ok("raw(" in out, "包含 raw 原语")
    r.ok("hex(" in out, "包含 hex 原语")
    r.ok("layer(" in out, "包含 layer 原语")
    r.ok("concat(" in out, "包含 concat 原语")
    r.ok("count(" in out, "包含 count 原语")
    r.ok("cksum(" in out, "包含 cksum 原语")
    r.ok("rand16(" in out, "包含 rand16 原语")
    r.ok("dns(" in out, "包含 dns 原语")
    return r


def test_E4():
    """E4: engine --hex 解码"""
    r = Result("E4", "engine_hex_decode")
    out, err, rc = run_cmd([str(PRPING), "engine", "--hex", "deadbeef"])
    r.ok(rc == 0, f"exit={rc}")
    r.ok("de ad be ef" in out.replace("  ", " ").strip() or "deadbeef" in out.lower(),
         "hex 解码输出正确")
    # 奇数长度应报错
    out2, err2, rc2 = run_cmd([str(PRPING), "engine", "--hex", "deadbee"])
    r.ok(rc2 != 0, "奇数长度 hex 正确报错")
    return r


def test_E5():
    """E5: engine --pcap 读取 pcap"""
    r = Result("E5", "engine_pcap_read")
    # 先用 --out 生成一个 pcap
    pcap = "/tmp/engine_test_e5.pcap"
    run_cmd([str(PRPING), "packet",
             str(EXAMPLES / "app_http/http_get.pkt"),
             "127.0.0.1:9999", "--raw", "--out", pcap,
             "-p", "port=9999,ip=127.0.0.1"])
    out, err, rc = run_cmd([str(PRPING), "engine", "--pcap", pcap])
    r.ok(rc == 0, f"engine --pcap exit={rc}")
    r.ok("ipv4" in out.lower() or "IP" in out, "pcap 包含 IP 层")
    # 清理
    try:
        os.unlink(pcap)
    except Exception:
        pass
    return r


def test_E6():
    """E6: engine 分析所有示例 pkt 无报错"""
    r = Result("E6", "engine_analyze_all_pkt")
    pkt_files = sorted(EXAMPLES.rglob("*.pkt"))
    r.ok(len(pkt_files) >= 10, f"找到 {len(pkt_files)} 个 .pkt 文件（>=10）")
    failed = []
    skipped = 0
    for pkt in pkt_files:
        out, err, rc = run_cmd(
            [str(PRPING), "engine", str(pkt), "-p", "ip=127.0.0.1"],
            timeout=10,
        )
        if rc != 0:
            # 依赖配方 global 的 pkt（如 tcp_handshake/ack.pkt）独立分析会报错，属正常
            if "未设置" in err:
                skipped += 1
            else:
                failed.append(f"{pkt.name}: exit={rc} err={err[:80]}")
    r.ok(len(failed) == 0,
         f"{len(pkt_files)} 个 pkt 中 {len(pkt_files)-skipped} 个直接通过，"
         f"{skipped} 个需配方上下文（跳过）" if not failed
         else f"{len(failed)}/{len(pkt_files)} 个 pkt 解析失败: {failed[0]}")
    return r


def test_E7():
    """E7: engine 分析所有示例 pktl 无报错"""
    r = Result("E7", "engine_analyze_all_pktl")
    pktl_files = sorted(EXAMPLES.rglob("*.pktl"))
    r.ok(len(pktl_files) >= 6, f"找到 {len(pktl_files)} 个 .pktl 文件（>=6）")
    failed = []
    for pktl in pktl_files:
        out, err, rc = run_cmd(
            [str(PRPING), "engine", str(pktl)],
            timeout=10,
        )
        if rc != 0:
            failed.append(f"{pktl.name}: exit={rc} err={err[:80]}")
    r.ok(len(failed) == 0,
         f"全部 {len(pktl_files)} 个 pktl 解析通过" if not failed
         else f"{len(failed)}/{len(pktl_files)} 个 pktl 失败: {failed[0]}")
    return r


def test_E8():
    """E8: engine 带 --params 展示参数注入"""
    r = Result("E8", "engine_params_injection")
    out, err, rc = run_cmd(
        [str(PRPING), "engine", str(EXAMPLES / "app_http/http_get.pkt"),
         "-p", "ip=10.0.0.1,port=8080"],
    )
    r.ok(rc == 0, f"exit={rc}")
    r.ok("10.0.0.1" in out, "参数 ip=10.0.0.1 注入到 dst")
    r.ok("8080" in out, "参数 port=8080 注入到 dport")
    return r


def test_E9():
    """E9: engine 带 sniffer 展示"""
    r = Result("E9", "engine_sniffer_display")
    out, err, rc = run_cmd(
        [str(PRPING), "engine", str(EXAMPLES / "app_http/http_get.pkt")],
    )
    r.ok(rc == 0, f"exit={rc}")
    r.ok("sniffer:" in out, "显示 sniffer 段")
    r.ok("tcp" in out and "ack()" in out, "sniffer 包含 TCP ack() 匹配")
    return r


def test_E10():
    """E10: engine hexdump 字节校验"""
    r = Result("E10", "engine_hexdump_bytes")
    out, err, rc = run_cmd(
        [str(PRPING), "engine", str(EXAMPLES / "app_http/http_get.pkt"),
         "-p", "ip=127.0.0.1"],
    )
    r.ok(rc == 0, f"exit={rc}")
    # hexdump 应包含 "47 45 54" = "GET"
    r.ok("47 45 54" in out, "hexdump 包含 'GET' 的 ASCII hex")
    # eth dst_mac = 66:77:88:99:aa:bb
    r.ok("66 77 88 99 aa bb" in out, "hexdump 包含 eth dst MAC")
    # ipv4 src = 192.168.81.1 = c0 a8 51 01
    r.ok("c0 a8 51 01" in out, "hexdump 包含 ipv4 src IP")
    return r


# ─── 主入口 ──────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("pktlang_tests: engine analysis")
    print("=" * 60)
    print(f"  prping   : {PRPING}")
    print(f"  examples : {EXAMPLES}")
    print()

    tests = [test_E1, test_E2, test_E3, test_E4, test_E5,
             test_E6, test_E7, test_E8, test_E9, test_E10]

    results = []
    for test_fn in tests:
        tid = test_fn.__doc__.split(":")[0].strip().split(" ")[0]
        name = test_fn.__doc__.split(":")[1].strip().split("→")[0].strip()
        print(f"── {tid} {name} ──")
        try:
            r = test_fn()
            results.append(r)
            for passed, msg in r.checks:
                sym = "  ✅" if passed else "  ❌"
                print(f"{sym} {msg}")
        except Exception as e:
            print(f"  ❌ EXCEPTION: {e}")
            r = Result(tid, name)
            r.checks.append((False, f"exception: {e}"))
            results.append(r)
        print()

    print("=" * 60)
    total = sum(len(r.checks) for r in results)
    passed_count = sum(sum(1 for c in r.checks if c[0]) for r in results)
    n_pass = sum(1 for r in results if r.passed)
    for r in results:
        print(f"  {r.summary_line()}")
    print()
    print(f"  {n_pass}/{len(results)} tests passed, {passed_count}/{total} assertions passed")
    print("=" * 60)
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
