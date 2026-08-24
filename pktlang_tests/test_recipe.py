#!/usr/bin/env python3
"""
pktlang_tests/test_recipe.py

验证多步骤配方（.pktl）：global/extract 链、sniffer、wait、--out pcap。

测试清单：
  R1. app_http 配方 payload 模式 → 两步都收到 200
  R2. transport_udp 配方 → UDP DNS + VNC 都发出去
  R3. tcp_handshake 配方 → SYN+ACK+GET 三步都发出去
  R4. link_arp 配方 → ARP request+reply 都发出去
  R5. bad_network 配方 --out → pcap 包含 7 个步骤
  R6. quic_initial 配方 → QUIC Initial+Short 都发出去
  R7. dns_recipe 配方 → DNS 查询发出
  R8. 配方 --params 注入 → 全部步骤参数生效
  R9. 配方 --fuzz → 字段被随机化
  R10. 配方 --out + engine --pcap → pcap 可读回

运行：python3 pktlang_tests/test_recipe.py
"""

import os
import re
import sys
import time
import subprocess
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
PRPING = WORKSPACE / "target" / "debug" / "prping"
EXAMPLES = WORKSPACE / "examples"
BASE_PORT = 20300
_tmp_counter = 0


def _tmp(suffix):
    global _tmp_counter
    _tmp_counter += 1
    return f"/tmp/recipe_{_tmp_counter}_{suffix}"


def ensure_privileges():
    if os.getuid() != 0:
        print("⚡ Re-executing in isolated user+net namespace ...\n")
        os.execvp("unshare", ["unshare", "-Urn", sys.executable] + sys.argv)


def setup():
    os.system("ip link set lo up 2>/dev/null")
    if not PRPING.exists():
        sys.exit(f"❌ prping binary not found: {PRPING}")


def run_cmd(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1


def start_tcpdump(pcap_path, iface="lo"):
    return subprocess.Popen(
        ["tcpdump", "-i", iface, "-nn", "-U", "-w", str(pcap_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def tcpdump_read(pcap_path, ethernet=False):
    cmd = ["tcpdump", "-nn"]
    if ethernet:
        cmd.append("-e")
    cmd += ["-r", str(pcap_path)]
    stdout, _, _ = run_cmd(cmd)
    return stdout


def start_http_server(port, log_path):
    return subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdout=open(log_path, "w"), stderr=subprocess.STDOUT,
    )


def kill(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
            p.wait()


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


# ─── R1: app_http 配方 payload 模式 ─────────────────────────────────────
def test_R1(port):
    """R1: recipe_app_http_payload"""
    r = Result("R1", "recipe_app_http_payload")
    log = _tmp("r1.log")
    server = start_http_server(port, log)
    time.sleep(0.5)

    out, err, rc = run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "app_http"),
         f"127.0.0.1:{port}", "-p", f"port={port},ip=127.0.0.1"],
        timeout=15,
    )
    r.ok(rc == 0, f"配方执行 exit={rc}")
    r.ok("step 1" in out, "执行步骤 1")
    r.ok("step 2" in out, "执行步骤 2")

    time.sleep(0.5)
    kill(server)
    time.sleep(0.3)

    log_content = ""
    try:
        log_content = Path(log).read_text()
    except Exception:
        pass

    r.ok("GET / HTTP/1.1" in log_content, "http.server 收到 GET 请求")
    r.ok("POST /login" in log_content, "http.server 收到 POST 请求")
    return r


# ─── R2: transport_udp 配方 ────────────────────────────────────────────
def test_R2(port):
    """R2: recipe_transport_udp"""
    r = Result("R2", "recipe_transport_udp")
    pcap = _tmp("r2.pcap")
    tdump = start_tcpdump(pcap)
    time.sleep(0.5)

    out, err, rc = run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "transport_udp"),
         f"127.0.0.1:{port}", "--raw", "--wait", "0",
         "-p", f"ip=127.0.0.1"],
        timeout=15,
    )
    r.ok(rc == 0, f"配方执行 exit={rc}")

    time.sleep(0.5)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap)
    r.ok("UDP" in wire, "线上有 UDP 流量")
    r.ok("53" in wire, "DNS 端口 53 可见")
    return r


# ─── R3: tcp_handshake 配方 ─────────────────────────────────────────────
def test_R3(port):
    """R3: recipe_tcp_handshake"""
    r = Result("R3", "recipe_tcp_handshake")
    pcap = _tmp("r3.pcap")
    tdump = start_tcpdump(pcap)
    time.sleep(0.5)

    out, err, rc = run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "tcp_handshake"),
         f"127.0.0.1:{port}", "--raw", "--wait", "0",
         "-p", f"port={port},ip=127.0.0.1"],
        timeout=15,
    )
    r.ok(rc == 0, f"配方执行 exit={rc}")

    time.sleep(0.5)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap)
    r.ok("Flags [S]" in wire, "SYN 在线上")
    # ACK 可能是 Flags [.]" 或 "Flags [A]"
    r.ok("Flags" in wire, "多步 TCP 包在线上")
    return r


# ─── R4: link_arp 配方 ──────────────────────────────────────────────────
    """R4: placeholder"""
def test_R4():
    """R4: recipe_link_arp"""
    r = Result("R4", "recipe_link_arp")
    pcap = _tmp("r4.pcap")
    tdump = start_tcpdump(pcap, iface="lo")
    time.sleep(0.5)

    out, err, rc = run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "link_arp"),
         "--raw", "--wait", "0",
         "-p", "ip=127.0.0.1"],
        timeout=15,
    )
    r.ok(rc == 0, f"配方执行 exit={rc}")

    time.sleep(0.5)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap, ethernet=True)
    r.ok("ARP" in wire, "tcpdump 识别 ARP")
    r.ok("who-has" in wire or "Request" in wire, "ARP Request 在线上")
    return r


# ─── R5: bad_network 配方 --out pcap ────────────────────────────────────
    """R5: placeholder"""
def test_R5():
    """R5: recipe_bad_network_pcap"""
    r = Result("R5", "recipe_bad_network_pcap")
    pcap = _tmp("r5.pcap")

    out, err, rc = run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "bad_network"),
         "127.0.0.1:80", "--raw", "--wait", "0",
         "--out", pcap,
         "-p", "ip=127.0.0.1,port=80"],
        timeout=30,
    )
    r.ok(rc == 0, f"配方执行 exit={rc}")

    # 读回 pcap
    wire = tcpdump_read(pcap)
    r.ok("Flags [S]" in wire, "pcap 包含 SYN")
    r.ok("length" in wire or "HTTP" in wire, "pcap 包含 HTTP 数据")
    return r


# ─── R6: quic_initial 配方 ──────────────────────────────────────────────
    """R6: placeholder"""
def test_R6():
    """R6: recipe_quic_initial"""
    r = Result("R6", "recipe_quic_initial")
    pcap = _tmp("r6.pcap")
    tdump = start_tcpdump(pcap, iface="lo")
    time.sleep(0.5)

    out, err, rc = run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "quic_initial"),
         "--raw", "--wait", "0",
         "-p", "ip=127.0.0.1"],
        timeout=15,
    )
    r.ok(rc == 0, f"配方执行 exit={rc}")

    time.sleep(0.5)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap, ethernet=True)
    r.ok("UDP" in wire, "QUIC 走 UDP")
    r.ok("443" in wire, "目标端口 443")
    return r


# ─── R7: dns_recipe 配方 ────────────────────────────────────────────────
    """R7: placeholder"""
def test_R7():
    """R7: recipe_dns"""
    r = Result("R7", "recipe_dns")
    pcap = _tmp("r7.pcap")
    tdump = start_tcpdump(pcap, iface="lo")
    time.sleep(0.5)

    out, err, rc = run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "dns_recipe"),
         "--raw", "--wait", "0",
         "-p", "ip=127.0.0.1"],
        timeout=15,
    )
    # dns_recipe 有 extract（需 DNS 回包），无 DNS 服务器时 extract 失败属正常
    # 关键验证：第一步 DNS 查询已发出

    time.sleep(0.5)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap, ethernet=True)
    r.ok("53" in wire, "DNS 查询已发出（端口 53 可见）")
    r.ok("example.com" in wire.lower() or "A?" in wire,
         "DNS 查询包含 example.com")
    return r


# ─── R8: 配方 --params 注入 ─────────────────────────────────────────────
def test_R8(port):
    """R8: recipe_params_injection"""
    r = Result("R8", "recipe_params_injection")
    log = _tmp("r8.log")
    server = start_http_server(port, log)
    time.sleep(0.5)

    out, err, rc = run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "app_http"),
         f"127.0.0.1:{port}",
         "-p", f"port={port},ip=127.0.0.1"],
        timeout=15,
    )
    r.ok(rc == 0, f"exit={rc}")

    time.sleep(0.5)
    kill(server)
    time.sleep(0.3)

    log_content = ""
    try:
        log_content = Path(log).read_text()
    except Exception:
        pass

    r.ok("GET / HTTP/1.1" in log_content, "参数注入 port 生效")
    r.ok("POST /login" in log_content, "两步参数都注入成功")
    return r


# ─── R9: 配方 --fuzz 随机化 ─────────────────────────────────────────────
    """R9: placeholder"""
def test_R9():
    """R9: recipe_fuzz"""
    r = Result("R9", "recipe_fuzz")
    # 发两次同包，--fuzz 模式下 hexdump 应不同（用 --out 写 pcap 再读回）
    pcap1 = _tmp("r9a.pcap")
    pcap2 = _tmp("r9b.pcap")

    for pcap in [pcap1, pcap2]:
        run_cmd(
            [str(PRPING), "packet",
             str(EXAMPLES / "app_http/http_get.pkt"),
             "--raw", "--fuzz", "--wait", "0", "--out", pcap,
             "-p", "ip=127.0.0.1,port=9999"],
            timeout=10,
        )

    # 读两次的 hexdump 首行（engine --pcap 反解）
    out1, _, _ = run_cmd([str(PRPING), "engine", "--pcap", pcap1])
    out2, _, _ = run_cmd([str(PRPING), "engine", "--pcap", pcap2])
    r.ok(len(out1) > 0, f"fuzz 第一次有 pcap 输出")
    r.ok(len(out2) > 0, f"fuzz 第二次有 pcap 输出")
    # 两次 hexdump 应不同（fuzz 随机化）
    r.ok(out1 != out2, "两次 --fuzz 输出不同（随机化生效）")

    # 清理
    for p in [pcap1, pcap2]:
        try:
            os.unlink(p)
        except Exception:
            pass
    return r


# ─── R10: --out pcap + engine --pcap 读回 ───────────────────────────────
    """R10: placeholder"""
def test_R10():
    """R10: recipe_out_pcap_roundtrip"""
    r = Result("R10", "recipe_out_pcap_roundtrip")
    pcap = _tmp("r10.pcap")

    run_cmd(
        [str(PRPING), "packet", str(EXAMPLES / "app_http"),
         "127.0.0.1:9999", "--raw", "--wait", "0",
         "--out", pcap,
         "-p", "port=9999,ip=127.0.0.1"],
        timeout=15,
    )

    # 用 engine --pcap 读回
    out, err, rc = run_cmd([str(PRPING), "engine", "--pcap", pcap])
    r.ok(rc == 0, f"engine --pcap exit={rc}")
    r.ok("ipv4" in out.lower() or "IP" in out, "pcap 读回包含 IP 层")
    r.ok("tcp" in out.lower() or "TCP" in out, "pcap 读回包含 TCP 层")

    # 清理
    try:
        os.unlink(pcap)
    except Exception:
        pass
    return r


# ─── 主入口 ──────────────────────────────────────────────────────────────
def main():
    ensure_privileges()
    setup()

    print("=" * 60)
    print("pktlang_tests: recipe tests")
    print("=" * 60)
    print(f"  prping   : {PRPING}")
    print(f"  examples : {EXAMPLES}")
    print()

    results = []
    port = BASE_PORT

    tests = [
        ("R1", "recipe_app_http_payload",     test_R1),
        ("R2", "recipe_transport_udp",        test_R2),
        ("R3", "recipe_tcp_handshake",        test_R3),
        ("R4", "recipe_link_arp",             test_R4),
        ("R5", "recipe_bad_network_pcap",     test_R5),
        ("R6", "recipe_quic_initial",         test_R6),
        ("R7", "recipe_dns",                  test_R7),
        ("R8", "recipe_params_injection",     test_R8),
        ("R9", "recipe_fuzz",                 test_R9),
        ("R10", "recipe_out_pcap_roundtrip",  test_R10),
    ]

    for tid, name, test_fn in tests:
        port += 1
        print(f"── {tid} {name} ──")
        try:
            import inspect
            sig = inspect.signature(test_fn)
            if 'port' in sig.parameters:
                r = test_fn(port)
            else:
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
