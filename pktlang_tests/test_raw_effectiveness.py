#!/usr/bin/env python3
"""
pktlang_tests/test_raw_effectiveness.py

用 python -m http.server + tcpdump 作为地面真相，验证 prping 各发送模式的效果。

测试清单：
  T1. payload 模式（默认）  → http.server 收到请求，tcpdump 显示真实 src IP
  T2. raw 裸 IP 伪造 src    → tcpdump 显示伪造 src，http.server 收不到
  T3. raw 裸 IP 零 src 填充 → tcpdump 显示真实 src（patch_zero_src），http.server 收到
  T4. raw eth 帧伪造 src+MAC → tcpdump 显示伪造 IP+MAC，http.server 收不到
  T5. raw ICMP 伪造 src     → tcpdump 显示伪造 src 的 echo request
  T6. raw ICMP 零 src 填充  → tcpdump 显示真实 src 的 echo request

运行：python3 pktlang_tests/test_raw_effectiveness.py
（非 root 自动 re-exec 进 user+net namespace）
"""

import os
import re
import sys
import time
import signal
import subprocess
from pathlib import Path

# ─── 路径 ────────────────────────────────────────────────────────────────
WORKSPACE = Path(__file__).resolve().parent.parent
PRPING = WORKSPACE / "target" / "debug" / "prping"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
BASE_PORT = 18800
_tmp_counter = 0


def _tmp(suffix):
    """生成唯一临时文件路径（避免测试间冲突）。"""
    global _tmp_counter
    _tmp_counter += 1
    return f"/tmp/pktlang_test_{_tmp_counter}_{suffix}"


# ─── 权限/环境 ───────────────────────────────────────────────────────────
def ensure_privileges():
    """非 root 时自动 re-exec 进 user+net namespace（unshare -Urn）。"""
    if os.getuid() != 0:
        print("⚡ Not root — re-executing in isolated user+net namespace ...\n")
        os.execvp("unshare", ["unshare", "-Urn", sys.executable] + sys.argv)


def setup():
    os.system("ip link set lo up 2>/dev/null")
    if not PRPING.exists():
        sys.exit(f"❌ prping binary not found: {PRPING}\n   Run `cargo build` first.")


# ─── 进程/工具 ────────────────────────────────────────────────────────────
def run_cmd(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1


def start_http_server(port, log_path):
    return subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT,
    )


def start_tcpdump(pcap_path, iface="lo"):
    return subprocess.Popen(
        ["tcpdump", "-i", iface, "-nn", "-U", "-w", str(pcap_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def tcpdump_read(pcap_path, ethernet=False):
    cmd = ["tcpdump", "-nn"]
    if ethernet:
        cmd.append("-e")
    cmd += ["-r", str(pcap_path)]
    stdout, _, _ = run_cmd(cmd)
    return stdout


def read_file(path):
    try:
        return Path(path).read_text()
    except Exception:
        return ""


def kill(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
            p.wait()


# ─── 测试结果 ─────────────────────────────────────────────────────────────
class Result:
    def __init__(self, tid, name, cmd_desc):
        self.tid = tid
        self.name = name
        self.cmd_desc = cmd_desc
        self.checks = []  # (passed, msg)

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


def run_one(result, port, server_log, pcap, pkt, prping_args, ethernet=False):
    """启动 server/tcpdump → 运行 prping → 收集结果 → 返回 Result。"""
    server = start_http_server(port, server_log)
    tdump = start_tcpdump(pcap)
    time.sleep(0.5)

    cmd = [str(PRPING), "packet", str(pkt)] + prping_args
    stdout, stderr, rc = run_cmd(cmd, timeout=15)
    result.ok(rc == 0, f"prping exit={rc}")

    time.sleep(1)
    kill(tdump)
    time.sleep(0.3)

    http_log = read_file(server_log)
    wire = tcpdump_read(pcap, ethernet=ethernet)

    kill(server)
    return http_log, wire


# ─── T1: payload 模式 → 真实 IP，http.server 收到请求 ────────────────────
def test_T1(port):
    r = Result("T1", "payload_mode_real_ip",
               "prping packet http_get.pkt 127.0.0.1:PORT --params port=PORT,ip=127.0.0.1")
    log = _tmp("t1.log")
    pcap = _tmp("t1.pcap")
    pkt = WORKSPACE / "examples/app_http/http_get.pkt"

    http_log, wire = run_one(
        r, port, log, pcap, pkt,
        [f"127.0.0.1:{port}", "-p", f"port={port},ip=127.0.0.1"],
    )

    # — 断言 —
    r.ok("GET / HTTP/1.1" in http_log,
         "http.server 收到 GET 请求")
    r.ok("200" in http_log,
         "http.server 返回 200")
    # tcpdump 应显示真实 src 127.0.0.1 + 临时端口（不是 40000）
    pat = re.compile(rf"127\.0\.0\.1\.\d+ > 127\.0\.0\.1\.{port}")
    r.ok(pat.search(wire), "tcpdump 显示 src=127.0.0.1（真实 IP）")
    r.ok("40000" not in wire,
         "sport=40000 没有上线（内核选了临时端口）")
    return r


# ─── T2: raw 裸 IP 伪造 src → 伪造 src 上线，server 收不到 ──────────────
def test_T2(port):
    r = Result("T2", "raw_bare_ip_spoofed_src",
               "prping packet http_get_bare_spoof.pkt --raw -p port=PORT")
    log = _tmp("t2.log")
    pcap = _tmp("t2.pcap")
    pkt = FIXTURES / "http_get_bare_spoof.pkt"

    http_log, wire = run_one(
        r, port, log, pcap, pkt,
        ["--raw", "-p", f"port={port},ip=127.0.0.1"],
    )

    # — 断言 —
    r.ok("192.168.81.100" in wire,
         "tcpdump 显示伪造 src=192.168.81.100 ✓")
    r.ok(re.search(rf"192\.168\.81\.100.* > 127\.0\.0\.1\.{port}", wire),
         "伪造 src→目标端口 在线上可见")
    r.ok("GET /" not in http_log,
         "http.server 没有收到请求（TCP 握手未完成）")
    r.ok("SYN" in wire or "Flags" in wire,
         "线上是 TCP SYN（单向，无完整握手）")
    return r


# ─── T3: raw 裸 IP 零 src → patch_zero_src 填真实 IP，但 TCP 握手仍完不成 ──
# 裸 IP raw 发 TCP SYN 时，即使 src 被填成真实 IP（127.0.0.1），也没有客户端
# socket 完成三次握手：内核生成 SYN-ACK 回给 127.0.0.1:40000，但该端口无进程
# 监听 → 内核 RST → 握手失败 → http.server 永远收不到请求。
# 结论：raw TCP 与完成握手不可兼得——想让 server 收到请求必须用 payload 模式。
def test_T3(port):
    r = Result("T3", "raw_bare_ip_zero_src_patched",
               "prping packet http_get_bare_zero.pkt --raw -p port=PORT")
    log = _tmp("t3.log")
    pcap = _tmp("t3.pcap")
    pkt = FIXTURES / "http_get_bare_zero.pkt"

    http_log, wire = run_one(
        r, port, log, pcap, pkt,
        ["--raw", "-p", f"port={port},ip=127.0.0.1"],
    )

    # — 断言 —
    r.ok("127.0.0.1" in wire,
         "tcpdump 显示真实 src=127.0.0.1（patch_zero_src 生效）")
    r.ok("GET /" not in http_log,
         "http.server 没有收到请求（raw TCP 无客户端 socket，三次握手完不成）")
    r.ok("192.168.81.100" not in wire,
         "伪造 IP 没有出现在线上")
    r.ok("SYN" in wire or "Flags" in wire,
         "线上可见 TCP SYN（但只是单向，无完整握手）")
    return r


# ─── T4: raw eth 帧伪造 src+MAC → TCP SYN 上线，server 收不到 ──────────
def test_T4(port):
    r = Result("T4", "raw_eth_spoofed_src_mac",
               "prping packet http_get.pkt --raw --iface lo -p port=PORT,ip=127.0.0.1")
    log = _tmp("t4.log")
    pcap = _tmp("t4.pcap")
    pkt = WORKSPACE / "examples/app_http/http_get.pkt"

    http_log, wire = run_one(
        r, port, log, pcap, pkt,
        ["--raw", "--iface", "lo", "-p", f"port={port},ip=127.0.0.1"],
        ethernet=True,
    )

    # — 断言 —
    r.ok("192.168.81.1" in wire,
         "tcpdump 显示伪造 src IP=192.168.81.1")
    r.ok("00:11:22:33:44:55" in wire,
         "tcpdump 显示伪造 src MAC=00:11:22:33:44:55")
    r.ok("66:77:88:99:aa:bb" in wire,
         "tcpdump 显示伪造 dst MAC=66:77:88:99:aa:bb")
    r.ok("GET /" not in http_log,
         "http.server 没有收到请求（eth 帧 L2 注入，内核 TCP 无法完成握手）")
    return r


# ─── T5: raw ICMP 伪造 src → tcpdump 显示伪造 src 的 echo request ──────
def test_T5(port):
    r = Result("T5", "raw_icmp_spoofed_src",
               "prping packet icmp_echo_spoof.pkt --raw")
    pcap = _tmp("t5.pcap")
    pkt = FIXTURES / "icmp_echo_spoof.pkt"

    # ICMP 不需要 http.server，只看 tcpdump
    tdump = start_tcpdump(pcap)
    time.sleep(0.5)

    cmd = [str(PRPING), "packet", str(pkt), "--raw",
           "-p", "src=192.168.81.100,ip=127.0.0.1"]
    stdout, stderr, rc = run_cmd(cmd, timeout=15)
    r.ok(rc == 0, f"prping exit={rc}")
    time.sleep(1)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap)

    # — 断言 —
    r.ok("192.168.81.100" in wire,
         "tcpdump 显示伪造 src=192.168.81.100")
    r.ok("echo request" in wire.lower() or "ICMP echo" in wire,
         "线上是 ICMP echo request")
    r.ok("127.0.0.1" in wire,
         "目标 127.0.0.1 可见")
    return r


# ─── T6: raw ICMP 零 src → patch_zero_src 填真实 IP ─────────────────────
def test_T6(port):
    r = Result("T6", "raw_icmp_zero_src_patched",
               "prping packet icmp_echo_spoof.pkt --raw -p src=0.0.0.0,ip=127.0.0.1")
    pcap = _tmp("t6.pcap")
    pkt = FIXTURES / "icmp_echo_spoof.pkt"

    tdump = start_tcpdump(pcap)
    time.sleep(0.5)

    cmd = [str(PRPING), "packet", str(pkt), "--raw",
           "-p", "src=0.0.0.0,ip=127.0.0.1"]
    stdout, stderr, rc = run_cmd(cmd, timeout=15)
    r.ok(rc == 0, f"prping exit={rc}")
    time.sleep(1)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap)

    # — 断言 —
    r.ok("127.0.0.1" in wire,
         "tcpdump 显示真实 src=127.0.0.1（patch_zero_src 生效）")
    r.ok("echo request" in wire.lower() or "ICMP echo" in wire,
         "线上是 ICMP echo request")
    r.ok("192.168.81.100" not in wire,
         "伪造 IP 未出现")
    return r


# ─── T7: raw 裸 IP 伪造 src → 不同伪造地址也能上线 ───────────────────────
def test_T7(port):
    r = Result("T7", "raw_bare_ip_different_spoofed_src",
               "prping packet icmp_echo_spoof.pkt --raw -p src=10.99.99.99")
    pcap = _tmp("t7.pcap")
    pkt = FIXTURES / "icmp_echo_spoof.pkt"

    tdump = start_tcpdump(pcap)
    time.sleep(0.5)

    cmd = [str(PRPING), "packet", str(pkt), "--raw",
           "-p", "src=10.99.99.99,ip=127.0.0.1"]
    stdout, stderr, rc = run_cmd(cmd, timeout=15)
    r.ok(rc == 0, f"prping exit={rc}")
    time.sleep(1)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap)

    # — 断言 —
    r.ok("10.99.99.99" in wire,
         "tcpdump 显示伪造 src=10.99.99.99（任意 IP 可伪造）")
    r.ok("echo request" in wire.lower() or "ICMP echo" in wire,
         "线上是 ICMP echo request")
    return r


# ─── T8: payload 模式 → 真实 src 但不同端口 → server 正常接收 ────────────
def test_T8(port):
    r = Result("T8", "payload_mode_different_port",
               "prping packet http_get.pkt 127.0.0.1:PORT -p port=PORT")
    log = _tmp("t8.log")
    pcap = _tmp("t8.pcap")
    pkt = WORKSPACE / "examples/app_http/http_get.pkt"

    http_log, wire = run_one(
        r, port, log, pcap, pkt,
        [f"127.0.0.1:{port}", "-p", f"port={port},ip=127.0.0.1"],
    )

    # — 断言 —
    r.ok("GET / HTTP/1.1" in http_log,
         "http.server 收到 GET 请求")
    r.ok(f".{port}" in wire,
         f"tcpdump 显示目标端口 {port}")
    r.ok("127.0.0.1" in wire,
         "src 是真实 IP 127.0.0.1")
    return r


# ─── 主入口 ──────────────────────────────────────────────────────────────
def main():
    ensure_privileges()
    setup()

    print("=" * 60)
    print("pktlang_tests: raw sending effectiveness")
    print("=" * 60)
    print(f"  prping   : {PRPING}")
    print(f"  fixtures : {FIXTURES}")
    print(f"  workspace: {WORKSPACE}")
    print()

    results = []
    port = BASE_PORT

    tests = [
        test_T1, test_T2, test_T3, test_T4,
        test_T5, test_T6, test_T7, test_T8,
    ]

    for test_fn in tests:
        port += 1
        tid = test_fn.__doc__.split(":")[0].strip().split(" ")[0] if test_fn.__doc__ else "?"
        name = test_fn.__doc__.split(":")[1].strip().split("→")[0].strip() if test_fn.__doc__ else test_fn.__name__
        print(f"── {tid} {name} ──")

        try:
            r = test_fn(port)
            results.append(r)
            for passed, msg in r.checks:
                sym = "  ✅" if passed else "  ❌"
                print(f"{sym} {msg}")
            print(f"    cmd: {r.cmd_desc}")
        except Exception as e:
            print(f"  ❌ EXCEPTION: {e}")
            results.append(Result(tid, name, str(e)))
            results[-1].checks.append((False, f"exception: {e}"))
        print()

    # ─── 汇总 ────────────────────────────────────────────────────────────
    print("=" * 60)
    total = sum(len(r.checks) for r in results)
    passed = sum(sum(1 for c in r.checks if c[0]) for r in results)
    n_tests = len(results)
    n_pass = sum(1 for r in results if r.passed)

    for r in results:
        print(f"  {r.summary_line()}")

    print()
    print(f"  {n_pass}/{n_tests} tests passed, {passed}/{total} assertions passed")
    print("=" * 60)

    return 0 if n_pass == n_tests else 1


if __name__ == "__main__":
    sys.exit(main())
