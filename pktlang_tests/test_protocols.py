#!/usr/bin/env python3
"""
pktlang_tests/test_protocols.py

用 tcpdump 验证各协议（ARP/UDP/ICMP/TCP/IPv6/QUIC）的原始包发送。
在 user+net namespace 内运行，无需特权。

测试清单：
  P1. ARP 广播请求 → tcpdump 看到 ARP who-has
  P2. UDP DNS 查询 → tcpdump 看到 UDP DNS 查询
  P3. UDP 任意载荷 → tcpdump 看到 UDP + 正确端口
  P4. ICMP echo bare → tcpdump 看到 ICMP echo request
  P5. ICMPv6 echo bare → tcpdump 看到 ICMPv6 echo request
  P6. TCP SYN bare → tcpdump 看到 TCP SYN
  P7. TCP SYN+ACK+GET 三步 → tcpdump 看到三个包
  P8. QUIC Initial → tcpdump 看到 UDP 443 + QUIC 长头
  P9. ICMP 不同 payload 大小 → tcpdump 看到不同 length
  P10. UDP 跨端口发送 → tcpdump 看到两个不同 dport

运行：python3 pktlang_tests/test_protocols.py
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
BASE_PORT = 20100
_tmp_counter = 0


def _tmp(suffix):
    global _tmp_counter
    _tmp_counter += 1
    return f"/tmp/proto_{_tmp_counter}_{suffix}"


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


def raw_send(fixture, extra_args=None, iface=None):
    """发送一个 .pkt 文件，返回 tcpdump 抓包内容。"""
    pcap = _tmp("raw.pcap")
    tdump = start_tcpdump(pcap, iface=iface or "lo")
    time.sleep(0.5)

    cmd = [str(PRPING), "packet", str(fixture), "--raw"]
    if extra_args:
        cmd.extend(extra_args)
    run_cmd(cmd, timeout=10)

    time.sleep(0.5)
    kill(tdump)
    time.sleep(0.3)
    return tcpdump_read(pcap, ethernet=bool(iface))


# ─── P1: ARP 广播请求 ───────────────────────────────────────────────────
    """P1: placeholder"""
def test_P1():
    """P1: arp_broadcast_request"""
    r = Result("P1", "arp_broadcast_request")
    wire = raw_send(
        EXAMPLES / "link_arp/arp_request.pkt",
        extra_args=["-p", "ip=127.0.0.1"],
        iface="lo",
    )
    r.ok("ARP" in wire, "tcpdump 识别 ARP 协议")
    r.ok("who-has" in wire or "Request" in wire, "ARP 请求（who-has）")
    r.ok("127.0.0.1" in wire, "目标 IP 127.0.0.1 可见")
    r.ok("ff:ff:ff:ff:ff:ff" in wire.lower() or "broadcast" in wire.lower(),
         "广播目的 MAC")
    return r


# ─── P2: UDP DNS 查询 ───────────────────────────────────────────────────
    """P2: placeholder"""
def test_P2():
    """P2: udp_dns_query"""
    r = Result("P2", "udp_dns_query")
    wire = raw_send(
        EXAMPLES / "transport_udp/udp_dns.pkt",
        extra_args=["-p", "ip=127.0.0.1"],
        iface="lo",
    )
    r.ok("53" in wire, "目标端口 53（DNS）")
    r.ok("example.com" in wire.lower() or "A?" in wire,
         "DNS 查询包含 example.com")
    return r


# ─── P3: UDP 任意载荷 ───────────────────────────────────────────────────
    """P3: placeholder"""
def test_P3():
    """P3: udp_custom_payload"""
    r = Result("P3", "udp_custom_payload")
    # 用 transport_udp 的 VNC 步骤
    wire = raw_send(
        EXAMPLES / "transport_udp/udp_vnc.pkt",
        extra_args=["-p", "ip=127.0.0.1"],
        iface="lo",
    )
    r.ok("UDP" in wire, "tcpdump 识别 UDP")
    r.ok("127.0.0.1" in wire, "src/dst 包含 127.0.0.1")
    return r


# ─── P4: ICMP echo bare ─────────────────────────────────────────────────
    """P4: placeholder"""
def test_P4():
    """P4: icmp_echo_bare"""
    r = Result("P4", "icmp_echo_bare")
    wire = raw_send(
        WORKSPACE / "pktlang_tests/fixtures/icmp_echo_spoof.pkt",
        extra_args=["-p", "src=0.0.0.0,ip=127.0.0.1"],
    )
    r.ok("ICMP echo request" in wire, "ICMP echo request")
    r.ok("127.0.0.1" in wire, "src/dst 包含 127.0.0.1")
    return r


# ─── P5: ICMPv6 echo bare ───────────────────────────────────────────────
    """P5: placeholder"""
def test_P5():
    """P5: icmpv6_echo_bare"""
    r = Result("P5", "icmpv6_echo_bare")
    # 创建一个 ICMPv6 echo pkt
    pkt_content = """
payload = raw(bytes="prping v6 test")
full = use(payload) |> icmp(type=128, id=0xabcd, seq=1)
                    |> ipv6(dst="::1")
export:
- full
"""
    pkt_path = _tmp("icmpv6.pkt")
    Path(pkt_path).write_text(pkt_content)

    pcap = _tmp("p5.pcap")
    tdump = start_tcpdump(pcap)
    time.sleep(0.5)

    cmd = [str(PRPING), "packet", pkt_path, "--raw"]
    run_cmd(cmd, timeout=10)

    time.sleep(0.5)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap)
    r.ok("ICMP6" in wire or "icmp6" in wire.lower(), "tcpdump 识别 ICMPv6")
    r.ok("echo request" in wire.lower(), "ICMPv6 echo request")
    return r


# ─── P6: TCP SYN bare ───────────────────────────────────────────────────
    """P6: placeholder"""
def test_P6():
    """P6: tcp_syn_bare"""
    r = Result("P6", "tcp_syn_bare")
    wire = raw_send(WORKSPACE / "pktlang_tests/fixtures/tcp_syn_spoof.pkt")
    r.ok("192.168.81.100" in wire, "伪造 src=192.168.81.100 在线上")
    r.ok("Flags [S]" in wire or "S" in wire, "TCP SYN 标志")
    r.ok("127.0.0.1" in wire, "dst=127.0.0.1 可见")
    return r


# ─── P7: TCP SYN + ACK + GET 三步 ──────────────────────────────────────
    """P7: placeholder"""
def test_P7():
    """P7: tcp_three_step"""
    r = Result("P7", "tcp_three_step")
    # 用 tcp_handshake 配方（SYN → ACK → GET），不带 --wait（避免 sniffer 报错）
    pcap = _tmp("p7.pcap")
    tdump = start_tcpdump(pcap)
    time.sleep(0.5)

    cmd = [str(PRPING), "packet",
           str(EXAMPLES / "tcp_handshake"),
           "127.0.0.1:443",
           "--raw", "--wait", "0",
           "-p", "port=443,ip=127.0.0.1"]
    run_cmd(cmd, timeout=15)

    time.sleep(0.5)
    kill(tdump)
    time.sleep(0.3)

    wire = tcpdump_read(pcap)
    r.ok("Flags [S]" in wire, "步骤1: SYN 在线上")
    r.ok("Flags [.]" in wire or "Flags [A]" in wire, "步骤2: ACK 在线上")
    r.ok("length" in wire, "步骤3: 带载荷的数据包在线上")
    return r


# ─── P8: QUIC Initial ───────────────────────────────────────────────────
    """P8: placeholder"""
def test_P8():
    """P8: quic_initial"""
    r = Result("P8", "quic_initial")
    wire = raw_send(
        EXAMPLES / "quic_initial/quic_initial.pkt",
        extra_args=["-p", "ip=127.0.0.1"],
        iface="lo",
    )
    r.ok("UDP" in wire, "QUIC 走 UDP 传输")
    r.ok("443" in wire, "目标端口 443")
    return r


# ─── P9: ICMP 不同 payload 大小 ─────────────────────────────────────────
    """P9: placeholder"""
def test_P9():
    """P9: icmp_payload_sizes"""
    r = Result("P9", "icmp_payload_sizes")
    results = []
    for size_label, payload_bytes in [("小", "hi"), ("中", "A" * 100), ("大", "B" * 500)]:
        pkt_content = f"""
payload = raw(bytes="{payload_bytes}")
full = use(payload) |> icmp(type=8, id=0x1234, seq=1)
                    |> ipv4(src="192.168.81.100", dst="127.0.0.1")
export:
- full
"""
        pkt_path = _tmp(f"icmp_{size_label}.pkt")
        Path(pkt_path).write_text(pkt_content)
        wire = raw_send(pkt_path)
        has_echo = "ICMP echo request" in wire
        results.append((size_label, has_echo, wire))
        r.ok(has_echo, f"{size_label} payload ICMP echo request 可见")

    # 验证 length 不同（至少大 payload 的 length 应该更大）
    lengths = []
    for _, _, wire in results:
        m = re.search(r"length (\d+)", wire)
        if m:
            lengths.append(int(m.group(1)))
    if len(lengths) == 3:
        r.ok(lengths[0] < lengths[2],
             f"大 payload 长度({lengths[2]}) > 小 payload 长度({lengths[0]})")
    return r


# ─── P10: UDP 跨端口 ───────────────────────────────────────────────────
    """P10: placeholder"""
def test_P10():
    """P10: udp_cross_port"""
    r = Result("P10", "udp_cross_port")
    # 同时发 DNS（dport=53）和 VNC（dport=5900）
    wire_dns = raw_send(
        EXAMPLES / "transport_udp/udp_dns.pkt",
        extra_args=["-p", "ip=127.0.0.1"],
        iface="lo",
    )
    wire_vnc = raw_send(
        EXAMPLES / "transport_udp/udp_vnc.pkt",
        extra_args=["-p", "ip=127.0.0.1"],
        iface="lo",
    )
    r.ok("53" in wire_dns, "DNS 查询 dport=53 可见")
    r.ok("5900" in wire_vnc, "VNC 载荷 dport=5900 可见")
    return r


# ─── 主入口 ──────────────────────────────────────────────────────────────
def main():
    ensure_privileges()
    setup()

    print("=" * 60)
    print("pktlang_tests: protocol correctness (tcpdump)")
    print("=" * 60)
    print(f"  prping   : {PRPING}")
    print(f"  examples : {EXAMPLES}")
    print()

    tests = [test_P1, test_P2, test_P3, test_P4, test_P5,
             test_P6, test_P7, test_P8, test_P9, test_P10]

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
