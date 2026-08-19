# prping Manual

> A cross-platform network "multimeter" — a psping clone implemented in Rust.
> Measures: ICMP / TCP / UDP ping, latency tests, bandwidth tests, path MTU probing, jitter statistics.
> The packet-building engine lives in the same binary (`--eng`/`--pkg` modes, see Chapter 25).

## Table of Contents

1. [Introduction and Features](#1-introduction-and-features)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Mode Overview (Auto-Detection)](#4-mode-overview-auto-detection)
5. [ICMP Ping](#5-icmp-ping)
6. [TCP Ping](#6-tcp-ping)
7. [UDP Ping](#7-udp-ping)
8. [Latency Test](#8-latency-test)
9. [Bandwidth Test](#9-bandwidth-test)
10. [Server Mode](#10-server-mode)
11. [Receive Mode](#11-receive-mode)
12. [Test Control Options (count/interval/warmup/quiet/parallel)](#12-test-control-options-countintervalwarmupquietparallel)
13. [Histogram and Timeline (-H / -g / -p)](#13-histogram-and-timeline--h--g--p)
14. [Statistics (incl. jitter)](#14-statistics-incl-jitter)
15. [JSON Output](#15-json-output)
16. [MTU Probe (-M / --mtu)](#16-mtu-probe--m---mtu)
17. [Source Address Binding (-I)](#17-source-address-binding--i)
18. [IPv4 / IPv6 Dual-Stack](#18-ipv4-ipv6-dual-stack)
19. [Exit Codes and Scripting](#19-exit-codes-and-scripting)
20. [Signals and Interruption (Ctrl+C)](#20-signals-and-interruption-ctrlc)
21. [Language and Internationalization](#21-language-and-internationalization)
22. [Complete Example Collection](#22-complete-example-collection)
23. [Frequently Asked Questions (FAQ)](#23-frequently-asked-questions-faq)
24. [Comparison with psping](#24-comparison-with-psping)
25. [Packet-Building Engine (--eng / --pkg / packet-dsl)](#25-packet-building-engine---eng---pkg--packet-dsl)

> Tip: `prping --help-pkg <chapter-title>` jumps straight to a chapter for learning;
> both `prping --help-pkg 1` (by number) and `prping --help-pkg installation` (by title prefix) work.

---

## 1. Introduction and Features

prping is a cross-platform (Linux / macOS / Windows) command-line network measurement tool,
modeled after Microsoft's [psping](https://learn.microsoft.com/en-us/sysinternals/downloads/psping).
Think of it as a "multimeter" for network engineers: it quickly answers "can I reach it,
what's the latency, is there packet loss, is there jitter, how much bandwidth, what's the MTU".

### Feature overview

- **Four kinds of ping**: ICMP (IPv4/IPv6), TCP, UDP, with automatic port detection
- **Latency test**: client/server architecture, TCP/UDP dual modes, can measure the reverse direction (receive mode)
- **Bandwidth test**: multi-connection concurrency (`-P`), real-time progress bar
- **Path MTU probe** (`-M`): ICMP DF + binary search over variable payload sizes, resolved automatically
- **Jitter**: mean/max of consecutive RTT differences, a key metric for real-time stream troubleshooting
- **Statistics**: min/max/avg/stddev + P50/P95/P99 + packet loss rate + histogram + timeline
- **JSON output**: per-sample lines + summary, machine-readable, great for scripts/monitoring
- **Source address binding** (`-I`): multi-NIC / policy-routing scenarios
- **Count or duration**: `-n 10` for a fixed count, `-n 10s` to run by seconds
- **IPv4/IPv6 dual-stack**, graceful Ctrl+C exit, bilingual (Chinese/English), exit codes that reflect packet loss

### Command-line overview

```
prping [OPTIONS] <HOST[:PORT]>
```

With no options, the mode is auto-detected from the target:

| Target form | Mode |
|---|---|
| `HOST` (no port) | ICMP ping |
| `HOST:PORT` | TCP ping |
| `-u HOST:PORT` | UDP ping |
| `-l SIZE HOST:PORT` | Latency test |
| `-b -l SIZE HOST:PORT` | Bandwidth test |
| `-M HOST` | MTU probe |
| `-s ADDR:PORT` | Server |

---

## 2. Installation

### Building from source

```bash
git clone <repo-url> && cd prping
cargo build --release
```

On Linux, ICMP ping / MTU probing / raw sockets require root or `cap_net_raw`:

```bash
sudo setcap cap_net_raw+ep target/release/prping
```

### One-shot recipes (justfile)

```bash
just build-release        # release build
just build-windows        # all Windows artifacts (incl. Win7-compatible build)
just test                 # run all tests
just lint                 # clippy zero warnings
```

### Dependencies

- Rust 2024 edition (stable is enough)
- No runtime dependencies; the Windows 7-compatible build needs nightly + the xwin toolchain (see the project README)

---

## 3. Quick Start

```bash
# reachability
prping 8.8.8.8                    # ICMP, unlimited, stop with Ctrl+C
prping example.com                # domain name resolved automatically

# port reachability / connection latency
prping 192.168.1.1:80
prping 8.8.8.8:53 -n 10           # fixed 10 probes

# latency test (needs a server, see Chapter 10)
prping -l 64 -n 100 server:8080

# bandwidth test
prping -b -l 8k -n 10000 -P 4 server:8080

# quick one-round statistics (incl. jitter)
prping -n 20 -w 0 -H 10 192.168.1.1

# path MTU
prping -M 8.8.8.8

# bind a source address
prping -I 192.168.1.10 8.8.8.8
```

---

## 4. Mode Overview (Auto-Detection)

The mode is determined automatically from "options + target port" — no explicit mode argument is needed:

| Trigger | Mode | Description |
|---|---|---|
| No port, no `-u/-l/-b/-M` | ICMP | Default; `-4/-6` select the protocol |
| Port given, no `-u/-l/-b` | TCP | Connection latency + reachability |
| `-u` + port | UDP | Sends UDP datagrams, validates reply seq |
| `-l SIZE` + port | Latency test | Needs `prping -s` on the peer |
| `-b` + `-l SIZE` + port | Bandwidth test | Needs `prping -s` on the peer |
| `-M` | MTU probe | No port; IPv4 only |
| `-s ADDR:PORT` | Server | Cannot be combined with client arguments |

All modes share the "test control", "output", and "network" option groups (Chapters 12/13/15/18).

---

## 5. ICMP Ping

**Purpose**: the most basic connectivity + latency measurement; distinguishes network failures (unreachable / TTL exceeded).

```bash
prping 8.8.8.8                  # unlimited (stop with Ctrl+C)
prping -n 10 -i 0.2 8.8.8.8     # 10 probes, 200ms interval
prping -l 1400 8.8.8.8          # large payload (probe link limits)
prping -M 8.8.8.8               # see Chapter 16: automatic MTU
```

### Example output

```
正在 Ping 8.8.8.8，数据大小 32 字节:
10 次迭代 (预热 0) ping 测试:
来自 8.8.8.8: 字节=32 时间=1.23ms TTL=57
...
  发送 = 10，接收 = 10，丢失 = 0 (0% 丢失),
  最小 = 1.11ms，最大 = 1.87ms，平均 = 1.34ms，标准差 = 0.21ms
  P50 = 1.32ms, P95 = 1.87ms, P99 = 1.87ms
  抖动 = 0.18ms（最大 0.44ms）
```

### Notes

- Raw ICMP socket: Linux/macOS need root or `cap_net_raw`; Windows needs administrator
- `-l` controls the ICMP payload size in bytes (excluding the ICMP/IP headers)
- Distinguishes three kinds of replies: echo reply (normal), unreachable (type 3), TTL exceeded (type 11)

---

## 6. TCP Ping

**Purpose**: port connectivity + connection (connect) latency; equivalent to "telnet to a port and time it".

```bash
prping 192.168.1.1:22           # SSH port
prping -n 30 -i 0.1 -H 10 server:443
prping -I 10.0.0.2 server:443   # bind a source address (Chapter 17)
```

### Example output

```
TCP 连接到 192.168.1.1:22:
30 次迭代 (预热 0) ping 测试:
连接到 192.168.1.1:22: 从 192.168.1.100:54321: 0.32ms
...
  发送 = 30，接收 = 30，丢失 = 0 (0% 丢失),
  最小 = 0.25ms，最大 = 0.60ms，平均 = 0.33ms，标准差 = 0.08ms
```

### Notes

- Each probe opens a new TCP connection and closes it immediately (no application data is sent)
- Connection timeout is 5 seconds; multiple addresses (a domain with several IPs) are tried in turn automatically
- Packet loss = failed connections; firewall drops show up as timeout losses
- `-P` concurrency is meaningless in this mode (each probe connects only once)

---

## 7. UDP Ping

**Purpose**: UDP reachability testing (e.g. DNS port 53, game servers); unique to prping beyond psping.

```bash
prping -u 8.8.8.8:53
prping -u -n 10 192.168.1.1:5000
```

### Notes

- Sends UDP datagrams tagged with a sequence number; replies are validated against seq, filtering stray packets
- **The target must run a UDP echo service** (such as a `prping -s` server or a DNS responder) to reply;
  without one, every probe times out — this is inherent to UDP ping
- UDP is often silently dropped by firewalls; a 100% loss rate does not mean the host is unreachable —
  cross-check with ICMP/TCP

---

## 8. Latency Test

**Purpose**: end-to-end application latency (TCP connection + data round trip), closer to real user experience
than ping. Both ends need prping installed: the client triggers with `-l`, the server runs with `-s`.

```bash
# server (start it first)
prping -s 0.0.0.0:8080

# client
prping -l 64 -n 100 server:8080          # TCP latency test (default)
prping -l 64 -n 100 -u server:8080       # UDP latency test
prping -l 64 -n 100 -r server:8080       # reverse: measure the download direction (Chapter 11)
```

### How it works

1. The client connects to the server (TCP or UDP)
2. Sends a `size`-byte request; the server echoes it back unchanged
3. The client measures the round-trip time (RTT)
4. When the server exits on Ctrl+C, it prints aggregate statistics

### Notes

- `-l` is required to trigger a latency test (when a port is given)
- The server supports up to 1024 concurrent connections
- UDP latency-test echo bytes count toward the server's aggregate statistics

---

## 9. Bandwidth Test

**Purpose**: throughput measurement (Mbps), multi-connection stress testing with `-P`.

```bash
# server
prping -s 0.0.0.0:8080

# client: 8KB packets, 10k iterations, 4 concurrent connections
prping -b -l 8k -n 10000 -P 4 server:8080

# duration mode
prping -b -l 1m -n 10s -P 8 server:8080
```

### Example output

```
TCP Bandwidth test:
  Sent = 81920000 bytes in 0.42s
  Bandwidth = 1566.49 Mbps
```

### Notes

- For precise throughput measurement use iperf3; prping's bandwidth mode is a convenient "good enough" stress test
- `-P` concurrency: parallel connections, with the total exactly equal to `count`
- `-r` measures the download direction (receive mode, see Chapter 11)
- The progress bar only shows on a tty; silent under pipes / `--json` / `-q`
- UDP bandwidth mode automatically enlarges the kernel buffers to 4MB to avoid bursty loss

---

## 10. Server Mode

**Purpose**: the server side for latency / bandwidth tests; serves TCP/UDP and latency / bandwidth / receive modes
at the same time.

```bash
prping -s 0.0.0.0:8080
prping -s [::]:8080             # IPv6
```

### Notes

- One server supports all client modes at once (TCP/UDP × latency/bandwidth × send/receive directions)
- On Ctrl+C exit it prints aggregate statistics (connection count, bytes sent/received, etc.)
- Cannot be combined with any client arguments (`-n/-i/-l/-b/-u/-P/-I/-M`, etc.)
- Kept Win7-compatible on Windows

---

## 11. Receive Mode

**Purpose**: measure the "download direction" — the client only receives, the server only sends.

```bash
# server
prping -s 0.0.0.0:8080

# client: reverse latency test
prping -l 64 -n 100 -r server:8080

# client: reverse bandwidth test
prping -b -l 8k -n 10000 -P 4 -r server:8080
```

### Notes

- `-r` is legal only with `-b` (bandwidth), or `-l` + a port (latency)
- UDP receive-mode trigger protocol: the client sends a `[0xFF, 0xFF, size(2B), count(4B)]` trigger packet,
  and the server sends back `count` datagrams of `size` bytes
- Server UDP echo bytes count toward the aggregate statistics

---

## 12. Test Control Options (count/interval/warmup/quiet/parallel)

Common to all ping / latency / bandwidth modes.

| Option | Description |
|---|---|
| `-n N` | Fixed count (unlimited by default) |
| `-n 10s` | Run by seconds (10 seconds) |
| `-i S` | Interval in seconds (0 = fast, minimum 1ms) |
| `-w N` | Warmup count (default 4, not counted in statistics) |
| `-q` | Quiet: no per-probe output, summary only |
| `-P N` | Concurrent connections (bandwidth test only; other modes ignore it with a warning) |
| `-l SIZE` | Payload size; suffixes `64` / `8k` / `1m` supported |

### Examples

```bash
prping -n 1000 -i 0.01 8.8.8.8      # 1000 fast pings (10ms interval)
prping -n 30s -w 5 server:8080      # 30 seconds, 5 warmup probes
prping -q -n 100 192.168.1.1        # summary only
prping -n 1000000 -i 0 -q 8.8.8.8   # 1M fast pings (0 interval = fastest)
```

> Note: `-n` only supports the `s` suffix (seconds, e.g. `-n 10s`); `-n 1m` errors out —
> write fixed counts as plain numbers. Only `-l`'s `m` suffix means megabytes (`-l 1m` = 1MB payload).

---

## 13. Histogram and Timeline (-H / -g / -p)

### Histogram `-H`

Two forms:

```bash
prping -n 100 -H 10 8.8.8.8          # 10 buckets
prping -n 100 -H "1,5,10,50" 8.8.8.8 # custom ms thresholds: 1/5/10/50ms buckets
```

Rendered as ASCII `#` by default; `-p` (pretty) renders a Unicode bar chart with
[ploot](https://github.com/ploot-rs/ploot) (ANSI colors are stripped automatically off a tty).

### Timeline `-g`

```bash
prping -n 20 -i 0.1 -gp 127.0.0.1:22  # timeline chart (-p uses ploot Braille scatter)
```

`-g` shows a timeline of per-round latency, good for spotting jitter trends.

### Notes

- An invalid `-H` value (e.g. `-H abc`) errors out in red with exit code 1
- `--json` is mutually exclusive with `-p/-g/-H` (JSON is a machine format; no charts needed)

---

## 14. Statistics (incl. jitter)

Every test prints a summary of statistics when it finishes:

| Metric | Meaning |
|---|---|
| Sent / Received / Lost | Packet counts and loss rate |
| Min / Max / Avg | min / max / avg (ms) |
| Stddev | how spread out the latency is |
| **Jitter** | **mean absolute difference between consecutive RTTs** (loss breaks the chain) |
| Max jitter | maximum consecutive RTT difference |
| P50 / P95 / P99 | percentile latency (printed when there are ≥ 2 samples) |

### Example output

```
  发送 = 8，接收 = 8，丢失 = 0 (0% 丢失),
  最小 = 0.24ms，最大 = 2.18ms，平均 = 0.66ms，标准差 = 0.60ms
  P50 = 0.48ms, P95 = 2.18ms, P99 = 2.18ms
  抖动 = 0.40ms（最大 1.52ms）
```

### About jitter

- Jitter = the mean of differences between consecutive successful RTTs (mean of `|RTT[i] - RTT[i-1]|`)
- Loss breaks the "consecutive" chain: the first sample after a loss is not compared with the sample
  before the loss
- High jitter = unstable network (a common root cause of stutter in real-time audio/video and games);
  low latency + high jitter hurts real-time experience more than high latency

---

## 15. JSON Output

`--json` outputs JSONL (one record per line; you can `tail -f` it live; the last line is the summary).

### Per-sample lines

```json
{"type":"tcp","target":"127.0.0.1:22","ts":1787031710,"seq":0,"ok":true,"rtt_ms":0.26}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031711,"seq":1,"ok":true,"rtt_ms":0.31}
{"type":"tcp","target":"127.0.0.1:22","ts":1787031712,"seq":2,"ok":false,"error":"timeout"}
```

### Summary line (summary:true)

```json
{"type":"tcp","target":"127.0.0.1:22","ts":1787031713,"summary":true,"sent":3,"received":2,
 "lost":1,"loss_pct":33.3,"min_ms":0.26,"max_ms":0.31,"avg_ms":0.28,"stddev_ms":0.02,
 "jitter_ms":0.05,"jitter_max_ms":0.05,"p50_ms":0.26,"p95_ms":0.31,"p99_ms":0.31}
```

- `type`: `icmp` / `tcp` / `udp` / `latency` / `mtu`
- Summary fields: `sent/received/lost/loss_pct`, `min_ms/max_ms/avg_ms/stddev_ms`,
  `jitter_ms/jitter_max_ms` (when there are ≥ 2 samples), `p50_ms/p95_ms/p99_ms` (when there are ≥ 2 samples)
- MTU-mode summary: `payload_max`, `mtu`, `frag_needed_mtu` (when present)

### Script examples

```bash
prping -n 10 --json 8.8.8.8 | tail -1 | jq .jitter_ms
prping -n 30s --json server:8080 | jq -r 'select(.ok) | .rtt_ms' | awk '{s+=$1} END {print s/NR}'
```

> On Unix, `--json` disables the terminal's echoed `^C` while running (restored on exit).

---

## 16. MTU Probe (-M / --mtu)

**Purpose**: find the path MTU (path Maximum Transmission Unit) — the largest packet size between the two ends
that avoids fragmentation. Mismatched link MTUs are the classic cause of "small packets pass, big packets don't".

```bash
prping -M 8.8.8.8
prping -M 192.168.1.1 -I eth0     # bind a source
prping -M --json 8.8.8.8          # machine-readable
```

### Example output

```
  payload=32769 → ok（可过）
  payload=49153 → ok（可过）
  payload=57345 → 分片需要
  payload=53249 → 分片需要
  payload=51199 → ok（可过）
  ...

路径 MTU = 1500 字节（最大不分片载荷 1472 字节，目标 8.8.8.8）
  途中 Fragmentation Needed 报回 MTU = 1500
```

### How it works

1. Send ICMP echoes with the DF (don't fragment) bit set, probing payload sizes `[0, 65507]` with binary search
2. An echo reply means that size passes; Fragmentation Needed (type 3 code 4) means it is too large,
   and the packet carries the next-hop MTU
3. After convergence: **path MTU = largest passing payload + 28** (IPv4: 20-byte IP header + 8-byte ICMP header)
4. MTUs reported by routers along the path are also shown (the minimum is taken)

### Limitations

- **IPv4 only** (IPv6 path MTU would need ICMPv6 Packet Too Big; not supported yet)
- Needs a raw socket (root / `cap_net_raw`)
- If a firewall drops ICMP, a "no echo" error is reported — probing is impossible then
- Probe timeouts are treated as "exceeds limit" and noted (at most 2 retries per size)

---

## 17. Source Address Binding (-I)

**Purpose**: specify the probe source address / interface — multi-NIC hosts, policy routing, dual-link troubleshooting.

```bash
prping -I 192.168.1.10 8.8.8.8        # bind source IP (works for TCP/ICMP/UDP)
prping -I 10.0.0.2 server:8080 -l 64  # latency test with a source
prping -I eth0 8.8.8.8                # Linux: interface name → IPv4 automatically
prping -M -I eth1 8.8.8.8             # MTU probe with a source
```

### Notes

- The argument can be an IP address, or a **Linux interface name** (its IPv4 is looked up via `SIOCGIFADDR`;
  for IPv6 write the address directly)
- Works in every mode: ICMP / TCP / UDP ping, latency, bandwidth, MTU probe
- Server mode (`-s`) does not accept `-I`
- Errors on address-family mismatch (e.g. `-I` with an IPv6 address while the target is IPv4)

---

## 18. IPv4 / IPv6 Dual-Stack

```bash
prping 8.8.8.8                # IPv4
prping 2001:4860:4860::8888   # IPv6 (no brackets needed)
prping [::1]:80               # IPv6 with a port needs square brackets
prping -6 example.com         # force IPv6 (when a domain has multiple records)
prping -4 example.com         # force IPv4
```

### Rules

- Without `-4/-6`, the family is chosen automatically from the target's form; when a domain resolves to
  multiple records, the first is used
- `-4` and `-6` are mutually exclusive (giving both errors out)
- MTU probing is IPv4 only (Chapter 16)

---

## 19. Exit Codes and Scripting

| Exit code | Meaning |
|---|---|
| 0 | No packet loss (incl. successful MTU probe) |
| 1 | Packet loss / connection failure / argument error |
| 2 | Other runtime errors |

```bash
prping -n 10 8.8.8.8 || echo "network problem"
prping -n 10 --json 8.8.8.8 >/dev/null && echo OK

# monitoring script: alert on a loss threshold
loss=$(prping -n 5 --json 8.8.8.8 | tail -1 | jq -r .loss_pct)
[ "$(echo "$loss > 10" | bc)" = 1 ] && alert
```

---

## 20. Signals and Interruption (Ctrl+C)

- **First Ctrl+C**: stop the test, print the full statistics, then exit
- **Second Ctrl+C**: force exit (without waiting for statistics)
- In `--json` mode on Unix, the terminal's echoed `^C` is disabled while running
  (the `^C` is a terminal echo and never enters the stdout pipe; it is restored on exit)

---

## 21. Language and Internationalization

Auto-detected: `$LANG` (Unix) / system UI language (Windows); `--lang` overrides manually.

```bash
prping --lang en-US 8.8.8.8    # English
prping --lang zh-CN 8.8.8.8    # Chinese (default follows the system)
LANG=zh_CN.UTF-8 prping 8.8.8.8
```

### Manual language

The `--help-pkg` manual switches with the language:

```bash
prping --lang zh-CN --help-pkg 16     # Chinese manual, Chapter 16 (MTU)
prping --lang en-US --help-pkg MTU    # English manual
```

---

## 22. Complete Example Collection

### Everyday troubleshooting

```bash
# 1. is it reachable?
prping 8.8.8.8 -n 4

# 2. full picture: latency / jitter / loss (20 probes, threshold histogram)
prping -n 20 -w 0 -H "1,5,10,50" 8.8.8.8

# 3. a specific port
prping 8.8.8.8:53 -n 10
prping 192.168.1.1:443 -n 10 -i 0.5

# 4. do large packets pass? (MTU issues)
prping -l 1400 8.8.8.8
prping -M 8.8.8.8

# 5. multi-NIC: bind a source
prping -I eth1 10.0.0.1:80 -n 20
```

### Latency / bandwidth (the peer needs `prping -s`)

```bash
prping -s 0.0.0.0:8080                       # server
prping -l 64 -n 1000 server:8080             # TCP latency
prping -l 64 -n 1000 -u server:8080          # UDP latency
prping -l 64 -n 1000 -r server:8080          # reverse (download direction)
prping -b -l 8k -n 10000 -P 4 server:8080    # bandwidth
prping -b -l 1m -n 10s -P 8 server:8080      # duration-mode bandwidth
prping -b -l 8k -n 10000 -P 4 -r server:8080 # reverse bandwidth
```

### Scripts / monitoring

```bash
# measure latency every 30 seconds and log it
while true; do
  echo "$(date +%s) $(prping -n 3 --json 8.8.8.8 | tail -1 | jq -r .avg_ms)"
  sleep 30
done >> latency.log

# packet-loss trend
prping -n 60 -i 1 --json 8.8.8.8 | jq -c 'select(.summary)'
```

---

## 23. Frequently Asked Questions (FAQ)

### Q1: ICMP ping reports "cannot create raw socket"
You need root or `cap_net_raw`:
```bash
sudo setcap cap_net_raw+ep $(which prping)
```
On Windows, run as administrator.

### Q2: UDP ping times out entirely
No UDP echo service (or a firewall drops it). Cross-check with TCP/ICMP;
for a DNS server try `prping -u 8.8.8.8:53` (DNS replies).

### Q3: Small packets pass, big packets don't
Most likely an MTU issue: probe the path MTU with `prping -M <host>`,
and check the MTU configuration on both ends plus tunnel overhead (e.g. PPPoE subtracts 8 bytes).

### Q4: Low latency but video/voice stutters
Look at **jitter** (Chapter 14) — high jitter hurts real-time streams more than high latency.
Check the distribution with `prping -n 100 -H 1,5,10,50 <host>`.

### Q5: Does `-n 1m` mean one million probes?
No, it errors out. `-n` only supports the `s` suffix (seconds; `-n 10s` = 10 seconds);
write fixed counts as plain numbers (`-n 1000000`). Only `-l`'s `m` suffix means megabytes (`-l 1m` = 1MB payload).

### Q6: `-P` has no effect on TCP ping?
`-P` only works for the bandwidth test; other modes ignore it with a warning.

### Q7: Bandwidth numbers differ from iperf3?
That's normal. prping's bandwidth mode is a convenient stress test without window / congestion tuning;
use iperf3 for precise throughput.

### Q8: How do I measure the download direction?
Use `-r` receive mode (Chapter 11); the peer runs `prping -s`.

### Q9: Can `--json` be combined with `-p/-g/-H`?
No — they are mutually exclusive. JSON is a machine format.

### Q10: Is Win7 supported?
Yes (the Win7-compatible build recipe is in Chapter 2 and the project README).

### Q11: Want to build / send custom packets?
That's the packet-building engine (Chapter 25): `prping --pkg demo.pkt ...`.

---

## 24. Comparison with psping

| Feature | psping | prping | Notes |
|---|---|---|---|
| ICMP ping | ✓ | ✓ | raw socket |
| TCP ping | ✓ | ✓ | connection latency |
| UDP ping | ✗ | ✓ | unique to prping |
| Latency test | ✓ | ✓ | TCP/UDP |
| Bandwidth test | ✓ | ✓ | TCP/UDP, `-P` concurrency |
| Receive mode `-r` | ✓ | ✓ | measures the download direction |
| MTU probe | ✗ | ✓ | unique to prping (automatic binary search) |
| Jitter | ✗ | ✓ | unique to prping |
| Histogram | `-h` | `-H` | bucket count or custom thresholds (ms) |
| Timeline | ✓ | `-g` | `-p` renders with ploot |
| JSON output | ✗ | ✓ | script-friendly |
| Exit codes | Partial | ✓ | returns 1 on packet loss |
| i18n | ✗ | ✓ | automatic Chinese/English switching |
| Cross-platform | Windows | Linux/macOS/Windows | incl. Win7-compatible build |
| Firewall `-f` | ✓ | — | Windows only; no such need cross-platform |

---

## 25. Packet-Building Engine (--eng / --pkg / packet-dsl)

### packet-dsl (workspace sub-crate)

A `.pkt` network-packet-building DSL: parsing + semantic analysis → structured IR → serialized bytes.
Supports an import/export module system, runtime parameters (`params("name")`), byte primitives
(`concat`/`be16`/`rand16`/..., random values generated at build time, e.g. `sport=rand16()`),
user functions (`func name(args) { ... }`),
packet dissection (`dissect(bytes)`), and pcap read/write. Design doc: `packet-dsl/DESIGN.md`.

### Engine modes (same binary)

The packet-building engine CLI, fully separated from prping itself:

```bash
prping --eng FILE.pkt            # analyze: layer stack + hexdump
prping --eng --lsp               # .pkt language server
prping --pkg FILE.pkt [HOST:PORT] # build and send (target optional, inferred from the packet)
prping --pkg FILE.pkt --wait 3   # reply matching + RTT
prping --pkg FILE.pkt --fuzz     # randomize all fields
prping --pkg FILE.pkt --out x.pcap  # save to pcap
prping --eng --ls / --hex ... / --pcap x.pcap
```

**sniffer block** (reply validation): with `--wait`, replies are matched against the
`sniffer` declaration in the `.pkt` file; a match prints `✓ reply matched: field=value (rtt)`,
a timeout prints `✗ no matching reply`:

```pkt
sniffer:
  - match icmp(type=0, id=id, seq=seq)   # reply must be an echo reply with the same id/seq as sent
  # - match dns(id=id)                    # DNS reply id matches the query (replaces the default DNS id match)
  # right-hand literals = constants (type=0); bare idents = same-named field of the sent packet (id=id)
  # multiple clauses: any match wins (list style, like export:)
```

Example:

```
# net.pkt — composable function: builds ipv4+eth two layers at once
import net { net4 }
use(p) |> net4(dst="1.1.1.1")
```

### Raw-send platform differences (--pkg --raw)

`--pkg --raw` sends fully serialized bytes; the underlying transport differs by platform:

| Platform | eth layer (Ethernet frame) | ipv4 layer (bare IP) | ipv6 layer (bare IPv6) |
|---|---|---|---|
| Linux | AF_PACKET (needs root/cap_net_raw; `--iface` selects the NIC, default lo) | IPPROTO_RAW + IP_HDRINCL | AF_INET6 + IPPROTO_RAW + IPV6_HDRINCL |
| Windows | Npcap `pcap_sendpacket` link-layer injection (Npcap must be installed; `--iface` matches the Npcap device name/description) | Npcap injection + automatic Ethernet wrapping (src MAC = interface MAC, dst MAC = next-hop ARP) | Loopback `::1` only (via the Npcap Loopback Adapter) |
| macOS/BSD | Not supported | IPPROTO_RAW works (no IP_HDRINCL; the IP header is built by the kernel, semantics differ from Linux) | Not supported |

Windows notes:

- **Requirements**: Npcap ([npcap.com](https://npcap.com/)). If the installer option "Allow non-admin applications to capture packets" is unchecked, capture/injection requires administrator privileges.
- **Windows 7**: Npcap still supports Windows 7; the driver is SHA-2 signed, so KB4474419 + KB4490628 must be installed or the driver will fail to load.
- **Loopback**: targeting `127.0.0.1`/`::1` automatically selects the Npcap Loopback Adapter (enable "Install Npcap Loopback Adapter" during install).
- **MAC resolution**: before sending bare IPv4, the next hop (`GetBestRoute`) and ARP cache (`GetIpNetTable`) are resolved automatically; on a miss a 1-byte UDP packet is sent to trigger kernel ARP, and if that still fails a broadcast address is used with a warning.
- **IPv6 limitation**: non-loopback bare IPv6 is not supported yet (Windows 7 has no `GetIpNetTable2`, so the v6 neighbor table cannot be enumerated).
- **`--wait`**: the capture handle is opened before sending (to avoid missing fast replies) and filtered by direction so frames we just sent are excluded.

See `packet-dsl/README.md` for details.
