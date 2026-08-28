# prping Manual

> A cross-platform network "multimeter" — a psping clone implemented in Rust.
> Measures: ICMP / TCP / UDP ping, latency tests, bandwidth tests, path MTU probing, traceroute, jitter statistics.
> The packet-building engine lives in the same binary (`engine`/`packet` subcommands, see Chapter 26).

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
16. [MTU Probe (-m / --mtu)](#16-mtu-probe--m---mtu)
17. [Traceroute (-t / --traceroute)](#17-traceroute--t---traceroute)
18. [Source Address Binding (-s)](#18-source-address-binding--s)
19. [IPv4 / IPv6 Dual-Stack](#19-ipv4-ipv6-dual-stack)
20. [Exit Codes and Scripting](#20-exit-codes-and-scripting)
21. [Signals and Interruption (Ctrl+C)](#21-signals-and-interruption-ctrlc)
22. [Language and Internationalization](#22-language-and-internationalization)
23. [Complete Example Collection](#23-complete-example-collection)
24. [Frequently Asked Questions (FAQ)](#24-frequently-asked-questions-faq)
25. [Comparison with psping](#25-comparison-with-psping)
26. [Packet-Building Engine (engine / packet / packet-dsl)](#26-packet-building-engine-engine--packet--packet-dsl)

> Tip: `prping document <chapter-title>` jumps straight to a chapter for learning;
> both `prping document 1` (by number) and `prping document installation` (by title prefix) work.

---

## 1. Introduction and Features

prping is a cross-platform (Linux / macOS / Windows) command-line network measurement tool,
modeled after Microsoft's [psping](https://learn.microsoft.com/en-us/sysinternals/downloads/psping).
Think of it as a "multimeter" for network engineers: it quickly answers "can I reach it,
what's the latency, is there packet loss, is there jitter, how much bandwidth, what's the MTU".

### Feature overview

- **Four kinds of ping**: ICMP (IPv4/IPv6), TCP, UDP, with automatic port detection
- **Latency test**: client/server architecture, TCP/UDP dual modes, can measure the reverse direction (receive mode)
- **Bandwidth test**: multi-connection concurrency (`--parallel`), real-time progress bar
- **Path MTU probe** (`-m`): ICMP DF + binary search over variable payload sizes, resolved automatically
- **Traceroute** (`-t`): ICMP echo with increasing TTL, hop-by-hop path discovery + reverse DNS
- **Jitter**: mean/max of consecutive RTT differences, a key metric for real-time stream troubleshooting
- **Statistics**: min/max/avg/stddev + P50/P95/P99 + packet loss rate + histogram + timeline
- **JSON output**: per-sample lines + summary, machine-readable, great for scripts/monitoring
- **Source address binding** (`-s`): multi-NIC / policy-routing scenarios
- **Count or duration**: `-n 10` for a fixed count, `-n 10s` to run by seconds
- **IPv4/IPv6 dual-stack**, graceful Ctrl+C exit, bilingual (Chinese/English), exit codes that reflect packet loss

### Command-line overview

```
prping ping [OPTIONS] <HOST[:PORT]>
```

Everything is organized by subcommand (see Chapters 3.1/4); the mode is decided by "subcommand + target form":

| Subcommand + target form | Mode |
|---|---|
| `ping HOST` (no port) | ICMP ping |
| `ping HOST:PORT` | TCP ping |
| `ping -u HOST:PORT` | UDP ping |
| `latency -l SIZE HOST:PORT` | Latency test |
| `bandwidth -l SIZE HOST:PORT` | Bandwidth test |
| `ping -m HOST` | MTU probe |
| `trace HOST` | Traceroute |
| `server ADDR:PORT` | Server |

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
prping ping 8.8.8.8                    # ICMP, unlimited, stop with Ctrl+C
prping ping example.com                # domain name resolved automatically

# port reachability / connection latency
prping ping 192.168.1.1:80
prping ping 8.8.8.8:53 -n 10           # fixed 10 probes

# latency test (needs a server, see Chapter 10)
prping latency -l 64 -n 100 server:8080

# bandwidth test
prping bandwidth -l 8k -n 10000 --parallel 4 server:8080

# quick one-round statistics (incl. jitter)
prping ping -n 20 -w 0 -H 10 192.168.1.1

# path MTU
prping ping -m 8.8.8.8

# traceroute
prping trace 8.8.8.8

# bind a source address
prping ping -s 192.168.1.10 8.8.8.8

# packet engine / send (Chapter 26)
prping engine file.pkt
prping packet file.pkt 192.168.1.1:9000
```

---

## 3.1 Subcommands and Migration

prping organizes everything into **subcommands**; any **unique prefix** abbreviates one
(`prping e file.pkt` ≡ `prping engine file.pkt`; an ambiguous prefix like `p` errors with the candidates):

| Subcommand | Purpose | Old syntax (removed) |
|---|---|---|
| `ping` | ICMP / TCP / UDP / MTU probe | `prping HOST`, `prping -u`, `prping -m` |
| `latency` | Latency test (TCP/UDP, `-r` receive mode) | `prping -l SIZE HOST:PORT` |
| `bandwidth` | Bandwidth test (`--parallel` conns) | `prping -b -l SIZE HOST:PORT` |
| `server` | Test server (serves latency/bandwidth) | `prping -s ADDR:PORT` |
| `trace` | Traceroute (`-m` hops / `-d` no DNS) | `prping -t HOST` |
| `engine` | Packet engine: analyze .pkt/.pktl, LSP, `--ls/--hex/--pcap`, pcap→.pkt/.pktl convert (`--to-pkt`) | `prping --eng ...` |
| `packet` | Build a .pkt/.pktl and send (`--raw/--wait/--fuzz/--out`) | `prping --pkt ...` |

Top-level `--version` and `--lang` do not occupy the subcommand
position and may appear anywhere (e.g. `prping --lang zh-CN ping 8.8.8.8`).

---

## 4. Subcommand Overview

Functionality is organized by subcommand; each subcommand exposes only the options that are
effective for that mode (structurally exclusive — no cross-argument conflict checks needed):

| Subcommand | Target | Key options | Notes |
|---|---|---|---|
| `ping` | `HOST` (ICMP) / `HOST:PORT` (TCP) / `-u HOST:PORT` (UDP) | `-n/-i/-w/-q/-H/-g/-p/-s/-4/-6/--json`; `-m` MTU probe | `-m` takes no port, IPv4 only, exclusive with `-u/-l/-g/-p/-H/-n/-i/-w/-q` |
| `latency` | `HOST:PORT` (required) | `-l SIZE` (default 64), `-u/-r/-g/-p/-H` + test/network options | Needs `prping server` on the peer |
| `bandwidth` | `HOST:PORT` (required) | `-l SIZE` (default 8k), `-u/-r/--parallel N` + test/network options | Needs `prping server` on the peer |
| `server` | `ADDR:PORT` (required) | No client options | Serves latency/bandwidth/receive modes |
| `trace` | `HOST` (no port) | `-m N/-d/-s/-4/-6/--json` | ICMP echo + increasing TTL |
| `engine` | `FILE.pkt/.pktl` (optional) | `--lsp/--ls/--hex/--pcap` (exclusive, no file), `--to-pkt DIR/--structured/--skip/--limit` (with `--pcap`), `--lib/-p/-g` | Analyze/LSP/overview/convert |
| `packet` | `FILE.pkt/.pktl` (required) + `[HOST:PORT]` (optional) | `--raw/--iface/--wait/--fuzz/--out/--lib/-p/-g` | Build/send, recipes |

Measurement subcommands share the "test control", "output", and "network" option groups (Chapters 12/13/15/19).

---

## 5. ICMP Ping

**Purpose**: the most basic connectivity + latency measurement; distinguishes network failures (unreachable / TTL exceeded).

```bash
prping ping 8.8.8.8                  # unlimited (stop with Ctrl+C)
prping ping -n 10 -i 0.2 8.8.8.8     # 10 probes, 200ms interval
prping ping -l 1400 8.8.8.8          # large payload (probe link limits)
prping ping -m 8.8.8.8               # see Chapter 16: automatic MTU
prping trace 8.8.8.8               # see Chapter 17: traceroute
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

- Raw ICMP socket: Linux/macOS need root or `cap_net_raw`; **on Windows ICMP ping uses Iphlpapi.dll (`IcmpSendEcho2`, same as the system ping.exe)** — linked via windows-sys 0.59's `Win32_NetworkManagement_IpHelper` feature (Iphlpapi.dll is a system component, always present); no administrator privileges required, and immune to the Windows 7 RTM (SP0) raw socket defect (on that version `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` returns WSAEINVAL 10022 even as administrator; fixed in SP1); on Win7 SP0 the v4 `-s` source binding is not supported (IcmpSendEcho2 has no source parameter — warned and ignored; v6 supports it)
- `-l` controls the ICMP payload size in bytes (excluding the ICMP/IP headers)
- Distinguishes three kinds of replies: echo reply (normal), unreachable (type 3), TTL exceeded (type 11)

---

## 6. TCP Ping

**Purpose**: port connectivity + connection (connect) latency; equivalent to "telnet to a port and time it".

```bash
prping ping 192.168.1.1:22           # SSH port
prping ping -n 30 -i 0.1 -H 10 server:443
prping ping -s 10.0.0.2 server:443   # bind a source address (Chapter 18)
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
- `--parallel` concurrency is meaningless in this mode (each probe connects only once)

---

## 7. UDP Ping

**Purpose**: UDP reachability testing (e.g. DNS port 53, game servers); unique to prping beyond psping.

```bash
prping ping -u 8.8.8.8:53
prping ping -u -n 10 192.168.1.1:5000
```

### Notes

- Sends UDP datagrams tagged with a sequence number; replies are validated against seq, filtering stray packets
- **The target must run a UDP echo service** (such as a `prping server` server or a DNS responder) to reply;
  without one, every probe times out — this is inherent to UDP ping
- UDP is often silently dropped by firewalls; a 100% loss rate does not mean the host is unreachable —
  cross-check with ICMP/TCP

---

## 8. Latency Test

**Purpose**: end-to-end application latency (TCP connection + data round trip), closer to real user experience
than ping. Both ends need prping installed: the client triggers with `-l`, the server runs with `-s`.

```bash
# server (start it first)
prping server 0.0.0.0:8080

# client
prping latency -l 64 -n 100 server:8080          # TCP latency test (default)
prping latency -l 64 -n 100 -u server:8080       # UDP latency test
prping latency -l 64 -n 100 -r server:8080       # reverse: measure the download direction (Chapter 11)
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

**Purpose**: throughput measurement (Mbps), multi-connection stress testing with `--parallel`.

```bash
# server
prping server 0.0.0.0:8080

# client: 8KB packets, 10k iterations, 4 concurrent connections
prping bandwidth -l 8k -n 10000 --parallel 4 server:8080

# duration mode
prping bandwidth -l 1m -n 10s --parallel 8 server:8080
```

### Example output

```
TCP Bandwidth test:
  Sent = 81920000 bytes in 0.42s
  Bandwidth = 1566.49 Mbps
```

### Notes

- For precise throughput measurement use iperf3; prping's bandwidth mode is a convenient "good enough" stress test
- `--parallel` concurrency: parallel connections, with the total exactly equal to `count`
- `-r` measures the download direction (receive mode, see Chapter 11)
- The progress bar only shows on a tty; silent under pipes / `--json` / `-q`
- UDP bandwidth mode automatically enlarges the kernel buffers to 4MB to avoid bursty loss

---

## 10. Server Mode

**Purpose**: the server side for latency / bandwidth tests; serves TCP/UDP and latency / bandwidth / receive modes
at the same time.

```bash
prping server 0.0.0.0:8080
prping server [::]:8080             # IPv6
prping server -v 0.0.0.0:8080       # verbose: capture and dissect every received packet
prping server -v -a 0.0.0.0:8080    # full-frame capture: show all visible frames (requires -v)
prping server -v -a --filter "arp or icmp" 0.0.0.0:8080   # full-frame capture + only ARP/ICMP
prping server -v -a --filter "tcp port 53" 0.0.0.0:8080  # full-frame capture + only TCP port 53
```

### Notes

- One server supports all client modes at once (TCP/UDP × latency/bandwidth × send/receive directions)
- On Ctrl+C exit it prints aggregate statistics (connection count, bytes sent/received, etc.)
- Cannot be combined with any client arguments (`-n/-i/-l/-b/-u/--parallel/-s/-m`, etc.)
- Kept Win7-compatible on Windows
- With `-v`, raw capture shows full frames (eth/IP/TCP headers + handshake). By default only
  traffic to the listening port is shown (Linux needs root/cap_net_raw, Windows needs Npcap,
  macOS needs root or ChmodBPF). Linux defaults to a single AF_PACKET socket bound to all
  interfaces (startup line shows "all interfaces"); when built with `--features pcap` it
  switches to the same libpcap multi-device path as Windows/macOS (startup line shows the
  real interface names)
- `-a`/`--capture-all` disables the port/address filter and shows every frame visible on the
  interface — ARP, ICMP (e.g. pings to this host), broadcast/multicast, traffic to other ports,
  and the server's own outgoing replies; the `[frame]` summary line also gives address-level
  summaries for non-TCP/UDP frames. On Linux promiscuous mode is attempted best-effort
  (needs CAP_NET_ADMIN; with only cap_net_raw you still see host-addressed/broadcast/multicast
  frames); the Windows/macOS pcap paths already default to promiscuous. Note that on the Linux
  loopback (lo) AF_PACKET delivers each packet twice (an outgoing and an incoming copy), so
  all-frame mode shows each loopback packet twice — inherent kernel behavior, same as raw
  AF_PACKET capture (tcpdump-style); the default mode only accepts PACKET_HOST and has no such
  duplication. **`-a` must be combined with `-v` explicitly** (full-frame display needs
  dissection); using `-a` alone is an error
- `--filter "expression"`: a tcpdump-style subset that only shows matching frames,
  identical across all three platforms. **`--filter` must be combined with `-a` explicitly
  (i.e. `-v -a`)**; using `--filter` alone is an error. Syntax: protocols `arp`/`icmp`/`icmp6`/`tcp`/`udp`/`ip`/`ip6`,
  ports `port 53` (or `src port`/`dst port`), addresses `host 1.2.3.4` (or `src host`/`dst host`;
  ARP matches on spa/tpa), combined with `and`/`or`/`not` and parentheses (`and` binds tighter
  than `or`); an invalid expression is a hard error. Examples: `"arp or icmp"`,
  `"tcp and not port 9000"`, `"(arp or icmp) and not host 10.0.0.1"`. **All
  protocol tokens are matched through the registry (dissect)** — including the
  built-in arp/icmp/icmp6/tcp/udp/ip/ip6 (normalized to layer names like
  ipv4/ipv6) and eng_lib dissectable protocols: fixed layers
  `eth`/`ipv4`/`ipv6`/`http`/`dns`/`raw`, or eng_lib protocols that declare a
  dissect dispatch rule `#[rule]` (currently dns/http/quic_initial; adding
  `#[rule]` to another eng_lib protocol makes it filterable). The filter matches
  exactly the layer stack that `-a` displays, so a frame that fails to dissect as a
  protocol is consistently not matched; `port`/`host` qualifiers also read from the
  dissected layers (e.g. `"dns"` shows only DNS frames, `"dns port 53"` adds a port
  qualifier). Requires the registry to be loaded (serve loads it automatically; an
  error is raised if it is missing)

---

## 11. Receive Mode

**Purpose**: measure the "download direction" — the client only receives, the server only sends.

```bash
# server
prping server 0.0.0.0:8080

# client: reverse latency test
prping latency -l 64 -n 100 -r server:8080

# client: reverse bandwidth test
prping bandwidth -l 8k -n 10000 --parallel 4 -r server:8080
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
| `--parallel N` | Concurrent connections (bandwidth test only; other modes ignore it with a warning) |
| `-l SIZE` | Payload size; suffixes `64` / `8k` / `1m` supported |

### Examples

```bash
prping ping -n 1000 -i 0.01 8.8.8.8      # 1000 fast pings (10ms interval)
prping ping -n 30s -w 5 server:8080      # 30 seconds, 5 warmup probes
prping ping -q -n 100 192.168.1.1        # summary only
prping ping -n 1000000 -i 0 -q 8.8.8.8   # 1M fast pings (0 interval = fastest)
```

> Note: `-n` only supports the `s` suffix (seconds, e.g. `-n 10s`); `-n 1m` errors out —
> write fixed counts as plain numbers. Only `-l`'s `m` suffix means megabytes (`-l 1m` = 1MB payload).

---

## 13. Histogram and Timeline (-H / -g / -p)

### Histogram `-H`

Two forms:

```bash
prping ping -n 100 -H 10 8.8.8.8          # 10 buckets
prping ping -n 100 -H "1,5,10,50" 8.8.8.8 # custom ms thresholds: 1/5/10/50ms buckets
```

Rendered as ASCII `#` by default; `-p` (pretty) renders a Unicode bar chart with
[ploot](https://github.com/ploot-rs/ploot) (ANSI colors are stripped automatically off a tty).

### Timeline `-g`

```bash
prping ping -n 20 -i 0.1 -gp 127.0.0.1:22  # timeline chart (-p uses ploot Braille scatter)
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
prping ping -n 10 --json 8.8.8.8 | tail -1 | jq .jitter_ms
prping ping -n 30s --json server:8080 | jq -r 'select(.ok) | .rtt_ms' | awk '{s+=$1} END {print s/NR}'
```

> On Unix, `--json` disables the terminal's echoed `^C` while running (restored on exit).

---

## 16. MTU Probe (-m / --mtu)

**Purpose**: find the path MTU (path Maximum Transmission Unit) — the largest packet size between the two ends
that avoids fragmentation. Mismatched link MTUs are the classic cause of "small packets pass, big packets don't".

```bash
prping ping -m 8.8.8.8
prping ping -m 192.168.1.1 -s eth0     # bind a source
prping ping -m --json 8.8.8.8          # machine-readable
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

## 17. Traceroute (trace / -t / --traceroute)

**Purpose**: discover the forwarding path to a target hop by hop — locate where loss or
high latency happens, spot asymmetric routes, verify multi-line egress. The default is
Windows `tracert`-style (ICMP echo); **a target with a port automatically switches to
the TCP SYN variant** (same as `ping`'s "port → TCP"), and `--udp`
to the classic UDP variant (like Unix `traceroute`) — both keep working when ICMP is
filtered.

```bash
prping trace www.baidu.com          # ICMP echo, at most 30 hops by default
prping trace -m 20 8.8.8.8          # at most 20 hops
prping trace -d 8.8.8.8             # no hostname resolution (IPs only)
prping trace --json 8.8.8.8         # machine-readable (one line per hop + summary)
prping trace -6 ::1                 # IPv6 (Hop Limit increments)
prping trace 8.8.8.8:443            # TCP SYN (auto when a port is given; SYN-ACK/RST from the target = reached)
prping trace --udp 8.8.8.8          # UDP (classic traceroute, ports start at 33434)
```

### Example output

```
Tracing route to www.baidu.com (110.242.68.66) over a maximum of 30 hops:
  1    0.35 ms   0.28 ms   0.31 ms  192.168.1.1
  2    2.10 ms   1.98 ms   2.05 ms  100.64.0.1
  3        *        *        *        *
  4   25.12 ms  24.80 ms  25.33 ms  dg-xxx.bj.baidubce.com (110.242.68.66)

Reached target www.baidu.com in 4 hops.
```

### How it works

**ICMP echo (default)**:

1. Send ICMP echo requests to the target with the TTL incremented hop by hop
   (Hop Limit for IPv6)
2. A router whose TTL expires replies ICMP Time Exceeded (type 11 / ICMPv6 type 3);
   its source address is that hop — the Time Exceeded message embeds the original packet
   (IP header + first 8 bytes of ICMP), matched by id/seq to confirm ownership
   (the same validation `tracert` uses)
3. The target itself replies ICMP echo reply → reached, tracing stops

**TCP SYN (`trace HOST:PORT`, auto when a port is given)**:

1. Send TCP SYNs with the TTL incremented hop by hop; each probe uses its own
   source port, matched by the embedded TCP header's (sport, dport) — no seq needed
2. Routers reply Time Exceeded (embedding the original TCP header); the target
   replies **SYN-ACK** (port open) or **RST** (port closed) — either counts as reached
3. Replies come from two sockets polled together: raw ICMP (Time Exceeded) + raw
   TCP (SYN-ACK/RST); the TCP pseudo-header checksum uses the local source address
   learned from a UDP route probe
4. **Windows uses Npcap** (raw TCP sockets are restricted): full frames are injected
   via Npcap and replies captured — Npcap must be installed (a hint is shown
   otherwise); IPv4 targets only

**UDP (`--udp HOST`, classic Unix traceroute)**:

1. A plain UDP socket sends a payload to increasing destination ports (starting at
   33434, +1 per probe, to dodge listening services), TTL incremented hop by hop;
   the kernel builds the UDP header (checksum included)
2. Routers reply Time Exceeded (embedding the original UDP header, matched by
   (sport, dport)); the target replies **Port Unreachable** (type 3 code 3 /
   ICMPv6 type 1 code 4) — reached
3. Only one raw ICMP socket is needed for replies; **works on Windows** (plain UDP
   + raw ICMP are allowed, unlike the TCP SYN variant)
4. If the target's UDP port happens to be open (e.g. DNS 53), it replies with data
   rather than ICMP — that probe shows `*` (classic traceroute behaves the same;
   high ports exist precisely to avoid this)

### Notes

- Timed-out hops print a red `*` (the router drops ICMP/TCP/UDP or the path loses packets);
  tracing continues
- 3 probes per hop (sent back-to-back; 1-second collection window per hop);
  each hop address gets a reverse DNS lookup
- `-m N` is capped at 255 (the TTL field limit), default 30; `-d` skips reverse DNS
  (avoid slow DNS stalling the whole path)
- If the target never echoes/answers, all `-m` hops are probed and it still ends as
  "not reached" → non-zero exit code
- Needs a raw socket (root / `cap_net_raw`); for TCP SYN pick a commonly open port
  (e.g. 80/443) — filtered ports just show `*`

---

## 18. Source Address Binding (-s)

**Purpose**: specify the probe source address / interface — multi-NIC hosts, policy routing, dual-link troubleshooting.

```bash
prping ping -s 192.168.1.10 8.8.8.8        # bind source IP (works for TCP/ICMP/UDP)
prping ping -s 10.0.0.2 server:8080 -l 64  # latency test with a source
prping ping -s eth0 8.8.8.8                # Linux: interface name → IPv4 automatically
prping ping -m -s eth1 8.8.8.8             # MTU probe with a source
```

### Notes

- The argument can be an IP address, or a **Linux interface name** (its IPv4 is looked up via `SIOCGIFADDR`;
  for IPv6 write the address directly)
- Works in every mode: ICMP / TCP / UDP ping, latency, bandwidth, MTU probe
- Server mode does not accept `-s` (`--source`)
- Errors on address-family mismatch (e.g. `-s` with an IPv6 address while the target is IPv4)

---

## 19. IPv4 / IPv6 Dual-Stack

```bash
prping ping 8.8.8.8                # IPv4
prping ping 2001:4860:4860::8888   # IPv6 (no brackets needed)
prping ping [::1]:80               # IPv6 with a port needs square brackets
prping ping -6 example.com         # force IPv6 (when a domain has multiple records)
prping ping -4 example.com         # force IPv4
```

### Rules

- Without `-4/-6`, the family is chosen automatically from the target's form; when a domain resolves to
  multiple records, the first is used
- `-4` and `-6` are mutually exclusive (giving both errors out)
- MTU probing is IPv4 only (Chapter 16)

---

## 20. Exit Codes and Scripting

| Exit code | Meaning |
|---|---|
| 0 | No packet loss (incl. successful MTU probe); traceroute reached the target |
| 1 | Packet loss / target not reached / connection failure / argument error |
| 2 | Other runtime errors |

```bash
prping ping -n 10 8.8.8.8 || echo "network problem"
prping ping -n 10 --json 8.8.8.8 >/dev/null && echo OK

# monitoring script: alert on a loss threshold
loss=$(prping ping -n 5 --json 8.8.8.8 | tail -1 | jq -r .loss_pct)
[ "$(echo "$loss > 10" | bc)" = 1 ] && alert
```

---

## 21. Signals and Interruption (Ctrl+C)

- **First Ctrl+C**: stop the test, print the full statistics, then exit
- **Second Ctrl+C**: force exit (without waiting for statistics)
- In `--json` mode on Unix, the terminal's echoed `^C` is disabled while running
  (the `^C` is a terminal echo and never enters the stdout pipe; it is restored on exit)

---

## 22. Language and Internationalization

Auto-detected: `$LANG` (Unix) / system UI language (Windows); `--lang` overrides manually.

```bash
prping ping --lang en-US 8.8.8.8    # English
prping ping --lang zh-CN 8.8.8.8    # Chinese (default follows the system)
LANG=zh_CN.UTF-8 prping ping 8.8.8.8
```

### Manual language

The `document` manual switches with the language:

```bash
prping --lang zh-CN document 16     # Chinese manual, Chapter 16 (MTU)
prping --lang en-US document MTU    # English manual
```

---

## 23. Complete Example Collection

### Everyday troubleshooting

```bash
# 1. is it reachable?
prping ping 8.8.8.8 -n 4

# 2. full picture: latency / jitter / loss (20 probes, threshold histogram)
prping ping -n 20 -w 0 -H "1,5,10,50" 8.8.8.8

# 3. a specific port
prping ping 8.8.8.8:53 -n 10
prping ping 192.168.1.1:443 -n 10 -i 0.5

# 4. do large packets pass? (MTU issues)
prping ping -l 1400 8.8.8.8
prping ping -m 8.8.8.8

# 5. routing path / where is it stuck
prping trace 8.8.8.8

# 6. multi-NIC: bind a source
prping ping -s eth1 10.0.0.1:80 -n 20
```

### Latency / bandwidth (the peer needs `prping server`)

```bash
prping server 0.0.0.0:8080                       # server
prping latency -l 64 -n 1000 server:8080             # TCP latency
prping latency -l 64 -n 1000 -u server:8080          # UDP latency
prping latency -l 64 -n 1000 -r server:8080          # reverse (download direction)
prping bandwidth -l 8k -n 10000 --parallel 4 server:8080    # bandwidth
prping bandwidth -l 1m -n 10s --parallel 8 server:8080      # duration-mode bandwidth
prping bandwidth -l 8k -n 10000 --parallel 4 -r server:8080 # reverse bandwidth
```

### Scripts / monitoring

```bash
# measure latency every 30 seconds and log it
while true; do
  echo "$(date +%s) $(prping ping -n 3 --json 8.8.8.8 | tail -1 | jq -r .avg_ms)"
  sleep 30
done >> latency.log

# packet-loss trend
prping ping -n 60 -i 1 --json 8.8.8.8 | jq -c 'select(.summary)'
```

---

## 24. Frequently Asked Questions (FAQ)

### Q1: ICMP ping reports "cannot create raw socket"
You need root or `cap_net_raw`:
```bash
sudo setcap cap_net_raw+ep $(which prping)
```
On Windows, run as administrator.

### Q2: UDP ping times out entirely
No UDP echo service (or a firewall drops it). Cross-check with TCP/ICMP;
for a DNS server try `prping ping -u 8.8.8.8:53` (DNS replies).

### Q3: Small packets pass, big packets don't
Most likely an MTU issue: probe the path MTU with `prping ping -m <host>`,
and check the MTU configuration on both ends plus tunnel overhead (e.g. PPPoE subtracts 8 bytes).

### Q4: Low latency but video/voice stutters
Look at **jitter** (Chapter 14) — high jitter hurts real-time streams more than high latency.
Check the distribution with `prping ping -n 100 -H 1,5,10,50 <host>`.

### Q5: Does `-n 1m` mean one million probes?
No, it errors out. `-n` only supports the `s` suffix (seconds; `-n 10s` = 10 seconds);
write fixed counts as plain numbers (`-n 1000000`). Only `-l`'s `m` suffix means megabytes (`-l 1m` = 1MB payload).

### Q6: `--parallel` has no effect on TCP ping?
`--parallel` only works for the bandwidth test; other modes ignore it with a warning.

### Q7: Bandwidth numbers differ from iperf3?
That's normal. prping's bandwidth mode is a convenient stress test without window / congestion tuning;
use iperf3 for precise throughput.

### Q8: How do I measure the download direction?
Use `-r` receive mode (Chapter 11); the peer runs `prping server`.

### Q9: Can `--json` be combined with `-p/-g/-H`?
No — they are mutually exclusive. JSON is a machine format.

### Q10: Is Win7 supported?
Yes (the Win7-compatible build recipe is in Chapter 2 and the project README).

### Q11: Want to build / send custom packets?
That's the packet-building engine (Chapter 26): `prping packet examples/network_icmp_bare ...`.

---

## 25. Comparison with psping

| Feature | psping | prping | Notes |
|---|---|---|---|
| ICMP ping | ✓ | ✓ | raw socket |
| TCP ping | ✓ | ✓ | connection latency |
| UDP ping | ✗ | ✓ | unique to prping |
| Latency test | ✓ | ✓ | TCP/UDP |
| Bandwidth test | ✓ | ✓ | TCP/UDP, `--parallel` concurrency |
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

## 26. Packet-Building Engine (engine / packet / packet-dsl)

### packet-dsl (workspace sub-crate)

A `.pkt` network-packet-building DSL: parsing + semantic analysis → structured IR → serialized bytes.
Supports an import/export module system, runtime parameters (`params("name")`), byte primitives
(`concat`/`be16`/`rand16`/..., random values generated at build time, e.g. `sport=rand16()`),
user functions (`func name(args) { ... }`),
packet dissection (`dissect(bytes)`), and pcap read/write. Design doc: `crates/packet-dsl/DESIGN.md`.

### Engine modes (same binary)

The packet-building engine CLI, fully separated from prping itself:

```bash
prping engine FILE.pkt            # analyze: layer stack + hexdump
prping engine --lsp               # .pkt language server
prping packet FILE.pkt [HOST:PORT] # build and send (target optional, inferred from the packet)
prping packet FILE.pkt --wait 3   # reply matching + RTT
prping packet FILE.pkt --fuzz     # randomize all fields
prping packet FILE.pkt --out x.pcap  # save to pcap
prping engine --ls / --hex ... / --pcap x.pcap
prping engine --pcap x.pcap --to-pkt dir/          # pcap → one .pkt per record + a .pktl recipe
prping engine --pcap x.pcap --to-pkt dir/ --structured  # semantic structured conversion
```

**Extension-less arguments auto-locate the pktl**: when the `engine`/`packet` file
argument has no extension, prping first tries `<arg>.pktl` (in the current directory /
the argument's directory), and if that file does not exist, tries the same-named
folder's `<arg>/<basename>.pktl`. The examples are organized this way — one folder
per pktl (`examples/<name>/<name>.pktl` plus its `.pkt` files):

```bash
prping engine examples/tcp_handshake    # = examples/tcp_handshake/tcp_handshake.pktl
prping packet tcp_handshake 127.0.0.1:80 --wait 1   # (from inside examples/)
```

### pcap → .pkt/.pktl conversion (`engine --pcap --to-pkt`)

The inverse of `--out`: converts a pcap into one `.pkt` per record
(`record_%05d.pkt`, numbered by the original pcap index) plus a `.pktl` recipe that
references them in order, with step `delay:` carrying the captured inter-frame gap
(<1μs gaps are omitted; the first step has no delay). You can replay them with
`packet dir/x.pktl [HOST:PORT] --raw`, or merge them back into a pcap with `--out`:

```bash
prping engine --pcap x.pcap --to-pkt dir/            # lossless byte-level (default)
prping engine --pcap x.pcap --to-pkt dir/ --structured   # semantic structured
prping engine --pcap x.pcap --to-pkt dir/ --skip 10 --limit 100  # records 11..110 only
prping engine --pcap x.pcap --to-pkt dir/ --threads 8       # parse with 8 threads
```

Two routes:

- **Lossless byte-level (A1, default)**: the whole frame/packet is fed through
  `layer("eth"/"ipv4"/"ipv6", hex(...))` or `raw(bytes=hex(...))` — bytes are
  100% preserved (semantic fields are bypassed, checksums are never recomputed),
  and frames with an eth/ipv4/ipv6 outer layer can be `--raw`-sent to reproduce the
  capture. Unknown link types (other than 1=Ethernet/101=Raw) are archived as
  `raw` only, with a header comment.
- **Semantic structured (A2, `--structured`)**: dissects the layer stack into
  readable, editable DSL source (`eth`/`arp`/`ipv4`/`ipv6`/`icmp`/`tcp`/`udp`
  semantic fields plus bit constants like `bor(syn(), ack())`; layers the DSL
  cannot express — IPv4/TCP option headers, the TCP URG pointer, IPv6 traffic
  class/flow label — plus `dns`/`http` are fed byte-exact via `*_bytes(hex(...))`).
  For valid captures, re-serialization is **byte-identical** (roundtrip fidelity via
  layer-order reversal + per-layer raw header bytes); records with leftover
  `remaining` bytes (Ethernet padding / unknown payloads) or that cannot be
  dissected fall back to A1 (`fallback`). Header comments carry the layer stack
  and dissect notes (e.g. checksum mismatch).

**Parallel parsing (`--threads N`)**: per-record dissect/rendering is pure and fully
independent, so conversion parallelizes across records (`std::thread::scope`, no new
crate; workers render + write their own files, results are re-ordered by index —
byte-identical to single-threaded output). `0` = auto (parallel via CPU count when
≥ 1024 records; small files stay single-threaded to avoid pool overhead); `1` = force
single-threaded; `N` = exactly N threads (capped at the record count). The lossless
A1 mode is I/O-bound, so threads mainly help `--structured` on large pcaps.

**Recipe `delay:` step option**: waits before the step starts (ignored for the
first step; chunked sleep responds to Ctrl+C) — the converted recipes use it to
reproduce capture pacing; hand-written recipes can use it too.

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

### Byte primitive relationship table (raw / hex / u8 / be16 / be32 / [])

The final form of every byte value in the DSL is a **byte list** — a `[0x12, 0x34]`-style
`[]` literal. The six forms below are all construction/consumption entry points
(`raw` is a **dual-position** primitive: layer = Raw payload layer, value = UTF-8 bytes):

| Primitive | Position | Input | Output | Equivalence |
| --- | --- | --- | --- | --- |
| `[]` literal | value | — | byte list | the common product of every byte primitive |
| `raw("abc")` | **layer / value** | string (UTF-8) or byte list | Raw payload layer / byte list | `raw("abc")` = `[0x61, 0x62, 0x63]` ≡ Python `b"abc"` |
| `hex("1234")` | value / layer | hex text (optional `0x` prefix, even length) | byte list / Raw layer | `hex("1234")` = `[0x12, 0x34]` |
| `u8(x)` | value | number 0..255 or 1 byte | 1 byte | `u8(0x61)` = `u8([0x61])` = `[0x61]` |
| `be16(x)` | value | number 0..65535 or 2 bytes | 2 bytes, big-endian | `be16(0x1234)` = `be16(hex("1234"))` = `[0x12, 0x34]` |
| `be32(x)` | value | number 0..2³²-1 or 4 bytes | 4 bytes, big-endian | same, width 4 |

Flow at a glance:

```
"abc" ──bytes()/raw()──► [61 62 63]         string = UTF-8 bytes (≡ Python b"abc")
"1234" ──hex()──► [12 34]                    hex text = bytes
0x1234 ──be16()──► [12 34]  ──le16()──► [34 12]    number encoded big-/little-endian by width
[12 34] ──be16()──► [12 34]  ──int()──► 0x1234     same-width passthrough / big-endian decode
```

Interchange rules (**width is the type** — values with the same byte count convert directly,
no wrapper needed):

- `be16(hex("1234"))` = `be16([0x12, 0x34])` = `u8(raw("a"))` — same-width byte passthrough;
  only a width mismatch errors (`be16(hex("123456"))` → needs 2 bytes)
- **params parse by shape** (`0x` prefix = hex number, plain digits = decimal number, else string):
- `le16`/`le32` little-endian encode (`le16(0x1234)` = `[0x34, 0x12]`); byte input is reversed
  (`le16([0x01, 0x02])` = `[0x02, 0x01]`)
- string literals never implicitly become numbers: `be16("0x4242")` errors — write
  `be16(0x4242)` or `be16(hex("0x4242"))`
- `raw` is a dual-position primitive (layer = payload layer, value = UTF-8 bytes).
  `params` parse by shape: `be16(params("port", "53"))` / `icmp(id=params("id", "0x1234"))`
  work directly (`--params port=5353`); the default may be any value expression
  (`params("port", be16(0x1235))` = `[0x12,0x35]`)

### Raw-send platform differences (packet --raw)

`packet --raw` sends fully serialized bytes; the underlying transport differs by platform:

| Platform | eth layer (Ethernet frame) | ipv4 layer (bare IP) | ipv6 layer (bare IPv6) |
|---|---|---|---|
| Linux | AF_PACKET (needs root/cap_net_raw; `--iface` selects the NIC, default lo) | IPPROTO_RAW + IP_HDRINCL | AF_INET6 + IPPROTO_RAW + IPV6_HDRINCL |
| Windows | Npcap `pcap_sendpacket` link-layer injection (Npcap must be installed; `--iface` matches the Npcap device name/description) | Npcap injection + automatic Ethernet wrapping (src MAC = interface MAC, dst MAC = next-hop ARP) | Loopback `::1` only (via the Npcap Loopback Adapter) |
| macOS/BSD | Not supported | IPPROTO_RAW works (no IP_HDRINCL; the IP header is built by the kernel, semantics differ from Linux) | Not supported |

Windows notes:

- **Requirements**: only `packet --raw` (Npcap link-layer injection) needs Npcap ([npcap.com](https://npcap.com/)). wpcap.dll is now delay-loaded (`/DELAYLOAD`), so on machines without Npcap every other prping feature (ping/latency/bandwidth/trace/engine etc.) works normally — only `packet --raw` reports that Npcap is required. If the installer option "Allow non-admin applications to capture packets" is unchecked, capture/injection requires administrator privileges.
- **Windows 7**: Npcap still supports Windows 7; the driver is SHA-2 signed, so KB4474419 + KB4490628 must be installed or the driver will fail to load.
- **Loopback**: targeting `127.0.0.1`/`::1` automatically selects the Npcap Loopback Adapter (enable "Install Npcap Loopback Adapter" during install).
- **MAC resolution**: before sending bare IPv4, the next hop (`GetBestRoute`) and ARP cache (`GetIpNetTable`) are resolved automatically; on a miss a 1-byte UDP packet is sent to trigger kernel ARP, and if that still fails a broadcast address is used with a warning.
- **IPv6 limitation**: non-loopback bare IPv6 is not supported yet (Windows 7 has no `GetIpNetTable2`, so the v6 neighbor table cannot be enumerated).
- **`--wait`**: the capture handle is opened before sending (to avoid missing fast replies) and filtered by direction so frames we just sent are excluded.

### Target derivation and link-layer frames

For `packet FILE.pkt [HOST:PORT]` the target priority is: **explicit `HOST:PORT` >
derivation from the outermost IP layer `dst` > omitted**. In raw mode the port is
meaningless (raw sockets carry no port), so a bare `HOST` is enough
(e.g. `packet foo.pkt --raw 192.168.1.5`).

**Link-layer frames (outermost eth, no IP layer — e.g. ARP) need no target for raw
sending**: AF_PACKET delivers by the frame's dst MAC (`--iface` selects the NIC,
default lo); the target is only used for side logic such as IP source-address filling:

```bash
prping packet examples/link_arp/arp_request.pkt --raw   # ARP request (broadcast) sent directly
#   target: none — link-layer frame, no IP target (AF_PACKET sends by the frame dst MAC)
```

**Bare layer exports** (no TCP/UDP transport and no eth/ipv4/ipv6 outer layer — e.g.
`req = arp(...)` elements that exist only for `--eng` display/composition) are
skipped with a yellow note in both payload and raw modes, not counted as send
failures; if every export is skipped, the run reports "no packets to send". Bare
IPv4/IPv6 sends still require a target (used for the `sendto` route).

**Send-mode hint (`--eng`)**: packets with no TCP/UDP transport but a raw-sendable
outer layer (e.g. ICMP over IP, ARP over eth) get an orange `note:` in the
`engine FILE.pkt` per-packet view — the full packet can only be sent via raw mode
(`--raw`, or recipe step `raw: true`); payload mode cannot extract a payload
(without `--raw` the send falls back to raw sockets automatically).

See `crates/packet-dsl/README.md` for details.

### Recipes (`.pktl`, multiple packets in sequence)

A `.pktl` (package list) file runs several `.pkt` files in order as one session
(handshake / multi-packet flows) and shares data across steps through a
**global store** — any step can read values set by any earlier step, not just the previous one:

```text
# examples/dns_recipe/dns_recipe.pktl
global:
- name: tid             # shared variable (init optional; -g overrides init)
  init: 0x4321

recipe:
- pkg: recipe_query.pkt   # send recipe_query.pkt, wait for the reply, extract dns.id → global.tid
  wait: 1
  extract:
  - name: tid
    from: reply.dns.id    # dissected reply field (layer.field, same field set as sniffer)
    as: hex               # default int; also hex / str / bytes
- pkg: recipe_query.pkt   # bare filename = no extra options
```

- **Syntax**: `global:` / `recipe:` section headers and step items (`- `) start at
  column 0; step option lines are indented. A step item is `- pkg: FILE` (followed
  by `wait:` / `raw:` / `params:` / `extract:` / `on_error:`) or a bare `- FILE`;
  `#` comments;
  paths resolve relative to the `.pktl` directory. A global item has three forms:
  `- name: NAME` (optionally followed by an indented `init:`), a bare `- NAME`
  (declared but unset), or `- NAME=VALUE` (inline init; `VALUE` uses the same
  literal syntax as `init:`).
- **Global store**: `.pkt` files read it with the new value primitive
  **`global("name"[, default])`** — symmetric with `params`, but values are
  **typed** (Int/Hex/Str/byte list, no string shape parsing), so they compose
  directly with `+` / `be16` / bitwise ops, e.g. `tcp(ack=global("seq") + 1)`.
  Unset with no default → error. Writes: `init` initial value (a global item may
  spell it inline as `- NAME=VALUE`), step `extract`
  (from replies; multiple replies apply in order, last write wins), CLI
  `-g k=v` (`--global`, overrides `init`).
- **extract** needs a reply for that step (`wait:` or `--wait`). `from:` has two forms:
  - `reply.<layer>.<field>` picks the dissected reply field (same layer/field set as
    sniffer), `as:` controls the form — `int` (numeric fields, default) / `hex` /
    `str` (formatted IP/MAC strings) / `bytes` (raw field bytes, network order);
  - **value expression** (functions / primitives / `+` arithmetic, with embedded
    `reply.<layer>.<field>` leaves): `from: reply.tcp.seq + 1`,
    `from: be16(reply.dns.id)`, `from: cksum(reply.icmp.payload)` — the expression
    evaluates to a typed value (numeric fields → int, address/string fields →
    string, payload fields `icmp.payload` / `http.body` / `raw.bytes` → byte list),
    and may call the step's own `.pkt` `func` value functions, `params(...)` and
    `global(...)`; `as:` is optional (default = the expression's natural type; an
    explicit `as:` converts to int / hex / str / bytes). TCP echo bodies are kept
    in the reply too, so extract works there as well.
- **Failure handling**: a failing step (send error / extract with no reply or
  missing field) **stops** the whole recipe by default (exit code 1);
  `on_error: continue` records the failure and keeps going (final exit code
  still non-zero).
- **Raw switch**: a step `raw: true` forces this step to send the full serialized
  bytes via raw sockets (per-step `--raw`; the interface is inherited from the CLI
  `--iface`); `raw: eth0` also picks the interface; `raw: false` forces the step
  back to normal TCP/UDP payload sending (overriding a CLI `--raw`) — one recipe
  can mix raw and payload steps, e.g. `raw: eth0` for an ARP/ethernet frame first,
  then `raw: false` for a TCP payload.
- **CLI**: `packet FILE.pktl [HOST:PORT]` runs it; `--wait` / `--raw` /
  `-p` (`--params`) / `--fuzz` / `--out` / `--lib` are global defaults, overridden per
  step by `wait:` / `raw:` / `delay:` / `params:` (a step `delay: N` waits N seconds before
  starting — ignored for the first step, chunked sleep responds to Ctrl+C; the
  pcap-converted recipes use it to carry capture pacing); in recipe mode `--out`
  collects every step's packets into one pcap; `-g k=v` injects globals.
  `engine FILE.pktl` shows a recipe overview (global declarations + the **param
  surface of the step pkts** — a lexical scan of `params("name", default)` with
  defaults and the using steps, hinting `-p k=v` injection; an unparseable step
  pkt is reported early, same philosophy as the extract-field validation — plus
  step options, and validates extract field names — the expression form
  validates its `reply(...)` leaves too). `packet FILE.pktl` prints the same
  param summary in its header.
- **Examples** (one folder per protocol — a same-named `.pktl` plus its `.pkt`
  files, every one a **sendable multi-packet flow**): `examples/tcp_handshake/`
  (TCP three-way handshake: SYN → ACK → HTTP GET, seq/ack chained via
  `global("cseq") + 1` arithmetic), `examples/transport_udp/` (UDP send tests:
  DNS query + VNC banner payloads), `examples/dns_recipe/` (DNS query: extract
  the reply `dns.id` and reuse it), `examples/network_icmp_bare/` (ICMP echo:
  sniffer + extract id/seq reuse, bare IP through kernel routing; `--raw` needs
  root), `examples/app_http/` (HTTP GET/POST over TCP, `-p port=` injection),
  `examples/link_arp/` (ARP request/reply), `examples/quic_initial/`
  (QUIC Initial/Short headers).
  Run e.g. `prping packet examples/dns_recipe 127.0.0.1:5353 --wait 1`.
