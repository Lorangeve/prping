# pktlang_tests

用 `python -m http.server` + `tcpdump` 作为地面真相，验证 prping 各发送模式在"线上"的真实行为。

## 运行

```bash
# 自动进入 user+net namespace（无需 sudo）
python3 pktlang_tests/test_raw_effectiveness.py

# 或手动
unshare -Urn python3 pktlang_tests/test_raw_effectiveness.py
```

需要 `target/debug/prping` 已编译。

## 测试清单

| ID | 名称 | 验证点 |
|----|------|--------|
| T1 | payload_mode_real_ip | payload 模式走内核 TCP，http.server 收到请求，tcpdump 显示真实 src |
| T2 | raw_bare_ip_spoofed_src | 裸 IP raw + 伪造 src → tcpdump 显示伪造 src，server 收不到（握手失败）|
| T3 | raw_bare_ip_zero_src_patched | 裸 IP raw + src=0.0.0.0 → patch_zero_src 填真实 IP，server 收到 |
| T4 | raw_eth_spoofed_src_mac | eth 帧 raw → tcpdump 显示伪造 IP+MAC，server 收不到 |
| T5 | raw_icmp_spoofed_src | ICMP raw + 伪造 src → tcpdump 显示伪造 src |
| T6 | raw_icmp_zero_src_patched | ICMP raw + src=0.0.0.0 → tcpdump 显示真实 src |
| T7 | raw_bare_ip_different_spoofed_src | 不同伪造 IP 也能上线（10.99.99.99）|
| T8 | payload_mode_different_port | payload 模式换端口，server 正常接收 |

## fixtures/

| 文件 | 层栈 | 用途 |
|------|------|------|
| `http_get_bare_spoof.pkt` | IPv4 + TCP + HTTP | 裸 IP，伪造 src=192.168.81.100 |
| `http_get_bare_zero.pkt` | IPv4 + TCP + HTTP | 裸 IP，src=0.0.0.0（触发零源填充）|
| `icmp_echo_spoof.pkt` | IPv4 + ICMP | ICMP echo，src 可注入 |
