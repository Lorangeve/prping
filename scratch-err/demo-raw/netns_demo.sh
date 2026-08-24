#!/bin/sh
# 全套对比演示：在独立 user+net namespace 里抓包验证
# 1) payload 模式（默认）→ 内核真实 TCP，抓包应见 127.0.0.1
# 2) raw 模式 eth 帧 → 伪造 src 原样上线，抓包应见 192.168.81.1
# 3) raw 裸 ICMP 伪造 src → 同上
set -x
ip link set lo up
tcpdump -i lo -nn -U -w /mnt/mydata/mycoding/prping/scratch-err/demo-raw/netns.pcap >/dev/null 2>&1 &
TPID=$!
sleep 0.3
python3 -m http.server 8000 --bind 127.0.0.1 >/mnt/mydata/mycoding/prping/scratch-err/demo-raw/netns_http.log 2>&1 &
HPID=$!
sleep 0.5
cd /mnt/mydata/mycoding/prping/examples
echo "===== 1) payload 模式（默认，不带 --raw）====="
/mnt/mydata/mycoding/prping/target/debug/prping packet app_http/http_get.pkt 127.0.0.1:8000 -p port=8000 2>&1 | tail -3
sleep 0.3
echo "===== 2) raw 模式（eth 帧，显式 src=192.168.81.1）====="
/mnt/mydata/mycoding/prping/target/debug/prping packet app_http/http_get.pkt 127.0.0.1:8000 --raw -p port=8000 2>&1 | tail -3
sleep 0.3
echo "===== 3) raw 裸 ICMP（伪造 src=192.168.81.1 → 127.0.0.1）====="
/mnt/mydata/mycoding/prping/target/debug/prping packet network_icmp_bare/icmp_bare1.pkt --raw -p src=192.168.81.1 2>&1 | tail -3
sleep 0.6
kill $TPID 2>/dev/null
sleep 0.3
echo "===== http.server 收到的请求 ====="
cat /mnt/mydata/mycoding/prping/scratch-err/demo-raw/netns_http.log
