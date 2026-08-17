#!/usr/bin/env bash
# 集成基准：本地回环吞吐/延迟，阈值断言防回归。
#
# 用法: bash scripts/bench.sh <prping 二进制路径>
# 非门禁（CI 中 continue-on-error）：失败告警不拦合并。
set -u

BIN="${1:-target/release/prping}"
PORT="${PORT:-23100}"
MIN_MBPS="${MIN_MBPS:-1000}"   # 本地回环绝对下限（Mbps）
FAIL=0

echo "== prping 基准 =="
"$BIN" --version

"$BIN" -s "127.0.0.1:$PORT" >/dev/null 2>&1 &
SRV=$!
trap 'kill -9 $SRV 2>/dev/null' EXIT
sleep 0.5

check_mbps() {
    local label="$1" mbps="$2"
    printf "  %-28s %10.0f Mbps\n" "$label" "$mbps"
    if awk "BEGIN{exit !($mbps < $MIN_MBPS)}"; then
        echo "    ✗ 低于下限 ${MIN_MBPS} Mbps"
        FAIL=1
    fi
}

# 带宽（count 模式，-w 0 免预热）
for spec in \
    "TCP 发送     -b -l 8k -n 5000" \
    "TCP 并发 P4  -b -l 8k -n 20000 -P 4" \
    "TCP 接收     -b -l 8k -n 5000 -r" \
    "UDP 发送     -b -l 8k -n 5000 -u" \
    "UDP 接收     -b -l 8k -n 2000 -u -r"; do
    label="${spec%%  *}"
    args="${spec#*  }"
    mbps=$("$BIN" $args --json "127.0.0.1:$PORT" 2>/dev/null | grep -oP '"mbps":\K[0-9.]+')
    check_mbps "$label" "${mbps:-0}"
done

# 延迟：TCP ping 丢包率必须为 0
loss=$("$BIN" -n 50 -w 0 --json "127.0.0.1:$PORT" 2>/dev/null | grep -oP '"loss_pct":\K[0-9.]+')
echo "  TCP ping 50 次丢包率: ${loss:-?}%"
if [ "${loss:-100}" != "0.0" ] && [ "${loss:-100}" != "0" ]; then
    echo "    ✗ 存在丢包"
    FAIL=1
fi

echo "== 结束（FAIL=$FAIL）=="
exit $FAIL
