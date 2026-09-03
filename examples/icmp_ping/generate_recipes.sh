#!/bin/bash
# 生成不同次数的 ICMP ping 配方文件
# 生成 1-10 次的 pktl 配方文件

set -e

echo "Generating ICMP ping recipes..."

for i in $(seq 1 10); do
    FILE="icmp_ping_real_${i}.pktl"
    
    cat > "$FILE" << EOF
# 配方：ICMP Echo Request ${i} 次（真实 ping 用）
# 包含 ${i} 个步骤，每个步骤发送一个 ICMP Echo Request 并等待真实应答
#
# 运行（在 examples/ 目录下，无扩展名参数自动定位到本目录同名 pktl）：
#   prping engine icmp_ping_real_${i}               # 概览
#   sudo prping packet icmp_ping_real_${i} --raw --wait 1 -p ip=127.0.0.1
#     （--raw 发原始 ICMP 包需 root/cap_net_raw；ICMP 无端口，用裸 HOST 即可；
#       目标默认 127.0.0.1 本机内核直接回 echo reply；可注入 -p ip=www.baidu.com）
#
# 演示点：
#   - 多步配方：${i} 个步骤，每个步骤发送一个 ICMP Echo Request
#   - sniffer 匹配：每个步骤的回包必须是 ICMP Echo Reply 且 id/seq 与发包一致
#   - 参数注入：可通过 -p ip=... 注入目标地址
#   - 模拟 ping：${i} 次发送，统计应答情况

global:
EOF

    # 生成 global 变量声明
    for j in $(seq 1 "$i"); do
        echo "- name: id${j}       # 步骤 ${j} 的标识符" >> "$FILE"
        echo "- name: seq${j}      # 步骤 ${j} 的序列号" >> "$FILE"
    done

    echo "" >> "$FILE"
    echo "recipe:" >> "$FILE"

    # 生成 recipe 步骤
    for j in $(seq 1 "$i"); do
        echo "- packet: icmp_ping_step.pkt" >> "$FILE"
        echo "  wait: 1" >> "$FILE"
        echo "  extract:" >> "$FILE"
        echo "  - name: id${j}" >> "$FILE"
        echo "    from: reply.icmp.id" >> "$FILE"
        echo "    as: int" >> "$FILE"
        echo "  - name: seq${j}" >> "$FILE"
        echo "    from: reply.icmp.seq" >> "$FILE"
        echo "    as: int" >> "$FILE"
    done

    echo "Generated: $FILE"
done

echo "Done! Generated 10 recipes."