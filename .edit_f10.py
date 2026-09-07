from pathlib import Path

def sub(path, old, new, tag, expect=1):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == expect, tag + " count=" + str(s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")

sub("crates/prping-core/tests/pkg.rs", """    // 段内步骤 1：标记包落观测端口 + 从触发未命中的包取对端（reply.peer.*）
    let notify_pkt = format!("m = raw(bytes=\"MISMATCH\")\nuse(m) |> udp(dport={sink}) |> ipv4(dst=\"127.0.0.1\") |> eth()\n\nextract:\n- name: m_port\n  from: reply.peer.port\n  as: int\n- name: m_ip\n  from: reply.peer.ip\n  as: str\n\nexport:\n- m\n");
    std::fs::write(dir.join("notify.pkt"), notify_pkt).unwrap();""", """    // 段内步骤 1：标记包落观测端口；extract（写在配方步骤上）从触发未命中
    // 的包取对端（reply.peer.*，无需本步 wait）
    let notify_pkt = format!("m = raw(bytes=\"MISMATCH\")\nuse(m) |> udp(dport={sink}) |> ipv4(dst=\"127.0.0.1\") |> eth()\n\nexport:\n- m\n");
    std::fs::write(dir.join("notify.pkt"), notify_pkt).unwrap();""", "notify-fix")
sub("crates/prping-core/tests/pkg.rs", """        "global:\n- tid\n- cport\n\nrecipe:\n- serve:\n  max: 1\n  on_mismatch:\n  - packet: notify.pkt\n  - packet: err.pkt\n  rules:\n  - packet: listen.pkt\n    extract:\n    - name: tid\n      from: reply.dns.id\n    - name: cport\n      from: reply.peer.port\n    handler:\n    - packet: reply.pkt\n",
    )
    .unwrap();

    // 发起方 socket（ephemeral 端口）+ 观测端口先绑""", """        "global:\n- tid\n- cport\n\nrecipe:\n- serve:\n  max: 1\n  on_mismatch:\n  - packet: notify.pkt\n    extract:\n    - name: m_port\n      from: reply.peer.port\n      as: int\n    - name: m_ip\n      from: reply.peer.ip\n      as: str\n  - packet: err.pkt\n  rules:\n  - packet: listen.pkt\n    extract:\n    - name: tid\n      from: reply.dns.id\n    - name: cport\n      from: reply.peer.port\n    handler:\n    - packet: reply.pkt\n",
    )
    .unwrap();

    // 发起方 socket（ephemeral 端口）+ 观测端口先绑""", "server-fix")
print("test fixed")