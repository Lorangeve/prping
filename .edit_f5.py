from pathlib import Path

def sub(path, old, new, tag, expect=1):
    p = Path(path)
    s = p.read_text(encoding="utf-8")
    assert s.count(old) == expect, tag + " count=" + str(s.count(old))
    p.write_text(s.replace(old, new), encoding="utf-8")

sub("crates/prping-core/tests/pkg.rs", """    let ack = |marker: &str| {
        format!("{m} = dns(id=global(\"tid\"), flags=0x8180, questions=[\"example.com\"])\nfull = use({m}) |> udp(sport=53, dport=global(\"cport\")) |> ipv4(dst=\"127.0.0.1\") |> eth()\n\nexport:\n- full\n").replace("{m}", marker)
    };""", """    let ack = |marker: &str| {
        String::from("@V@ = dns(id=global(\"tid\"), flags=0x8180, questions=[\"example.com\"])\nfull = use(@V@) |> udp(sport=53, dport=global(\"cport\")) |> ipv4(dst=\"127.0.0.1\") |> eth()\n\nexport:\n- full\n")
            .replace("@V@", marker)
    };""", "ack-tpl")
print("ack closure fixed")