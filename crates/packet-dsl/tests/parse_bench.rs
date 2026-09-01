//! 入口解析基准（手动运行，CI 跳过）：
//! `cargo test -p packet-dsl --release --test parse_bench -- --ignored --nocapture`
//!
//! 度量「一次入口解析」的全成本：读取 + 解析全部库模块（默认 eng_lib，21 个
//! 文件）+ import 图 + 名字解析。LSP 每次击键（诊断 + 补全 + 悬停）触发 3~5
//! 次入口解析，此基准是库模块会话级缓存（semantic.rs `cached_module`）的
//! 前后对比标尺。

use std::time::Instant;

const ENTRY: &str = "q = icmp(type=8)\nfull = use(q) |> udp(sport=40000, dport=53) |> ipv4(dst=\"127.0.0.1\") |> eth()\nexport:\n- full\n";

#[test]
#[ignore = "手动基准：见文件头命令"]
fn bench_entry_parse_over_libs() {
    let dir = std::env::temp_dir();
    // 预热（磁盘缓存 / 进程内库模块缓存）
    for _ in 0..3 {
        packet_dsl::parse_source_at("bench", &dir, ENTRY).unwrap();
    }
    let n = 30;
    let t0 = Instant::now();
    for _ in 0..n {
        packet_dsl::parse_source_at("bench", &dir, ENTRY)
            .unwrap_or_else(|e| panic!("解析失败：{e}"));
    }
    println!(
        "entry parse avg {:?}/次（{n} 次，含全部库模块读取+解析+名字解析）",
        t0.elapsed() / n
    );
}
