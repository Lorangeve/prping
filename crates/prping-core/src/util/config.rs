//! 测试参数结构体。

use std::net::IpAddr;

/// 一次测试的全部参数（收敛各模块的长参数列表）。
#[derive(Debug, Clone)]
pub struct PingConfig {
    pub host: String,
    pub port: u16,
    pub count: u64,
    pub duration: Option<f64>,
    pub interval: f64,
    /// 负载大小（`-l`，None = 未指定）。
    pub size: Option<usize>,
    pub quiet: bool,
    pub histogram: Option<crate::stats::HistogramSpec>,
    pub warmup: u64,
    pub v4: bool,
    pub v6: bool,
    pub parallel: u32,
    pub udp: bool,
    pub receive: bool,
    /// 带宽测试模式（`-b`）。
    pub bandwidth: bool,
    /// MTU 探测模式（`--mtu`）。
    pub mtu: bool,
    /// 路由跟踪模式（trace 子命令）。
    pub traceroute: bool,
    /// 路由跟踪使用 TCP SYN 探测（`trace --tcp`，需端口；默认 ICMP echo）。
    pub trace_tcp: bool,
    /// 路由跟踪使用 UDP 探测（`trace --udp`，经典 traceroute：33434 起递增端口）。
    pub trace_udp: bool,
    /// 路由跟踪最大跳数（`-m`，默认 30）。
    pub max_hops: u32,
    /// 路由跟踪跳过反向 DNS（`-d`）。
    pub no_dns: bool,
    /// 是否打印时间线图（`-g`）。
    pub graph: bool,
    /// 源地址/网卡绑定（`-s`，None = 内核自动选）。
    pub source: Option<IpAddr>,
}
