//! 测试参数结构体。

use std::net::IpAddr;

/// 一次测试的全部参数（收敛各模块的长参数列表）。
///
/// `Default` 提供合理的默认值（ICMP ping 模式），各子命令只需覆盖差异字段：
/// ```rust
/// use prping_core::PingConfig;
/// let cfg = PingConfig {
///     host: "1.2.3.4".into(),
///     count: 10,
///     ..PingConfig::default()
/// };
/// ```
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
    /// 路由跟踪使用 TCP SYN 探测（`trace HOST:PORT` 自动启用，需端口；
    /// 库调用方也可显式置 true 指定；默认 ICMP echo）。
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

impl Default for PingConfig {
    /// 默认值：ICMP ping 模式，无限迭代，间隔 1s，预热 4 次，30 跳。
    ///
    /// 必填字段 `host`/`port` 默认空值（`""`/`0`），各调用方覆盖。
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
            count: 0,
            duration: None,
            interval: 1.0,
            size: None,
            quiet: false,
            histogram: None,
            warmup: 4,
            v4: false,
            v6: false,
            parallel: 1,
            udp: false,
            receive: false,
            bandwidth: false,
            mtu: false,
            traceroute: false,
            trace_tcp: false,
            trace_udp: false,
            max_hops: crate::ping::trace::DEFAULT_MAX_HOPS,
            no_dns: false,
            graph: false,
            source: None,
        }
    }
}
