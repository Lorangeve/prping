//! 共享基础设施：配置、DNS、网络 I/O、raw socket、格式化、中断控制。

mod config;
pub(crate) mod dns;
mod format;
mod interrupt;
mod net;
pub(crate) mod socket;

// 配置
pub use config::PingConfig;

// DNS
pub use dns::{local_bind, print_resolving, resolve, resolve_source, resolve_vec};

// 网络 I/O
pub use net::{
    bind_udp, configure_executor_threads, connect_first, connect_timeout, drain_after_send,
    init_slice, udp_recv, udp_send,
};

// Raw socket
// icmp_offset_v4 仅 raw 收包路径用（Windows ping 走 ICMP.DLL，不解析外层 IP 头）
#[cfg(not(windows))]
pub(crate) use socket::icmp_offset_v4;
pub use socket::{create_icmp_socket, create_udp_socket, raw_socket_error, set_ttl};
// raw TCP socket 仅 `trace --tcp` 用（Windows 不支持 raw TCP）
#[cfg(unix)]
pub use socket::create_tcp_socket;

// 格式化与协议原语
pub use format::{echo_fill, format_bytes, rand_u16, udp_receive_trigger, unix_ts};
// rand_u32 仅 `trace --tcp` 的 Unix raw TCP 路径用（Windows 不支持 raw TCP）
#[cfg(unix)]
pub use format::rand_u32;

// 中断控制与运行循环
pub use interrupt::{Run, interrupted, reset_interrupt, set_interrupted};
