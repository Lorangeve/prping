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
pub(crate) use socket::icmp_offset_v4;
pub use socket::{
    create_icmp_socket, create_tcp_socket, create_udp_socket, raw_socket_error, set_ttl,
};

// 格式化与协议原语
pub use format::{echo_fill, format_bytes, rand_u16, rand_u32, udp_receive_trigger, unix_ts};

// 中断控制与运行循环
pub use interrupt::{Run, interrupted, reset_interrupt, set_interrupted};
