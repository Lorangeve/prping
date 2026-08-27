//! 网络 I/O：UDP socket 创建/收发、TCP 连接、executor 配置。

use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
// Duration 仅 Unix 的 connect_timeout 路径用（Windows 走 select workaround）
#[cfg(not(windows))]
use std::time::Duration;

/// 创建带大收发缓冲的 UDP socket（socket2 设置后包成 smol::Async）。
///
/// 内核默认 UDP 缓冲（~212KB）在带宽测试突发下会溢出丢包，这里放大到 4MB。
pub fn bind_udp(bind: SocketAddr) -> anyhow::Result<smol::Async<socket2::Socket>> {
    let domain = if bind.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_recv_buffer_size(4 * 1024 * 1024)?;
    sock.set_send_buffer_size(4 * 1024 * 1024)?;
    sock.bind(&socket2::SockAddr::from(bind))?;
    sock.set_nonblocking(true)?;
    Ok(smol::Async::new(sock)?)
}

/// 异步 UDP 发送。
pub async fn udp_send(
    sock: &smol::Async<socket2::Socket>,
    payload: &[u8],
    addr: &SocketAddr,
) -> std::io::Result<usize> {
    sock.write_with(|s| s.send_to(payload, &socket2::SockAddr::from(*addr)))
        .await
}

/// 异步 UDP 接收，返回（字节数, 来源地址）。
pub async fn udp_recv(
    sock: &smol::Async<socket2::Socket>,
    buf: &mut [MaybeUninit<u8>],
) -> std::io::Result<(usize, SocketAddr)> {
    sock.read_with(|s| s.recv_from(buf))
        .await
        .map(|(n, a)| (n, a.as_socket().expect("UDP socket 地址必为 INET")))
}

/// 把已初始化的接收前缀转成 `&[u8]`（配合 `udp_recv`/`recv_from` 的 MaybeUninit 缓冲）。
pub fn init_slice(buf: &[MaybeUninit<u8>], n: usize) -> &[u8] {
    // SAFETY: 所有字节均以 0 初始化（调用方用 MaybeUninit::new(0) 构造），
    // 且 MaybeUninit<u8> 与 u8 布局一致。
    unsafe { std::mem::transmute(&buf[..n]) }
}

/// 配置多线程 executor：smol 全局 executor 默认单线程，`--parallel` 并发与服务端连接
/// 无法真正并行。在首次 `smol::spawn` 之前设置 `SMOL_THREADS`（spawn 时才惰性初始化）。
pub fn configure_executor_threads() {
    if std::env::var_os("SMOL_THREADS").is_none() {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .max(2);
        // SAFETY: 进程启动早期、无并发线程竞争时调用；edition 2024 要求显式 unsafe。
        unsafe { std::env::set_var("SMOL_THREADS", n.to_string()) };
    }
}

/// 带 5 秒超时的 TCP 连接（黑洞地址不会挂死 OS 超时）。
pub async fn connect_timeout(
    addr: SocketAddr,
    source: Option<IpAddr>,
) -> std::io::Result<smol::Async<std::net::TcpStream>> {
    let std_stream: std::net::TcpStream =
        smol::unblock(move || -> std::io::Result<std::net::TcpStream> {
            let domain = if addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let sock =
                socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
            if let Some(src) = source {
                sock.bind(&socket2::SockAddr::from(SocketAddr::new(src, 0)))?;
            }
            connect_blocking(&sock, &socket2::SockAddr::from(addr))?;
            Ok(sock.into())
        })
        .await?;
    std_stream.set_nonblocking(true)?;
    smol::Async::new(std_stream)
}

/// 逐个尝试连接（多地址回退），全部失败返回最后一个错误。
pub async fn connect_first(
    addrs: &[SocketAddr],
    source: Option<IpAddr>,
) -> std::io::Result<smol::Async<std::net::TcpStream>> {
    let mut last = None;
    for a in addrs {
        match connect_timeout(*a, source).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses to connect")
    }))
}

/// 阻塞 connect + 5s 超时。
///
/// - Unix：`socket2::connect_timeout`（内部用 `poll`，各版本正确）。
/// - Windows：`win_connect_select`——socket2 的 `connect_timeout` 在 Windows 内部
///   用 **WSAPoll**，而 WSAPoll 在 **Win7 RTM（SP0）** 对非阻塞 socket 有缺陷。
fn connect_blocking(sock: &socket2::Socket, addr: &socket2::SockAddr) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        win_connect_select(sock, addr)
    }
    #[cfg(not(windows))]
    {
        sock.connect_timeout(addr, Duration::from_secs(5))
    }
}

/// Windows：非阻塞 connect + `select()` 等待可写 + `SO_ERROR` 取连接结果。
#[cfg(windows)]
fn win_connect_select(sock: &socket2::Socket, addr: &socket2::SockAddr) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    #[repr(C)]
    struct FdSet {
        fd_count: u32,
        fd_array: [usize; 64],
    }
    #[repr(C)]
    struct TimeVal {
        tv_sec: i32,
        tv_usec: i32,
    }

    const SOCKET_ERROR: i32 = -1;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn select(
            nfds: i32,
            readfds: *mut FdSet,
            writefds: *mut FdSet,
            exceptfds: *mut FdSet,
            timeout: *const TimeVal,
        ) -> i32;
    }

    sock.set_nonblocking(true)?;
    match sock.connect(addr) {
        Ok(()) => {
            sock.set_nonblocking(false)?;
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => {
            sock.set_nonblocking(false)?;
            return Err(e);
        }
    }
    let mut wfds = FdSet {
        fd_count: 1,
        fd_array: [sock.as_raw_socket() as usize; 64],
    };
    let tv = TimeVal {
        tv_sec: 5,
        tv_usec: 0,
    };
    let rc = unsafe {
        select(
            0,
            std::ptr::null_mut(),
            &mut wfds,
            std::ptr::null_mut(),
            &tv,
        )
    };
    sock.set_nonblocking(false)?;
    if rc == SOCKET_ERROR {
        return Err(std::io::Error::last_os_error());
    }
    if rc == 0 || wfds.fd_count == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
    }
    match sock.take_error()? {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// 优雅结束发送方向：shutdown(Write) 后排空残余数据至 EOF。
pub async fn drain_after_send(stream: &mut smol::Async<std::net::TcpStream>) {
    use smol::io::AsyncReadExt;
    let _ = stream.get_ref().shutdown(std::net::Shutdown::Write);
    let mut buf = [0u8; 65536];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_init_slice() {
        let buf: [MaybeUninit<u8>; 4] = [MaybeUninit::new(0xAB); 4];
        let s = init_slice(&buf, 4);
        assert_eq!(s, &[0xAB, 0xAB, 0xAB, 0xAB]);
    }
    #[test]
    fn test_bind_udp() {
        smol::block_on(async {
            let sock = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
            let local: SocketAddr = sock.get_ref().local_addr().unwrap().as_socket().unwrap();
            assert!(local.port() != 0);
        });
    }
}
