//! 统一输出和颜色管理。

use rust_i18n::t;
use std::io::Result;
use std::net::SocketAddr;
use termcolor::{Color, ColorSpec, StandardStream, WriteColor};

/// 获取标准输出流（自动检测颜色支持）。
pub fn stdout() -> StandardStream {
    StandardStream::stdout(termcolor::ColorChoice::Auto)
}

/// 获取标准错误流（自动检测颜色支持）。
pub fn stderr() -> StandardStream {
    StandardStream::stderr(termcolor::ColorChoice::Auto)
}

/// 打印绿色文本。
pub fn print_green<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    w.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
    write!(w, "{}", text.as_ref())?;
    w.reset()
}

/// 打印青色文本。
pub fn print_cyan<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    w.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)))?;
    write!(w, "{}", text.as_ref())?;
    w.reset()
}

/// 打印黄色文本。
pub fn print_yellow<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    w.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))?;
    write!(w, "{}", text.as_ref())?;
    w.reset()
}

/// 打印红色文本。
pub fn print_red<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    w.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
    write!(w, "{}", text.as_ref())?;
    w.reset()
}

/// 打印粗体文本。
pub fn print_bold<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    w.set_color(ColorSpec::new().set_bold(true))?;
    write!(w, "{}", text.as_ref())?;
    w.reset()
}

/// 打印红色行。
pub fn writeln_red<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    print_red(w, text)?;
    writeln!(w)
}

/// 打印橙色文本（警告）。
pub fn print_orange<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    w.set_color(ColorSpec::new().set_fg(Some(Color::Ansi256(208))))?;
    write!(w, "{}", text.as_ref())?;
    w.reset()
}

/// 打印橙色行（警告）。
pub fn writeln_orange<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    print_orange(w, text)?;
    writeln!(w)
}

/// 打印品红文本（端口号）。
pub fn print_magenta<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    w.set_color(ColorSpec::new().set_fg(Some(Color::Magenta)))?;
    write!(w, "{}", text.as_ref())?;
    w.reset()
}

/// 获取指定层级的缩进字符串。
///
/// # 缩进层级
/// - 0: 无缩进
/// - 1: 2空格（一级列表、子标题）
/// - 2: 4空格（二级内容、文档字符串）
/// - 3: 8空格（hexdump等特殊用途）
/// - 4+: 12空格或更多（深度嵌套）
pub fn indent(level: usize) -> &'static str {
    match level {
        0 => "",
        1 => "  ",
        2 => "    ",
        3 => "        ",
        _ => "            ", // 4+ 层级使用12空格
    }
}

/// 将文本填充到指定宽度，用于对齐。
///
/// `output` 模块为私有（lib 公开面最小化，只 re-export
/// `output::{stderr, writeln_red, writeln_orange}`），此函数仅供 crate 内部
/// 调用；等价于 `format!("{:<width$}", text)`。
pub fn pad_to(text: &str, width: usize) -> String {
    format!("{:<width$}", text, width = width)
}

/// 创建指定长度的空格字符串。
///
/// 用于动态计算缩进，比硬编码空格更灵活。
pub fn spaces(count: usize) -> String {
    " ".repeat(count)
}

/// 打印暗淡文本（次要信息）。
pub fn print_dim<W: WriteColor>(w: &mut W, text: impl AsRef<str>) -> Result<()> {
    w.set_color(
        ColorSpec::new()
            .set_fg(Some(Color::Ansi256(245)))
            .set_intense(false),
    )?;
    write!(w, "{}", text.as_ref())?;
    w.reset()
}

/// 打印探测结果行（udp/latency/tcp/icmp 共用）。
///
/// 格式：`<label> <ip>:<port>: bytes=<N> time=<ms> [ttl=<N>] [warmup]`
/// - `label`：标签文本（如 `"Reply from"` / `"Connecting to"`）
/// - `addr`：SocketAddr（ip + port）；ICMP 无端口时 port=0 可隐藏
#[allow(clippy::too_many_arguments)]
pub fn print_probe_result<W: WriteColor>(
    w: &mut W,
    label: &str,
    addr: std::net::SocketAddr,
    size: Option<usize>,
    rtt: std::time::Duration,
    ttl: Option<u8>,
    warmup: bool,
    local: Option<std::net::SocketAddr>,
) -> Result<()> {
    print_green(w, label)?;
    print_cyan(w, addr.ip().to_string())?;
    if addr.port() != 0 {
        write!(w, ":")?;
        print_magenta(w, addr.port().to_string())?;
    }
    if let Some(sz) = size {
        write!(w, ": {}{sz} ", t!("common.bytes"))?;
    }
    if warmup {
        print_dim(w, format!(" {} ", t!("common.warmup")))?;
    }
    if let Some(l) = local {
        write!(w, "{} {}:", t!("common.from"), l.ip())?;
        print_dim(w, l.port().to_string())?;
        write!(w, ": ")?;
    }
    write!(w, ": ")?;
    print_yellow(
        w,
        format!("{}{:.2}ms", t!("common.time"), rtt.as_secs_f64() * 1000.0),
    )?;
    if let Some(t) = ttl {
        write!(w, " {}={t}", t!("common.ttl"))?;
    }
    writeln!(w)?;
    Ok(())
}

/// 服务端连接日志（三态：发送 -r 触发模式 / 接收 / 纯连接；着色统一在此）。
pub fn print_server_log<W: WriteColor>(
    w: &mut W,
    peer: SocketAddr,
    total: u64,
    sent_total: u64,
    elapsed: f64,
) -> Result<()> {
    let ip = peer.ip().to_string();
    let port = peer.port();
    if sent_total > 0 && elapsed > 0.0 {
        // 服务端发送方向（-r 触发模式）：打印发送的数据量
        let mbits = (sent_total as f64 * 8.0) / (elapsed * 1_000_000.0);
        let size_str = crate::util::format_bytes(sent_total);
        print_green(w, t!("server.sent_tag"))?;
        print_cyan(w, format!("{ip}:{port} "))?;
        print_yellow(
            w,
            format!("{size_str} ({sent_total}) in {elapsed:.2}s — {mbits:.2} Mbps"),
        )?;
        writeln!(w)
    } else if total > 0 && elapsed > 0.0 {
        let mbits = (total as f64 * 8.0) / (elapsed * 1_000_000.0);
        let size_str = crate::util::format_bytes(total);
        print_green(w, t!("server.recv_tag"))?;
        print_cyan(w, format!("{ip}:{port} "))?;
        print_yellow(
            w,
            format!("{size_str} ({total}) in {elapsed:.2}s — {mbits:.2} Mbps"),
        )?;
        writeln!(w)
    } else {
        print_green(w, t!("server.connect_tag"))?;
        print_cyan(w, format!("{ip}:{port} "))?;
        print_yellow(w, format!("{:.2}ms", elapsed * 1000.0))?;
        writeln!(w)
    }
}
