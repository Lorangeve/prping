//! 统一输出和颜色管理。

use std::io::Result;
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
