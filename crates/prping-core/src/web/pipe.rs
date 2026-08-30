//! 异步↔阻塞字节桥：WS 任务（async）与 LSP 会话线程（阻塞 `run_lsp_on`）之间
//! 的两根单向管道。基于 `smol::channel`（无锁队列 + 阻塞收发两侧同源），EOF 语义
//! = 发送端 drop：WS 断开 → 请求侧发送端 drop → LSP 读到 EOF 退出 → 响应侧发送端
//! drop → 转发任务结束 → WS 关闭。

use std::collections::VecDeque;
use std::io;

use smol::channel::{Receiver, Sender};

/// LSP 请求方向（WS 任务 send → LSP 线程 `Read`）。发送端用 `Sender`，读取端实现
/// `io::Read`（阻塞 `recv_blocking`，发送端全部 drop 后返回 EOF）。
pub(crate) struct ChanReader {
    rx: Receiver<Vec<u8>>,
    buf: VecDeque<u8>,
    eof: bool,
}

impl ChanReader {
    pub(crate) fn new(rx: Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: VecDeque::new(),
            eof: false,
        }
    }
}

impl io::Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // 空读（零缓冲）直接返回，避免在 recv 上阻塞
        if out.is_empty() {
            return Ok(0);
        }
        // 缓冲为空时阻塞取块；通道关闭（发送端 drop）= EOF
        while self.buf.is_empty() {
            if self.eof {
                return Ok(0);
            }
            match self.rx.recv_blocking() {
                Ok(chunk) => {
                    self.buf.extend(chunk);
                }
                Err(_) => {
                    self.eof = true;
                    return Ok(0);
                }
            }
        }
        let n = out.len().min(self.buf.len());
        for (i, b) in self.buf.drain(..n).enumerate() {
            out[i] = b;
        }
        Ok(n)
    }
}

/// LSP 响应方向（LSP 线程 `Write` → WS 任务 recv）。每次 write 整块入队；
/// `flush` 为空操作（信道本身保序）。
pub(crate) struct ChanWriter {
    tx: Sender<Vec<u8>>,
}

impl ChanWriter {
    pub(crate) fn new(tx: Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl io::Write for ChanWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send_blocking(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "lsp pipe closed"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn chan_roundtrip_and_eof() {
        let (tx, rx) = smol::channel::unbounded::<Vec<u8>>();
        let mut r = ChanReader::new(rx);
        tx.send_blocking(b"hello ".to_vec()).unwrap();
        tx.send_blocking(b"world".to_vec()).unwrap();
        drop(tx);

        let mut out = [0u8; 3];
        assert_eq!(r.read(&mut out).unwrap(), 3);
        assert_eq!(&out, b"hel");
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"lo world");
        // EOF 后继续读仍为 0
        assert_eq!(r.read(&mut out).unwrap(), 0);
    }

    #[test]
    fn chan_zero_len_read() {
        let (_tx, rx) = smol::channel::unbounded::<Vec<u8>>();
        let mut r = ChanReader::new(rx);
        assert_eq!(r.read(&mut []).unwrap(), 0);
    }

    #[test]
    fn chan_writer_broken_pipe() {
        let (tx, rx) = smol::channel::unbounded::<Vec<u8>>();
        drop(rx);
        let mut w = ChanWriter::new(tx);
        let err = w.write(b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
