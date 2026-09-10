//! Origin servers a scenario points its traffic at.
//!
//! They bind port 0 and report the address they got, and they stop when the
//! handle is dropped, so a scenario never leaves a listener behind for the next
//! case in the same process.

use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

pub struct Origin {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Origin {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Echoes every byte back, one connection at a time or many in parallel.
    pub async fn tcp_echo() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// Reads `expect` bytes and then closes, without replying.
    ///
    /// For the cases about a peer that ends the conversation first: the close
    /// has to travel back through the chain to the client.
    pub async fn tcp_sink(expect: usize) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; expect];
                    let _ = tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// Sends `size` bytes and closes, without waiting to be asked.
    ///
    /// The shape of a server that speaks first and ends its reply by closing:
    /// a greeting, or a response whose length is the connection itself. The
    /// bytes are [`greeting`], so a client can check it received all of them.
    pub async fn tcp_greeting(size: usize) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let payload = greeting(size);
                    if stream.write_all(&payload).await.is_ok() {
                        let _ = stream.shutdown().await;
                    }
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// Sends a repeating block for as long as the peer keeps reading.
    ///
    /// One direction only. An echo makes the two directions rise and fall
    /// together, so a regression in the encode path alone -- or in the decode
    /// path alone -- hides behind the other one still working.
    pub async fn tcp_source() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let block = source_block();
                    // Until the reader goes away, which arrives as a write
                    // error rather than as anything worth reporting.
                    while stream.write_all(&block).await.is_ok() {}
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// Reads until the peer stops writing, then says so.
    ///
    /// Answers the one question a half-close asks: did the far end learn that
    /// the request had ended? The marker comes back only when this origin has
    /// seen an end of stream, so a client that half-closes and waits for it is
    /// asking about propagation and nothing else.
    pub async fn tcp_eof_reporter() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8 * 1024];
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                            Ok(0) => break,
                            Ok(_) => continue,
                            Err(_) => return,
                        }
                    }
                    // The reply travels the other way, which is still open.
                    let _ = stream.write_all(&[EOF_SEEN]).await;
                    let _ = stream.flush().await;
                    // Held open so the marker is not racing a close.
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// Reads and discards, and answers with a single byte once it has taken
    /// `expect` of them.
    ///
    /// The other half of a one-directional measurement: somewhere to push to
    /// that will not push back, and an end the sender can observe. The
    /// acknowledgement is what makes the end observable without a half-close,
    /// which not every chain carries: leaf's websocket transport has no way to
    /// say "the request has ended", so a sender that waited for the origin's
    /// close would be timing leaf's ten-second idle timeout instead of the
    /// transfer -- as this meter did until it stopped asking for one.
    pub async fn tcp_discard(expect: usize) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut taken = 0usize;
                    let mut buf = vec![0u8; 64 * 1024];
                    while taken < expect {
                        match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => taken += n,
                        }
                    }
                    let _ = stream.write_all(&[ACK]).await;
                    // Kept open: closing here would race the acknowledgement
                    // against a reset on some paths, and the sender closes as
                    // soon as it has read the byte.
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                });
            }
        });
        Ok(Self { addr, task })
    }

    /// Echoes every datagram back to its sender.
    pub async fn udp_echo() -> Result<Self> {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let addr = socket.local_addr()?;
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if socket.send_to(&buf[..n], peer).await.is_err() {
                    return;
                }
            }
        });
        Ok(Self { addr, task })
    }
}

/// What [`Origin::tcp_discard`] answers with once it has everything.
pub const ACK: u8 = 0xa5;

/// What [`Origin::tcp_eof_reporter`] answers with once the request has ended.
pub const EOF_SEEN: u8 = 0x5e;

/// What [`Origin::tcp_greeting`] sends.
pub fn greeting(size: usize) -> Vec<u8> {
    crate::flow::pseudo_random(size, GREETING_SEED)
}

const GREETING_SEED: u64 = 0x9ee7;

/// The block [`Origin::tcp_source`] repeats.
///
/// Pseudo-random rather than a pattern, so that a transport which compresses
/// or deduplicates -- now or in some future plugin -- cannot flatter a
/// throughput measurement, and so that a reader can tell where in the block it
/// is.
pub fn source_block() -> Vec<u8> {
    crate::flow::pseudo_random(SOURCE_BLOCK, SOURCE_SEED)
}

/// How much the source writes per call. A window's worth, so the write side is
/// the socket rather than the loop around it.
pub const SOURCE_BLOCK: usize = 64 * 1024;
const SOURCE_SEED: u64 = 0x50c;

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
