//! The peer the conformance plugin's datagram engine talks to.
//!
//! The engine's framing is deliberately trivial -- the point is what the host
//! does with the pieces, not the format -- and this is the other end of it. A
//! peer can also choose *how* it puts the bytes on the wire: one frame at a
//! time, several in a single write, a byte at a time, with keepalives mixed in.
//! Over a reliable transport those are exactly the shapes `decode_packet` has
//! to report differently, and the host has to act on:
//!
//! * a partial frame -- nothing consumed, nothing produced;
//! * a keepalive -- bytes consumed, no datagram;
//! * several frames in one read -- consumed one at a time until they run out.
//!
//! Driving them from the peer means the engine stays honest and the host is the
//! only thing under test.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

const FRAME_DATA: u8 = b'D';
const FRAME_KEEPALIVE: u8 = b'K';
const DATA_HEAD: usize = 1 + 1 + 2 + 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub port: u16,
    pub addr: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DATA_HEAD + self.addr.len() + self.payload.len());
        out.push(FRAME_DATA);
        out.push(self.kind);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&(self.addr.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.addr);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

pub fn keepalive() -> Vec<u8> {
    vec![FRAME_KEEPALIVE]
}

/// Decodes one frame, returning it and its length. `Ok(None)` means the input
/// holds only part of one.
pub fn decode(input: &[u8]) -> Result<Option<(Option<Frame>, usize)>> {
    let Some(&tag) = input.first() else {
        return Ok(None);
    };
    if tag == FRAME_KEEPALIVE {
        return Ok(Some((None, 1)));
    }
    if tag != FRAME_DATA {
        anyhow::bail!("unknown frame tag {:#04x}", tag);
    }
    if input.len() < DATA_HEAD {
        return Ok(None);
    }
    let addr_len = u16::from_be_bytes([input[4], input[5]]) as usize;
    if input.len() < DATA_HEAD + addr_len + 2 {
        return Ok(None);
    }
    let payload_start = DATA_HEAD + addr_len + 2;
    let payload_len =
        u16::from_be_bytes([input[payload_start - 2], input[payload_start - 1]]) as usize;
    if input.len() < payload_start + payload_len {
        return Ok(None);
    }
    Ok(Some((
        Some(Frame {
            kind: input[1],
            port: u16::from_be_bytes([input[2], input[3]]),
            addr: input[DATA_HEAD..DATA_HEAD + addr_len].to_vec(),
            payload: input[payload_start..payload_start + payload_len].to_vec(),
        }),
        payload_start + payload_len,
    )))
}

/// How a peer puts its replies on the wire.
#[derive(Clone, Copy, Default)]
pub struct Style {
    /// Send this many keepalive frames before each reply.
    pub keepalives: usize,
    /// Split each write into pieces of at most this many bytes.
    pub chunk: Option<usize>,
    /// Hold replies back until this many have accumulated, then send them
    /// together.
    pub batch: usize,
}

impl Style {
    pub fn plain() -> Style {
        Style::default()
    }

    pub fn with_keepalives(count: usize) -> Style {
        Style {
            keepalives: count,
            ..Style::default()
        }
    }

    /// A byte at a time to begin with, so every reply arrives as a series of
    /// partial frames. See `CHUNKED_PIECES` for where the dribbling stops.
    pub fn dribbled() -> Style {
        Style {
            chunk: Some(1),
            ..Style::default()
        }
    }

    pub fn batched(frames: usize) -> Style {
        Style {
            batch: frames,
            ..Style::default()
        }
    }

    fn wrap(&self, frame: &Frame) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..self.keepalives {
            out.extend_from_slice(&keepalive());
        }
        out.extend_from_slice(&frame.encode());
        out
    }
}

pub struct Peer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Peer {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Echoes each framed datagram back to its sender.
    pub async fn udp_echo(style: Style) -> Result<Self> {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
        let addr = socket.local_addr()?;
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(Some((Some(frame), _))) = decode(&buf[..n]) else {
                    continue;
                };
                // One datagram per frame, so keepalives go as datagrams of
                // their own; the host has to skip them and keep waiting.
                for _ in 0..style.keepalives {
                    if socket.send_to(&keepalive(), from).await.is_err() {
                        return;
                    }
                }
                if socket.send_to(&frame.encode(), from).await.is_err() {
                    return;
                }
            }
        });
        Ok(Self { addr, task })
    }

    /// Echoes framed datagrams carried over a byte stream.
    pub async fn tcp_echo(style: Style) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let _ = serve_stream(stream, style).await;
                });
            }
        });
        Ok(Self { addr, task })
    }
}

async fn serve_stream(mut stream: tokio::net::TcpStream, style: Style) -> Result<()> {
    let mut pending = Vec::new();
    let mut held: Vec<Frame> = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&buf[..n]);

        while let Some((frame, len)) = decode(&pending)? {
            pending.drain(..len);
            let Some(frame) = frame else { continue };
            held.push(frame);
            if held.len() < style.batch.max(1) {
                continue;
            }
            let mut reply = Vec::new();
            for frame in held.drain(..) {
                reply.extend_from_slice(&style.wrap(&frame));
            }
            write_out(&mut stream, &reply, style).await?;
        }
    }
}

/// How many pieces of a chunked write are paused between.
///
/// The pause is what stops the pieces coalescing in the socket, and it cannot
/// be shorter than the platform's timer granularity: a 200µs sleep is 200µs on
/// Unix and about 16ms on Windows, so a pause per byte costs a 1200 byte reply
/// a quarter of a second on one and half a minute on the other. Bounding the
/// count rather than the pause keeps the cost flat everywhere.
///
/// What the host has to do is hold a frame that arrived in pieces, and the
/// pieces that make that hard are the ones carrying the length prefix and the
/// start of the body. Those are all in the first few; the remainder of the
/// reply rides along in one write, which is a shape the host has to handle
/// anyway.
const CHUNKED_PIECES: usize = 32;

async fn write_out(stream: &mut tokio::net::TcpStream, bytes: &[u8], style: Style) -> Result<()> {
    match style.chunk {
        None => {
            stream.write_all(bytes).await?;
            stream.flush().await?;
        }
        Some(size) => {
            let size = size.max(1);
            let (head, tail) = bytes.split_at((CHUNKED_PIECES * size).min(bytes.len()));
            for piece in head.chunks(size) {
                stream.write_all(piece).await?;
                stream.flush().await?;
                // Enough for the host to see the partial frame as partial
                // rather than for the pieces to coalesce in the socket.
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
            if !tail.is_empty() {
                stream.write_all(tail).await?;
                stream.flush().await?;
            }
        }
    }
    Ok(())
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
