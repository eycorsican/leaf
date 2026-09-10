//! A SOCKS5 client, spoken over the wire.
//!
//! Deliberately not built on leaf's own socks outbound: the point of the
//! harness is to observe a leaf node the way an application would, so a bug
//! that lives in both the inbound and the outbound cannot cancel itself out.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// A destination as it travels through the proxy.
///
/// Domain targets matter on their own: they are what makes leaf resolve at the
/// far end, and what a datagram engine has to echo back unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn domain(host: &str, port: u16) -> Self {
        Target::Domain(host.to_string(), port)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Target::Ip(SocketAddr::V4(addr)) => {
                out.push(0x01);
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            Target::Ip(SocketAddr::V6(addr)) => {
                out.push(0x04);
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            Target::Domain(host, port) => {
                out.push(0x03);
                out.push(u8::try_from(host.len()).expect("domain fits in a byte"));
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// Decodes an address, returning it and how many bytes it occupied.
    fn decode(input: &[u8]) -> Result<(Target, usize)> {
        let kind = *input.first().context("truncated socks address")?;
        match kind {
            0x01 => {
                if input.len() < 7 {
                    bail!("truncated socks ipv4 address");
                }
                let ip = std::net::Ipv4Addr::new(input[1], input[2], input[3], input[4]);
                let port = u16::from_be_bytes([input[5], input[6]]);
                Ok((Target::Ip(SocketAddr::from((ip, port))), 7))
            }
            0x03 => {
                let len = *input.get(1).context("truncated socks domain length")? as usize;
                if input.len() < 2 + len + 2 {
                    bail!("truncated socks domain address");
                }
                let host = std::str::from_utf8(&input[2..2 + len])
                    .context("socks domain is not utf-8")?
                    .to_string();
                let port = u16::from_be_bytes([input[2 + len], input[3 + len]]);
                Ok((Target::Domain(host, port), 4 + len))
            }
            0x04 => {
                if input.len() < 19 {
                    bail!("truncated socks ipv6 address");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&input[1..17]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([input[17], input[18]]);
                Ok((Target::Ip(SocketAddr::from((ip, port))), 19))
            }
            other => bail!("unknown socks address type {}", other),
        }
    }
}

impl From<SocketAddr> for Target {
    fn from(addr: SocketAddr) -> Self {
        Target::Ip(addr)
    }
}

#[derive(Clone, Copy)]
pub struct Socks5 {
    proxy: SocketAddr,
}

impl Socks5 {
    pub fn new(proxy: SocketAddr) -> Self {
        Self { proxy }
    }

    /// Opens a proxied TCP connection.
    pub async fn connect(&self, target: impl Into<Target>) -> Result<TcpStream> {
        let target = target.into();
        let mut stream = TcpStream::connect(self.proxy)
            .await
            .with_context(|| format!("connecting to the socks inbound at {}", self.proxy))?;
        greet(&mut stream).await?;
        request(&mut stream, 0x01, &target).await?;
        Ok(stream)
    }

    /// Sets up a UDP association and returns a socket bound to the relay.
    pub async fn udp_associate(&self) -> Result<UdpSession> {
        let mut control = TcpStream::connect(self.proxy)
            .await
            .with_context(|| format!("connecting to the socks inbound at {}", self.proxy))?;
        greet(&mut control).await?;
        // All-zero request address: the client does not commit to a source.
        let relay = request(
            &mut control,
            0x03,
            &Target::Ip(SocketAddr::from(([0, 0, 0, 0], 0))),
        )
        .await?;
        let relay = match relay {
            Target::Ip(addr) if !addr.ip().is_unspecified() => addr,
            // Some servers answer with an unspecified address, meaning "the
            // address you already reached me on".
            _ => self.proxy,
        };
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
        Ok(UdpSession {
            _control: control,
            socket,
            relay,
        })
    }
}

pub struct UdpSession {
    /// Kept open for the lifetime of the association, as SOCKS5 requires.
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

impl UdpSession {
    pub async fn send_to(&self, payload: &[u8], target: impl Into<Target>) -> Result<()> {
        let mut packet = vec![0x00, 0x00, 0x00];
        target.into().encode(&mut packet);
        packet.extend_from_slice(payload);
        self.socket.send_to(&packet, self.relay).await?;
        Ok(())
    }

    /// Receives one proxied datagram, returning the payload and the address the
    /// proxy says it came from.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Target)> {
        let mut packet = vec![0u8; 64 * 1024];
        let (n, _) = self.socket.recv_from(&mut packet).await?;
        if n < 4 {
            bail!("truncated socks udp datagram: {} bytes", n);
        }
        let (source, addr_len) = Target::decode(&packet[3..n])?;
        let payload = &packet[3 + addr_len..n];
        if payload.len() > buf.len() {
            bail!(
                "socks udp payload of {} bytes does not fit in {}",
                payload.len(),
                buf.len()
            );
        }
        buf[..payload.len()].copy_from_slice(payload);
        Ok((payload.len(), source))
    }
}

async fn greet(stream: &mut TcpStream) -> Result<()> {
    // One method offered: no authentication.
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .context("socks greeting was not answered")?;
    if reply != [0x05, 0x00] {
        bail!("socks greeting refused: {:02x?}", reply);
    }
    Ok(())
}

/// Sends a request and returns the bound address from the reply.
async fn request(stream: &mut TcpStream, command: u8, target: &Target) -> Result<Target> {
    let mut out = vec![0x05, command, 0x00];
    target.encode(&mut out);
    stream.write_all(&out).await?;

    let mut head = [0u8; 3];
    stream
        .read_exact(&mut head)
        .await
        .context("socks request was not answered")?;
    if head[0] != 0x05 {
        bail!("unexpected socks version in reply: {:02x}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("socks request failed with reply code {:02x}", head[1]);
    }

    // The bound address is variable-length, so read the type first.
    let mut kind = [0u8; 1];
    stream.read_exact(&mut kind).await?;
    let rest_len = match kind[0] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut tail = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut tail).await?;
            let mut encoded = vec![0x03, len[0]];
            encoded.extend_from_slice(&tail);
            return Ok(Target::decode(&encoded)?.0);
        }
        other => bail!("unknown socks address type in reply: {}", other),
    };
    let mut tail = vec![0u8; rest_len];
    stream.read_exact(&mut tail).await?;
    let mut encoded = vec![kind[0]];
    encoded.extend_from_slice(&tail);
    Ok(Target::decode(&encoded)?.0)
}
