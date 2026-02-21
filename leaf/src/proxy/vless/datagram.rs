pub fn build_vless_udp_header(
    uuid_bytes: &[u8; 16],
    dst_addr: &str,
    dst_port: u16,
    addr_type: u8,
) -> Vec<u8> {
    let mut header = vec![];
    header.push(0x00); // VLESS version
    header.extend_from_slice(uuid_bytes);
    header.push(0x00); // Addons length = 0 (no flow for UDP)
    header.push(0x02); // Command: UDP
    header.push((dst_port >> 8) as u8); // Port high byte
    header.push((dst_port & 0xFF) as u8); // Port low byte
    header.push(addr_type);
    match addr_type {
        1 => {
            let parts: Vec<u8> = dst_addr
                .split('.')
                .map(|s| s.parse().unwrap_or(0))
                .collect();
            header.extend_from_slice(&parts);
        }
        2 => {
            header.push(dst_addr.len() as u8);
            header.extend_from_slice(dst_addr.as_bytes());
        }
        3 => {
            if let Ok(addr6) = dst_addr.parse::<std::net::Ipv6Addr>() {
                header.extend_from_slice(&addr6.octets());
            }
        }
        _ => {}
    }
    header
}

pub struct VlessUdpParser {
    buffer: Vec<u8>,
    header_parsed: bool,
    expected_len: Option<usize>,
}

impl VlessUdpParser {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            header_parsed: false,
            expected_len: None,
        }
    }

    pub fn parse(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        let mut packets = Vec::new();

        if !self.header_parsed {
            if self.buffer.len() >= 2 {
                self.buffer.drain(..2);
                self.header_parsed = true;
            } else {
                return packets;
            }
        }

        loop {
            if self.expected_len.is_none() {
                if self.buffer.len() >= 2 {
                    let len = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
                    self.buffer.drain(..2);
                    self.expected_len = Some(len);
                } else {
                    break;
                }
            }

            if let Some(len) = self.expected_len {
                if self.buffer.len() >= len {
                    let packet: Vec<u8> = self.buffer.drain(..len).collect();
                    packets.push(packet);
                    self.expected_len = None;
                } else {
                    break;
                }
            }
        }
        packets
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct VlessDatagram<S> {
    stream: S,
    parser: VlessUdpParser,
    write_buf: Vec<u8>,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> VlessDatagram<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            parser: VlessUdpParser::new(),
            write_buf: Vec::with_capacity(65535),
        }
    }

    pub fn get_stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub async fn recv_from(&mut self) -> std::io::Result<Vec<Vec<u8>>> {
        let mut io_buf = [0u8; 8192];
        match self.stream.read(&mut io_buf).await {
            Ok(0) => Ok(Vec::new()), // EOF
            Ok(n) => {
                let packets = self.parser.parse(&io_buf[..n]);
                Ok(packets)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn send_to(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let payload_len = payload.len() as u16;
        self.write_buf.clear();
        self.write_buf.extend_from_slice(&payload_len.to_be_bytes());
        self.write_buf.extend_from_slice(payload);
        self.stream.write_all(&self.write_buf).await?;
        self.stream.flush().await?;
        Ok(())
    }
}
