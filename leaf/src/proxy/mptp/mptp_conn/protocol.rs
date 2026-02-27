use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const VER: u8 = 1;

// Message Types
pub const MTYP_DATA: u8 = 0x01;
pub const MTYP_PING: u8 = 0x02;
pub const MTYP_PONG: u8 = 0x03;
pub const MTYP_FIN: u8 = 0x04;
pub const MTYP_RST: u8 = 0x05;

// Handshake
pub const CMD_CONNECT: u8 = 0x01; // TCP
pub const CMD_UDP: u8 = 0x03; // UDP (SOCKS5 style)

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// Data Frame Header: MTYP(1) + PN(8) + LEN(4)
pub const DATA_HEADER_LEN: usize = 1 + 8 + 4;
// Control Frame Header (min): MTYP(1)
pub const MIN_HEADER_LEN: usize = 1;

#[derive(Debug, Clone)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

impl Address {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Address::Ipv4(addr) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&addr.octets());
            }
            Address::Domain(domain) => {
                buf.put_u8(ATYP_DOMAIN);
                let bytes = domain.as_bytes();
                buf.put_u8(bytes.len() as u8);
                buf.put_slice(bytes);
            }
            Address::Ipv6(addr) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&addr.octets());
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        buf.to_vec()
    }

    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>> {
        if buf.is_empty() {
            return Ok(None);
        }
        let atyp = buf[0];
        match atyp {
            ATYP_IPV4 => {
                if buf.len() < 1 + 4 {
                    return Ok(None);
                }
                buf.advance(1);
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&buf[..4]);
                buf.advance(4);
                Ok(Some(Address::Ipv4(Ipv4Addr::from(octets))))
            }
            ATYP_DOMAIN => {
                if buf.len() < 2 {
                    return Ok(None);
                }
                let len = buf[1] as usize;
                if buf.len() < 1 + 1 + len {
                    return Ok(None);
                }
                buf.advance(2);
                let domain = String::from_utf8_lossy(&buf[..len]).to_string();
                buf.advance(len);
                Ok(Some(Address::Domain(domain)))
            }
            ATYP_IPV6 => {
                if buf.len() < 1 + 16 {
                    return Ok(None);
                }
                buf.advance(1);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[..16]);
                buf.advance(16);
                Ok(Some(Address::Ipv6(Ipv6Addr::from(octets))))
            }
            _ => bail!("Unknown ATYP: {}", atyp),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub ver: u8,
    pub cid: uuid::Uuid,
    pub cmd: u8,
    pub dst_addr: Address,
    pub dst_port: u16,
}

impl HandshakeRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ver);
        buf.put_slice(self.cid.as_bytes());
        buf.put_u8(self.cmd);
        self.dst_addr.encode(buf);
        buf.put_u16(self.dst_port);
    }

    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>> {
        // VER(1) + CID(16) + CMD(1) + ATYP(1) ...
        if buf.len() < 1 + 16 + 1 + 1 {
            return Ok(None);
        }

        // Peek to check if we have enough for address
        // But Address::decode advances buffer. We need to be careful.
        // Actually, let's clone the buffer to try decode, or just implement peek logic.
        // Since `Address::decode` handles length check, we can try to decode strictly if we are sure.
        // However, we need to handle "Partial" state.
        // Let's implement a safe way.

        let mut reader = std::io::Cursor::new(&buf[..]);

        // Skip VER, CID, CMD
        reader.advance(1 + 16 + 1);

        // Check Address
        if !reader.has_remaining() {
            return Ok(None);
        }
        let atyp = reader.get_u8();
        let addr_len = match atyp {
            ATYP_IPV4 => 4,
            ATYP_DOMAIN => {
                if !reader.has_remaining() {
                    return Ok(None);
                }
                reader.get_u8() as usize
            }
            ATYP_IPV6 => 16,
            _ => return Err(anyhow::anyhow!("Unknown ATYP: {}", atyp)),
        };

        if reader.remaining() < addr_len + 2 {
            // +2 for Port
            return Ok(None);
        }

        // Now we know we have enough data.
        let ver = buf.get_u8();
        if ver != VER {
            return Err(anyhow::anyhow!("Unsupported Version: {}", ver));
        }

        let cid = uuid::Uuid::from_bytes({
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[..16]);
            buf.advance(16);
            b
        });

        let cmd = buf.get_u8();

        let dst_addr = match Address::decode(buf)? {
            Some(a) => a,
            None => unreachable!("We checked length"),
        };

        let dst_port = buf.get_u16();

        Ok(Some(HandshakeRequest {
            ver,
            cid,
            cmd,
            dst_addr,
            dst_port,
        }))
    }
}

// UDP Header Helper
// SOCKS5 UDP: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
// We'll simplify this for internal use or reuse SOCKS5 format.
// We should implement SOCKS5 UDP header parsing/encoding.
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub frag: u8,
    pub addr: Address,
    pub port: u16,
}

impl UdpHeader {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(0); // RSV
        buf.put_u8(self.frag);
        self.addr.encode(buf);
        buf.put_u16(self.port);
    }

    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>> {
        if buf.len() < 4 {
            // RSV(2) + FRAG(1) + ATYP(1)
            return Ok(None);
        }

        // Peek
        let mut reader = std::io::Cursor::new(&buf[..]);
        reader.advance(3); // RSV + FRAG

        let atyp = reader.get_u8();
        let addr_len = match atyp {
            ATYP_IPV4 => 4,
            ATYP_DOMAIN => {
                if !reader.has_remaining() {
                    return Ok(None);
                }
                reader.get_u8() as usize
            }
            ATYP_IPV6 => 16,
            _ => return Err(anyhow::anyhow!("Unknown ATYP: {}", atyp)),
        };

        if reader.remaining() < addr_len + 2 {
            return Ok(None);
        }

        // Consume
        buf.advance(2); // RSV
        let frag = buf.get_u8();
        let addr = match Address::decode(buf)? {
            Some(a) => a,
            None => unreachable!(),
        };
        let port = buf.get_u16();

        Ok(Some(UdpHeader { frag, addr, port }))
    }
}

#[derive(Debug, Clone)]
pub enum Frame {
    Data { pn: u64, payload: Bytes },
    Ping,
    Pong,
    Fin,
    Rst,
    Unknown(u8, Bytes),
}

impl Frame {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Frame::Data { pn, payload } => {
                buf.reserve(DATA_HEADER_LEN + payload.len());
                buf.put_u8(MTYP_DATA);
                buf.put_u64(*pn);
                buf.put_u32(payload.len() as u32);
                buf.put_slice(payload);
            }
            Frame::Ping => buf.put_u8(MTYP_PING),
            Frame::Pong => buf.put_u8(MTYP_PONG),
            Frame::Fin => buf.put_u8(MTYP_FIN),
            Frame::Rst => buf.put_u8(MTYP_RST),
            Frame::Unknown(mtyp, cnt) => {
                buf.put_u8(*mtyp);
                buf.put_slice(cnt);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_encoding() {
        let req = HandshakeRequest {
            ver: VER,
            cid: uuid::Uuid::new_v4(),
            cmd: CMD_CONNECT,
            dst_addr: Address::Ipv4("127.0.0.1".parse().unwrap()),
            dst_port: 8080,
        };

        let mut buf = BytesMut::new();
        req.encode(&mut buf);

        let mut decode_buf = buf.clone();
        let decoded = HandshakeRequest::decode(&mut decode_buf).unwrap().unwrap();

        assert_eq!(req.ver, decoded.ver);
        assert_eq!(req.cid, decoded.cid);
        assert_eq!(req.cmd, decoded.cmd);
        assert_eq!(req.dst_port, decoded.dst_port);
        match (req.dst_addr, decoded.dst_addr) {
            (Address::Ipv4(a), Address::Ipv4(b)) => assert_eq!(a, b),
            _ => panic!("Address mismatch"),
        }
    }
}
