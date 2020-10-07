use std::convert::TryFrom;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use bytes::{Buf, BufMut, BytesMut};

// pub const MAX_SOCKS_ADDR_SIZE: usize = 1 + 1 + 255 + 2;

struct SocksAddrType;

impl SocksAddrType {
    const V4: u8 = 0x1;
    const V6: u8 = 0x3;
    const DOMAIN: u8 = 0x2;
}

#[derive(Debug)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

const INSUFF_BYTES: &str = "insufficient bytes";

/// Tries to read `SocksAddr` from `BytesBuf` and advances the cursor.
impl TryFrom<&mut BytesMut> for SocksAddr {
    type Error = &'static str;

    fn try_from(buf: &mut BytesMut) -> Result<Self, Self::Error> {
        if buf.remaining() < 1 {
            return Err(INSUFF_BYTES);
        }

        match buf.get_u8() {
            SocksAddrType::V4 => {
                if buf.remaining() < 4 + 2 {
                    return Err(INSUFF_BYTES);
                }
                let ip = Ipv4Addr::from(buf.get_u32());
                let port = buf.get_u16();
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::V6 => {
                if buf.remaining() < 16 + 2 {
                    return Err(INSUFF_BYTES);
                }
                let ip = Ipv6Addr::from(buf.get_u128());
                let port = buf.get_u16();
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::DOMAIN => {
                if buf.remaining() < 1 {
                    return Err(INSUFF_BYTES);
                }
                let domain_len = buf.get_u8() as usize;
                if buf.remaining() < domain_len + 2 {
                    return Err(INSUFF_BYTES);
                }
                let domain = String::from_utf8((&buf[..domain_len]).to_vec())
                    .map_err(|_| "invalid domain")?;
                buf.advance(domain_len);
                let port = buf.get_u16();
                Ok(Self::Domain(domain, port))
            }
            _ => Err("invalid address type"),
        }
    }
}

/// Tries to read `SocksAddr` from `&[u8]`.
impl TryFrom<&[u8]> for SocksAddr {
    type Error = &'static str;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 1 {
            return Err(INSUFF_BYTES);
        }

        match buf[0] {
            SocksAddrType::V4 => {
                if buf.len() < 1 + 4 + 2 {
                    return Err(INSUFF_BYTES);
                }
                let mut ip_bytes = [0u8; 4];
                (&mut ip_bytes).copy_from_slice(&buf[1..5]);
                let ip = Ipv4Addr::from(ip_bytes);
                let mut port_bytes = [0u8; 2];
                (&mut port_bytes).copy_from_slice(&buf[5..7]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::V6 => {
                if buf.len() < 1 + 16 + 2 {
                    return Err(INSUFF_BYTES);
                }
                let mut ip_bytes = [0u8; 16];
                (&mut ip_bytes).copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(ip_bytes);
                let mut port_bytes = [0u8; 2];
                (&mut port_bytes).copy_from_slice(&buf[17..19]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::DOMAIN => {
                if buf.len() < 1 {
                    return Err(INSUFF_BYTES);
                }
                let domain_len = buf[1] as usize;
                if buf.len() < 1 + domain_len + 2 {
                    return Err(INSUFF_BYTES);
                }
                let domain = String::from_utf8((&buf[2..domain_len + 2]).to_vec())
                    .map_err(|_| "invalid domain")?;
                let mut port_bytes = [0u8; 2];
                (&mut port_bytes).copy_from_slice(&buf[domain_len + 2..domain_len + 4]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Domain(domain, port))
            }
            _ => Err("invalid address type"),
        }
    }
}

fn insuff() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "buffer too small")
}

impl SocksAddr {
    pub fn size(&self) -> usize {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(_addr) => 1 + 4 + 2,
                SocketAddr::V6(_addr) => 1 + 16 + 2,
            },
            Self::Domain(domain, _port) => 1 + 1 + domain.len() + 2,
        }
    }

    /// Writes `self` into `buf`.
    pub fn write_into<T: BufMut>(&self, buf: &mut T) -> io::Result<()> {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => {
                    if buf.remaining_mut() < 1 + 4 + 2 {
                        return Err(insuff());
                    }
                    buf.put_u16(addr.port());
                    buf.put_u8(SocksAddrType::V4);
                    buf.put_slice(&addr.ip().octets());
                }
                SocketAddr::V6(addr) => {
                    if buf.remaining_mut() < 1 + 16 + 2 {
                        return Err(insuff());
                    }
                    buf.put_u16(addr.port());
                    buf.put_u8(SocksAddrType::V6);
                    buf.put_slice(&addr.ip().octets());
                }
            },
            Self::Domain(domain, port) => {
                if buf.remaining_mut() < 1 + domain.len() + 2 {
                    return Err(insuff());
                }
                buf.put_u16(*port);
                buf.put_u8(SocksAddrType::DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
            }
        }
        Ok(())
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

impl From<&SocketAddr> for SocksAddr {
    fn from(addr: &SocketAddr) -> Self {
        Self::Ip(addr.to_owned())
    }
}

impl TryFrom<(String, u16)> for SocksAddr {
    type Error = &'static str;

    fn try_from((domain, port): (String, u16)) -> Result<Self, Self::Error> {
        if domain.len() > 0xff {
            Err("domain too long")
        } else {
            Ok(Self::Domain(domain, port))
        }
    }
}

impl TryFrom<(&String, u16)> for SocksAddr {
    type Error = &'static str;

    fn try_from((domain, port): (&String, u16)) -> Result<Self, Self::Error> {
        if domain.len() > 0xff {
            Err("domain too long")
        } else {
            Ok(Self::Domain(domain.to_owned(), port))
        }
    }
}

impl TryFrom<(&str, u16)> for SocksAddr {
    type Error = &'static str;

    fn try_from((domain, port): (&str, u16)) -> Result<Self, Self::Error> {
        let domain = domain.to_owned();
        if domain.len() > 0xff {
            Err("domain too long")
        } else {
            Ok(Self::Domain(domain, port))
        }
    }
}

impl ToString for SocksAddr {
    fn to_string(&self) -> String {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => addr.to_string(),
                SocketAddr::V6(addr) => addr.to_string(),
            },
            Self::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}
