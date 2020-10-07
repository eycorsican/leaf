use std::{
    convert::TryFrom,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    string::ToString,
};

use bytes::BufMut;
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt};

pub struct Session {
    pub source: Option<SocketAddr>,
    pub destination: SocksAddr,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Session {
            source: self.source.clone(),
            destination: self.destination.clone(),
        }
    }
}

struct SocksAddrType;

impl SocksAddrType {
    const V4: u8 = 0x1;
    const V6: u8 = 0x4;
    const DOMAIN: u8 = 0x3;
}

#[derive(Debug)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

const INSUFF_BYTES: &str = "insufficient bytes";

fn invalid_domain() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "invalid domain")
}

fn invalid_addr_type() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "invalid address type")
}

impl SocksAddr {
    pub fn empty_ipv4() -> Self {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        Self::from(addr)
    }

    pub fn must_ip(self) -> SocketAddr {
        match self {
            SocksAddr::Ip(a) => a,
            _ => {
                error!("assert SocksAddr as SocketAddr failed");
                panic!("");
            }
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(_addr) => 1 + 4 + 2,
                SocketAddr::V6(_addr) => 1 + 16 + 2,
            },
            Self::Domain(domain, _port) => 1 + 1 + domain.len() + 2,
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(addr) => addr.port(),
            SocksAddr::Domain(_, port) => *port,
        }
    }

    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(_, _) => true,
        }
    }

    pub fn domain(&self) -> Option<&String> {
        if let SocksAddr::Domain(domain, _) = self {
            Some(domain)
        } else {
            None
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        if let SocksAddr::Ip(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(addr) => {
                let ip = addr.ip();
                ip.to_string()
            }
            SocksAddr::Domain(domain, _) => domain.to_owned(),
        }
    }

    /// Writes `self` into `buf`.
    pub fn write_into<T: BufMut>(&self, buf: &mut T) -> io::Result<()> {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => {
                    buf.put_u8(SocksAddrType::V4);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
                SocketAddr::V6(addr) => {
                    buf.put_u8(SocksAddrType::V6);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
            },
            Self::Domain(domain, port) => {
                buf.put_u8(SocksAddrType::DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
        }
        Ok(())
    }

    pub async fn read_from<T: AsyncRead + Unpin>(r: &mut T) -> io::Result<Self> {
        match r.read_u8().await? {
            SocksAddrType::V4 => {
                let ip = Ipv4Addr::from(r.read_u32().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::V6 => {
                let ip = Ipv6Addr::from(r.read_u128().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::DOMAIN => {
                let domain_len = r.read_u8().await? as usize;
                let mut buf = vec![0u8; domain_len];
                let n = r.read_exact(&mut buf).await?;
                debug_assert_eq!(domain_len, n);
                let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                let port = r.read_u16().await?;
                Ok(Self::Domain(domain, port))
            }
            _ => Err(invalid_addr_type()),
        }
    }
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::Ip(a) => Self::from(a.to_owned()),
            SocksAddr::Domain(domain, port) => Self::from((domain.to_owned(), *port)),
        }
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SocksAddr::Ip(addr) => addr.to_string(),
            SocksAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        };
        write!(f, "{}", s)
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

impl From<(String, u16)> for SocksAddr {
    fn from((domain, port): (String, u16)) -> Self {
        Self::Domain(domain, port)
    }
}

impl From<(&'_ str, u16)> for SocksAddr {
    fn from((domain, port): (&'_ str, u16)) -> Self {
        Self::Domain(domain.to_owned(), port)
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<SocketAddrV4> for SocksAddr {
    fn from(value: SocketAddrV4) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddrV6> for SocksAddr {
    fn from(value: SocketAddrV6) -> Self {
        Self::Ip(value.into())
    }
}

impl TryFrom<String> for SocksAddr {
    type Error = &'static str;

    fn try_from(addr: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            return Err("invalid address");
        }
        if let Ok(port) = parts[1].parse::<u16>() {
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                return Ok(Self::from((ip, port)));
            }
            if parts[0].len() > 0xff {
                return Err("domain too long");
            }
            return Ok(Self::from((parts[0], port)));
        } else {
            return Err("invalid port");
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
