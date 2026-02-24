use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

pub struct Handler {
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Handler {
    async fn handle_socks4(
        &self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let mut buf = BytesMut::new();
        // CD, DSTPORT, DSTIP
        buf.resize(1 + 2 + 4, 0);
        stream.read_exact(&mut buf[..]).await?;

        if buf[0] != 0x01 {
            return Err(io::Error::other(format!(
                "unsupported socks4 cmd {}",
                buf[0]
            )));
        }

        let port = u16::from_be_bytes([buf[1], buf[2]]);
        let ip_bytes = [buf[3], buf[4], buf[5], buf[6]];

        // USERID
        let mut userid = Vec::new();
        loop {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await?;
            if b[0] == 0 {
                break;
            }
            userid.push(b[0]);
        }

        // SOCKS4a check: 0.0.0.x, x != 0
        let is_socks4a =
            ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0;

        let destination = if is_socks4a {
            let mut domain = Vec::new();
            loop {
                let mut b = [0u8; 1];
                stream.read_exact(&mut b).await?;
                if b[0] == 0 {
                    break;
                }
                domain.push(b[0]);
            }
            let domain_str = String::from_utf8_lossy(&domain).to_string();
            SocksAddr::Domain(domain_str, port)
        } else {
            let ip = std::net::Ipv4Addr::from(ip_bytes);
            SocksAddr::Ip(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                ip, port,
            )))
        };

        // Reply: VN=0, CD=90(Granted), DSTPORT, DSTIP
        let mut reply = BytesMut::new();
        reply.put_u8(0);
        reply.put_u8(90);
        reply.put_u16(port);
        reply.put_slice(&ip_bytes);
        stream.write_all(&reply).await?;

        sess.destination = destination;
        Ok(InboundTransport::Stream(stream, sess))
    }

    async fn handle_socks5(
        &self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let mut buf = BytesMut::new();

        // handle auth
        buf.resize(1, 0);
        // nmethods
        stream.read_exact(&mut buf[..]).await?;
        if buf[0] == 0 {
            return Err(io::Error::other(
                "no socks5 authentication method specified",
            ));
        }
        let nmethods = buf[0] as usize;
        buf.resize(nmethods, 0);
        // methods
        stream.read_exact(&mut buf[..]).await?;
        let mut method_accepted = false;
        let supported_method: u8 = if self.username.is_some() { 0x02 } else { 0x00 };

        for method in buf[..].iter() {
            if method == &supported_method {
                method_accepted = true;
                break;
            }
        }
        if !method_accepted {
            stream.write_all(&[0x05, 0xff]).await?;
            return Err(io::Error::other(format!(
                "unsupported socks5 authentication methods, client sent: {:?}, server expects: {}",
                &buf[..],
                supported_method
            )));
        }

        stream.write_all(&[0x05, supported_method]).await?;

        if supported_method == 0x02 {
            buf.resize(2, 0);
            // ver, ulen
            stream.read_exact(&mut buf[..]).await?;
            if buf[0] != 0x01 {
                return Err(io::Error::other(format!(
                    "unknown socks5 auth version {}",
                    buf[0]
                )));
            }
            let ulen = buf[1] as usize;
            buf.resize(ulen, 0);
            // uname
            stream.read_exact(&mut buf[..]).await?;
            let username = String::from_utf8_lossy(&buf).to_string();

            buf.resize(1, 0);
            // plen
            stream.read_exact(&mut buf[..]).await?;
            let plen = buf[0] as usize;
            buf.resize(plen, 0);
            // passwd
            stream.read_exact(&mut buf[..]).await?;
            let password = String::from_utf8_lossy(&buf).to_string();

            if self.username.as_ref().unwrap() == &username
                && self.password.as_ref().unwrap() == &password
            {
                stream.write_all(&[0x01, 0x00]).await?;
            } else {
                stream.write_all(&[0x01, 0x01]).await?;
                return Err(io::Error::other("socks5 authentication failed"));
            }
        }

        // handle request
        buf.resize(3, 0);
        // ver, cmd, rsv
        stream.read_exact(&mut buf[..]).await?;
        if buf[0] != 0x05 {
            // TODO reply?
            return Err(io::Error::other(format!(
                "unknown socks version {}",
                buf[0]
            )));
        }
        if buf[2] != 0x0 {
            // TODO reply?
            return Err(io::Error::other("non-zero socks5 reserved field"));
        }
        let cmd = buf[1];
        // connect, udp associate
        if cmd != 0x01 && cmd != 0x03 {
            // TODO reply?
            return Err(io::Error::other(format!("unsupported socks5 cmd {}", cmd)));
        }

        let destination = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;

        match cmd {
            0x01 => {
                // handle response
                buf.clear();
                buf.put_u8(0x05); // version 5
                buf.put_u8(0x0); // succeeded
                buf.put_u8(0x0); // rsv
                let resp_addr = SocksAddr::any();
                resp_addr.write_buf(&mut buf, SocksAddrWireType::PortLast);
                stream.write_all(&buf[..]).await?;
                sess.destination = destination;
                Ok(InboundTransport::Stream(stream, sess))
            }
            0x03 => {
                buf.clear();
                buf.put_u8(0x05); // version 5
                buf.put_u8(0x0); // succeeded
                buf.put_u8(0x0); // rsv
                let relay_addr = SocksAddr::from(sess.local_addr);
                relay_addr.write_buf(&mut buf, SocksAddrWireType::PortLast);
                stream.write_all(&buf[..]).await?;
                tokio::spawn(async move {
                    let mut buf = [0u8; 1];
                    // TODO explicitly drop resources allocated above before waiting?
                    // if stream.read_exact(&mut buf).await.is_err() {
                    //     // perhaps explicitly notifies the NAT manager?
                    //     debug!("udp association end");
                    // }
                    if let Err(e) = stream.read_exact(&mut buf).await {
                        // perhaps explicitly notifies the NAT manager?
                        debug!("udp association end: {}", e);
                    }
                });
                Ok(InboundTransport::Empty)
            }
            _ => Err(io::Error::other("invalid cmd")),
        }
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream session: {:?}", sess);
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;
        match buf[0] {
            0x04 => self.handle_socks4(sess, stream).await,
            0x05 => self.handle_socks5(sess, stream).await,
            v => Err(io::Error::other(format!("unknown socks version {}", v))),
        }
    }
}
