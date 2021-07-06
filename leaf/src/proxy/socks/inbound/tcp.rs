use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use log::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

pub struct Handler;

#[async_trait]
impl TcpInboundHandler for Handler {
    type TStream = AnyStream;
    type TDatagram = AnyInboundDatagram;

    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: Self::TStream,
    ) -> std::io::Result<InboundTransport<Self::TStream, Self::TDatagram>> {
        let mut buf = BytesMut::with_capacity(1024);

        // handle auth
        buf.resize(2, 0);
        // ver, nmethods
        if let Err(e) = stream.read_exact(&mut buf[..]).await {
            debug!("read ver, nmethods failed: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        };
        if buf[0] != 0x05 {
            warn!("unknown socks version {}", buf[0]);
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        }
        if buf[1] == 0 {
            warn!("no socks5 authentication method specified");
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        }
        let nmethods = buf[1] as usize;
        buf.resize(nmethods, 0);
        // methods
        if let Err(e) = stream.read_exact(&mut buf[..]).await {
            debug!("read methods failed: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        };
        let mut method_accepted = false;
        let mut method_idx: u8 = 0;
        let supported_method: u8 = 0x0;
        for (idx, method) in buf[..].iter().enumerate() {
            if method == &supported_method {
                method_accepted = true;
                method_idx = idx as u8;
                break;
            }
        }
        if !method_accepted {
            warn!("unsupported socks5 authentication methods");
            if let Err(e) = stream.write_all(&[0x05, 0xff]).await {
                debug!("write auth response failed: {}", e);
            };
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        } else if let Err(e) = stream.write_all(&[0x05, method_idx]).await {
            debug!("write auth response failed: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        };

        // handle request
        buf.resize(3, 0);
        // ver, cmd, rsv
        if let Err(e) = stream.read_exact(&mut buf[..]).await {
            debug!("read request failed: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        };
        if buf[0] != 0x05 {
            warn!("unknown socks version {}", buf[0]);
            // TODO reply?
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        }
        if buf[2] != 0x0 {
            warn!("non-zero socks5 reserved field");
            // TODO reply?
            return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
        }
        let cmd = buf[1];
        match cmd {
            // connect
            0x01 => {}
            // udp associate
            0x03 => {}
            _ => {
                warn!("unsupported socks5 cmd {}", cmd);
                // TODO reply?
                return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
            }
        }
        let destination = match SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await
        {
            Ok(v) => v,
            Err(e) => {
                debug!("read address failed: {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
            }
        };

        match cmd {
            0x01 => {
                // handle response
                buf.clear();
                buf.put_u8(0x05); // version 5
                buf.put_u8(0x0); // succeeded
                buf.put_u8(0x0); // rsv
                let resp_addr = SocksAddr::any();
                if let Err(e) = resp_addr.write_buf(&mut buf, SocksAddrWireType::PortLast) {
                    debug!("write address buffer: {}", e);
                    return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
                };
                if let Err(e) = stream.write_all(&buf[..]).await {
                    debug!("write response failed: {}", e);
                    return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
                };

                sess.destination = destination;

                Ok(InboundTransport::Stream(stream, sess))
            }
            0x03 => {
                buf.clear();
                buf.put_u8(0x05); // version 5
                buf.put_u8(0x0); // succeeded
                buf.put_u8(0x0); // rsv
                let relay_addr = SocksAddr::from(sess.local_addr);
                if let Err(e) = relay_addr.write_buf(&mut buf, SocksAddrWireType::PortLast) {
                    debug!("write address buffer: {}", e);
                    return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
                };
                if let Err(e) = stream.write_all(&buf[..]).await {
                    debug!("write response failed: {}", e);
                    return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
                };
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
            _ => Err(io::Error::new(io::ErrorKind::Other, "invalid cmd")),
        }
    }
}
