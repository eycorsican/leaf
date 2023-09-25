use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug};

use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

pub struct Handler;

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let mut buf = BytesMut::new();

        // handle auth
        buf.resize(2, 0);
        // ver, nmethods
        stream.read_exact(&mut buf[..]).await?;
        if buf[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unknown socks version {}", buf[0]),
            ));
        }
        if buf[1] == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("no socks5 authentication method specified"),
            ));
        }
        let nmethods = buf[1] as usize;
        buf.resize(nmethods, 0);
        // methods
        stream.read_exact(&mut buf[..]).await?;
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
            stream.write_all(&[0x05, 0xff]).await?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unsupported socks5 authentication methods"),
            ));
        }

        stream.write_all(&[0x05, method_idx]).await?;

        // handle request
        buf.resize(3, 0);
        // ver, cmd, rsv
        stream.read_exact(&mut buf[..]).await?;
        if buf[0] != 0x05 {
            // TODO reply?
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unknown socks version {}", buf[0]),
            ));
        }
        if buf[2] != 0x0 {
            // TODO reply?
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("non-zero socks5 reserved field"),
            ));
        }
        let cmd = buf[1];
        // connect, udp associate
        if cmd != 0x01 && cmd != 0x03 {
            // TODO reply?
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unsupported socks5 cmd {}", cmd),
            ));
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
            _ => Err(io::Error::new(io::ErrorKind::Other, "invalid cmd")),
        }
    }
}
