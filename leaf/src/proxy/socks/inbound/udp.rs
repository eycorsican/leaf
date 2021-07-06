use std::cmp::min;
use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use log::*;

use crate::{
    proxy::*,
    session::{DatagramSource, SocksAddr, SocksAddrWireType},
};

pub struct Handler;

#[async_trait]
impl UdpInboundHandler for Handler {
    type UStream = AnyStream;
    type UDatagram = AnyInboundDatagram;

    async fn handle<'a>(
        &'a self,
        socket: Self::UDatagram,
    ) -> io::Result<InboundTransport<Self::UStream, Self::UDatagram>> {
        Ok(InboundTransport::Datagram(Box::new(Datagram { socket })))
    }
}

pub struct Datagram {
    socket: Box<dyn InboundDatagram>,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (rh, sh) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(rh)),
            Box::new(DatagramSendHalf(sh)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        self.socket.into_std()
    }
}

pub struct DatagramRecvHalf(Box<dyn InboundDatagramRecvHalf>);

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, DatagramSource, Option<SocksAddr>)> {
        let mut recv_buf = [0u8; 2 * 1024];
        let (n, src_addr, _) = self.0.recv_from(&mut recv_buf).await?;
        if n < 3 {
            warn!("short socks5 udp pkt");
            return Ok((0, src_addr, None));
        }
        let dst_addr = match SocksAddr::try_from((&recv_buf[3..], SocksAddrWireType::PortLast)) {
            Ok(v) => v,
            Err(e) => {
                warn!("read addr from socks5 message failed: {}", e);
                return Ok((0, src_addr, None));
            }
        };
        let header_size = 3 + dst_addr.size();
        let payload_size = n - header_size;
        let to_recv = min(buf.len(), payload_size);
        if to_recv < payload_size {
            warn!("truncated pkt");
        }
        (&mut buf[..to_recv]).copy_from_slice(&recv_buf[header_size..header_size + to_recv]);
        Ok((payload_size, src_addr, Some(dst_addr)))
    }
}

pub struct DatagramSendHalf(Box<dyn InboundDatagramSendHalf>);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: Option<&SocksAddr>,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let mut send_buf = BytesMut::new();
        send_buf.put_u16(0);
        send_buf.put_u8(0);

        if let Some(src_addr) = src_addr {
            src_addr.write_buf(&mut send_buf, SocksAddrWireType::PortLast)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "sending message without source",
            ));
        }

        send_buf.put_slice(buf);
        self.0.send_to(&send_buf[..], None, dst_addr).await
    }
}
