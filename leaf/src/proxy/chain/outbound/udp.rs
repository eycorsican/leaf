use std::convert::TryFrom;
use std::io;

use async_trait::async_trait;

use crate::{
    proxy::*,
    session::{Session, SocksAddr},
};

fn invalid_chain(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid chain: {}", reason),
    )
}

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
}

impl Handler {
    fn next_connect_addr(&self, start: usize) -> Option<OutboundConnect> {
        for i in start..self.actors.len() {
            if let Some(addr) = UdpOutboundHandler::connect_addr(self.actors[i].as_ref()) {
                return Some(addr);
            }
        }
        None
    }

    fn next_session(&self, mut sess: Session, start: usize) -> Session {
        if let Some(OutboundConnect::Proxy(address, port)) = self.next_connect_addr(start) {
            if let Ok(addr) = SocksAddr::try_from((address, port)) {
                sess.destination = addr;
            }
        }
        sess
    }

    fn is_udp_chain(&self, start: usize) -> bool {
        for i in start..self.actors.len() {
            if self.actors[i].transport_type() != DatagramTransportType::Datagram {
                return false;
            }
        }
        true
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        mut stream: Option<Box<dyn ProxyStream>>,
        mut dgram: Option<Box<dyn OutboundDatagram>>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        for (i, a) in self.actors.iter().enumerate() {
            let new_sess = self.next_session(sess.clone(), i + 1);

            // Handle the final actor. We're handling UDP traffic, if we're given
            // a stream, this is our last chance to convert it to a datagram.
            if i == self.actors.len() - 1 {
                if let Some(d) = dgram.take() {
                    return UdpOutboundHandler::handle(
                        a.as_ref(),
                        &new_sess,
                        Some(OutboundTransport::Datagram(d)),
                    )
                    .await;
                } else if let Some(s) = stream.take() {
                    return UdpOutboundHandler::handle(
                        a.as_ref(),
                        &new_sess,
                        Some(OutboundTransport::Stream(s)),
                    )
                    .await;
                } else {
                    return Err(invalid_chain("neither stream nor datagram exists"));
                }
            }

            if let Some(s) = stream.take() {
                // Got a stream, check if we can convert it to a datagram.
                if self.is_udp_chain(i + 1) {
                    dgram.replace(
                        UdpOutboundHandler::handle(
                            a.as_ref(),
                            &new_sess,
                            Some(OutboundTransport::Stream(s)),
                        )
                        .await?,
                    );
                } else {
                    stream
                        .replace(TcpOutboundHandler::handle(a.as_ref(), &new_sess, Some(s)).await?);
                }
            } else if let Some(d) = dgram.take() {
                // Got a datagram, it can not be converted to stream and it can
                // only be handled by a UDP handler.
                dgram.replace(
                    UdpOutboundHandler::handle(
                        a.as_ref(),
                        &new_sess,
                        Some(OutboundTransport::Datagram(d)),
                    )
                    .await?,
                );
            } else {
                // NoConnect handlers such as amux.
                stream.replace(TcpOutboundHandler::handle(a.as_ref(), &new_sess, None).await?);
            }
        }
        unreachable!();
    }
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        for a in self.actors.iter() {
            if let Some(addr) = UdpOutboundHandler::connect_addr(a.as_ref()) {
                return Some(addr);
            }
        }
        None
    }

    fn transport_type(&self) -> DatagramTransportType {
        for a in self.actors.iter() {
            if a.transport_type() == DatagramTransportType::Stream {
                return DatagramTransportType::Stream;
            }
        }
        DatagramTransportType::Datagram
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        match transport {
            Some(transport) => match transport {
                OutboundTransport::Datagram(dgram) => self.handle(sess, None, Some(dgram)).await,
                OutboundTransport::Stream(stream) => self.handle(sess, Some(stream), None).await,
            },
            None => match self.next_connect_addr(0) {
                Some(OutboundConnect::NoConnect) => self.handle(sess, None, None).await,
                _ => Err(invalid_chain("invalid transport")),
            },
        }
    }
}
