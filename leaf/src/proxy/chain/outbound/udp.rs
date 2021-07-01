use std::convert::TryFrom;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    app::SyncDnsClient,
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundHandler, OutboundTransport, ProxyStream,
        SimpleOutboundDatagram, TcpConnector, TcpOutboundHandler, UdpConnector, UdpOutboundHandler,
        DatagramTransportType,
    },
    session::{Session, SocksAddr},
};

fn invalid_chain(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid chain: {}", reason),
    )
}

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub dns_client: SyncDnsClient,
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
        if let Some(OutboundConnect::Proxy(address, port, _)) = self.next_connect_addr(start) {
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
                if self.is_udp_chain(i) {
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

impl TcpConnector for Handler {}
impl UdpConnector for Handler {}

#[async_trait]
impl UdpOutboundHandler for Handler {
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
        transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        match transport {
            Some(transport) => match transport {
                OutboundTransport::Datagram(dgram) => self.handle(sess, None, Some(dgram)).await,
                OutboundTransport::Stream(stream) => self.handle(sess, Some(stream), None).await,
            },
            None => {
                let init_transport_type = if self.is_udp_chain(0) {
                    DatagramTransportType::Datagram
                } else {
                    DatagramTransportType::Stream
                };
                let init_connect_addr = self.next_connect_addr(0);
                match init_connect_addr {
                    Some(OutboundConnect::Proxy(address, port, bind_addr)) => {
                        match init_transport_type {
                            DatagramTransportType::Datagram => {
                                let socket = self.new_udp_socket(&bind_addr, &sess.source).await?;
                                let dgram: Option<Box<dyn OutboundDatagram>> =
                                    Some(Box::new(SimpleOutboundDatagram::new(
                                        socket,
                                        None,
                                        self.dns_client.clone(),
                                        bind_addr,
                                    )));
                                self.handle(sess, None, dgram).await
                            }
                            DatagramTransportType::Stream => {
                                let stream = Some(
                                    self.new_tcp_stream(
                                        self.dns_client.clone(),
                                        &bind_addr,
                                        &address,
                                        &port,
                                    )
                                    .await?,
                                );
                                self.handle(sess, stream, None).await
                            }
                            _ => Err(invalid_chain("unknown UDP transport type")),
                        }
                    }
                    Some(OutboundConnect::Direct(_)) => {
                        unimplemented!("chain outbound direct connect addr");
                    }
                    Some(OutboundConnect::NoConnect) => self.handle(sess, None, None).await,
                    None => Err(invalid_chain("none initial connect address")),
                }
            }
        }
    }
}
