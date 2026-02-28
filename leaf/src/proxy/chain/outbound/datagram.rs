use std::convert::TryFrom;
use std::io;

use async_trait::async_trait;
use tracing::{trace, Instrument};

use crate::{proxy::*, session::*};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
}

impl Handler {
    fn next_connect_addr(&self, start: usize) -> OutboundConnect {
        for a in self.actors[start..].iter() {
            match a.datagram() {
                Ok(h) => {
                    if self.unreliable_chain(start + 1) {
                        let oc = h.connect_addr();
                        if let OutboundConnect::Next = oc {
                            continue;
                        }
                        return oc;
                    } else if let Ok(h) = a.stream() {
                        let oc = h.connect_addr();
                        if let OutboundConnect::Next = oc {
                            continue;
                        }
                        return oc;
                    }
                }
                _ => {
                    if let Ok(h) = a.stream() {
                        let oc = h.connect_addr();
                        if let OutboundConnect::Next = oc {
                            continue;
                        }
                        return oc;
                    }
                }
            }
        }
        OutboundConnect::Unknown
    }

    fn next_session(&self, mut sess: Session, start: usize) -> Session {
        if let OutboundConnect::Proxy(_, address, port) = self.next_connect_addr(start) {
            if let Ok(addr) = SocksAddr::try_from((address, port)) {
                sess.destination = addr;
                sess.dns_sniffed_domain = None;
                sess.http_sniffed_domain = None;
                sess.tls_sniffed_domain = None;
            }
        }
        sess
    }

    fn unreliable_chain(&self, start: usize) -> bool {
        for a in self.actors[start..].iter() {
            if let Ok(uh) = a.datagram() {
                if uh.transport_type() != DatagramTransportType::Unreliable {
                    return false;
                }
            } else {
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

            trace!("handle actor idx={} tag={}", i, a.tag());

            if let Ok(uh) = a.datagram() {
                trace!("has datagram");
                if let Some(d) = dgram.take() {
                    dgram.replace(
                        uh.handle(&new_sess, Some(OutboundTransport::Datagram(d)))
                            .instrument(tracing::Span::current())
                            .await?,
                    );
                } else if let Some(s) = stream.take() {
                    trace!("has input stream");
                    // Check whether all subsequent handlers can use unreliable
                    // transport, otherwise we must not convert the stream to
                    // a datagram.
                    if self.unreliable_chain(i + 1) {
                        trace!("unreliable chain");
                        dgram.replace(
                            uh.handle(&new_sess, Some(OutboundTransport::Stream(s)))
                                .instrument(tracing::Span::current())
                                .await?,
                        );
                    } else {
                        trace!("reliable chain");
                        stream.replace(
                            a.stream()?
                                .handle(&new_sess, None, Some(s))
                                .instrument(tracing::Span::current())
                                .await?,
                        );
                    }
                } else if self.unreliable_chain(i + 1) {
                    trace!("unreliable chain fallback");
                    dgram.replace(
                        uh.handle(&new_sess, None)
                            .instrument(tracing::Span::current())
                            .await?,
                    );
                } else {
                    trace!("reliable chain");
                    stream.replace(
                        a.stream()?
                            .handle(&new_sess, None, None)
                            .instrument(tracing::Span::current())
                            .await?,
                    );
                }
            } else {
                trace!("no datagram, use stream");
                let s = stream.take();
                stream.replace(
                    a.stream()?
                        .handle(&new_sess, None, s)
                        .instrument(tracing::Span::current())
                        .await?,
                );
            }
        }
        dgram.ok_or_else(|| io::Error::other("no datagram"))
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        self.next_connect_addr(0)
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.actors
            .first()
            .map(|x| {
                x.datagram()
                    .map(|x| x.transport_type())
                    .unwrap_or(DatagramTransportType::Unknown)
            })
            .unwrap_or(DatagramTransportType::Unknown)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        match transport {
            Some(transport) => match transport {
                OutboundTransport::Datagram(dgram) => {
                    trace!("datagram transport");
                    self.handle(sess, None, Some(dgram))
                        .instrument(tracing::Span::current())
                        .await
                }
                OutboundTransport::Stream(stream) => {
                    trace!("stream transport");
                    self.handle(sess, Some(stream), None)
                        .instrument(tracing::Span::current())
                        .await
                }
            },
            None => {
                trace!("stream=None, datagram=None");
                self.handle(sess, None, None)
                    .instrument(tracing::Span::current())
                    .await
            }
        }
    }
}
