use std::io;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tracing::debug;

use super::Group;
use crate::{
    app::SyncDnsClient,
    proxy::*,
    session::{Session, SocksAddr},
};

/// UDP has no handshake to judge: a session goes to the first up actor (the
/// TCP-derived state); an actor that fails to set it up or to send counts a
/// failure.
pub struct Handler {
    actors: Vec<AnyOutboundHandler>,
    group: Arc<Group>,
    dns_client: SyncDnsClient,
}

impl Handler {
    pub fn new(
        actors: Vec<AnyOutboundHandler>,
        group: Arc<Group>,
        dns_client: SyncDnsClient,
    ) -> Self {
        Self {
            actors,
            group,
            dns_client,
        }
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let deadline = tokio::time::Instant::now() + self.group.params().timeout;
        let mut last_err = None;
        for idx in self.group.udp_order() {
            let a = &self.actors[idx];
            // An actor without UDP is no verdict on its health.
            let Ok(h) = a.datagram() else { continue };
            let attempt = async {
                let transport = connect_datagram_outbound(sess, self.dns_client.clone(), a).await?;
                h.handle(sess, transport).await
            };
            match tokio::time::timeout_at(deadline, attempt).await {
                Ok(Ok(d)) => {
                    debug!(
                        "standby [{}] handles [{}:{}] to [{}]",
                        self.group.tag(),
                        sess.network,
                        sess.destination,
                        a.tag()
                    );
                    return Ok(Box::new(Datagram {
                        inner: d,
                        group: self.group.clone(),
                        idx,
                        epoch: self.group.epoch(),
                    }));
                }
                Ok(Err(e)) => {
                    let r = format!("udp: {:?}", e.kind());
                    self.group.failure(idx, Instant::now(), true, &r);
                    last_err = Some(e);
                }
                Err(_) => {
                    self.group
                        .failure(idx, Instant::now(), true, "udp: timeout");
                    break;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::other(format!("standby [{}]: no actor for udp", self.group.tag()))
        }))
    }
}

struct Datagram {
    inner: AnyOutboundDatagram,
    group: Arc<Group>,
    idx: usize,
    epoch: u64,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, s) = self.inner.split();
        (
            r,
            Box::new(SendHalf {
                inner: s,
                group: self.group,
                idx: self.idx,
                epoch: self.epoch,
                failed: false,
            }),
        )
    }
}

/// Counts the first send error of the session as a failure.
struct SendHalf {
    inner: Box<dyn OutboundDatagramSendHalf>,
    group: Arc<Group>,
    idx: usize,
    /// No report after a network switch.
    epoch: u64,
    failed: bool,
}

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        let r = self.inner.send_to(buf, dst_addr).await;
        if let Err(e) = &r {
            if !self.failed && self.group.epoch() == self.epoch {
                self.failed = true;
                let reason = format!("udp send: {:?}", e.kind());
                self.group.failure(self.idx, Instant::now(), false, &reason);
            }
        }
        r
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}
