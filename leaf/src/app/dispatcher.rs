use std::convert::TryFrom;
use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use async_recursion::async_recursion;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::{
    app::SyncDnsClient,
    common::{self, sniff},
    option,
    proxy::*,
    session::*,
};

use tokio::io::AsyncWriteExt;

async fn healthcheck_respond_simple<T>(stream: &mut T) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    stream.write_all(b"PONG").await?;
    stream.flush().await?;
    Ok(())
}

use crate::app::SyncStatManager;

use super::outbound::manager::OutboundManager;
use super::router::Router;

struct HealthcheckUdpRecvHalf {
    responded: bool,
    src_addr: SocksAddr,
}

#[async_trait::async_trait]
impl OutboundDatagramRecvHalf for HealthcheckUdpRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        if self.responded {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no more data"));
        }
        let pong = b"PONG";
        if buf.len() < pong.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "buffer too small"));
        }
        buf[..pong.len()].copy_from_slice(pong);
        self.responded = true;
        Ok((pong.len(), self.src_addr.clone()))
    }
}

struct HealthcheckUdpSendHalf;

#[async_trait::async_trait]
impl OutboundDatagramSendHalf for HealthcheckUdpSendHalf {
    async fn send_to(&mut self, buf: &[u8], _dst_addr: &SocksAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HealthcheckUdpDatagram {
    recv: HealthcheckUdpRecvHalf,
    send: HealthcheckUdpSendHalf,
}

impl OutboundDatagram for HealthcheckUdpDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

#[inline]
fn log_request(
    sess: &Session,
    outbound_tag: &str,
    outbound_tag_color: &colored::Color,
    handshake_time: Option<u128>,
) {
    let hs = handshake_time.map_or("failed".to_string(), |hs| format!("{}ms", hs));
    let (network, outbound_tag) = if !*crate::option::LOG_NO_COLOR {
        use colored::Colorize;
        let network_color = match sess.network {
            Network::Tcp => colored::Color::Blue,
            Network::Udp => colored::Color::Yellow,
        };
        (
            sess.network.to_string().color(network_color).to_string(),
            outbound_tag.color(*outbound_tag_color).to_string(),
        )
    } else {
        (sess.network.to_string(), outbound_tag.to_string())
    };

    #[cfg(feature = "rule-process-name")]
    {
        let process_name = sess
            .process_name
            .as_ref()
            .map(|x| {
                std::path::Path::new(x)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(x)
            })
            .unwrap_or("");
        info!(
            "[{}] [{}] [{}] [{}] [{}] [{}] [{}]",
            process_name,
            sess.forwarded_source.unwrap_or_else(|| sess.source.ip()),
            network,
            &sess.inbound_tag,
            outbound_tag,
            hs,
            &sess.destination,
        );
    }

    #[cfg(not(feature = "rule-process-name"))]
    {
        info!(
            "[{}] [{}] [{}] [{}] [{}] [{}]",
            sess.forwarded_source.unwrap_or_else(|| sess.source.ip()),
            network,
            &sess.inbound_tag,
            outbound_tag,
            hs,
            &sess.destination,
        );
    }
}

pub struct Dispatcher {
    outbound_manager: Arc<RwLock<OutboundManager>>,
    router: Arc<RwLock<Router>>,
    dns_client: SyncDnsClient,
    stat_manager: SyncStatManager,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: Arc<RwLock<OutboundManager>>,
        router: Arc<RwLock<Router>>,
        dns_client: SyncDnsClient,
        stat_manager: SyncStatManager,
    ) -> Self {
        Dispatcher {
            outbound_manager,
            router,
            dns_client,
            stat_manager,
        }
    }

    pub async fn dispatch_stream<T>(&self, mut sess: Session, mut lhs: T)
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        debug!("dispatching {}:{}", &sess.network, &sess.destination);

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.leaf" {
                if let Err(e) = healthcheck_respond_simple(&mut lhs).await {
                    debug!("healthcheck response failed: {}", e);
                }
                return;
            }
        }

        let mut lhs: Box<dyn ProxyStream> = if sniff::should_sniff(&sess) {
            let mut lhs = sniff::SniffingStream::new(lhs);
            match lhs.sniff(&sess).await {
                Ok(res) => {
                    if let Some(domain) = res {
                        debug!(
                            "sniffed domain {} for tcp link {} <-> {}",
                            &domain, &sess.source, &sess.destination,
                        );
                        // TODO Add an option to use the sniffed domain for routing only
                        //
                        // TODO Add DNS sniff, sniff domain name from DNS response, keep
                        // an IP -> domain mapping, use this info for routing only.
                        sess.destination =
                            match SocksAddr::try_from((&domain, sess.destination.port())) {
                                Ok(a) => a,
                                Err(e) => {
                                    warn!(
                                        "convert sniffed domain {} to destination failed: {}",
                                        &domain, e,
                                    );
                                    return;
                                }
                            };
                    }
                }
                Err(e) => {
                    debug!(
                        "sniff tcp uplink {} -> {} failed: {}",
                        &sess.source, &sess.destination, e,
                    );
                    return;
                }
            }
            Box::new(lhs)
        } else {
            Box::new(lhs)
        };

        let outbound = {
            let router = self.router.read().await;
            match router.pick_route(&sess).await {
                Ok(tag) => {
                    debug!(
                        "picked route [{}] for {} -> {}",
                        tag, &sess.source, &sess.destination
                    );
                    tag.to_owned()
                }
                Err(err) => {
                    debug!("pick route failed: {}", err);
                    if let Some(tag) = self.outbound_manager.read().await.default_handler() {
                        debug!(
                            "picked default route [{}] for {} -> {}",
                            tag, &sess.source, &sess.destination
                        );
                        tag
                    } else {
                        warn!("can not find any handlers");
                        return;
                    }
                }
            }
        };

        sess.outbound_tag = outbound.clone();

        let h = if let Some(h) = self.outbound_manager.read().await.get(&outbound) {
            h
        } else {
            // FIXME use  the default handler
            warn!("handler not found");
            return;
        };
        debug!(
            "handling {}:{} with {}",
            &sess.network,
            &sess.destination,
            h.tag()
        );

        let handshake_start = tokio::time::Instant::now();
        let stream =
            match crate::proxy::connect_stream_outbound(&sess, self.dns_client.clone(), &h).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(
                        "dispatch tcp {} -> {} to [{}] failed: {}",
                        &sess.source,
                        &sess.destination,
                        &h.tag(),
                        e
                    );
                    log_request(&sess, h.tag(), h.color(), None);
                    return;
                }
            };
        let th = match h.stream() {
            Ok(th) => th,
            Err(e) => {
                warn!(
                    "dispatch tcp {} -> {} to [{}] failed: {}",
                    &sess.source,
                    &sess.destination,
                    &h.tag(),
                    e
                );
                return;
            }
        };
        match th.handle(&sess, Some(&mut lhs), stream).await {
            Ok(mut rhs) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                log_request(&sess, h.tag(), h.color(), Some(elapsed.as_millis()));

                rhs = self
                    .stat_manager
                    .write()
                    .await
                    .stat_stream(rhs, sess.clone());

                match common::io::copy_buf_bidirectional_with_timeout(
                    &mut lhs,
                    &mut rhs,
                    *option::LINK_BUFFER_SIZE * 1024,
                    Duration::from_secs(*option::TCP_UPLINK_TIMEOUT),
                    Duration::from_secs(*option::TCP_DOWNLINK_TIMEOUT),
                )
                .await
                {
                    Ok((up_count, down_count)) => {
                        debug!(
                            "tcp link {} <-> {} done, ({}, {}) bytes transferred [{}]",
                            &sess.source,
                            &sess.destination,
                            up_count,
                            down_count,
                            &h.tag(),
                        );
                    }
                    Err(e) => {
                        debug!(
                            "tcp link {} <-> {} error: {} [{}]",
                            &sess.source,
                            &sess.destination,
                            e,
                            &h.tag()
                        );
                    }
                }
            }
            Err(e) => {
                debug!(
                    "dispatch tcp {} -> {} to [{}] failed: {}",
                    &sess.source,
                    &sess.destination,
                    &h.tag(),
                    e
                );
                log_request(&sess, h.tag(), h.color(), None);
            }
        }
    }

    #[async_recursion]
    pub async fn dispatch_datagram(
        &self,
        mut sess: Session,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        debug!("dispatching {}:{}", &sess.network, &sess.destination);

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.leaf" {
                let recv = HealthcheckUdpRecvHalf {
                    responded: false,
                    src_addr: sess.destination.clone(),
                };
                let d = HealthcheckUdpDatagram {
                    recv,
                    send: HealthcheckUdpSendHalf,
                };
                let d: Box<dyn OutboundDatagram> = Box::new(d);
                return Ok(d);
            }
        }

        let outbound = {
            let router = self.router.read().await;
            match router.pick_route(&sess).await {
                Ok(tag) => {
                    debug!(
                        "picked route [{}] for {} -> {}",
                        tag, &sess.source, &sess.destination
                    );
                    tag.to_owned()
                }
                Err(err) => {
                    debug!("pick route failed: {}", err);
                    if let Some(tag) = self.outbound_manager.read().await.default_handler() {
                        debug!(
                            "picked default route [{}] for {} -> {}",
                            tag, &sess.source, &sess.destination
                        );
                        tag
                    } else {
                        warn!("no handler found");
                        return Err(io::Error::new(ErrorKind::Other, "no available handler"));
                    }
                }
            }
        };

        sess.outbound_tag = outbound.clone();

        let h = if let Some(h) = self.outbound_manager.read().await.get(&outbound) {
            h
        } else {
            warn!("handler not found");
            return Err(io::Error::new(ErrorKind::Other, "handler not found"));
        };

        let handshake_start = tokio::time::Instant::now();
        let transport =
            crate::proxy::connect_datagram_outbound(&sess, self.dns_client.clone(), &h).await?;
        debug!(
            "handling {}:{} with {}",
            &sess.network,
            &sess.destination,
            h.tag()
        );
        match h.datagram()?.handle(&sess, transport).await {
            #[allow(unused_mut)]
            Ok(mut d) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                log_request(&sess, h.tag(), h.color(), Some(elapsed.as_millis()));

                d = self
                    .stat_manager
                    .write()
                    .await
                    .stat_outbound_datagram(d, sess.clone());

                Ok(d)
            }
            Err(e) => {
                debug!(
                    "dispatch udp {} -> {} to [{}] failed: {}",
                    &sess.source,
                    &sess.destination,
                    &h.tag(),
                    e
                );
                log_request(&sess, h.tag(), h.color(), None);
                Err(e)
            }
        }
    }
}
