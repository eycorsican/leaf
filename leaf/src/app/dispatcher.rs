use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::future::{self, Either};
use log::*;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[cfg(not(target_os = "ios"))]
use colored::Colorize;

use crate::{
    // common::stream,
    option,
    proxy::{OutboundDatagram, ProxyHandlerType},
    session::{Session, SocksAddr},
};

use super::outbound::manager::OutboundManager;
use super::router::Router;

#[inline]
fn log_tcp(
    inbound_tag: &str,
    outbound_tag: &str,
    outbound_tag_color: colored::Color,
    handshake_time: u128,
    addr: &SocksAddr,
) {
    #[cfg(not(target_os = "ios"))]
    {
        info!(
            "[{}] [{}] [{}] [{}ms] {}",
            inbound_tag,
            "tcp".color(colored::Color::Blue),
            outbound_tag.color(outbound_tag_color),
            handshake_time,
            addr,
        );
    }
    #[cfg(target_os = "ios")]
    {
        info!(
            "[{}] [{}] [{}] [{}ms] {}",
            "tcp", inbound_tag, outbound_tag, handshake_time, addr
        );
    }
}

#[inline]
fn log_udp(
    inbound_tag: &str,
    outbound_tag: &str,
    outbound_tag_color: colored::Color,
    handshake_time: u128,
    addr: &SocksAddr,
) {
    #[cfg(not(target_os = "ios"))]
    {
        info!(
            "[{}] [{}] [{}] [{}ms] {}",
            inbound_tag,
            "udp".color(colored::Color::Yellow),
            outbound_tag.color(outbound_tag_color),
            handshake_time,
            addr,
        );
    }
    #[cfg(target_os = "ios")]
    {
        info!(
            "[{}] [{}] [{}] [{}ms] {}",
            "udp", inbound_tag, outbound_tag, handshake_time, addr
        );
    }
}

pub struct Dispatcher {
    outbound_manager: OutboundManager,
    router: Router,
    endpoint_tcp_sem: Semaphore,
    direct_tcp_sem: Semaphore,
    num_endpoint_tcp: AtomicUsize,
    num_direct_tcp: AtomicUsize,
}

impl Dispatcher {
    pub fn new(outbound_manager: OutboundManager, router: Router) -> Self {
        Dispatcher {
            outbound_manager,
            router,
            endpoint_tcp_sem: Semaphore::new(option::ENDPOINT_TCP_CONCURRENCY),
            direct_tcp_sem: Semaphore::new(option::DIRECT_TCP_CONCURRENCY),
            num_endpoint_tcp: AtomicUsize::new(0),
            num_direct_tcp: AtomicUsize::new(0),
        }
    }

    async fn dispatch_endpoint_tcp_start(&self) {
        self.endpoint_tcp_sem.acquire().await.forget();
        let pn = self.num_endpoint_tcp.fetch_add(1, Ordering::SeqCst);
        trace!("active proxied tcp connections +1: {}", pn + 1);
    }

    fn dispatch_endpoint_tcp_done(&self) {
        self.endpoint_tcp_sem.add_permits(1);
        let pn = self.num_endpoint_tcp.fetch_sub(1, Ordering::SeqCst);
        trace!("active proxied tcp connections -1: {}", pn - 1)
    }

    async fn dispatch_direct_tcp_start(&self) {
        self.direct_tcp_sem.acquire().await.forget();
        let pn = self.num_direct_tcp.fetch_add(1, Ordering::SeqCst);
        trace!("active direct tcp connections +1: {}", pn + 1);
    }

    fn dispatch_direct_tcp_done(&self) {
        self.direct_tcp_sem.add_permits(1);
        let pn = self.num_direct_tcp.fetch_sub(1, Ordering::SeqCst);
        trace!("active direct tcp connections -1: {}", pn - 1)
    }

    pub async fn dispatch_tcp<T>(&self, sess: &mut Session, lhs: T) -> io::Result<()>
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        // let lhs: Box<dyn ProxyStream> =
        //     if sess.destination.is_domain() && sess.destination.port() == 443 {
        //         Box::new(SimpleProxyStream(lhs))
        //     } else {
        //         let mut lhs = stream::SniffingStream::new(lhs);
        //         if let Some(domain) = lhs.sniff().await? {
        //             debug!("sniffed domain {}", &domain);
        //             sess.destination = SocksAddr::from((domain, sess.destination.port()));
        //         }
        //         Box::new(SimpleProxyStream(lhs))
        //     };

        let outbound = match self.router.pick_route(&sess) {
            Ok(tag) => {
                debug!(
                    "picked route [{}] for {} -> {}",
                    tag, &sess.source, &sess.destination
                );
                tag
            }
            Err(err) => {
                trace!("pick route failed: {}", err);
                if let Some(tag) = self.outbound_manager.default_handler() {
                    debug!(
                        "picked default route [{}] for {} -> {}",
                        tag, &sess.source, &sess.destination
                    );
                    tag
                } else {
                    return Err(io::Error::new(ErrorKind::Other, "no available handler"));
                }
            }
        };

        let handshake_start = tokio::time::Instant::now();
        if let Some(h) = self.outbound_manager.get(outbound) {
            match h.handler_type() {
                ProxyHandlerType::Direct => self.dispatch_direct_tcp_start().await,
                ProxyHandlerType::Endpoint | ProxyHandlerType::Ensemble => {
                    self.dispatch_endpoint_tcp_start().await
                }
            }

            match h.handle_tcp(sess, None).await {
                Ok(rhs) => {
                    let elapsed = tokio::time::Instant::now().duration_since(handshake_start);
                    log_tcp(
                        &sess.inbound_tag,
                        h.tag(),
                        h.color(),
                        elapsed.as_millis(),
                        &sess.destination,
                    );

                    let (mut lr, mut lw) = tokio::io::split(lhs);
                    let (mut rr, mut rw) = tokio::io::split(rhs);

                    let l2r = tokio::io::copy(&mut lr, &mut rw);
                    let r2l = tokio::io::copy(&mut rr, &mut lw);

                    match future::select(l2r, r2l).await {
                        Either::Left((up_res, new_r2l)) => {
                            match up_res {
                                Ok(up_n) => {
                                    debug!(
                                        "tcp uplink {} -> {} done, {} bytes transfered [{}]",
                                        &sess.source,
                                        &sess.destination,
                                        up_n,
                                        &h.tag(),
                                    );
                                }
                                Err(up_e) => {
                                    debug!(
                                        "tcp uplink {} -> {} error: {} [{}]",
                                        &sess.source,
                                        &sess.destination,
                                        up_e,
                                        &h.tag()
                                    );
                                }
                            }

                            // FIXME run both shutdown and r2l in parallel?
                            rw.shutdown().await;

                            let timed_r2l =
                                timeout(Duration::from_secs(option::TCP_DOWNLINK_TIMEOUT), new_r2l);
                            match timed_r2l.await {
                                Ok(down_res) => match down_res {
                                    Ok(down_n) => {
                                        debug!(
                                            "tcp downlink {} <- {} done, {} bytes transfered [{}]",
                                            &sess.source,
                                            &sess.destination,
                                            down_n,
                                            &h.tag(),
                                        );
                                    }
                                    Err(down_e) => {
                                        debug!(
                                            "tcp downlink {} <- {} error: {} [{}]",
                                            &sess.source,
                                            &sess.destination,
                                            down_e,
                                            &h.tag()
                                        );
                                    }
                                },
                                Err(timeout_e) => {
                                    debug!(
                                        "tcp downlink {} <- {} timeout: {} [{}]",
                                        &sess.source,
                                        &sess.destination,
                                        timeout_e,
                                        &h.tag()
                                    );
                                }
                            }

                            lw.shutdown().await;
                        }
                        Either::Right((down_res, new_l2r)) => {
                            match down_res {
                                Ok(down_n) => {
                                    debug!(
                                        "tcp downlink {} <- {} done, {} bytes transfered [{}]",
                                        &sess.source,
                                        &sess.destination,
                                        down_n,
                                        &h.tag(),
                                    );
                                }
                                Err(down_e) => {
                                    debug!(
                                        "tcp downlink {} <- {} error: {} [{}]",
                                        &sess.source,
                                        &sess.destination,
                                        down_e,
                                        &h.tag()
                                    );
                                }
                            }

                            lw.shutdown().await;

                            let timed_l2r =
                                timeout(Duration::from_secs(option::TCP_UPLINK_TIMEOUT), new_l2r);
                            match timed_l2r.await {
                                Ok(up_res) => match up_res {
                                    Ok(up_n) => {
                                        debug!(
                                            "tcp uplink {} -> {} done, {} bytes transfered [{}]",
                                            &sess.source,
                                            &sess.destination,
                                            up_n,
                                            &h.tag(),
                                        );
                                    }
                                    Err(up_e) => {
                                        debug!(
                                            "tcp uplink {} -> {} error: {} [{}]",
                                            &sess.source,
                                            &sess.destination,
                                            up_e,
                                            &h.tag()
                                        );
                                    }
                                },
                                Err(timeout_e) => {
                                    debug!(
                                        "tcp uplink {} -> {} timeout: {} [{}]",
                                        &sess.source,
                                        &sess.destination,
                                        timeout_e,
                                        &h.tag()
                                    );
                                }
                            }

                            rw.shutdown().await;
                        }
                    }

                    match h.handler_type() {
                        ProxyHandlerType::Direct => self.dispatch_direct_tcp_done(),
                        ProxyHandlerType::Endpoint | ProxyHandlerType::Ensemble => {
                            self.dispatch_endpoint_tcp_done()
                        }
                    }

                    Ok(())
                }
                Err(e) => {
                    debug!(
                        "dispatch tcp {} -> {} to [{}] failed: {}",
                        &sess.source,
                        &sess.destination,
                        &h.tag(),
                        e
                    );

                    match h.handler_type() {
                        ProxyHandlerType::Direct => self.dispatch_direct_tcp_done(),
                        ProxyHandlerType::Endpoint | ProxyHandlerType::Ensemble => {
                            self.dispatch_endpoint_tcp_done()
                        }
                    }

                    Err(e)
                }
            }
        } else {
            // FIXME use  the default handler
            debug!("handler not found");
            Err(io::Error::new(ErrorKind::Other, "handler not found"))
        }
    }

    pub async fn dispatch_udp(&self, sess: &Session) -> io::Result<Box<dyn OutboundDatagram>> {
        let outbound = match self.router.pick_route(&sess) {
            Ok(tag) => {
                debug!(
                    "picked route [{}] for {} -> {}",
                    tag, &sess.source, &sess.destination
                );
                tag
            }
            Err(err) => {
                trace!("pick route failed: {}", err);
                if let Some(tag) = self.outbound_manager.default_handler() {
                    debug!(
                        "picked default route [{}] for {} -> {}",
                        tag, &sess.source, &sess.destination
                    );
                    tag
                } else {
                    return Err(io::Error::new(ErrorKind::Other, "no available handler"));
                }
            }
        };

        let handshake_start = tokio::time::Instant::now();

        if let Some(h) = self.outbound_manager.get(outbound) {
            match h.handle_udp(sess, None).await {
                Ok(c) => {
                    let elapsed = tokio::time::Instant::now().duration_since(handshake_start);
                    log_udp(
                        &sess.inbound_tag,
                        h.tag(),
                        h.color(),
                        elapsed.as_millis(),
                        &sess.destination,
                    );
                    Ok(c)
                }
                Err(e) => {
                    debug!(
                        "dispatch udp {} -> {} to [{}] failed: {}",
                        &sess.source,
                        &sess.destination,
                        &h.tag(),
                        e
                    );
                    Err(e)
                }
            }
        } else {
            Err(io::Error::new(ErrorKind::Other, "handler not found"))
        }
    }
}
