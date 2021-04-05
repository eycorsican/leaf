use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::future::{self, Either};
use log::*;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::{
    common::sniff,
    option,
    proxy::{OutboundDatagram, ProxyHandlerType, ProxyStream, SimpleProxyStream},
    session::{Session, SocksAddr},
};

use super::outbound::manager::OutboundManager;
use super::router::Router;

#[inline]
fn log_request(
    sess: &Session,
    outbound_tag: &str,
    outbound_tag_color: Option<colored::Color>,
    handshake_time: u128,
) {
    if let Some(color) = outbound_tag_color {
        use colored::Colorize;
        info!(
            "[{}] [{}] [{}] [{}ms] {}",
            &sess.inbound_tag,
            sess.network.to_string().color(colored::Color::Blue),
            outbound_tag.color(color),
            handshake_time,
            &sess.destination,
        );
    } else {
        info!(
            "[{}] [{}] [{}] [{}ms] {}",
            sess.network, &sess.inbound_tag, outbound_tag, handshake_time, &sess.destination,
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
        // FIXME panic
        self.endpoint_tcp_sem.acquire().await.unwrap().forget();
        let pn = self.num_endpoint_tcp.fetch_add(1, Ordering::SeqCst);
        trace!("active proxied tcp connections +1: {}", pn + 1);
    }

    fn dispatch_endpoint_tcp_done(&self) {
        self.endpoint_tcp_sem.add_permits(1);
        let pn = self.num_endpoint_tcp.fetch_sub(1, Ordering::SeqCst);
        trace!("active proxied tcp connections -1: {}", pn - 1)
    }

    async fn dispatch_direct_tcp_start(&self) {
        // FIXME panic
        self.direct_tcp_sem.acquire().await.unwrap().forget();
        let pn = self.num_direct_tcp.fetch_add(1, Ordering::SeqCst);
        trace!("active direct tcp connections +1: {}", pn + 1);
    }

    fn dispatch_direct_tcp_done(&self) {
        self.direct_tcp_sem.add_permits(1);
        let pn = self.num_direct_tcp.fetch_sub(1, Ordering::SeqCst);
        trace!("active direct tcp connections -1: {}", pn - 1)
    }

    pub async fn dispatch_tcp<T>(&self, sess: &mut Session, lhs: T)
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let mut lhs: Box<dyn ProxyStream> =
            if !sess.destination.is_domain() && sess.destination.port() == 443 {
                let mut lhs = sniff::SniffingStream::new(lhs);
                match lhs.sniff().await {
                    Ok(res) => {
                        if let Some(domain) = res {
                            debug!(
                                "sniffed domain {} for tcp link {} <-> {}",
                                &domain, &sess.source, &sess.destination,
                            );
                            sess.destination = SocksAddr::from((domain, sess.destination.port()));
                        }
                    }
                    Err(e) => {
                        trace!(
                            "sniff tcp uplink {} -> {} failed: {}",
                            &sess.source,
                            &sess.destination,
                            e,
                        );
                        return;
                    }
                }
                Box::new(SimpleProxyStream(lhs))
            } else {
                Box::new(SimpleProxyStream(lhs))
            };

        let outbound = match self.router.pick_route(&sess).await {
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
                    warn!("can not find any handlers");
                    if let Err(e) = lhs.shutdown().await {
                        debug!(
                            "tcp downlink {} <- {} error: {}",
                            &sess.source, &sess.destination, e,
                        );
                    }
                    return;
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

                    #[cfg(not(any(target_os = "ios", target_os = "android")))]
                    {
                        log_request(&sess, h.tag(), Some(h.color()), elapsed.as_millis());
                    }
                    #[cfg(any(target_os = "ios", target_os = "android"))]
                    {
                        log_request(&sess, h.tag(), None, elapsed.as_millis());
                    }

                    let (lr, mut lw) = tokio::io::split(lhs);
                    let (rr, mut rw) = tokio::io::split(rhs);

                    let mut lr = BufReader::with_capacity(*option::LINK_BUFFER_SIZE * 1024, lr);
                    let mut rr = BufReader::with_capacity(*option::LINK_BUFFER_SIZE * 1024, rr);

                    let l2r = Box::pin(tokio::io::copy_buf(&mut lr, &mut rw));
                    let r2l = Box::pin(tokio::io::copy_buf(&mut rr, &mut lw));

                    // TODO Propagate EOF signal.

                    // Drives both uplink and downlink to completion, i.e. read till EOF.
                    match future::select(l2r, r2l).await {
                        // Uplink task returns first, with the result of the completed uplink
                        // task and the uncompleted downlink task.
                        Either::Left((up_res, new_r2l)) => {
                            // Logs the uplink result, either successful with bytes transfered
                            // or an error.
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
                                    // FIXME Perhaps we should terminate the pipe immediately.
                                    debug!(
                                        "tcp uplink {} -> {} error: {} [{}]",
                                        &sess.source,
                                        &sess.destination,
                                        up_e,
                                        &h.tag()
                                    );
                                }
                            }

                            // Puts a timeout limit on the uncompleted downlink task, because uplink
                            // has been completed, and we don't like half-closed connections, the other
                            // half must complete before timeout.
                            let timed_r2l = timeout(
                                Duration::from_secs(*option::TCP_DOWNLINK_TIMEOUT),
                                new_r2l,
                            );

                            trace!(
                                "applied {}s downlink timeout to {} <- {}",
                                *option::TCP_DOWNLINK_TIMEOUT,
                                &sess.source,
                                &sess.destination
                            );

                            // Because uplink has been completed, no furture data from the inbound
                            // connection, we would like to close the write side of the outbound
                            // connection, so that notifies the close of the pipeline.
                            //
                            // TODO Perhaps we should not send FIN in order to compatible with some
                            // of the improperly implemented server programs, e.g. a server closes
                            // the write side after reading EOF on read side.
                            // let rw_shutdown = rw.shutdown();

                            // Drives both the above tasks to completion simultaneously and get the
                            // results.
                            // let (shutdown_res, timed_r2l_res) =
                            //     future::join(rw_shutdown, timed_r2l).await;

                            let timed_r2l_res = timed_r2l.await;

                            // Logs the shutdown result.
                            // if let Err(e) = shutdown_res {
                            //     debug!(
                            //         "tcp uplink {} -> {} error: {} [{}]",
                            //         &sess.source,
                            //         &sess.destination,
                            //         e,
                            //         &h.tag()
                            //     );
                            // }

                            // Logs the downlink result.
                            match timed_r2l_res {
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

                            // Finally shuts down the inbound connection.
                            // if let Err(e) = lw.shutdown().await {
                            //     debug!(
                            //         "tcp downlink {} <- {} error: {} [{}]",
                            //         &sess.source,
                            //         &sess.destination,
                            //         e,
                            //         &h.tag()
                            //     );
                            // }
                        }

                        // In case downlink returns first, the process is similar to the other
                        // side described above, with the roles of uplink and downlink interchanged.
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

                            let timed_l2r =
                                timeout(Duration::from_secs(*option::TCP_UPLINK_TIMEOUT), new_l2r);

                            trace!(
                                "applied {}s uplink timeout to {} -> {}",
                                *option::TCP_UPLINK_TIMEOUT,
                                &sess.source,
                                &sess.destination
                            );

                            // let (shutdown_res, timed_l2r_res) =
                            //     future::join(lw.shutdown(), timed_l2r).await;

                            let timed_l2r_res = timed_l2r.await;

                            // if let Err(e) = shutdown_res {
                            //     debug!(
                            //         "tcp downlink {} <- {} error: {} [{}]",
                            //         &sess.source,
                            //         &sess.destination,
                            //         e,
                            //         &h.tag()
                            //     );
                            // }

                            match timed_l2r_res {
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

                            // if let Err(e) = rw.shutdown().await {
                            //     debug!(
                            //         "tcp uplink {} -> {} error: {} [{}]",
                            //         &sess.source,
                            //         &sess.destination,
                            //         e,
                            //         &h.tag()
                            //     );
                            // }
                        }
                    }

                    if let Err(e) = rw.shutdown().await {
                        debug!(
                            "tcp uplink {} -> {} error: {} [{}]",
                            &sess.source,
                            &sess.destination,
                            e,
                            &h.tag()
                        );
                    }

                    if let Err(e) = lw.shutdown().await {
                        debug!(
                            "tcp downlink {} <- {} error: {} [{}]",
                            &sess.source,
                            &sess.destination,
                            e,
                            &h.tag()
                        );
                    }

                    match h.handler_type() {
                        ProxyHandlerType::Direct => self.dispatch_direct_tcp_done(),
                        ProxyHandlerType::Endpoint | ProxyHandlerType::Ensemble => {
                            self.dispatch_endpoint_tcp_done()
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

                    if let Err(e) = lhs.shutdown().await {
                        debug!(
                            "tcp downlink {} <- {} error: {} [{}]",
                            &sess.source,
                            &sess.destination,
                            e,
                            &h.tag()
                        );
                    }

                    match h.handler_type() {
                        ProxyHandlerType::Direct => self.dispatch_direct_tcp_done(),
                        ProxyHandlerType::Endpoint | ProxyHandlerType::Ensemble => {
                            self.dispatch_endpoint_tcp_done()
                        }
                    }
                }
            }
        } else {
            // FIXME use  the default handler
            debug!("handler not found");
            if let Err(e) = lhs.shutdown().await {
                debug!(
                    "tcp downlink {} <- {} error: {}",
                    &sess.source, &sess.destination, e,
                );
            }
        }
    }

    pub async fn dispatch_udp(&self, sess: &Session) -> io::Result<Box<dyn OutboundDatagram>> {
        let outbound = match self.router.pick_route(&sess).await {
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

                    #[cfg(not(any(target_os = "ios", target_os = "android")))]
                    {
                        log_request(&sess, h.tag(), Some(h.color()), elapsed.as_millis());
                    }
                    #[cfg(any(target_os = "ios", target_os = "android"))]
                    {
                        log_request(&sess, h.tag(), None, elapsed.as_millis());
                    }

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
