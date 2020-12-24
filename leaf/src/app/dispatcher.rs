use std::cmp::min;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use futures::future::{self, Either};
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;

#[cfg(not(target_os = "ios"))]
use colored::Colorize;

use crate::{
    option,
    proxy::{stream::SimpleProxyStream, OutboundDatagram, ProxyHandlerType, ProxyStream},
    session::{Session, SocksAddr},
};

use super::outbound::manager::OutboundManager;
use super::router::Router;

struct SniffingStream<T> {
    inner: T,
    buf: BytesMut,
}

impl<T> SniffingStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: T) -> Self {
        SniffingStream {
            inner,
            buf: BytesMut::new(),
        }
    }

    pub async fn sniff(&mut self) -> io::Result<Option<String>> {
        let mut buf = vec![0u8; 2 * 1024];
        'outer: for _ in 0..2 {
            match timeout(Duration::from_millis(100), self.inner.read(&mut buf)).await {
                Ok(res) => match res {
                    Ok(n) => {
                        self.buf.extend_from_slice(&buf[..n]);

                        // https://tls.ulfheim.net/

                        let sbuf = &self.buf[..];
                        if sbuf.len() < 5 {
                            continue;
                        }
                        // handshake record type
                        if sbuf[0] != 0x16 {
                            return Ok(None);
                        }
                        // protocol version
                        if sbuf[1] != 0x3 {
                            return Ok(None);
                        }
                        let header_len = BigEndian::read_u16(&sbuf[3..5]) as usize;
                        if sbuf.len() < 5 + header_len {
                            continue;
                        }
                        let sbuf = &sbuf[5..5 + header_len];
                        // ?
                        if sbuf.len() < 42 {
                            continue;
                        }
                        let session_id_len = sbuf[38] as usize;
                        if session_id_len > 32 || sbuf.len() < 39 + session_id_len {
                            continue;
                        }
                        let sbuf = &sbuf[39 + session_id_len..];
                        if sbuf.len() < 2 {
                            continue;
                        }
                        let cipher_suite_bytes = BigEndian::read_u16(&sbuf[..2]) as usize;
                        if sbuf.len() < 2 + cipher_suite_bytes {
                            continue;
                        }
                        let sbuf = &sbuf[2 + cipher_suite_bytes..];
                        if sbuf.is_empty() {
                            continue;
                        }
                        let compression_method_bytes = sbuf[0] as usize;
                        if sbuf.len() < 1 + compression_method_bytes {
                            continue;
                        }
                        let sbuf = &sbuf[1 + compression_method_bytes..];
                        if sbuf.len() < 2 {
                            continue;
                        }
                        let extensions_bytes = BigEndian::read_u16(&sbuf[..2]) as usize;
                        if sbuf.len() < 2 + extensions_bytes {
                            continue;
                        }
                        let mut sbuf = &sbuf[2..2 + extensions_bytes];
                        while !sbuf.is_empty() {
                            // extension + extension-specific-len
                            if sbuf.len() < 4 {
                                continue 'outer;
                            }
                            let extension = BigEndian::read_u16(&sbuf[..2]);
                            let extension_len = BigEndian::read_u16(&sbuf[2..4]) as usize;
                            sbuf = &sbuf[4..];
                            if sbuf.len() < extension_len {
                                continue 'outer;
                            }
                            // extension "server name"
                            if extension == 0x0 {
                                let mut ebuf = &sbuf[..extension_len];
                                if ebuf.len() < 2 {
                                    continue 'outer;
                                }
                                let entry_len = BigEndian::read_u16(&ebuf[..2]) as usize;
                                ebuf = &ebuf[2..];
                                if ebuf.len() < entry_len {
                                    continue 'outer;
                                }
                                // just make sure no oob
                                if ebuf.is_empty() {
                                    continue 'outer;
                                }
                                let entry_type = ebuf[0];
                                // type "DNS hostname"
                                if entry_type == 0x0 {
                                    ebuf = &ebuf[1..];
                                    // just make sure no oob
                                    if ebuf.len() < 2 {
                                        continue 'outer;
                                    }
                                    let hostname_len = BigEndian::read_u16(&ebuf[..2]) as usize;
                                    ebuf = &ebuf[2..];
                                    if ebuf.len() < hostname_len {
                                        continue 'outer;
                                    }
                                    return Ok(Some(
                                        String::from_utf8_lossy(&ebuf[..hostname_len]).into(),
                                    ));
                                } else {
                                    // TODO
                                    // I assume there's only "DNS hostname" type
                                    // in the the "server name" extension, should
                                    // check if this is true later.
                                    //
                                    // I also assume there's only one entry in the
                                    // "server name" extension list.
                                    return Ok(None);
                                }
                            } else {
                                sbuf = &sbuf[extension_len..];
                            }
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                },
                Err(_) => {
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SniffingStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.buf.is_empty() {
            let to_read = min(buf.len(), self.buf.len());
            let for_read = self.buf.split_to(to_read);
            (&mut buf[..to_read]).copy_from_slice(&for_read[..to_read]);
            Poll::Ready(Ok(to_read))
        } else {
            AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf)
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SniffingStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

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
    endpoint_tcp_tx: TokioMutex<Sender<bool>>,
    endpoint_tcp_rx: TokioMutex<Receiver<bool>>,
    direct_tcp_tx: TokioMutex<Sender<bool>>,
    direct_tcp_rx: TokioMutex<Receiver<bool>>,
    num_endpoint_tcp: TokioMutex<u32>,
    num_direct_tcp: TokioMutex<u32>,
}

impl Dispatcher {
    pub fn new(outbound_manager: OutboundManager, router: Router) -> Self {
        let (endpoint_tcp_tx, endpoint_tcp_rx) = mpsc::channel(option::ENDPOINT_TCP_CONCURRENCY);
        let (direct_tcp_tx, direct_tcp_rx) = mpsc::channel(option::DIRECT_TCP_CONCURRENCY);
        Dispatcher {
            outbound_manager,
            router,
            endpoint_tcp_tx: TokioMutex::new(endpoint_tcp_tx),
            endpoint_tcp_rx: TokioMutex::new(endpoint_tcp_rx),
            direct_tcp_tx: TokioMutex::new(direct_tcp_tx),
            direct_tcp_rx: TokioMutex::new(direct_tcp_rx),
            num_endpoint_tcp: TokioMutex::new(0),
            num_direct_tcp: TokioMutex::new(0),
        }
    }

    async fn dispatch_endpoint_tcp_start(&self) {
        match self.endpoint_tcp_tx.lock().await.send(true).await {
            Ok(_) => (),
            Err(e) => {
                warn!("send tcp dispatch placeholder failed: {}", e);
                return;
            }
        };
        *self.num_endpoint_tcp.lock().await += 1;
        trace!(
            "active proxied tcp connections +1: {}",
            self.num_endpoint_tcp.lock().await
        );
    }

    async fn dispatch_endpoint_tcp_done(&self) {
        if self.endpoint_tcp_rx.lock().await.try_recv().is_ok() {
            *self.num_endpoint_tcp.lock().await -= 1;
            trace!(
                "active proxied tcp connections -1: {}",
                self.num_endpoint_tcp.lock().await
            );
        }
    }

    async fn dispatch_direct_tcp_start(&self) {
        match self.direct_tcp_tx.lock().await.send(true).await {
            Ok(_) => (),
            Err(e) => {
                warn!("send tcp dispatch placeholder failed: {}", e);
                return;
            }
        };
        *self.num_direct_tcp.lock().await += 1;
        trace!(
            "active direct tcp connections +1: {}",
            self.num_direct_tcp.lock().await
        );
    }

    async fn dispatch_direct_tcp_done(&self) {
        if self.direct_tcp_rx.lock().await.try_recv().is_ok() {
            *self.num_direct_tcp.lock().await -= 1;
            trace!(
                "active direct tcp connections -1: {}",
                self.num_direct_tcp.lock().await
            );
        }
    }

    pub async fn dispatch_tcp<T>(&self, sess: &mut Session, lhs: T) -> io::Result<()>
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let lhs: Box<dyn ProxyStream> =
            if sess.destination.is_domain() && sess.destination.port() == 443 {
                Box::new(SimpleProxyStream(lhs))
            } else {
                let mut lhs = SniffingStream::new(lhs);
                if let Some(domain) = lhs.sniff().await? {
                    debug!("sniffed domain {}", &domain);
                    sess.destination = SocksAddr::from((domain, sess.destination.port()));
                }
                Box::new(SimpleProxyStream(lhs))
            };

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
                        ProxyHandlerType::Direct => self.dispatch_direct_tcp_done().await,
                        ProxyHandlerType::Endpoint | ProxyHandlerType::Ensemble => {
                            self.dispatch_endpoint_tcp_done().await
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
                        ProxyHandlerType::Direct => self.dispatch_direct_tcp_done().await,
                        ProxyHandlerType::Endpoint | ProxyHandlerType::Ensemble => {
                            self.dispatch_endpoint_tcp_done().await
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
