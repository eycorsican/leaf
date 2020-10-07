use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::{self, try_select, Either, Future, FutureExt, TryFutureExt};
use futures::ready;
use log::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;

use crate::{
    option,
    proxy::{ProxyDatagram, ProxyHandlerType},
    session::Session,
};

use super::handler_manager::HandlerManager;
use super::router::Router;

// The same as tokio::io::copy(), except it takes ownership of the reader and writer.
struct Transfer<R, W> {
    reader: R,
    read_done: bool,
    writer: W,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

fn transfer<R, W>(reader: R, writer: W) -> Transfer<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    Transfer {
        reader,
        read_done: false,
        writer,
        amt: 0,
        pos: 0,
        cap: 0,
        buf: vec![0; 2048].into_boxed_slice(),
    }
}

impl<R, W> Future for Transfer<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let n = ready!(Pin::new(&mut me.reader).poll_read(cx, &mut me.buf))?;
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let me = &mut *self;
                let i = ready!(Pin::new(&mut me.writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                let me = &mut *self;
                ready!(Pin::new(&mut me.writer).poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

pub struct Dispatcher {
    handler_manager: HandlerManager,
    router: Router,
    endpoint_tcp_tx: TokioMutex<Sender<bool>>,
    endpoint_tcp_rx: TokioMutex<Receiver<bool>>,
    direct_tcp_tx: TokioMutex<Sender<bool>>,
    direct_tcp_rx: TokioMutex<Receiver<bool>>,
    num_endpoint_tcp: TokioMutex<u32>,
    num_direct_tcp: TokioMutex<u32>,
}

impl Dispatcher {
    pub fn new(handler_manager: HandlerManager, router: Router) -> Self {
        let (endpoint_tcp_tx, endpoint_tcp_rx) = mpsc::channel(option::ENDPOINT_TCP_CONCURRENCY);
        let (direct_tcp_tx, direct_tcp_rx) = mpsc::channel(option::DIRECT_TCP_CONCURRENCY);
        Dispatcher {
            handler_manager,
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
        debug!(
            "active proxied tcp connections +1: {}",
            self.num_endpoint_tcp.lock().await
        );
    }

    async fn dispatch_endpoint_tcp_done(&self) {
        match self.endpoint_tcp_rx.lock().await.try_recv() {
            Ok(_) => {
                *self.num_endpoint_tcp.lock().await -= 1;
                debug!(
                    "active proxied tcp connections -1: {}",
                    self.num_endpoint_tcp.lock().await
                );
            }
            Err(_) => (),
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
        debug!(
            "active direct tcp connections +1: {}",
            self.num_direct_tcp.lock().await
        );
    }

    async fn dispatch_direct_tcp_done(&self) {
        match self.direct_tcp_rx.lock().await.try_recv() {
            Ok(_) => {
                *self.num_direct_tcp.lock().await -= 1;
                debug!(
                    "active direct tcp connections -1: {}",
                    self.num_direct_tcp.lock().await
                );
            }
            Err(_) => (),
        }
    }

    pub async fn dispatch_tcp<T: 'static + AsyncRead + AsyncWrite + Send>(
        &self,
        sess: &Session,
        lhs: T,
    ) -> io::Result<()> {
        let outbound = match self.router.pick_route(&sess) {
            Ok(tag) => {
                debug!(
                    "picked route [{}] for {} -> {}",
                    tag,
                    &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                    &sess.destination
                );
                tag
            }
            Err(err) => {
                trace!("pick route failed: {}", err);
                if let Some(tag) = self.handler_manager.default_handler() {
                    debug!(
                        "picked default route [{}] for {} -> {}",
                        tag,
                        &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                        &sess.destination
                    );
                    tag
                } else {
                    return Err(io::Error::new(ErrorKind::Other, "no available handler"));
                }
            }
        };

        if let Some(h) = self.handler_manager.get(outbound) {
            match h.handler_type() {
                ProxyHandlerType::Direct => self.dispatch_direct_tcp_start().await,
                ProxyHandlerType::Endpoint | ProxyHandlerType::Ensemble => {
                    self.dispatch_endpoint_tcp_start().await
                }
            }

            match h.handle(sess, None).await {
                Ok(rhs) => {
                    let (lr, lw) = tokio::io::split(lhs);
                    let (rr, rw) = tokio::io::split(rhs);

                    let r2l = transfer(rr, lw);
                    let l2r = transfer(lr, rw);

                    type TransferResult = Box<
                        dyn Future<Output = io::Result<(io::Result<u64>, io::Result<u64>)>>
                            + Unpin
                            + Send,
                    >;
                    let transfer = try_select(l2r, r2l).then(|res| -> TransferResult {
                        match res {
                            Ok(Either::Left((up_n, r2l))) => {
                                let timed_r2l =
                                    timeout(Duration::from_secs(option::TCP_DOWNLINK_TIMEOUT), r2l);
                                let timed_r2l = timed_r2l.map_ok(move |down_res| match down_res {
                                    Ok(down_n) => (Ok(up_n), Ok(down_n)),
                                    Err(down_e) => (Ok(up_n), Err(down_e)),
                                });
                                let timed_r2l = timed_r2l.map_err(|_to| {
                                    io::Error::new(io::ErrorKind::TimedOut, "downlink timeout")
                                });
                                Box::new(timed_r2l)
                            }
                            Ok(Either::Right((down_n, l2r))) => {
                                let timed_l2r =
                                    timeout(Duration::from_secs(option::TCP_UPLINK_TIMEOUT), l2r);
                                let timed_l2r = timed_l2r.map_ok(move |up_res| match up_res {
                                    Ok(up_n) => (Ok(up_n), Ok(down_n)),
                                    Err(up_e) => (Err(up_e), Ok(down_n)),
                                });
                                let timed_l2r = timed_l2r.map_err(|_to| {
                                    io::Error::new(io::ErrorKind::TimedOut, "uplink timeout")
                                });
                                Box::new(timed_l2r)
                            }
                            Err(Either::Left((up_e, _))) => Box::new(future::err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                format!("uplink error: {}", up_e),
                            ))),
                            Err(Either::Right((down_e, _))) => {
                                Box::new(future::err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    format!("downlink error: {}", down_e),
                                )))
                            }
                        }
                    });

                    match transfer.await {
                        Ok((up_res, down_res)) => {
                            match up_res {
                                Ok(up_n) => {
                                    debug!(
                                        "tcp uplink {} -> {} done, {} bytes transfered [{}]",
                                        &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                                        &sess.destination,
                                        up_n,
                                        &h.tag(),
                                    );
                                }
                                Err(e) => {
                                    debug!(
                                        "tcp uplink {} -> {} error: {} [{}]",
                                        &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                                        &sess.destination,
                                        e,
                                        &h.tag()
                                    );
                                }
                            }
                            match down_res {
                                Ok(down_n) => {
                                    debug!(
                                        "tcp downlink {} <- {} done, {} bytes transfered [{}]",
                                        &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                                        &sess.destination,
                                        down_n,
                                        &h.tag(),
                                    );
                                }
                                Err(e) => {
                                    debug!(
                                        "tcp downlink {} <- {} error: {} [{}]",
                                        &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                                        &sess.destination,
                                        e,
                                        &h.tag()
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            debug!(
                                "tcp link {} <-> {} interrupted: {} [{}]",
                                &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                                &sess.destination,
                                e,
                                &h.tag()
                            );
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
                        &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
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
            debug!("handler not found");
            Err(io::Error::new(ErrorKind::Other, "handler not found"))
        }
    }

    pub async fn dispatch_udp(&self, sess: &Session) -> io::Result<Box<dyn ProxyDatagram>> {
        let outbound = match self.router.pick_route(&sess) {
            Ok(tag) => {
                debug!(
                    "picked route [{}] for {} -> {}",
                    tag,
                    &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                    &sess.destination
                );
                tag
            }
            Err(err) => {
                trace!("pick route failed: {}", err);
                if let Some(tag) = self.handler_manager.default_handler() {
                    debug!(
                        "picked default route [{}] for {} -> {}",
                        tag,
                        &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
                        &sess.destination
                    );
                    tag
                } else {
                    return Err(io::Error::new(ErrorKind::Other, "no available handler"));
                }
            }
        };
        if let Some(h) = self.handler_manager.get(outbound) {
            match h.connect(sess, None, None).await {
                Ok(c) => Ok(c),
                Err(e) => {
                    debug!(
                        "dispatch udp {} -> {} to [{}] failed: {}",
                        &sess.source.unwrap_or("0.0.0.0:0".parse().unwrap()),
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
