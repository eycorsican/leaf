use std::{
    io,
    os::raw,
    pin::Pin,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Once,
    },
    time,
};

use futures::{
    stream::StreamExt,
    task::{Context, Poll, Waker},
};
use log::*;
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tokio::sync::Mutex as TokioMutex;
use tokio::{
    self,
    io::{AsyncRead, AsyncWrite},
};

use crate::{
    app::dispatcher::Dispatcher,
    app::nat_manager::NatManager,
    app::nat_manager::UdpPacket,
    common::fake_dns::FakeDns,
    common::mutex::AtomicMutex,
    session::{Session, SocksAddr},
};

use super::lwip::*;
use super::output::{output_ip4, OUTPUT_CB_PTR};
use super::tcp_listener::TcpListener;
use super::tcp_stream::TcpStream;
use super::udp::{send_udp, UdpListener};

static LWIP_INIT: Once = Once::new();

pub struct NetStackImpl {
    pub lwip_lock: Arc<AtomicMutex>,
    waker: Option<Waker>,
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    fakedns: Arc<TokioMutex<FakeDns>>,
}

unsafe impl Sync for NetStackImpl {}
unsafe impl Send for NetStackImpl {}

impl NetStackImpl {
    pub fn new(
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
        fakedns: Arc<TokioMutex<FakeDns>>,
    ) -> Box<Self> {
        LWIP_INIT.call_once(|| unsafe { lwip_init() });

        unsafe {
            (*netif_list).output = Some(output_ip4);
            (*netif_list).mtu = 1500;
            // (*netif_list).output_ip6 = Some(output_ip6);
        }

        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();

        let stack = Box::new(NetStackImpl {
            lwip_lock: Arc::new(AtomicMutex::new()),
            waker: None,
            tx,
            rx,
            dispatcher,
            nat_manager,
            fakedns,
        });

        unsafe {
            OUTPUT_CB_PTR = &*stack as *const NetStackImpl as usize;
        }

        let lwip_lock = stack.lwip_lock.clone();
        tokio::spawn(async move {
            loop {
                {
                    let _g = lwip_lock.lock();
                    unsafe { sys_check_timeouts() };
                }
                tokio::time::delay_for(time::Duration::from_millis(250)).await;
            }
        });

        let lwip_locktcp = stack.lwip_lock.clone();
        let dispatcher = stack.dispatcher.clone();
        let fakedns = stack.fakedns.clone();
        tokio::spawn(async move {
            let mut listener = TcpListener::new(lwip_locktcp);

            while let Some(stream) = listener.next().await {
                let dispatcher = dispatcher.clone();
                let fakedns = fakedns.clone();

                tokio::spawn(async move {
                    let mut sess = if fakedns.lock().await.is_fake_ip(&stream.remote_addr().ip()) {
                        match fakedns
                            .lock()
                            .await
                            .query_domain(&stream.remote_addr().ip())
                        {
                            Some(domain) => Session {
                                source: Some(stream.local_addr().to_owned()),
                                destination: SocksAddr::Domain(domain, stream.remote_addr().port()),
                            },
                            None => Session {
                                source: Some(stream.local_addr().to_owned()),
                                destination: SocksAddr::Ip(*stream.remote_addr()),
                            },
                        }
                    } else {
                        Session {
                            source: Some(stream.local_addr().to_owned()),
                            destination: SocksAddr::Ip(*stream.remote_addr()),
                        }
                    };

                    // dispatch err logging was handled in dispatcher
                    let _ = dispatcher
                        .dispatch_tcp(&mut sess, TcpStream::new(stream))
                        .await;
                });
            }
        });

        let lwip_lock = stack.lwip_lock.clone();
        let nat_manager = stack.nat_manager.clone();
        let fakedns = stack.fakedns.clone();
        tokio::spawn(async move {
            let mut listener = UdpListener::new();
            let nat_manager = nat_manager.clone();
            let fakedns = fakedns.clone();
            let pcb = listener.pcb();

            let (client_ch_tx, mut client_ch_rx): (
                TokioSender<UdpPacket>,
                TokioReceiver<UdpPacket>,
            ) = tokio_channel(100);

            // downlink
            let lwip_lock2 = lwip_lock.clone();
            tokio::spawn(async move {
                while let Some(pkt) = client_ch_rx.recv().await {
                    let src_addr = match pkt.src_addr {
                        Some(a) => match a {
                            SocksAddr::Ip(a) => a,
                            _ => {
                                warn!("unexpected domain addr");
                                continue;
                            }
                        },
                        None => {
                            warn!("unexpected none src addr");
                            continue;
                        }
                    };
                    let dst_addr = match pkt.dst_addr {
                        Some(a) => match a {
                            SocksAddr::Ip(a) => a,
                            _ => {
                                warn!("unexpected domain addr");
                                continue;
                            }
                        },
                        None => {
                            warn!("unexpected dst addr");
                            continue;
                        }
                    };
                    send_udp(lwip_lock2.clone(), &src_addr, &dst_addr, pcb, &pkt.data[..]);
                }
                error!("unexpected udp downlink ended");
            });

            while let Some(pkt) = listener.next().await {
                let src_addr = match pkt.src_addr {
                    Some(a) => match a {
                        SocksAddr::Ip(a) => a,
                        _ => {
                            warn!("unexpected domain addr");
                            continue;
                        }
                    },
                    None => {
                        warn!("unexpected none src addr");
                        continue;
                    }
                };
                let dst_addr = match pkt.dst_addr {
                    Some(a) => match a {
                        SocksAddr::Ip(a) => a,
                        _ => {
                            warn!("unexpected domain addr");
                            continue;
                        }
                    },
                    None => {
                        warn!("unexpected dst addr");
                        continue;
                    }
                };

                if dst_addr.port() == 53 {
                    match fakedns.lock().await.generate_fake_response(&pkt.data) {
                        Ok(resp) => {
                            send_udp(lwip_lock.clone(), &dst_addr, &src_addr, pcb, resp.as_ref());
                            continue;
                        }
                        Err(err) => {
                            debug!("generate fake ip failed: {}", err);
                        }
                    }
                }

                if !nat_manager.contains_key(&src_addr).await {
                    let sess = Session {
                        source: Some(src_addr.clone()),
                        destination: SocksAddr::Ip(dst_addr),
                    };

                    if let Err(_) = nat_manager
                        .add_session(&sess, src_addr, client_ch_tx.clone(), 30)
                        .await
                    {
                        // dispatch err logging was handled in dispatcher
                        continue; // in case the pkt was sent to drop, err is returned immediately
                    }

                    debug!(
                        "udp session {}:{} -> {}:{} ({})",
                        &src_addr.ip(),
                        &src_addr.port(),
                        &dst_addr.ip(),
                        &dst_addr.port(),
                        nat_manager.size().await,
                    );
                }

                let pkt = UdpPacket {
                    data: pkt.data,
                    src_addr: Some(SocksAddr::Ip(src_addr)),
                    dst_addr: Some(SocksAddr::Ip(dst_addr)),
                };
                nat_manager.send(&src_addr, pkt).await;
            }
        });

        stack
    }

    pub fn output(&mut self, pkt: Vec<u8>) -> io::Result<usize> {
        let n = pkt.len();
        if let Err(err) = self.tx.send(pkt) {
            debug!("output packet failed: {}", err);
            return Ok(0);
        }
        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref();
            return Ok(n);
        }
        Ok(0)
    }
}

impl AsyncRead for NetStackImpl {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.rx.try_recv() {
            Ok(pkt) => {
                if pkt.len() > buf.len() {
                    warn!("truncated pkt, short buf");
                }
                (&mut buf[..pkt.len()]).copy_from_slice(&pkt);
                Poll::Ready(Ok(pkt.len()))
            }
            Err(_) => {
                if let Some(waker) = self.waker.as_ref() {
                    if !waker.will_wake(cx.waker()) {
                        self.waker.replace(cx.waker().clone());
                    }
                } else {
                    self.waker.replace(cx.waker().clone());
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for NetStackImpl {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        unsafe {
            let pbuf = pbuf_alloc(pbuf_layer_PBUF_RAW, buf.len() as u16_t, pbuf_type_PBUF_RAM);
            if pbuf.is_null() {
                warn!("alloc null pbuf");
                return Poll::Pending;
            }
            pbuf_take(pbuf, buf.as_ptr() as *const raw::c_void, buf.len() as u16_t);

            {
                let _g = self.lwip_lock.lock();
                if let Some(input_fn) = (*netif_list).input {
                    let err = input_fn(pbuf, netif_list);
                    if err == err_enum_t_ERR_OK as err_t {
                        Poll::Ready(Ok(buf.len()))
                    } else {
                        pbuf_free(pbuf);
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "input failed",
                        )))
                    }
                } else {
                    pbuf_free(pbuf);
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "none input fn",
                    )))
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
