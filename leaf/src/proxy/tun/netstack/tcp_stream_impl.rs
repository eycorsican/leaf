use std::{
    cmp::min,
    io,
    net::SocketAddr,
    os::raw,
    pin::Pin,
    sync::{
        mpsc::{sync_channel, Receiver, SyncSender},
        Arc, Mutex,
    },
};

use anyhow::Result;
use bytes::BytesMut;
use futures::task::{Context, Poll, Waker};
use log::*;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::mutex::AtomicMutex;

use super::lwip::*;
use super::util;

#[allow(unused_variables)]
pub extern "C" fn tcp_recv_cb(
    arg: *mut raw::c_void,
    tpcb: *mut tcp_pcb,
    p: *mut pbuf,
    err: err_t,
) -> err_t {
    unsafe {
        let stream: &mut TcpStreamImpl;
        let mut buf: Vec<u8>;

        stream = &mut *(arg as *mut TcpStreamImpl);

        if p.is_null() {
            debug!("tcp eof {}", stream.local_addr());
            stream.local_closed = true;
            if let Ok(waker) = stream.waker.lock() {
                if let Some(waker) = waker.as_ref() {
                    waker.wake_by_ref();
                }
            }
            return err_enum_t_ERR_OK as err_t;
        }

        let pbuflen = (*p).tot_len;
        let buflen = pbuflen as usize;
        buf = Vec::<u8>::with_capacity(buflen);
        pbuf_copy_partial(p, buf.as_mut_ptr() as *mut raw::c_void, pbuflen, 0);
        buf.set_len(pbuflen as usize);

        if let Err(err) = stream.tx.try_send((&buf[..buflen]).to_vec()) {
            debug!("send recv data failed: {}", err);
            if let Ok(waker) = stream.waker.lock() {
                if let Some(waker) = waker.as_ref() {
                    waker.wake_by_ref();
                }
            }
            return err_enum_t_ERR_CONN as err_t;
        }

        if let Ok(waker) = stream.waker.lock() {
            if let Some(waker) = waker.as_ref() {
                waker.wake_by_ref();
            }
        }

        pbuf_free(p);
        err_enum_t_ERR_OK as err_t
    }
}

#[allow(unused_variables)]
pub extern "C" fn tcp_sent_cb(arg: *mut raw::c_void, tpcb: *mut tcp_pcb, len: u16_t) -> err_t {
    unsafe {
        let stream: &mut TcpStreamImpl;
        stream = &mut *(arg as *mut TcpStreamImpl);
        if let Some(waker) = stream.write_waker.as_ref() {
            waker.wake_by_ref();
        }
        err_enum_t_ERR_OK as err_t
    }
}

#[allow(unused_variables)]
pub extern "C" fn tcp_err_cb(arg: *mut ::std::os::raw::c_void, err: err_t) {
    unsafe {
        let stream: &mut TcpStreamImpl;
        stream = &mut *(arg as *mut TcpStreamImpl);
        debug!("tcp err {} {}", err, stream.local_addr());
        stream.errored = true;
        if let Ok(waker) = stream.waker.lock() {
            if let Some(waker) = waker.as_ref() {
                waker.wake_by_ref();
            }
        }
    }
}

pub struct TcpStreamImpl {
    lwip_lock: Arc<AtomicMutex>,
    src_addr: SocketAddr,
    dest_addr: SocketAddr,
    pcb: *mut tcp_pcb,

    // without the mutex, uplink wakeup could lose synchronization
    // under large uplink throughput scenarios, causes extremelly
    // slow (sometimes zero) throughput and huge memory occupying
    // channel
    waker: Arc<Mutex<Option<Waker>>>,

    // FIXME perhaps a listener level write waker is more appropriate?
    // can should wake all connection writes when memory is available.
    write_waker: Option<Waker>,

    tx: SyncSender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    errored: bool,
    local_closed: bool,
    write_buf: BytesMut,
}

impl TcpStreamImpl {
    pub fn new(lwip_lock: Arc<AtomicMutex>, pcb: *mut tcp_pcb) -> Result<Box<Self>> {
        unsafe {
            let (tx, rx): (SyncSender<Vec<u8>>, Receiver<Vec<u8>>) = sync_channel(100);
            let src_addr = util::to_socket_addr(&(*pcb).remote_ip, (*pcb).remote_port)?;
            let dest_addr = util::to_socket_addr(&(*pcb).local_ip, (*pcb).local_port)?;
            let stream = Box::new(TcpStreamImpl {
                lwip_lock,
                src_addr,
                dest_addr,
                pcb,
                waker: Arc::new(Mutex::new(None)),
                write_waker: None,
                tx,
                rx,
                errored: false,
                local_closed: false,
                write_buf: BytesMut::with_capacity(4 * 1024),
            });
            let arg = &*stream as *const TcpStreamImpl as *mut raw::c_void;
            tcp_arg(pcb, arg);
            tcp_recv(pcb, Some(tcp_recv_cb));
            tcp_sent(pcb, Some(tcp_sent_cb));
            tcp_err(pcb, Some(tcp_err_cb));

            stream.apply_pcb_opts();

            debug!("tcp new {}", stream.local_addr());

            Ok(stream)
        }
    }

    #[cfg(not(target_os = "ios"))]
    fn apply_pcb_opts(&self) {}

    #[cfg(target_os = "ios")]
    fn apply_pcb_opts(&self) {
        unsafe { (*self.pcb).so_options |= SOF_KEEPALIVE as u8 };
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dest_addr
    }
}

impl Drop for TcpStreamImpl {
    fn drop(&mut self) {
        debug!("tcp drop {}", self.local_addr());
        unsafe {
            let _g = self.lwip_lock.lock();
            if !self.errored {
                // tcp_arg(self.pcb, std::ptr::null_mut());
                // tcp_recv(self.pcb, None);
                // tcp_sent(self.pcb, None);
                // tcp_err(self.pcb, None);
                // tcp_close(self.pcb);
                tcp_abort(self.pcb);
            }
        }
    }
}

impl AsyncRead for TcpStreamImpl {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_buf.len() > 0 {
            let to_read = min(buf.len(), self.write_buf.len());
            let piece = self.write_buf.split_to(to_read);
            (&mut buf[..to_read]).copy_from_slice(&piece[..to_read]);
            return Poll::Ready(Ok(to_read));
        }
        if self.errored {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "read on broken pipe",
            )));
        }
        if self.local_closed {
            return Poll::Ready(Ok(0));
        }
        match self.rx.try_recv() {
            Ok(data) => {
                let to_read = min(buf.len(), data.len());
                (&mut buf[..to_read]).copy_from_slice(&data[..to_read]);
                if buf.len() < to_read {
                    self.write_buf.extend_from_slice(&data[to_read..]);
                }
                unsafe {
                    let _g = self.lwip_lock.lock();
                    tcp_recved(self.pcb, to_read as u16_t);
                }
                Poll::Ready(Ok(to_read))
            }
            Err(_) => {
                if let Ok(mut waker) = self.waker.lock() {
                    if let Some(waker_ref) = waker.as_ref() {
                        if !waker_ref.will_wake(cx.waker()) {
                            waker.replace(cx.waker().clone());
                        }
                    } else {
                        waker.replace(cx.waker().clone());
                    }
                }
                Poll::Pending
            }
        }
    }
}

unsafe impl Sync for TcpStreamImpl {}
unsafe impl Send for TcpStreamImpl {}

impl AsyncWrite for TcpStreamImpl {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.errored {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write on broken pipe",
            )));
        }
        let mut to_write = buf.len();
        let lwip_lock = self.lwip_lock.clone();
        unsafe {
            let _g = lwip_lock.lock();
            let snd_buf_size = (*self.pcb).snd_buf as usize;
            if snd_buf_size < to_write {
                to_write = snd_buf_size;
            }
            if to_write == 0 {
                if let Some(waker) = self.write_waker.as_ref() {
                    if !waker.will_wake(cx.waker()) {
                        self.write_waker.replace(cx.waker().clone());
                    }
                } else {
                    self.write_waker.replace(cx.waker().clone());
                }
                return Poll::Pending;
            }
            let err = tcp_write(
                self.pcb,
                buf.as_ptr() as *const raw::c_void,
                to_write as u16_t,
                TCP_WRITE_FLAG_COPY as u8,
            );
            if err == err_enum_t_ERR_OK as err_t {
                tcp_output(self.pcb);
            } else if err == err_enum_t_ERR_MEM as err_t {
                return Poll::Pending;
            } else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    format!("tcp_write error {:?}", err),
                )));
            }
        }
        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        // FIXME perhaps call tcp_output?
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
