use std::{cmp::min, io, net::SocketAddr, os::raw, pin::Pin, sync::Arc};

use anyhow::Result;
use bytes::BytesMut;
use futures::{
    ready,
    task::{Context, Poll},
};
use log::*;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{unbounded_channel, UnboundedReceiver},
};

use crate::common::mutex::AtomicMutex;

use super::lwip::*;
use super::tcp_stream_context::{TcpStreamContext, TcpStreamContextInner};
use super::util;

#[allow(unused_variables)]
pub extern "C" fn tcp_recv_cb(
    arg: *mut raw::c_void,
    tpcb: *mut tcp_pcb,
    p: *mut pbuf,
    err: err_t,
) -> err_t {
    // SAFETY: tcp_recv_cb is called from tcp_input or sys_check_timeouts only when
    // a data packet or previously refused data is received. Thus lwip_lock must be locked.
    // See also `<NetStackImpl as AsyncWrite>::poll_write`.
    let TcpStreamContextInner {
        local_addr,
        remote_addr,
        ref mut tx,
        ..
    } = *unsafe { TcpStreamContext::lock_from_lwip_callback(arg as *const TcpStreamContext) };

    if p.is_null() {
        trace!("tcp eof {}", local_addr);
        let _ = tx.take();
        return err_enum_t_ERR_OK as err_t;
    }

    let pbuflen = unsafe { (*p).tot_len };
    let buflen = pbuflen as usize;
    let mut buf = Vec::<u8>::with_capacity(buflen);
    unsafe {
        pbuf_copy_partial(p, buf.as_mut_ptr() as _, pbuflen, 0);
        buf.set_len(pbuflen as usize);
    };

    if let Some(Err(err)) = tx.as_ref().map(|tx| tx.send(buf)) {
        // rx is closed
        // TODO remove this message
        trace!(
            "recv {} bytes data on {} -> {} failed: {}",
            pbuflen,
            local_addr,
            remote_addr,
            err
        );
        return err_enum_t_ERR_CONN as err_t;
    }

    unsafe { pbuf_free(p) };
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_sent_cb(arg: *mut raw::c_void, tpcb: *mut tcp_pcb, len: u16_t) -> err_t {
    // SAFETY: tcp_sent_cb is called from tcp_input only when
    // an ACK packet is received. Thus lwip_lock must be locked.
    // See also `<NetStackImpl as AsyncWrite>::poll_write`.
    let ctx =
        &*unsafe { TcpStreamContext::lock_from_lwip_callback(arg as *const TcpStreamContext) };
    if let Some(waker) = ctx.write_waker.as_ref() {
        waker.wake_by_ref();
    }
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_err_cb(arg: *mut ::std::os::raw::c_void, err: err_t) {
    // SAFETY: tcp_err_cb is called from
    // tcp_input, tcp_abandon, tcp_abort, tcp_alloc and tcp_new.
    // Thus lwip_lock must be locked before calling any of these.
    let TcpStreamContextInner {
        local_addr,
        tx,
        errored,
        ..
    } = &mut *unsafe { TcpStreamContext::lock_from_lwip_callback(arg as *const TcpStreamContext) };
    trace!("tcp err {} {}", err, local_addr);
    *errored = true;
    let _ = tx.take();
}

pub struct TcpStreamImpl {
    lwip_lock: Arc<AtomicMutex>,
    src_addr: SocketAddr,
    dest_addr: SocketAddr,
    pcb: *mut tcp_pcb,
    rx: UnboundedReceiver<Vec<u8>>,
    write_buf: BytesMut,
    callback_ctx: TcpStreamContext,
}

impl TcpStreamImpl {
    pub fn new(lwip_lock: Arc<AtomicMutex>, pcb: *mut tcp_pcb) -> Result<Box<Self>> {
        unsafe {
            // Since we have no idea how to deal with a full bounded channel upon receiving
            // data from lwIP, an unbounded channel is used instead.
            //
            // Note that lwIP is in charge of flow control. If reader is slower than writer,
            // lwIP will propagate the pressure back by announcing a decreased window size.
            // Thus our unbounded channel will never be overwhelmed. To achieve this, we must
            // call `tcp_recved` when the data from our internal buffer are consumed.
            let (tx, rx) = unbounded_channel();
            let src_addr = util::to_socket_addr(&(*pcb).remote_ip, (*pcb).remote_port)?;
            let dest_addr = util::to_socket_addr(&(*pcb).local_ip, (*pcb).local_port)?;
            let stream = Box::new(TcpStreamImpl {
                lwip_lock,
                src_addr,
                dest_addr,
                pcb,
                rx,
                write_buf: BytesMut::new(),
                callback_ctx: TcpStreamContext::new(src_addr, dest_addr, tx),
            });
            let arg = &stream.callback_ctx as *const _;
            tcp_arg(pcb, arg as *mut raw::c_void);
            tcp_recv(pcb, Some(tcp_recv_cb));
            tcp_sent(pcb, Some(tcp_sent_cb));
            tcp_err(pcb, Some(tcp_err_cb));

            stream.apply_pcb_opts();

            trace!("tcp new {}", stream.local_addr());

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
        trace!("tcp drop {}", self.local_addr());
        let guard = self.lwip_lock.lock();
        if !self.callback_ctx.lock(&guard).errored {
            unsafe {
                let err = tcp_close(self.pcb);
                if err != err_enum_t_ERR_OK as err_t {
                    warn!("tcp_close err {}", err);
                }
                tcp_arg(self.pcb, std::ptr::null_mut());
                tcp_recv(self.pcb, None);
                tcp_sent(self.pcb, None);
                tcp_err(self.pcb, None);
            }
        }
    }
}

impl AsyncRead for TcpStreamImpl {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        if !self.write_buf.is_empty() {
            let to_read = min(buf.remaining(), self.write_buf.len());
            let piece = self.write_buf.split_to(to_read);
            buf.put_slice(&piece[..to_read]);
            unsafe {
                let _g = self.lwip_lock.lock();
                tcp_recved(self.pcb, to_read as u16_t);
            }
            return Poll::Ready(Ok(()));
        }
        let res = {
            let guard = self.lwip_lock.lock();
            let errored = self.callback_ctx.lock(&guard).errored;
            errored
        };
        if res {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "read on broken pipe",
            )));
        }
        match ready!(self.rx.poll_recv(cx)) {
            Some(data) => {
                let to_read = min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_read]);
                if to_read < data.len() {
                    self.write_buf.extend_from_slice(&data[to_read..]);
                }
                unsafe {
                    let _g = self.lwip_lock.lock();
                    tcp_recved(self.pcb, to_read as u16_t);
                }
                Poll::Ready(Ok(()))
            }
            None => Poll::Ready(Ok(())),
        }
    }
}

unsafe impl Sync for TcpStreamImpl {}
unsafe impl Send for TcpStreamImpl {}

impl AsyncWrite for TcpStreamImpl {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let guard = self.lwip_lock.lock();
        let TcpStreamContextInner {
            write_waker: ref mut waker,
            errored,
            ..
        } = *self.callback_ctx.lock(&guard);
        if errored {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write on broken pipe",
            )));
        }
        let mut to_write = buf.len();
        unsafe {
            let snd_buf_size = (*self.pcb).snd_buf as usize;
            if snd_buf_size < to_write {
                to_write = snd_buf_size;
            }
            if to_write == 0 {
                if waker
                    .as_ref()
                    .map(|w| !w.will_wake(cx.waker()))
                    .unwrap_or(true)
                {
                    waker.replace(cx.waker().clone());
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
                let err = tcp_output(self.pcb);
                if err != err_enum_t_ERR_OK as err_t {
                    warn!("tcp_output err {}", err);
                }
            } else if err == err_enum_t_ERR_MEM as err_t {
                warn!("tcp err_mem");
                if waker
                    .as_ref()
                    .map(|w| !w.will_wake(cx.waker()))
                    .unwrap_or(true)
                {
                    waker.replace(cx.waker().clone());
                }
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
