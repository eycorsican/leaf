use std::{collections::VecDeque, os::raw, pin::Pin, sync::Arc};

use futures::stream::Stream;
use futures::task::{Context, Poll, Waker};
use log::*;

use crate::common::mutex::AtomicMutex;

use super::lwip::*;
use super::tcp_stream_impl::TcpStreamImpl;

#[allow(unused_variables)]
pub extern "C" fn tcp_accept_cb(arg: *mut raw::c_void, newpcb: *mut tcp_pcb, err: err_t) -> err_t {
    if newpcb.is_null() {
        warn!("tcp full");
        return err_enum_t_ERR_OK as err_t;
    }
    let listener = unsafe { &mut *(arg as *mut TcpListenerImpl) };
    let stream = match TcpStreamImpl::new(listener.lwip_lock.clone(), newpcb) {
        Ok(s) => s,
        Err(e) => {
            error!("new tcp stream failed: {}", e);
            return err_enum_t_ERR_OK as err_t;
        }
    };
    listener.queue.push_back(stream);
    if let Some(waker) = listener.waker.as_ref() {
        waker.wake_by_ref();
    }
    err_enum_t_ERR_OK as err_t
}

pub struct TcpListenerImpl {
    pub tpcb: *mut tcp_pcb,
    pub lwip_lock: Arc<AtomicMutex>,
    pub waker: Option<Waker>,
    pub queue: VecDeque<Box<TcpStreamImpl>>,
}

impl TcpListenerImpl {
    pub fn new(lwip_lock: Arc<AtomicMutex>) -> Box<Self> {
        unsafe {
            let _g = lwip_lock.lock();
            let mut tpcb = tcp_new();
            let err = tcp_bind(tpcb, &ip_addr_any_type, 0);
            if err != err_enum_t_ERR_OK as err_t {
                error!("bind tcp failed");
                panic!("");
            }
            let mut reason: err_t = 0;
            tpcb = tcp_listen_with_backlog_and_err(
                tpcb,
                TCP_DEFAULT_LISTEN_BACKLOG as u8,
                &mut reason,
            );
            if tpcb.is_null() {
                error!("listen tcp failed: {}", reason);
                panic!("");
            }
            let listener = Box::new(TcpListenerImpl {
                tpcb,
                lwip_lock: lwip_lock.clone(),
                waker: None,
                queue: VecDeque::new(),
            });
            let arg = &*listener as *const TcpListenerImpl as *mut raw::c_void;
            tcp_arg(listener.tpcb, arg);
            tcp_accept(listener.tpcb, Some(tcp_accept_cb));
            listener
        }
    }
}

unsafe impl Sync for TcpListenerImpl {}
unsafe impl Send for TcpListenerImpl {}

impl Drop for TcpListenerImpl {
    fn drop(&mut self) {
        unsafe {
            let _g = self.lwip_lock.lock();
            tcp_accept(self.tpcb, None);
            tcp_close(self.tpcb);
        }
    }
}

impl Stream for TcpListenerImpl {
    type Item = Box<TcpStreamImpl>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Some(stream) = self.queue.pop_front() {
            return Poll::Ready(Some(stream));
        }
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
