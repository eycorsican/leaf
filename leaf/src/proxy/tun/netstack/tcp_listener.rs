use std::{pin::Pin, sync::Arc};

use futures::stream::Stream;
use futures::task::{Context, Poll};

use crate::common::mutex::AtomicMutex;

use super::tcp_listener_impl::TcpListenerImpl;
use super::tcp_stream_impl::TcpStreamImpl;

pub struct TcpListener {
    inner: Box<TcpListenerImpl>,
}

impl TcpListener {
    pub fn new(lwip_lock: Arc<AtomicMutex>) -> Self {
        TcpListener {
            inner: TcpListenerImpl::new(lwip_lock),
        }
    }
}

impl Stream for TcpListener {
    type Item = Box<TcpStreamImpl>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Stream::poll_next(Pin::new(&mut self.inner), cx)
    }
}
