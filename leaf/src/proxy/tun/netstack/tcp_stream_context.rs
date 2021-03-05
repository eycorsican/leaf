use futures::task::Waker;
use std::{
    cell::UnsafeCell,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::common::mutex::AtomicMutexGuard;

pub struct TcpStreamContextInner {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub tx: Option<UnboundedSender<Vec<u8>>>,
    pub errored: bool,
    // perhaps a listener level write waker is more appropriate?
    //
    // can should wake all connection writes when memory is available.
    pub write_waker: Option<Waker>,
}

#[repr(transparent)]
pub struct TcpStreamContextRef<'a> {
    ctx: &'a TcpStreamContext,
}

impl<'a> Deref for TcpStreamContextRef<'a> {
    type Target = TcpStreamContextInner;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ctx.inner.get() }
    }
}

impl<'a> DerefMut for TcpStreamContextRef<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ctx.inner.get() }
    }
}

impl<'a> Drop for TcpStreamContextRef<'a> {
    fn drop(&mut self) {
        self.ctx.borrowed.store(false, Ordering::Release);
    }
}

/// Context shared by TcpStreamImpl and lwIP callbacks.
pub struct TcpStreamContext {
    inner: UnsafeCell<TcpStreamContextInner>,
    borrowed: AtomicBool,
}

// Users must hold a lwip_lock to get the mutable reference to inner data,
// or go through unsafe interfaces.
unsafe impl Sync for TcpStreamContext {}

impl TcpStreamContext {
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        tx: UnboundedSender<Vec<u8>>,
    ) -> Self {
        TcpStreamContext {
            inner: UnsafeCell::new(TcpStreamContextInner {
                local_addr,
                remote_addr,
                tx: Some(tx),
                errored: false,
                write_waker: None,
            }),
            borrowed: AtomicBool::new(false),
        }
    }

    fn lock_raw(&self) -> TcpStreamContextRef {
        if self.borrowed.swap(true, Ordering::Acquire) {
            panic!("TcpStreamContext locked twice within a locked period")
        }
        TcpStreamContextRef { ctx: self }
    }

    /// Access to inner data with lwip_lock locked.
    ///
    /// # Panics
    ///
    /// Panics if another reference to inner data exists.
    pub fn lock<'a>(&'a self, _guard: &'a AtomicMutexGuard) -> TcpStreamContextRef<'a> {
        self.lock_raw()
    }

    /// Access to inner data within a lwIP callback where lwip_lock is guaranteed to be locked.
    ///
    /// # Panics
    ///
    /// Panics if another reference to inner data exists.
    pub unsafe fn lock_from_lwip_callback<'a>(ptr: *const Self) -> TcpStreamContextRef<'a> {
        (&*ptr).lock_raw()
    }
}
