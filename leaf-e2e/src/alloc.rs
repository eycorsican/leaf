//! How much memory the process is holding.
//!
//! Nodes run in the case's own process, so the host's buffers -- an engine's
//! `read_decoded`, `write_pending`, a datagram instance's output -- are this
//! allocator's. That makes "the buffers stayed bounded under load" something a
//! case can assert directly, without reading RSS, which on both platforms the
//! suite runs on reports pages the allocator has not returned rather than
//! bytes anyone is using.
//!
//! Counting is two relaxed atomics on a path that is already doing a `malloc`,
//! and it is only ever compared against itself: what a case asserts is that
//! [`live_bytes`] stopped growing, never what it is.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

/// Wraps another allocator with a live-bytes counter.
pub struct Counting<A> {
    inner: A,
    allocated: AtomicU64,
    freed: AtomicU64,
}

impl<A> Counting<A> {
    pub const fn new(inner: A) -> Self {
        Self {
            inner,
            allocated: AtomicU64::new(0),
            freed: AtomicU64::new(0),
        }
    }
}

// Safety: every method forwards to `inner` with the layout it was given, and
// only adds counter arithmetic around it.
unsafe impl<A: GlobalAlloc> GlobalAlloc for Counting<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = self.inner.alloc(layout);
        if !ptr.is_null() {
            self.allocated
                .fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.inner.alloc_zeroed(layout);
        if !ptr.is_null() {
            self.allocated
                .fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.freed
            .fetch_add(layout.size() as u64, Ordering::Relaxed);
        self.inner.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = self.inner.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            // The old block is gone whether or not it moved, so both sides are
            // recorded rather than the difference: a `new_size` below the old
            // one would otherwise underflow the counter.
            self.allocated.fetch_add(new_size as u64, Ordering::Relaxed);
            self.freed
                .fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: Counting<System> = Counting::new(System);

/// Bytes allocated and not yet freed.
///
/// Only meaningful as a difference between two readings taken at the same
/// point in a repeating workload: an allocator's own bookkeeping, a growing
/// `Vec`'s spare capacity and any lazily built cache all count here.
pub fn live_bytes() -> u64 {
    let allocated = ALLOCATOR.allocated.load(Ordering::Relaxed);
    let freed = ALLOCATOR.freed.load(Ordering::Relaxed);
    allocated.saturating_sub(freed)
}

/// Every byte ever handed out, freed or not. A workload that allocates per
/// chunk instead of reusing a buffer shows up here without moving
/// [`live_bytes`] at all.
pub fn total_allocated() -> u64 {
    ALLOCATOR.allocated.load(Ordering::Relaxed)
}

/// Two readings of [`live_bytes`] around a piece of work.
#[derive(Clone, Copy, Debug)]
pub struct Growth {
    pub before: u64,
    pub after: u64,
}

impl Growth {
    /// Starts a measurement.
    pub fn start() -> Self {
        let before = live_bytes();
        Self {
            before,
            after: before,
        }
    }

    /// Takes the closing reading.
    pub fn finish(mut self) -> Self {
        self.after = live_bytes();
        self
    }

    /// How much more is held now than at the start. Saturating, because a
    /// workload that ends holding less is not a defect.
    pub fn bytes(&self) -> u64 {
        self.after.saturating_sub(self.before)
    }
}

impl std::fmt::Display for Growth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.1} MiB -> {:.1} MiB (+{:.1} MiB)",
            self.before as f64 / (1024.0 * 1024.0),
            self.after as f64 / (1024.0 * 1024.0),
            self.bytes() as f64 / (1024.0 * 1024.0)
        )
    }
}
