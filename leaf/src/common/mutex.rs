use std::sync::atomic::{AtomicBool, Ordering::*};

#[derive(Debug)]
pub struct AtomicMutex {
    locked: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
pub struct AtomicMutexErr;

pub struct AtomicMutexGuard<'a> {
    mutex: &'a AtomicMutex,
}

impl AtomicMutex {
    pub fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    pub fn try_lock(&self) -> Result<AtomicMutexGuard<'_>, AtomicMutexErr> {
        if self.locked.swap(true, Acquire) {
            Err(AtomicMutexErr)
        } else {
            Ok(AtomicMutexGuard { mutex: self })
        }
    }

    pub fn lock(&self) -> AtomicMutexGuard<'_> {
        loop {
            if let Ok(m) = self.try_lock() {
                break m;
            }
        }
    }
}

impl Default for AtomicMutex {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Send for AtomicMutex {}

unsafe impl Sync for AtomicMutex {}

impl<'a> Drop for AtomicMutexGuard<'a> {
    fn drop(&mut self) {
        let _prev = self.mutex.locked.swap(false, Release);
        debug_assert!(_prev);
    }
}
