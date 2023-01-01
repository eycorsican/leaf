use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    pub fn new() -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; 2 * 1024].into_boxed_slice(),
        }
    }

    pub fn new_with_capacity(size: usize) -> Result<Self, std::io::Error> {
        let mut buf = Vec::new();
        buf.try_reserve(size).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("new buffer failed: {}", e),
            )
        })?;
        buf.resize(size, 0);
        Ok(Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: buf.into_boxed_slice(),
        })
    }

    pub fn amount_transfered(&self) -> u64 {
        self.amt
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);

                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Try flushing when the reader has no progress to avoid deadlock
                        // when the reader depends on buffered writer.
                        if self.need_flush {
                            ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }

                        return Poll::Pending;
                    }
                }

                let n = buf.filled().len();
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
                let i = ready!(writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                }
            }

            // If pos larger than cap, this loop will never stop.
            // In particular, user's wrong poll_write implementation returning
            // incorrect written length may lead to thread blocking.
            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
    a_to_b_count: u64,
    b_to_a_count: u64,
    a_to_b_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    b_to_a_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
            a_to_b_count,
            b_to_a_count,
            a_to_b_delay,
            b_to_a_delay,
            a_to_b_timeout_duration,
            b_to_a_timeout_duration,
        } = &mut *self;

        let mut a = Pin::new(a);
        let mut b = Pin::new(b);

        loop {
            match a_to_b {
                TransferState::Running(buf) => {
                    let res = buf.poll_copy(cx, a.as_mut(), b.as_mut());
                    match res {
                        Poll::Ready(Ok(count)) => {
                            *a_to_b = TransferState::ShuttingDown(count);
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            if let Some(delay) = a_to_b_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *a_to_b =
                                            TransferState::ShuttingDown(buf.amount_transfered());
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = b.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *a_to_b_count += *count;
                            *a_to_b = TransferState::Done;
                            b_to_a_delay
                                .replace(Box::pin(tokio::time::sleep(*b_to_a_timeout_duration)));
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match b_to_a {
                TransferState::Running(buf) => {
                    let res = buf.poll_copy(cx, b.as_mut(), a.as_mut());
                    match res {
                        Poll::Ready(Ok(count)) => {
                            *b_to_a = TransferState::ShuttingDown(count);
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            if let Some(delay) = b_to_a_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *b_to_a =
                                            TransferState::ShuttingDown(buf.amount_transfered());
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = a.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *b_to_a_count += *count;
                            *b_to_a = TransferState::Done;
                            a_to_b_delay
                                .replace(Box::pin(tokio::time::sleep(*a_to_b_timeout_duration)));
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match (&a_to_b, &b_to_a) {
                (TransferState::Done, TransferState::Done) => break,
                _ => return Poll::Pending,
            }
        }

        Poll::Ready(Ok((*a_to_b_count, *b_to_a_count)))
    }
}

pub async fn copy_buf_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    size: usize,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
) -> Result<(u64, u64), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running(CopyBuffer::new_with_capacity(size)?),
        b_to_a: TransferState::Running(CopyBuffer::new_with_capacity(size)?),
        a_to_b_count: 0,
        b_to_a_count: 0,
        a_to_b_delay: None,
        b_to_a_delay: None,
        a_to_b_timeout_duration,
        b_to_a_timeout_duration,
    }
    .await
}
