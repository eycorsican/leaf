use std::{cmp::min, io, net::SocketAddr, pin::Pin, sync::Arc};

use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::{
    ready,
    task::{Context, Poll},
};
use log::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::io::{AsyncRead, AsyncWrite};

use super::crypto::{AeadCipher, Cipher, Decryptor, Encryptor};
use crate::proxy::{ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf};

enum ReadState {
    WaitingSalt,
    WaitingLength,
    WaitingData(usize),
    PendingData(usize),
}

enum WriteState {
    WaitingSalt,
    PendingSalt(usize, usize),
    WaitingChunk,
    PendingChunk(usize, (usize, usize)),
}

pub struct ShadowedStream<T> {
    inner: T,
    cipher: Box<dyn Cipher>,
    enc: Option<Box<dyn Encryptor>>,
    dec: Option<Box<dyn Decryptor>>,
    read_buf: BytesMut,
    write_buf: BytesMut,
    read_state: ReadState,
    write_state: WriteState,
    read_pos: usize,
}

impl<T> ShadowedStream<T> {
    pub fn new(s: T, cipher: &String, password: &String) -> Result<Self> {
        let cipher = Box::new(AeadCipher::new(cipher, password)?);
        Ok(ShadowedStream {
            inner: s,
            cipher,
            enc: None,
            dec: None,

            // never depend on these sizes, reserve when need
            read_buf: BytesMut::with_capacity(0x3fff + 0x20),
            write_buf: BytesMut::with_capacity(0x2 + 0x3fff + 0x20 * 2),

            read_state: ReadState::WaitingSalt,
            write_state: WriteState::WaitingSalt,
            read_pos: 0,
        })
    }
}

trait ReadExt {
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>>;
}

impl<T: AsyncRead + Unpin> ReadExt for ShadowedStream<T> {
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>> {
        self.read_buf.reserve(size);
        unsafe { self.read_buf.set_len(size) };
        loop {
            if self.read_pos < size {
                let n =
                    ready!(Pin::new(&mut self.inner)
                        .poll_read(cx, &mut self.read_buf[self.read_pos..]))?;
                self.read_pos += n;
                if n == 0 {
                    return Err(eof()).into();
                }
            }
            if self.read_pos >= size {
                self.read_pos = 0;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
}

fn crypto_err() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "crypto error")
}

impl<T: AsyncRead + Unpin> AsyncRead for ShadowedStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.read_state {
                ReadState::WaitingSalt => {
                    // read salt and create decryptor
                    let salt_size = self.cipher.salt_size();
                    ready!(self.poll_read_exact(cx, salt_size))?;
                    let dec = self
                        .cipher
                        .decryptor(&self.read_buf[..salt_size])
                        .map_err(|_| crypto_err())?;
                    self.dec.replace(dec);
                    self.read_buf.clear();

                    // ready to read payload length
                    self.read_state = ReadState::WaitingLength;
                }
                ReadState::WaitingLength => {
                    // read and decipher payload length
                    let me = &mut *self;
                    let read_size = 2 + me.cipher.tag_len();
                    ready!(me.poll_read_exact(cx, read_size))?;
                    let dec = me.dec.as_mut().expect("uninitialized cipher");
                    dec.decrypt(&mut me.read_buf).map_err(|_| crypto_err())?;
                    let payload_len = BigEndian::read_u16(&me.read_buf) as usize;

                    // ready to read payload
                    me.read_state = ReadState::WaitingData(payload_len);
                }
                ReadState::WaitingData(n) => {
                    // read and decipher payload
                    let me = &mut *self;
                    let read_size = n + me.cipher.tag_len();
                    ready!(me.poll_read_exact(cx, read_size))?;
                    let dec = me.dec.as_mut().expect("uninitialized cipher");
                    dec.decrypt(&mut me.read_buf).map_err(|_| crypto_err())?;

                    // ready to read plaintext payload into buf
                    me.read_state = ReadState::PendingData(n);
                }
                ReadState::PendingData(n) => {
                    let to_read = min(buf.len(), n);
                    let payload = self.read_buf.split_to(to_read);
                    (&mut buf[..to_read]).copy_from_slice(&payload);
                    if to_read < n {
                        // there're unread data, continues in next poll
                        self.read_state = ReadState::PendingData(n - to_read);
                    } else {
                        // all data consumed, ready to read next chunk
                        self.read_state = ReadState::WaitingLength;
                    }
                    return Poll::Ready(Ok(to_read));
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ShadowedStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.write_state {
                WriteState::WaitingSalt => {
                    // generate random salt and create encryptor
                    let salt_size = self.cipher.salt_size();
                    self.write_buf.reserve(salt_size);
                    unsafe { self.write_buf.set_len(salt_size) };
                    let mut rng = StdRng::from_entropy();
                    for i in 0..salt_size {
                        self.write_buf[i] = rng.gen();
                    }
                    let enc = self
                        .cipher
                        .encryptor(&self.write_buf[..salt_size])
                        .map_err(|_| crypto_err())?;
                    self.enc.replace(enc);

                    // ready to write salt
                    self.write_state = WriteState::PendingSalt(salt_size, 0);
                }
                WriteState::PendingSalt(total, written) => {
                    let me = &mut *self;

                    // write salt
                    // TODO write salt together with payload
                    let nw = ready!(Pin::new(&mut me.inner).poll_write_buf(cx, &mut me.write_buf))?;
                    if nw == 0 {
                        return Err(eof()).into();
                    }

                    if written + nw >= total {
                        self.write_state = WriteState::WaitingChunk;
                    } else {
                        self.write_state = WriteState::PendingSalt(total, written + nw);
                    }
                }
                WriteState::WaitingChunk => {
                    let me = &mut *self;
                    // 0x3fff is the mandatory maximum size in ss spec
                    let consume_len = min(buf.len(), 0x3fff);
                    let enc = me.enc.as_mut().expect("uninitialized cipher");

                    // seal payload length
                    let piece1_size = 2 + me.cipher.tag_len();
                    me.write_buf.reserve(piece1_size);
                    unsafe { me.write_buf.set_len(2) };
                    BigEndian::write_u16(&mut me.write_buf[..2], consume_len as u16);
                    enc.encrypt(&mut me.write_buf).map_err(|_| crypto_err())?;
                    let mut piece2 = me.write_buf.split_off(piece1_size);

                    // seal payload
                    let piece2_size = consume_len + me.cipher.tag_len();
                    piece2.reserve(piece2_size);
                    piece2.put_slice(&buf[..consume_len]);
                    enc.encrypt(&mut piece2).map_err(|_| crypto_err())?;

                    // merge length and payload pieces
                    me.write_buf.unsplit(piece2);

                    // ready to write data
                    self.write_state =
                        WriteState::PendingChunk(consume_len, (me.write_buf.len(), 0));
                }

                // consumed is the consumed plaintext length we're going to return to caller.
                // total is total length of the ciphertext data chunk we're going to write to remote.
                // written is the number of ciphertext bytes were written.
                WriteState::PendingChunk(consumed, (total, written)) => {
                    let me = &mut *self;

                    // There would be trouble if the caller change the buf upon pending, but I
                    // believe that's not a usual use case.
                    let nw = ready!(Pin::new(&mut me.inner).poll_write_buf(cx, &mut me.write_buf))?;
                    if nw == 0 {
                        return Err(eof()).into();
                    }

                    if written + nw >= total {
                        // data chunk written, go to next chunk
                        me.write_state = WriteState::WaitingChunk;
                        return Poll::Ready(Ok(consumed));
                    }

                    me.write_state = WriteState::PendingChunk(consumed, (total, written + nw));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct InnerHalf {
    // server: SocketAddr,
    cipher: Box<dyn Cipher>,
}

struct Half<T> {
    half: T,
    buffer: BytesMut,
    inner: Arc<InnerHalf>,
}

fn short_packet() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "short packet")
}

pub struct ShadowedDatagramRecvHalf(Half<Box<dyn ProxyDatagramRecvHalf>>);

impl ShadowedDatagramRecvHalf {
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let salt_size = self.0.inner.cipher.salt_size();
        let tag_len = self.0.inner.cipher.tag_len();
        let buffer_size = salt_size + /* addr::MAX_SOCKS_ADDR_SIZE + */ buf.len() + tag_len;

        // prepare buffer
        self.0.buffer.reserve(buffer_size);
        unsafe { self.0.buffer.set_len(buffer_size) };

        // recv data
        let (n, addr) = self.0.half.recv_from(&mut self.0.buffer).await?;
        if n < salt_size {
            debug!("salt size {}", n);
            return Err(short_packet());
        }

        let _ = self.0.buffer.split_off(n);

        // buffer: |salt|ciphertext(addr+payload)|tag|

        let salt = self.0.buffer.split_to(salt_size);

        // buffer: |ciphertext(addr+payload)|tag|

        let mut dec = self
            .0
            .inner
            .cipher
            .decryptor(&salt)
            .map_err(|_| crypto_err())?;
        if self.0.buffer.len() < tag_len {
            debug!("buffer size {}", self.0.buffer.len());
            return Err(short_packet());
        }
        debug_assert_eq!(tag_len, dec.tag_len());

        dec.decrypt(&mut self.0.buffer).map_err(|_| crypto_err())?;

        // buffer: |plaintext(addr+payload)|tag|

        let _ = self.0.buffer.split_off(n - salt_size - tag_len);

        // buffer: |plaintext(addr+payload)|

        // let addr = SocksAddr::try_from(&mut self.0.buffer).map_err(|_| invalid_addr())?;

        // buffer: |plaintext(payload)|

        let to_recv = min(buf.len(), self.0.buffer.len());
        (&mut buf[..to_recv]).copy_from_slice(&self.0.buffer[..to_recv]);
        Ok((to_recv, addr))
    }
}

pub struct ShadowedDatagramSendHalf(Half<Box<dyn ProxyDatagramSendHalf>>);

impl ShadowedDatagramSendHalf {
    pub async fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let salt_size = self.0.inner.cipher.salt_size();
        let tag_len = self.0.inner.cipher.tag_len();
        let buffer_size = salt_size + /* target.size() + */ buf.len() + tag_len;

        // prepare buffer
        self.0.buffer.reserve(buffer_size);
        unsafe { self.0.buffer.set_len(salt_size) };

        // generate random salt
        let mut rng = StdRng::from_entropy();
        for i in 0..salt_size {
            self.0.buffer[i] = rng.gen();
        }

        // buffer: |salt|

        let mut enc = self
            .0
            .inner
            .cipher
            .encryptor(&self.0.buffer[..salt_size])
            .map_err(|_| crypto_err())?;
        debug_assert_eq!(enc.tag_len(), tag_len);

        let mut piece = self.0.buffer.split_off(salt_size);

        // buffer: |salt|
        // piece: ||

        // target.write_into(&mut piece)?;

        // buffer: |salt|
        // piece: |addr|

        piece.put_slice(buf);

        // buffer: |salt|
        // piece: |addr+payload|

        enc.encrypt(&mut piece).map_err(|_| crypto_err())?;

        // buffer: |salt|
        // piece: |ciphertext(addr+payload)|tag|

        self.0.buffer.unsplit(piece);

        // buffer: |salt|ciphertext(addr+payload)|tag|

        self.0.half.send_to(&self.0.buffer, addr).await?;
        Ok(buf.len())
    }
}

pub struct ShadowedDatagram {
    inner: Box<dyn ProxyDatagram>,
    // server: SocketAddr,
    cipher: Box<dyn Cipher>,
    recv_buf: BytesMut,
    send_buf: BytesMut,
}

impl ShadowedDatagram {
    pub fn new(
        socket: Box<dyn ProxyDatagram>,
        /* server: SocketAddr,*/ cipher: Box<dyn Cipher>,
    ) -> Self {
        ShadowedDatagram {
            inner: socket,
            // server,
            cipher,
            recv_buf: BytesMut::with_capacity(65507),
            send_buf: BytesMut::with_capacity(65507),
        }
    }

    /// Creates a shadowed datagram with a given initial buffer size. This buffer size is
    /// only used for the buffer's initialization, the buffer actually used will reserve
    /// (allocate extra memory when need) enough space each time sending or receiving packets.
    pub fn with_initial_buffer_size(
        socket: Box<dyn ProxyDatagram>,
        // server: SocketAddr,
        cipher: Box<dyn Cipher>,
        buf_size: usize,
    ) -> Self {
        ShadowedDatagram {
            inner: socket,
            // server,
            cipher,
            recv_buf: BytesMut::with_capacity(buf_size),
            send_buf: BytesMut::with_capacity(buf_size),
        }
    }

    pub fn split(self) -> (ShadowedDatagramRecvHalf, ShadowedDatagramSendHalf) {
        let (r, s) = self.inner.split();
        let hi = Arc::new(InnerHalf {
            // server: self.server,
            cipher: self.cipher,
        });
        (
            ShadowedDatagramRecvHalf(Half {
                half: r,
                buffer: self.recv_buf,
                inner: hi.clone(),
            }),
            ShadowedDatagramSendHalf(Half {
                half: s,
                buffer: self.send_buf,
                inner: hi,
            }),
        )
    }
}
