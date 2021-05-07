use std::mem::MaybeUninit;
use std::{cmp::min, io, pin::Pin};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{
    ready,
    task::{Context, Poll},
};
use log::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::crypto::{
    aead::{AeadCipher, AeadDecryptor, AeadEncryptor},
    Cipher, Decryptor, Encryptor, SizedCipher,
};

use super::crypto::{hkdf_sha1, kdf, ShadowsocksNonceSequence};

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
    cipher: AeadCipher,
    psk: Vec<u8>,
    enc: Option<AeadEncryptor<ShadowsocksNonceSequence>>,
    dec: Option<AeadDecryptor<ShadowsocksNonceSequence>>,
    read_buf: BytesMut,
    write_buf: BytesMut,
    read_state: ReadState,
    write_state: WriteState,
    read_pos: usize,
}

impl<T> ShadowedStream<T> {
    pub fn new(s: T, cipher: &str, password: &str) -> io::Result<Self> {
        let cipher = AeadCipher::new(cipher).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("create AEAD cipher failed: {}", e),
            )
        })?;
        let psk = kdf(password, cipher.key_len()).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("derive key failed: {}", e))
        })?;
        Ok(ShadowedStream {
            inner: s,
            cipher,
            psk,
            enc: None,
            dec: None,

            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),

            read_state: ReadState::WaitingSalt,
            write_state: WriteState::WaitingSalt,
            read_pos: 0,
        })
    }
}

trait ReadExt {
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>>;
}

fn early_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
}

impl<T> ReadExt for ShadowedStream<T>
where
    T: AsyncRead + Unpin,
{
    // Read exactly `size` bytes into `read_buf`, starting from position 0.
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>> {
        self.read_buf.reserve(size);
        unsafe { self.read_buf.set_len(size) }
        loop {
            if self.read_pos < size {
                let dst = unsafe {
                    &mut *((&mut self.read_buf[self.read_pos..size]) as *mut _
                        as *mut [MaybeUninit<u8>])
                };
                let mut buf = ReadBuf::uninit(dst);
                let ptr = buf.filled().as_ptr();
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
                assert_eq!(ptr, buf.filled().as_ptr());
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(early_eof()));
                }
                self.read_pos += buf.filled().len();
            } else {
                assert!(self.read_pos == size);
                self.read_pos = 0;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

pub fn crypto_err() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "crypto error")
}

impl<T> AsyncRead for ShadowedStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::WaitingSalt => {
                    // read salt and create decryptor
                    let salt_size = self.cipher.key_len();
                    ready!(self.poll_read_exact(cx, salt_size))?;
                    let key = hkdf_sha1(
                        &self.psk,
                        &self.read_buf[..salt_size],
                        String::from("ss-subkey").as_bytes().to_vec(),
                        self.cipher.key_len(),
                    )
                    .map_err(|_| crypto_err())?;
                    let nonce =
                        super::crypto::ShadowsocksNonceSequence::new(self.cipher.nonce_len());
                    let dec = self
                        .cipher
                        .decryptor(&key, nonce)
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
                    if let Err(e) = ready!(me.poll_read_exact(cx, read_size)) {
                        if e.kind() == io::ErrorKind::UnexpectedEof {
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(e));
                        }
                    }
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
                    let to_read = min(buf.remaining(), n);
                    let payload = self.read_buf.split_to(to_read);
                    buf.put_slice(&payload);
                    if to_read < n {
                        // there're unread data, continues in next poll
                        self.read_state = ReadState::PendingData(n - to_read);
                    } else {
                        // all data consumed, ready to read next chunk
                        self.read_state = ReadState::WaitingLength;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<T> AsyncWrite for ShadowedStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use tokio_util::io::poll_write_buf;
        loop {
            match self.write_state {
                WriteState::WaitingSalt => {
                    // generate random salt and create encryptor
                    let salt_size = self.cipher.key_len();
                    self.write_buf.reserve(salt_size);
                    unsafe { self.write_buf.set_len(salt_size) };
                    let mut rng = StdRng::from_entropy();
                    for i in 0..salt_size {
                        self.write_buf[i] = rng.gen();
                    }

                    let key = hkdf_sha1(
                        &self.psk,
                        &self.write_buf[..salt_size],
                        String::from("ss-subkey").as_bytes().to_vec(),
                        self.cipher.key_len(),
                    )
                    .map_err(|_| crypto_err())?;
                    let nonce =
                        super::crypto::ShadowsocksNonceSequence::new(self.cipher.nonce_len());
                    let enc = self
                        .cipher
                        .encryptor(&key, nonce)
                        .map_err(|_| crypto_err())?;

                    self.enc.replace(enc);

                    // ready to write salt
                    self.write_state = WriteState::PendingSalt(salt_size, 0);
                }
                WriteState::PendingSalt(total, written) => {
                    let me = &mut *self;

                    // write salt
                    // TODO write salt together with payload
                    let nw = ready!(poll_write_buf(
                        Pin::new(&mut me.inner),
                        cx,
                        &mut me.write_buf
                    ))?;
                    if nw == 0 {
                        return Err(early_eof()).into();
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
                    let nw = ready!(poll_write_buf(
                        Pin::new(&mut me.inner),
                        cx,
                        &mut me.write_buf
                    ))?;
                    if nw == 0 {
                        return Err(early_eof()).into();
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

fn short_packet() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "short packet")
}

pub struct ShadowedDatagram {
    cipher: AeadCipher,
    psk: Vec<u8>,
}

impl ShadowedDatagram {
    pub fn new(cipher: &str, password: &str) -> io::Result<Self> {
        let cipher = AeadCipher::new(cipher).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("create AEAD cipher failed: {}", e),
            )
        })?;
        let psk = kdf(password, cipher.key_len()).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("derive key failed: {}", e))
        })?;
        Ok(ShadowedDatagram { cipher, psk })
    }

    /// Decrypts a message. On success, returns the plaintext.
    pub fn decrypt(&self, mut buf: BytesMut) -> io::Result<Bytes> {
        let salt_size = self.cipher.key_len();
        let tag_len = self.cipher.tag_len();
        let buf_len = buf.len();

        if buf.len() < salt_size {
            return Err(short_packet());
        }

        let salt = buf.split_to(salt_size);

        let key = hkdf_sha1(
            &self.psk,
            &salt,
            String::from("ss-subkey").as_bytes().to_vec(),
            self.cipher.key_len(),
        )
        .map_err(|_| crypto_err())?;
        let nonce = ShadowsocksNonceSequence::new(self.cipher.nonce_len());
        let mut dec = self
            .cipher
            .decryptor(&key, nonce)
            .map_err(|_| crypto_err())?;

        if buf.len() < tag_len {
            debug!("buffer size {}", buf.len());
            return Err(short_packet());
        }

        dec.decrypt(&mut buf).map_err(|_| crypto_err())?;

        let _ = buf.split_off(buf_len - salt_size - tag_len);

        Ok(buf.freeze())
    }

    /// Encrypts a message. On success, returns the ciphertext.
    pub fn encrypt(&self, mut buf: BytesMut) -> io::Result<Bytes> {
        if buf.is_empty() {
            return Ok(Bytes::new());
        }

        let salt_size = self.cipher.key_len();

        let mut buffer = BytesMut::new(); // TODO optimize
        buffer.resize(salt_size, 0);

        // generate random salt
        let mut rng = StdRng::from_entropy();
        for i in 0..salt_size {
            buffer[i] = rng.gen();
        }

        let key = hkdf_sha1(
            &self.psk,
            &buffer[..salt_size],
            String::from("ss-subkey").as_bytes().to_vec(),
            self.cipher.key_len(),
        )
        .map_err(|_| crypto_err())?;
        let nonce = ShadowsocksNonceSequence::new(self.cipher.nonce_len());
        let mut enc = self
            .cipher
            .encryptor(&key, nonce)
            .map_err(|_| crypto_err())?;

        enc.encrypt(&mut buf).map_err(|_| crypto_err())?;

        buffer.extend_from_slice(&buf[..]);

        Ok(buffer.freeze())
    }
}
