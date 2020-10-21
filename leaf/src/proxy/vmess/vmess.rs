use std::time::{SystemTime, UNIX_EPOCH};
use std::{cmp::min, io, io::Read, pin::Pin};

use aes::Aes128;
use anyhow::anyhow;
use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use cfb_mode::stream_cipher::{NewStreamCipher, StreamCipher};
use cfb_mode::Cfb;
use digest::ExtendableOutputDirty;
use futures::{
    ready,
    task::{Context, Poll},
};
use hmac::{Hmac, Mac, NewMac};
use log::*;
use lz_fnv::{Fnv1a, FnvHasher};
use md5::{Digest, Md5};
use rand::{rngs::StdRng, Rng, SeedableRng};
use ring::{
    aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, NONCE_LEN},
    error::Unspecified,
};
use sha3::Shake128;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::common;
use crate::session::{SocksAddr, SocksAddrWireType};

type RequestCommand = u8;

pub const REQUEST_COMMAND_TCP: RequestCommand = 0x01;
pub const REQUEST_COMMAND_UDP: RequestCommand = 0x02;

type Security = u8;

pub const SECURITY_TYPE_AES128_GCM: Security = 0x03;
pub const SECURITY_TYPE_CHACHA20_POLY1305: Security = 0x04;

type RequestOption = u8;

pub const REQUEST_OPTION_CHUNK_STREAM: RequestOption = 0x01;
pub const REQUEST_OPTION_CHUNK_MASKING: RequestOption = 0x04;
pub const REQUEST_OPTION_GLOBAL_PADDING: RequestOption = 0x08;

pub struct RequestHeader {
    pub version: u8,
    pub command: RequestCommand,
    pub option: u8,
    pub security: Security,
    pub address: SocksAddr,
    pub uuid: Uuid,
}

impl RequestHeader {
    pub fn set_option(&mut self, opt: RequestOption) {
        self.option |= opt;
    }

    pub fn encode(&self, buf: &mut BytesMut, sess: &ClientSession) -> anyhow::Result<()> {
        // generate auth info
        let mut timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => return Err(anyhow!("invalid system time")),
        };
        let mut rng = StdRng::from_entropy();
        let delta: i32 = rng.gen_range(0, 30 * 2) - 30;
        timestamp = timestamp.wrapping_add(delta as u64);
        let mut mac =
            Hmac::<Md5>::new_varkey(self.uuid.as_bytes()).map_err(|_| anyhow!("md5 failed"))?;
        let mut tmp = [0u8; 8];
        BigEndian::write_u64(&mut tmp, timestamp as u64);
        mac.update(&tmp);
        let auth_info = mac.finalize().into_bytes();

        buf.put_slice(&auth_info[..]);

        buf.put_u8(self.version);
        buf.put_slice(&sess.request_body_iv);
        buf.put_slice(&sess.request_body_key);
        buf.put_u8(sess.response_header);
        buf.put_u8(self.option);

        let padding_len = StdRng::from_entropy().gen_range(0, 16) as u8;
        let security = (padding_len << 4) | self.security as u8;

        buf.put_u8(security);
        buf.put_u8(0);
        buf.put_u8(self.command);

        self.address.write_buf(buf, SocksAddrWireType::PortFirst)?;

        // add random bytes
        if padding_len > 0 {
            let mut padding_bytes = BytesMut::with_capacity(padding_len as usize);
            unsafe { padding_bytes.set_len(padding_len as usize) };
            let mut rng = StdRng::from_entropy();
            for i in 0..padding_bytes.len() {
                padding_bytes[i] = rng.gen();
            }
            buf.put_slice(&padding_bytes);
        }

        // checksum
        let mut hasher = Fnv1a::<u32>::default();
        hasher.write(&buf[auth_info.len()..]);
        let h = hasher.finish();
        let buf_size = buf.len();
        buf.resize(buf_size + 4, 0);
        BigEndian::write_u32(&mut buf[buf_size..], h);

        // iv for header encryption
        let mut tmp = [0u8; 8];
        BigEndian::write_u64(&mut tmp, timestamp as u64);
        let mut hasher = Md5::new();
        hasher.update(&tmp);
        hasher.update(&tmp);
        hasher.update(&tmp);
        hasher.update(&tmp);
        let iv = hasher.finalize();

        // key for header ecnryption
        let mut hasher = Md5::new();
        hasher.update(self.uuid.as_bytes());
        hasher.update(
            "c48619fe-8f02-49e0-b9e9-edf763e17e21"
                .to_string()
                .as_bytes(),
        );
        let key = hasher.finalize();

        // encrypt cmd part
        let mut enc =
            Cfb::<Aes128>::new_var(&key, &iv).map_err(|_| anyhow!("new aes128 enc failed"))?;
        enc.encrypt(&mut buf[auth_info.len()..]);
        Ok(())
    }
}

pub struct ClientSession {
    pub request_body_key: Vec<u8>,
    pub request_body_iv: Vec<u8>,
    pub response_body_key: Vec<u8>,
    pub response_body_iv: Vec<u8>,
    pub response_header: u8,
}

impl ClientSession {
    pub fn new() -> Self {
        let mut request_body_key = vec![0u8; 16];
        let mut request_body_iv = vec![0u8; 16];
        let response_header: u8;

        // fill random bytes
        let mut rand_bytes = BytesMut::with_capacity(16 + 16 + 1);
        unsafe { rand_bytes.set_len(16 + 16 + 1) };
        let mut rng = StdRng::from_entropy();
        for i in 0..rand_bytes.len() {
            rand_bytes[i] = rng.gen();
        }
        (&mut request_body_key[..]).copy_from_slice(&rand_bytes[..16]);
        (&mut request_body_iv[..]).copy_from_slice(&rand_bytes[16..32]);
        response_header = rand_bytes[32];

        let response_body_key = Md5::digest(&request_body_key).to_vec();
        let response_body_iv = Md5::digest(&request_body_iv).to_vec();

        ClientSession {
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            response_header,
        }
    }
}

pub struct VMessAEADSequence {
    nonce: Vec<u8>,
    size: usize,
    count: u16,
}

impl VMessAEADSequence {
    pub fn new(nonce: Vec<u8>, size: usize) -> Self {
        assert_eq!(nonce.len() >= size, true);
        VMessAEADSequence {
            nonce,
            size,
            count: 0xffff,
        }
    }

    fn inc(&mut self) {
        self.count = self.count.wrapping_add(1);
    }
}

impl NonceSequence for VMessAEADSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.inc();
        BigEndian::write_u16(&mut self.nonce, self.count);
        Nonce::try_assume_unique_for_key(&self.nonce[..self.size])
    }
}

pub struct ShakeSizeParser {
    shake_reader: sha3::Sha3XofReader,
    buf: [u8; 2],
}

impl ShakeSizeParser {
    pub fn new(nonce: &[u8]) -> Self {
        let mut shake = Shake128::default();
        digest::Update::update(&mut shake, nonce);
        let shake_reader = shake.finalize_xof_dirty();
        ShakeSizeParser {
            shake_reader,
            buf: [0, 0],
        }
    }

    pub fn size_bytes(&self) -> usize {
        2
    }

    fn next(&mut self) -> u16 {
        match self.shake_reader.read(&mut self.buf) {
            Ok(_) => (),
            Err(e) => {
                error!("read from shake reader failed: {}", e);
            }
        };
        BigEndian::read_u16(&self.buf)
    }

    pub fn decode(&mut self, b: &[u8]) -> u16 {
        assert_eq!(b.len() >= 2, true);
        let mask = self.next();
        let size = BigEndian::read_u16(b);
        mask ^ size
    }

    pub fn encode(&mut self, size: u16, b: &mut [u8]) {
        let mask = self.next();
        BigEndian::write_u16(b, mask ^ size);
    }
}

pub trait PaddingLengthGenerator {
    fn next_padding_len(&mut self) -> u16;
    fn max_padding_len(&self) -> u16;
}

impl PaddingLengthGenerator for ShakeSizeParser {
    fn next_padding_len(&mut self) -> u16 {
        self.next() % 64
    }

    fn max_padding_len(&self) -> u16 {
        64
    }
}

fn generate_chacha20poly1305_key(key: &[u8]) -> Vec<u8> {
    let key_1 = Md5::digest(&key).to_vec();
    let key_2 = Md5::digest(&key_1).to_vec();
    [key_1, key_2].concat()
}

pub fn new_encryptor(cipher: &str, key: &[u8], iv: &[u8]) -> Result<SealingKey<VMessAEADSequence>> {
    let key = generate_chacha20poly1305_key(key);
    let nonce = VMessAEADSequence::new(iv.to_vec(), NONCE_LEN);
    let unbound_key = if let Some(cipher) = common::crypto::AEAD_LIST.get(cipher) {
        let key = match UnboundKey::new(cipher, &key) {
            Ok(k) => k,
            Err(e) => {
                return Err(anyhow!(format!("new unbound key failed: {}", e)));
            }
        };
        key
    } else {
        return Err(anyhow!(format!("invalid cipher {}", cipher)));
    };
    Ok(SealingKey::new(unbound_key, nonce))
}

pub fn new_decryptor(cipher: &str, key: &[u8], iv: &[u8]) -> Result<OpeningKey<VMessAEADSequence>> {
    let key = generate_chacha20poly1305_key(key);
    let nonce = VMessAEADSequence::new(iv.to_vec(), NONCE_LEN);
    let unbound_key = if let Some(cipher) = common::crypto::AEAD_LIST.get(cipher) {
        let key = match UnboundKey::new(cipher, &key) {
            Ok(k) => k,
            Err(e) => {
                return Err(anyhow!(format!("new unbound key failed: {}", e)));
            }
        };
        key
    } else {
        return Err(anyhow!(format!("invalid cipher {}", cipher)));
    };
    Ok(OpeningKey::new(unbound_key, nonce))
}

enum ReadState {
    WaitingResponseHeader,
    WaitingLength,
    WaitingData(usize, usize),
    PendingData(usize),
}

enum WriteState {
    WaitingChunk,
    PendingChunk(usize, (usize, usize)),
}

pub struct VMessAuthStream<T> {
    inner: T,
    sess: ClientSession,
    enc: SealingKey<VMessAEADSequence>,
    enc_size_parser: ShakeSizeParser,
    dec: OpeningKey<VMessAEADSequence>,
    dec_size_parser: ShakeSizeParser,
    read_buf: BytesMut,
    write_buf: BytesMut,
    read_state: ReadState,
    write_state: WriteState,
    read_pos: usize,
}

impl<T> VMessAuthStream<T> {
    pub fn new(
        s: T,
        sess: ClientSession,
        enc: SealingKey<VMessAEADSequence>,
        enc_size_parser: ShakeSizeParser,
        dec: OpeningKey<VMessAEADSequence>,
        dec_size_parser: ShakeSizeParser,
    ) -> Self {
        VMessAuthStream {
            inner: s,
            sess,
            enc,
            enc_size_parser,
            dec,
            dec_size_parser,

            // never depend on these sizes, reserve when need
            read_buf: BytesMut::with_capacity(0x2 + 0x4000),
            write_buf: BytesMut::with_capacity(0x2 + 0x4000),

            read_state: ReadState::WaitingResponseHeader,
            write_state: WriteState::WaitingChunk,
            read_pos: 0,
        }
    }
}

trait ReadExt {
    fn poll_read_exact(&mut self, cx: &mut Context, size: usize) -> Poll<io::Result<()>>;
}

impl<T: AsyncRead + Unpin> ReadExt for VMessAuthStream<T> {
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

impl<T: AsyncRead + Unpin> AsyncRead for VMessAuthStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.read_state {
                ReadState::WaitingResponseHeader => {
                    let me = &mut *self;
                    ready!(me.poll_read_exact(cx, 4))?;
                    let mut enc = Cfb::<Aes128>::new_var(
                        &me.sess.response_body_key,
                        &me.sess.response_body_iv,
                    )
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "crypto error"))?;
                    enc.decrypt(&mut me.read_buf[..4]);

                    if me.read_buf[0] != me.sess.response_header {
                        return Poll::Ready(Err(crypto_err()));
                    }

                    // ready to read data chunks
                    me.read_state = ReadState::WaitingLength;
                }
                ReadState::WaitingLength => {
                    // read and decode payload length
                    let me = &mut *self;
                    let size_bytes = me.dec_size_parser.size_bytes();
                    ready!(me.poll_read_exact(cx, size_bytes))?;
                    let padding_size = me.dec_size_parser.next_padding_len() as usize;
                    let size = me.dec_size_parser.decode(&me.read_buf[..size_bytes]) as usize;

                    // ready to read payload
                    me.read_state = ReadState::WaitingData(size, padding_size);
                }
                ReadState::WaitingData(size, padding_size) => {
                    // read and decipher payload
                    let me = &mut *self;
                    ready!(me.poll_read_exact(cx, size))?;
                    let encrypted_size = size - padding_size;
                    let _ = me.read_buf.split_off(encrypted_size); // trim padding
                    me.dec
                        .open_within(Aad::empty(), &mut me.read_buf, 0..)
                        .map_err(|_| crypto_err())?;

                    // ready to read plaintext payload into buf
                    me.read_state =
                        ReadState::PendingData(encrypted_size - me.dec.algorithm().tag_len());
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

impl<T: AsyncWrite + Unpin> AsyncWrite for VMessAuthStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.write_state {
                WriteState::WaitingChunk => {
                    let me = &mut *self;
                    let tag_len = me.enc.algorithm().tag_len();
                    let padding_size = me.enc_size_parser.next_padding_len() as usize;
                    let max_payload_size = 0x4000 - tag_len - padding_size;
                    let consume_len = min(buf.len(), max_payload_size);
                    let payload_len = consume_len + tag_len + padding_size;

                    // encode size
                    let size_bytes = me.enc_size_parser.size_bytes();
                    me.write_buf.resize(size_bytes, 0);
                    me.enc_size_parser
                        .encode(payload_len as u16, &mut me.write_buf);

                    let mut piece2 = me.write_buf.split_off(size_bytes);

                    // seal payload
                    piece2.reserve(consume_len + tag_len);
                    piece2.put_slice(&buf[..consume_len]);
                    me.enc
                        .seal_in_place_append_tag(Aad::empty(), &mut piece2)
                        .map_err(|_| crypto_err())?;

                    let mut piece3 = piece2.split_off(consume_len + tag_len);

                    // add random paddings
                    if padding_size > 0 {
                        piece3.resize(padding_size, 0);
                        let mut rng = StdRng::from_entropy();
                        for i in 0..piece3.len() {
                            piece3[i] = rng.gen();
                        }
                    }

                    piece2.unsplit(piece3);
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
