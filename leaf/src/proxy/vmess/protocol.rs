use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use cfb_mode::cipher::{NewStreamCipher, StreamCipher};
use cfb_mode::Cfb;
use hmac::{Hmac, Mac, NewMac};
use lz_fnv::{Fnv1a, FnvHasher};
use md5::{Digest, Md5};
use rand::{rngs::StdRng, Rng, SeedableRng};
use uuid::Uuid;

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

    pub fn encode(&self, buf: &mut BytesMut, sess: &ClientSession) -> Result<()> {
        // generate auth info
        let mut timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => return Err(anyhow!("invalid system time")),
        };
        let mut rng = StdRng::from_entropy();
        let delta: i32 = rng.gen_range(0..30 * 2) - 30;
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

        let padding_len = StdRng::from_entropy().gen_range(0..16) as u8;
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
