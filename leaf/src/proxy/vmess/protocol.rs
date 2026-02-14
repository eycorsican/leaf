use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{AsyncStreamCipher, BlockEncrypt, KeyInit, KeyIvInit};
use aes::Aes128;
use aes_gcm::{AeadInPlace, Aes128Gcm};
use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use hmac::{Hmac, Mac};
use lz_fnv::{Fnv1a, FnvHasher};
use md5::{Digest, Md5};
use rand::RngCore;
use rand::{rngs::StdRng, Rng, SeedableRng};
use uuid::Uuid;

use crate::session::{SocksAddr, SocksAddrWireType};

use super::kdf::{self, *};

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

    fn create_auth_id(key: &[u8], ts: i64) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        buf.put_i64(ts);
        let mut rng = StdRng::from_entropy();
        let rand_bytes: [u8; 4] = rng.gen();
        buf.put_slice(&rand_bytes);
        buf.put_u32(crc32fast::hash(&buf));
        let cipher = Aes128::new_from_slice(
            &kdf::vmess_kdf_1_one_shot(key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY)[..16],
        )?;
        cipher.encrypt_block((&mut buf[..]).into());
        Ok(buf.into())
    }

    fn seal_vmess_aead_header(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let generated_auth_id = Self::create_auth_id(key, ts as i64)?;
        let mut connection_nonce = vec![0u8; 8];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut connection_nonce[..]);

        let mut aead_payload_length_serialize_buffer = BytesMut::new();
        aead_payload_length_serialize_buffer.put_u16(data.len() as u16);
        let payload_header_length_aead_key = &kdf::vmess_kdf_3_one_shot(
            key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &generated_auth_id,
            &connection_nonce,
        )[..16];
        let payload_header_length_aead_nonce = &kdf::vmess_kdf_3_one_shot(
            key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &generated_auth_id,
            &connection_nonce,
        )[..12];
        let cipher = Aes128Gcm::new_from_slice(payload_header_length_aead_key)?;
        let tag = cipher
            .encrypt_in_place_detached(
                payload_header_length_aead_nonce.into(),
                &generated_auth_id,
                &mut aead_payload_length_serialize_buffer[..],
            )
            .map_err(|_| anyhow!("crypto error"))?;
        aead_payload_length_serialize_buffer.put_slice(&tag);

        let mut data_out = BytesMut::new();
        data_out.put_slice(data);
        let payload_header_aead_key = &kdf::vmess_kdf_3_one_shot(
            key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &generated_auth_id,
            &connection_nonce,
        )[..16];
        let payload_header_aead_nonce = &kdf::vmess_kdf_3_one_shot(
            key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &generated_auth_id,
            &connection_nonce,
        )[..12];
        let cipher = Aes128Gcm::new_from_slice(payload_header_aead_key)
            .map_err(|_| anyhow!("crypto error"))?;
        let tag = cipher
            .encrypt_in_place_detached(
                payload_header_aead_nonce.into(),
                &generated_auth_id,
                &mut data_out[..],
            )
            .map_err(|_| anyhow!("crypto error"))?;
        data_out.put_slice(&tag);

        let mut out = BytesMut::new();
        out.put_slice(&generated_auth_id);
        out.put_slice(&aead_payload_length_serialize_buffer);
        out.put_slice(&connection_nonce);
        out.put_slice(&data_out);
        Ok(out.into())
    }

    pub fn encode(&self, buf: &mut BytesMut, sess: &ClientSession) -> Result<()> {
        let mut auth_info_len = 0;

        let mut timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => return Err(anyhow!("invalid system time")),
        };

        if !sess.aead {
            let mut rng = StdRng::from_entropy();
            let delta: i32 = rng.gen_range(0..30 * 2) - 30;
            timestamp = timestamp.wrapping_add(delta as u64);
            let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(self.uuid.as_bytes())
                .map_err(|_| anyhow!("md5 failed"))?;
            let mut tmp = [0u8; 8];
            BigEndian::write_u64(&mut tmp, timestamp as u64);
            mac.update(&tmp);
            let auth_info = mac.finalize().into_bytes();

            buf.put_slice(&auth_info[..]);
            auth_info_len = auth_info.len();
        }

        buf.put_u8(self.version);
        buf.put_slice(&sess.request_body_iv);
        buf.put_slice(&sess.request_body_key);
        buf.put_u8(sess.response_header);
        buf.put_u8(self.option);

        let padding_len = StdRng::from_entropy().gen_range(0..16) as u8;
        let security = (padding_len << 4) | self.security;

        buf.put_u8(security);
        buf.put_u8(0);
        buf.put_u8(self.command);

        self.address.write_buf(buf, SocksAddrWireType::PortFirst);

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
        hasher.write(&buf[auth_info_len..]);
        let h = hasher.finish();
        let buf_size = buf.len();
        buf.resize(buf_size + 4, 0);
        BigEndian::write_u32(&mut buf[buf_size..], h);

        let mut hasher = Md5::new();
        hasher.update(self.uuid.as_bytes());
        hasher.update(
            "c48619fe-8f02-49e0-b9e9-edf763e17e21"
                .to_string()
                .as_bytes(),
        );
        let key = hasher.finalize();

        if sess.aead {
            let out = Self::seal_vmess_aead_header(&key[..16], &buf)?;
            buf.clear();
            buf.extend_from_slice(&out);
        } else {
            let mut tmp = [0u8; 8];
            BigEndian::write_u64(&mut tmp, timestamp as u64);
            let mut hasher = Md5::new();
            hasher.update(tmp);
            hasher.update(tmp);
            hasher.update(tmp);
            hasher.update(tmp);
            let iv = hasher.finalize();

            cfb_mode::Encryptor::<aes::Aes128>::new(&key, &iv).encrypt(&mut buf[auth_info_len..]);
        }
        Ok(())
    }
}

pub struct ClientSession {
    pub request_body_key: Vec<u8>,
    pub request_body_iv: Vec<u8>,
    pub response_body_key: Vec<u8>,
    pub response_body_iv: Vec<u8>,
    pub response_header: u8,
    pub aead: bool,
}

impl ClientSession {
    pub fn new(aead: bool) -> Self {
        let mut request_body_key = vec![0u8; 16];
        let mut request_body_iv = vec![0u8; 16];

        // fill random bytes
        let mut rand_bytes = BytesMut::with_capacity(16 + 16 + 1);
        unsafe { rand_bytes.set_len(16 + 16 + 1) };
        let mut rng = StdRng::from_entropy();
        for i in 0..rand_bytes.len() {
            rand_bytes[i] = rng.gen();
        }
        request_body_key[..].copy_from_slice(&rand_bytes[..16]);
        request_body_iv[..].copy_from_slice(&rand_bytes[16..32]);
        let response_header: u8 = rand_bytes[32];

        let (response_body_key, response_body_iv) = if !aead {
            (
                Md5::digest(&request_body_key).to_vec(),
                Md5::digest(&request_body_iv).to_vec(),
            )
        } else {
            let key_hash = sha2::Sha256::digest(&request_body_key);
            let iv_hash = sha2::Sha256::digest(&request_body_iv);
            (key_hash[..16].to_vec(), iv_hash[..16].to_vec())
        };

        ClientSession {
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            response_header,
            aead,
        }
    }
}
