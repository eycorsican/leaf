use std::{collections::HashMap, convert::From};

use anyhow::anyhow;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use lazy_static::lazy_static;
use md5::{Digest, Md5};
use ring::{
    aead::{
        self, Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
        NONCE_LEN,
    },
    error::Unspecified,
};
use sha1::Sha1;

struct AeadAlgorithm {
    key_size: usize,
    salt_size: usize,
    algorithm: &'static Algorithm,
}

lazy_static! {
    static ref AEAD_LIST: HashMap<&'static str, AeadAlgorithm> = {
        let mut m = HashMap::new();
        m.insert(
            "chacha20-poly1305",
            AeadAlgorithm {
                key_size: 32,
                salt_size: 32,
                algorithm: &aead::CHACHA20_POLY1305,
            },
        );
        m.insert(
            "chacha20-ietf-poly1305",
            AeadAlgorithm {
                key_size: 32,
                salt_size: 32,
                algorithm: &aead::CHACHA20_POLY1305,
            },
        );
        m.insert(
            "aes-256-gcm",
            AeadAlgorithm {
                key_size: 32,
                salt_size: 32,
                algorithm: &aead::AES_256_GCM,
            },
        );
        m.insert(
            "aes-128-gcm",
            AeadAlgorithm {
                key_size: 16,
                salt_size: 16,
                algorithm: &aead::AES_128_GCM,
            },
        );
        m
    };
}

pub fn list_ciphers() {
    for key in AEAD_LIST.keys() {
        println!("{}", key);
    }
}

pub trait Cipher: Sync + Send + Unpin {
    fn key_size(&self) -> usize;
    fn salt_size(&self) -> usize;
    fn tag_len(&self) -> usize;
    fn encryptor(&self, salt: &[u8]) -> Result<Box<dyn Encryptor>>;
    fn decryptor(&self, salt: &[u8]) -> Result<Box<dyn Decryptor>>;
}

pub struct AeadCipher {
    psk: Bytes,
    key_size: usize,
    salt_size: usize,
    algorithm: &'static Algorithm,
}

impl AeadCipher {
    pub fn new(cipher: &str, password: &str) -> Option<Self> {
        let (ks, ss, alg) = if let Some(v) = AEAD_LIST.get(cipher) {
            (v.key_size, v.salt_size, v.algorithm)
        } else {
            return None;
        };
        let psk = match kdf(password, ks) {
            Ok(k) => k,
            Err(_) => return None,
        };
        Some(AeadCipher {
            psk: Bytes::from(psk),
            key_size: ks,
            salt_size: ss,
            algorithm: alg,
        })
    }
}

impl Cipher for AeadCipher {
    fn key_size(&self) -> usize {
        self.key_size
    }

    fn salt_size(&self) -> usize {
        self.salt_size
    }

    fn tag_len(&self) -> usize {
        self.algorithm.tag_len()
    }

    fn encryptor(&self, salt: &[u8]) -> Result<Box<dyn Encryptor>> {
        let subkey = hkdf_sha1(
            self.psk.as_ref(),
            salt,
            String::from("ss-subkey").as_bytes().to_vec(),
            self.key_size,
        )?;
        let unbound_key = UnboundKey::new(self.algorithm, &subkey)
            .map_err(|_| anyhow!("new unbound key failed"))?;
        let nonce = IncSequence::new(NONCE_LEN);
        Ok(Box::new(AeadEncryptor(SealingKey::new(unbound_key, nonce))))
    }

    fn decryptor(&self, salt: &[u8]) -> Result<Box<dyn Decryptor>> {
        let subkey = hkdf_sha1(
            self.psk.as_ref(),
            salt,
            String::from("ss-subkey").as_bytes().to_vec(),
            self.key_size,
        )?;
        let unbound_key = UnboundKey::new(&self.algorithm, &subkey)
            .map_err(|_| anyhow!("new unbound key failed"))?;
        let nonce = IncSequence::new(NONCE_LEN);
        Ok(Box::new(AeadDecryptor(OpeningKey::new(unbound_key, nonce))))
    }
}

const CRYPTO_ERROR: &str = "crypto error";

pub trait Encryptor: Sync + Send + Unpin {
    fn encrypt(&mut self, in_out: &mut BytesMut) -> Result<()>;
    fn tag_len(&self) -> usize;
}

struct AeadEncryptor(SealingKey<IncSequence>);

impl Encryptor for AeadEncryptor {
    fn encrypt(&mut self, in_out: &mut BytesMut) -> Result<()> {
        self.0
            .seal_in_place_append_tag(Aad::empty(), in_out)
            .map_err(|_| anyhow!(CRYPTO_ERROR))?;
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.0.algorithm().tag_len()
    }
}

pub trait Decryptor: Sync + Send + Unpin {
    fn decrypt(&mut self, in_out: &mut BytesMut) -> Result<()>;
    fn tag_len(&self) -> usize;
}

struct AeadDecryptor(OpeningKey<IncSequence>);

impl Decryptor for AeadDecryptor {
    fn decrypt(&mut self, in_out: &mut BytesMut) -> Result<()> {
        self.0
            .open_within(Aad::empty(), in_out, 0..)
            .map_err(|_| anyhow!(CRYPTO_ERROR))?;
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.0.algorithm().tag_len()
    }
}

pub struct IncSequence {
    counter: Vec<u8>,
}

impl IncSequence {
    fn new(size: usize) -> Self {
        let mut c = Vec::new();
        for _ in 0..size {
            c.push(0xff);
        }
        IncSequence { counter: c }
    }

    fn inc(&mut self) {
        for x in &mut self.counter {
            *x = (*x).wrapping_add(1);
            if *x != 0 {
                return;
            }
        }
    }
}

impl NonceSequence for IncSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.inc();
        Nonce::try_assume_unique_for_key(&self.counter)
    }
}

fn kdf(pass: &str, size: usize) -> Result<Vec<u8>> {
    let pass = pass.as_bytes();
    let mut key = Vec::new();
    let mut sum = Md5::digest(pass).to_vec();
    std::io::Write::write(&mut key, &sum)?;
    while key.len() < size {
        sum = Md5::digest(&[sum, pass.to_vec()].concat()).to_vec();
        std::io::Write::write(&mut key, &sum)?;
    }
    Ok(key)
}

fn hkdf_sha1(key: &[u8], salt: &[u8], info: Vec<u8>, size: usize) -> Result<Vec<u8>> {
    let (_, h) = Hkdf::<Sha1>::extract(Some(salt), key);
    let mut okm = vec![0u8; size];
    h.expand(&info, &mut okm)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok(okm.to_vec())
}
