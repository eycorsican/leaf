use std::io::Read;

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use digest::ExtendableOutputDirty;
use log::*;
use md5::{Digest, Md5};
use sha3::Shake128;

use crate::common::crypto::{
    aead::{AeadCipher, AeadDecryptor, AeadEncryptor},
    Cipher, NonceSequence, SizedCipher,
};

pub fn generate_chacha20poly1305_key(key: &[u8]) -> Vec<u8> {
    let key_1 = Md5::digest(key).to_vec();
    let key_2 = Md5::digest(&key_1).to_vec();
    [key_1, key_2].concat()
}

pub fn new_encryptor(
    cipher: &str,
    key: &[u8],
    iv: &[u8],
) -> Result<AeadEncryptor<VMessAEADSequence>> {
    let aead_cipher = AeadCipher::new(cipher)?;
    let key = match cipher.to_lowercase().as_str() {
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => generate_chacha20poly1305_key(key),
        "aes-128-gcm" => key.to_vec(),
        _ => return Err(anyhow!("unsupported cipher: {}", cipher)),
    };
    let nonce = VMessAEADSequence::new(iv.to_vec(), aead_cipher.nonce_len());
    let enc = aead_cipher.encryptor(&key, nonce)?;
    Ok(enc)
}

pub fn new_decryptor(
    cipher: &str,
    key: &[u8],
    iv: &[u8],
) -> Result<AeadDecryptor<VMessAEADSequence>> {
    let aead_cipher = AeadCipher::new(cipher)?;
    let key = match cipher.to_lowercase().as_str() {
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => generate_chacha20poly1305_key(key),
        "aes-128-gcm" => key.to_vec(),
        _ => return Err(anyhow!("unsupported cipher: {}", cipher)),
    };
    let nonce = VMessAEADSequence::new(iv.to_vec(), aead_cipher.nonce_len());
    let dec = aead_cipher.decryptor(&key, nonce)?;
    Ok(dec)
}

pub struct VMessAEADSequence {
    nonce: Vec<u8>,
    size: usize,
    count: u16,
}

impl VMessAEADSequence {
    pub fn new(nonce: Vec<u8>, size: usize) -> Self {
        assert!(nonce.len() >= size);
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
    fn advance(&mut self) -> Result<Vec<u8>> {
        self.inc();
        BigEndian::write_u16(&mut self.nonce, self.count);
        Ok(self.nonce[..self.size].to_vec())
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
        assert!(b.len() >= 2);
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
