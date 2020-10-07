use std::collections::HashMap;

use lazy_static::lazy_static;
use ring::aead::{self, Algorithm};

lazy_static! {
    pub static ref AEAD_LIST: HashMap<&'static str, &'static Algorithm> = {
        let mut m = HashMap::new();
        m.insert("chacha20-poly1305", &aead::CHACHA20_POLY1305);
        m.insert("chacha20-ietf-poly1305", &aead::CHACHA20_POLY1305);
        m.insert("aes-128-gcm", &aead::AES_128_GCM);
        m.insert("aes-256-gcm", &aead::AES_256_GCM);
        m
    };
}
