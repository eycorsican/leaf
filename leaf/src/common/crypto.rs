use std::collections::HashMap;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;

pub trait Cipher<N>: Sync + Send + Unpin
where
    N: NonceSequence,
{
    type Enc;
    type Dec;

    fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc>;
    fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec>;
}

pub trait SizedCipher {
    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;

    fn tag_len(&self) -> usize {
        // All AEAD ciphers we support use 128-bit tags.
        16
    }
}

pub trait Encryptor: Sync + Send + Unpin {
    fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
    where
        InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>;
}

pub trait Decryptor: Sync + Send + Unpin {
    fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
    where
        InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>;
}

pub trait NonceSequence: Sync + Send + Unpin {
    fn advance(&mut self) -> Result<Vec<u8>>;
}

#[cfg(feature = "openssl-aead")]
pub mod aead {
    use openssl::symm;

    use super::*;

    lazy_static! {
        static ref AEAD_LIST: HashMap<&'static str, symm::Cipher> = {
            let mut m = HashMap::new();
            m.insert("chacha20-poly1305", symm::Cipher::chacha20_poly1305());
            m.insert("chacha20-ietf-poly1305", symm::Cipher::chacha20_poly1305());
            m.insert("aes-256-gcm", symm::Cipher::aes_256_gcm());
            m.insert("aes-128-gcm", symm::Cipher::aes_128_gcm());
            m
        };
    }

    pub struct AeadCipher {
        cipher: symm::Cipher,
    }

    impl AeadCipher {
        pub fn new(cipher: &str) -> Result<Self> {
            let alg = match AEAD_LIST.get(cipher) {
                Some(v) => v,
                None => return Err(anyhow!("unsupported cipher: {}", cipher)),
            };
            Ok(AeadCipher { cipher: *alg })
        }
    }

    impl<N> Cipher<N> for AeadCipher
    where
        N: 'static + NonceSequence,
    {
        type Enc = AeadEncryptor<N>;
        type Dec = AeadDecryptor<N>;

        fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc> {
            Ok(AeadEncryptor::new(
                self.cipher,
                key.to_vec(),
                nonce,
                self.tag_len(),
            ))
        }

        fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec> {
            Ok(AeadDecryptor::new(
                self.cipher,
                key.to_vec(),
                nonce,
                self.tag_len(),
            ))
        }
    }

    impl SizedCipher for AeadCipher {
        fn key_len(&self) -> usize {
            self.cipher.key_len()
        }

        fn nonce_len(&self) -> usize {
            // All AEAD ciphers use IV.
            self.cipher.iv_len().unwrap()
        }
    }

    pub struct AeadEncryptor<N> {
        cipher: symm::Cipher,
        key: Vec<u8>,
        nonce: N,
        tag_len: usize,
    }

    impl<N> AeadEncryptor<N>
    where
        N: NonceSequence,
    {
        pub fn new(cipher: symm::Cipher, key: Vec<u8>, nonce: N, tag_len: usize) -> Self {
            AeadEncryptor {
                cipher,
                key,
                nonce,
                tag_len,
            }
        }
    }

    impl<N> Encryptor for AeadEncryptor<N>
    where
        N: NonceSequence,
    {
        fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            let mut tag = vec![0u8; self.tag_len];
            // TODO in-place?
            let ciphertext = symm::encrypt_aead(
                self.cipher,
                &self.key,
                Some(&nonce),
                &[],
                in_out.as_ref(),
                &mut tag,
            )
            .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            (&mut in_out.as_mut()[..ciphertext.len()]).copy_from_slice(&ciphertext);
            in_out.extend(&tag);
            Ok(())
        }
    }

    pub struct AeadDecryptor<N> {
        cipher: symm::Cipher,
        key: Vec<u8>,
        nonce: N,
        tag_len: usize,
    }

    impl<N> AeadDecryptor<N>
    where
        N: NonceSequence,
    {
        pub fn new(cipher: symm::Cipher, key: Vec<u8>, nonce: N, tag_len: usize) -> Self {
            AeadDecryptor {
                cipher,
                key,
                nonce,
                tag_len,
            }
        }
    }

    impl<N> Decryptor for AeadDecryptor<N>
    where
        N: NonceSequence,
    {
        fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("decrypt failed: {}", e))?;
            let in_out_ref = in_out.as_ref();
            let data = &in_out_ref[..in_out_ref.len() - self.tag_len];
            let tag = &in_out_ref[in_out_ref.len() - self.tag_len..];
            // TODO in-place?
            let plaintext =
                symm::decrypt_aead(self.cipher, &self.key, Some(&nonce), &[], data, tag)
                    .map_err(|e| anyhow!("decrypt failed: {}", e))?;
            (&mut in_out.as_mut()[..plaintext.len()]).copy_from_slice(&plaintext);
            Ok(())
        }
    }
}

// BoringSSL (feature `boring-aead`): its EVP_AEAD interface, in place.
#[cfg(all(feature = "boring-aead", not(feature = "openssl-aead")))]
pub mod aead {
    use boring::aead::{AeadCtx, Algorithm};

    use super::*;

    lazy_static! {
        static ref AEAD_LIST: HashMap<&'static str, Algorithm> = {
            let mut m = HashMap::new();
            m.insert("chacha20-poly1305", Algorithm::chacha20_poly1305());
            m.insert("chacha20-ietf-poly1305", Algorithm::chacha20_poly1305());
            m.insert("aes-256-gcm", Algorithm::aes_256_gcm());
            m.insert("aes-128-gcm", Algorithm::aes_128_gcm());
            m
        };
    }

    pub struct AeadCipher {
        algorithm: Algorithm,
    }

    impl AeadCipher {
        pub fn new(cipher: &str) -> Result<Self> {
            let alg = match AEAD_LIST.get(cipher) {
                Some(v) => v,
                None => return Err(anyhow!("unsupported cipher: {}", cipher)),
            };
            Ok(AeadCipher { algorithm: *alg })
        }

        fn ctx(&self, key: &[u8]) -> Result<AeadCtx> {
            AeadCtx::new(&self.algorithm, key, self.tag_len())
                .map_err(|e| anyhow!("new aead key failed: {}", e))
        }
    }

    impl<N> Cipher<N> for AeadCipher
    where
        N: 'static + NonceSequence,
    {
        type Enc = AeadEncryptor<N>;
        type Dec = AeadDecryptor<N>;

        fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc> {
            Ok(AeadEncryptor {
                ctx: self.ctx(key)?,
                nonce,
                tag_len: self.tag_len(),
            })
        }

        fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec> {
            Ok(AeadDecryptor {
                ctx: self.ctx(key)?,
                nonce,
                tag_len: self.tag_len(),
            })
        }
    }

    impl SizedCipher for AeadCipher {
        fn key_len(&self) -> usize {
            self.algorithm.key_length()
        }

        fn nonce_len(&self) -> usize {
            self.algorithm.nonce_len()
        }
    }

    pub struct AeadEncryptor<N> {
        ctx: AeadCtx,
        nonce: N,
        tag_len: usize,
    }

    impl<N> Encryptor for AeadEncryptor<N>
    where
        N: NonceSequence,
    {
        fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            let mut tag = [0u8; 16];
            let tag = self
                .ctx
                .seal_in_place_mut(&nonce, in_out.as_mut(), &mut tag[..self.tag_len], &[])
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            in_out.extend(&*tag);
            Ok(())
        }
    }

    pub struct AeadDecryptor<N> {
        ctx: AeadCtx,
        nonce: N,
        tag_len: usize,
    }

    impl<N> Decryptor for AeadDecryptor<N>
    where
        N: NonceSequence,
    {
        fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("decrypt failed: {}", e))?;
            let buf = in_out.as_mut();
            let data_len = buf
                .len()
                .checked_sub(self.tag_len)
                .ok_or_else(|| anyhow!("decrypt failed: input shorter than the tag"))?;
            let (data, tag) = buf.split_at_mut(data_len);
            self.ctx
                .open_in_place_mut(&nonce, data, tag, &[])
                .map_err(|e| anyhow!("decrypt failed: {}", e))?;
            Ok(())
        }
    }
}

#[cfg(all(
    any(feature = "aws-lc-aead", feature = "ring-aead"),
    not(any(feature = "openssl-aead", feature = "boring-aead"))
))]
pub mod aead {
    #[cfg(feature = "aws-lc-aead")]
    use aws_lc_rs::aead::{self, Aad, Algorithm, LessSafeKey, Nonce, UnboundKey};
    #[cfg(all(feature = "ring-aead", not(feature = "aws-lc-aead")))]
    use ring::aead::{self, Aad, Algorithm, LessSafeKey, Nonce, UnboundKey};

    use super::*;

    lazy_static! {
        static ref AEAD_LIST: HashMap<&'static str, &'static Algorithm> = {
            let mut m = HashMap::new();
            m.insert("chacha20-poly1305", &aead::CHACHA20_POLY1305);
            m.insert("chacha20-ietf-poly1305", &aead::CHACHA20_POLY1305);
            m.insert("aes-256-gcm", &aead::AES_256_GCM);
            m.insert("aes-128-gcm", &aead::AES_128_GCM);
            m
        };
    }

    pub struct AeadCipher {
        algorithm: &'static Algorithm,
    }

    impl AeadCipher {
        pub fn new(cipher: &str) -> Result<Self> {
            let alg = match AEAD_LIST.get(cipher) {
                Some(v) => v,
                None => return Err(anyhow!("unsupported cipher: {}", cipher)),
            };
            Ok(AeadCipher { algorithm: alg })
        }
    }

    impl<N> Cipher<N> for AeadCipher
    where
        N: 'static + NonceSequence,
    {
        type Enc = AeadEncryptor<N>;
        type Dec = AeadDecryptor<N>;

        fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc> {
            let unbound_key = UnboundKey::new(self.algorithm, key)
                .map_err(|e| anyhow!("new unbound key failed: {}", e))?;
            let enc = AeadEncryptor {
                enc: LessSafeKey::new(unbound_key),
                nonce,
            };
            Ok(enc)
        }

        fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec> {
            let unbound_key = UnboundKey::new(self.algorithm, key)
                .map_err(|e| anyhow!("new unbound key failed: {}", e))?;
            let enc = AeadDecryptor {
                enc: LessSafeKey::new(unbound_key),
                nonce,
            };
            Ok(enc)
        }
    }

    impl SizedCipher for AeadCipher {
        fn key_len(&self) -> usize {
            self.algorithm.key_len()
        }

        fn nonce_len(&self) -> usize {
            self.algorithm.nonce_len()
        }
    }

    pub struct AeadEncryptor<N> {
        enc: LessSafeKey,
        nonce: N,
    }

    impl<N> AeadEncryptor<N>
    where
        N: NonceSequence,
    {
        pub fn new(enc: LessSafeKey, nonce: N) -> Self {
            AeadEncryptor { enc, nonce }
        }
    }

    impl<N> Encryptor for AeadEncryptor<N>
    where
        N: NonceSequence,
    {
        fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            let nonce = Nonce::try_assume_unique_for_key(&nonce)
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            self.enc
                .seal_in_place_append_tag(nonce, Aad::empty(), in_out)
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            Ok(())
        }
    }

    pub struct AeadDecryptor<N> {
        enc: LessSafeKey,
        nonce: N,
    }

    impl<N> AeadDecryptor<N>
    where
        N: NonceSequence,
    {
        pub fn new(enc: LessSafeKey, nonce: N) -> Self {
            AeadDecryptor { enc, nonce }
        }
    }

    impl<N> Decryptor for AeadDecryptor<N>
    where
        N: NonceSequence,
    {
        fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            let nonce = Nonce::try_assume_unique_for_key(&nonce)
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            self.enc
                .open_within(nonce, Aad::empty(), in_out.as_mut(), 0..)
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(
        feature = "aws-lc-aead",
        feature = "ring-aead",
        feature = "openssl-aead",
        feature = "boring-aead"
    ))]
    fn test_aead_enc_dec() {
        struct ShadowsocksNonceSequence(Vec<u8>);

        impl ShadowsocksNonceSequence {
            fn new(size: usize) -> Self {
                let mut c = Vec::new();
                for _ in 0..size {
                    c.push(0xff);
                }
                ShadowsocksNonceSequence(c)
            }

            fn inc(&mut self) {
                for x in &mut self.0 {
                    *x = (*x).wrapping_add(1);
                    if *x != 0 {
                        return;
                    }
                }
            }
        }

        impl NonceSequence for ShadowsocksNonceSequence {
            fn advance(&mut self) -> Result<Vec<u8>> {
                self.inc();
                Ok(self.0.clone())
            }
        }
        let plaintext = b"Hello, world!";
        let cipher = aead::AeadCipher::new("chacha20-poly1305").unwrap();
        let key = vec![0u8; cipher.key_len()];

        let mut buf = Vec::new();
        buf.extend_from_slice(plaintext);

        let nonce = ShadowsocksNonceSequence::new(cipher.nonce_len());
        let mut enc = cipher.encryptor(&key, nonce).unwrap();
        enc.encrypt(&mut buf).unwrap();

        let dec_nonce = ShadowsocksNonceSequence::new(cipher.nonce_len());
        let mut dec = cipher.decryptor(&key, dec_nonce).unwrap();
        dec.decrypt(&mut buf).unwrap();

        assert_eq!(&buf[..plaintext.len()], plaintext);
    }

    #[cfg(any(
        feature = "aws-lc-aead",
        feature = "ring-aead",
        feature = "openssl-aead",
        feature = "boring-aead"
    ))]
    struct FixedNonce(Vec<u8>);

    #[cfg(any(
        feature = "aws-lc-aead",
        feature = "ring-aead",
        feature = "openssl-aead",
        feature = "boring-aead"
    ))]
    impl NonceSequence for FixedNonce {
        fn advance(&mut self) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    #[cfg(any(
        feature = "aws-lc-aead",
        feature = "ring-aead",
        feature = "openssl-aead",
        feature = "boring-aead"
    ))]
    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Known answers with an empty AAD, as leaf uses the ciphers: AES-GCM
    /// from the GCM specification (test cases 2 and 14), ChaCha20-Poly1305
    /// agreed by the ring, aws-lc and BoringSSL backends. Each case also
    /// decrypts, and a flipped bit is refused.
    #[test]
    #[cfg(any(
        feature = "aws-lc-aead",
        feature = "ring-aead",
        feature = "openssl-aead",
        feature = "boring-aead"
    ))]
    fn test_aead_known_answers() {
        let chacha_plaintext = b"leaf shadowsocks aead known answer".to_vec();
        // (cipher, key, nonce, plaintext, ciphertext and tag)
        type Case = (&'static str, Vec<u8>, Vec<u8>, Vec<u8>, &'static str);
        let cases: Vec<Case> = vec![
            (
                "aes-128-gcm",
                vec![0; 16],
                vec![0; 12],
                vec![0; 16],
                "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
            ),
            (
                "aes-256-gcm",
                vec![0; 32],
                vec![0; 12],
                vec![0; 16],
                "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
            ),
            (
                "chacha20-ietf-poly1305",
                (0..32).collect(),
                (0..12).collect(),
                chacha_plaintext.clone(),
                CHACHA_ANSWER,
            ),
            (
                "chacha20-poly1305",
                (0..32).collect(),
                (0..12).collect(),
                chacha_plaintext,
                CHACHA_ANSWER,
            ),
        ];
        for (name, key, nonce, plaintext, answer) in cases {
            let cipher = aead::AeadCipher::new(name).unwrap();
            assert_eq!(cipher.key_len(), key.len(), "{}", name);
            assert_eq!(cipher.nonce_len(), nonce.len(), "{}", name);
            let mut buf = plaintext.clone();
            let mut enc = cipher.encryptor(&key, FixedNonce(nonce.clone())).unwrap();
            enc.encrypt(&mut buf).unwrap();
            assert_eq!(hex(&buf), answer, "{}", name);

            let mut dec = cipher.decryptor(&key, FixedNonce(nonce.clone())).unwrap();
            let mut opened = buf.clone();
            dec.decrypt(&mut opened).unwrap();
            assert_eq!(&opened[..plaintext.len()], &plaintext[..], "{}", name);

            let mut dec = cipher.decryptor(&key, FixedNonce(nonce)).unwrap();
            buf[0] ^= 1;
            assert!(dec.decrypt(&mut buf).is_err(), "{}: tampered", name);
        }
        assert!(aead::AeadCipher::new("aes-192-gcm").is_err());
    }

    #[cfg(any(
        feature = "aws-lc-aead",
        feature = "ring-aead",
        feature = "openssl-aead",
        feature = "boring-aead"
    ))]
    const CHACHA_ANSWER: &str =
        "e59e69660964cd21d3ec4880f77e6510e911d7863554c6d789e041e514aed54b89f202becb929903f72f94d3627b8e329f09";
}
