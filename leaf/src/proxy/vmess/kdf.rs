use hmac::Hmac;
use hmac::Mac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

pub const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &[u8; 22] = b"AES Auth ID Encryption";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8; 24] = b"AEAD Resp Header Len Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8; 23] = b"AEAD Resp Header Len IV";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8; 20] = b"AEAD Resp Header Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8; 19] = b"AEAD Resp Header IV";
pub const KDF_SALT_CONST_VMESS_AEAD_KDF: &[u8; 14] = b"VMess AEAD KDF";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8; 21] = b"VMess Header AEAD Key";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8; 23] = b"VMess Header AEAD Nonce";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8; 28] =
    b"VMess Header AEAD Key_Length";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8; 30] =
    b"VMess Header AEAD Nonce_Length";

macro_rules! impl_hmac_with_hasher {
    ($name:tt, $hasher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            okey: [u8; Self::BLOCK_LEN],
            hasher: $hasher,
            hasher_outer: $hasher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = 64;
            pub const TAG_LEN: usize = 32;

            pub fn new(mut hasher: $hasher, key: &[u8]) -> Self {
                let mut ikey = [0u8; Self::BLOCK_LEN];
                let mut okey = [0u8; Self::BLOCK_LEN];
                let hasher_outer = hasher.clone();
                if key.len() > Self::BLOCK_LEN {
                    let mut hh = hasher.clone();
                    hh.update(key);
                    let hkey = hh.finalize();

                    ikey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                    okey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                } else {
                    ikey[..key.len()].copy_from_slice(key);
                    okey[..key.len()].copy_from_slice(key);
                }

                for idx in 0..Self::BLOCK_LEN {
                    ikey[idx] ^= IPAD;
                    okey[idx] ^= OPAD;
                }
                hasher.update(&ikey);
                Self {
                    okey,
                    hasher,
                    hasher_outer,
                }
            }

            pub fn update(&mut self, m: &[u8]) {
                self.hasher.update(m);
            }

            pub fn finalize(mut self) -> [u8; Self::TAG_LEN] {
                let h1 = self.hasher.finalize();

                self.hasher_outer.update(&self.okey);
                self.hasher_outer.update(&h1);

                let h2 = self.hasher_outer.finalize();
                h2
            }
        }
    };
}

#[derive(Clone)]
pub struct VmessKdf1 {
    okey: [u8; Self::BLOCK_LEN],
    hasher: HmacSha256,
    hasher_outer: HmacSha256,
}

impl VmessKdf1 {
    pub const BLOCK_LEN: usize = 64;
    pub const TAG_LEN: usize = 32;

    pub fn new(mut hasher: HmacSha256, key: &[u8]) -> Self {
        let mut ikey = [0u8; Self::BLOCK_LEN];
        let mut okey = [0u8; Self::BLOCK_LEN];
        let hasher_outer = hasher.clone();
        if key.len() > Self::BLOCK_LEN {
            let mut hh = hasher.clone();
            hh.update(key);
            let hkey = hh.finalize().into_bytes();

            ikey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
            okey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
        } else {
            ikey[..key.len()].copy_from_slice(key);
            okey[..key.len()].copy_from_slice(key);
        }

        for idx in 0..Self::BLOCK_LEN {
            ikey[idx] ^= IPAD;
            okey[idx] ^= OPAD;
        }
        hasher.update(&ikey);
        Self {
            okey,
            hasher,
            hasher_outer,
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        self.hasher.update(m);
    }

    pub fn finalize(mut self) -> [u8; Self::TAG_LEN] {
        let h1 = self.hasher.finalize().into_bytes();

        self.hasher_outer.update(&self.okey);
        self.hasher_outer.update(&h1);

        self.hasher_outer.finalize().into_bytes().into()
    }
}

impl_hmac_with_hasher!(VmessKdf2, VmessKdf1);
impl_hmac_with_hasher!(VmessKdf3, VmessKdf2);

#[inline]
fn get_vmess_kdf_1(key1: &[u8]) -> VmessKdf1 {
    VmessKdf1::new(
        HmacSha256::new_from_slice(KDF_SALT_CONST_VMESS_AEAD_KDF).unwrap(),
        key1,
    )
}

pub fn vmess_kdf_1_one_shot(id: &[u8], key1: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_1(key1);
    h.update(id);
    h.finalize()
}

#[inline]
fn get_vmess_kdf_2(key1: &[u8], key2: &[u8]) -> VmessKdf2 {
    VmessKdf2::new(get_vmess_kdf_1(key1), key2)
}

#[inline]
fn get_vmess_kdf_3(key1: &[u8], key2: &[u8], key3: &[u8]) -> VmessKdf3 {
    VmessKdf3::new(get_vmess_kdf_2(key1, key2), key3)
}

pub fn vmess_kdf_3_one_shot(id: &[u8], key1: &[u8], key2: &[u8], key3: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_3(key1, key2, key3);
    h.update(id);
    h.finalize()
}
