use aws_lc_rs::{
    aead::{AES_128_GCM, AES_256_GCM, Algorithm, CHACHA20_POLY1305},
    digest,
    hmac::{self, HMAC_SHA256, HMAC_SHA384},
};

pub const DEFAULT_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::AES_128_GCM_SHA256,
    CipherSuite::AES_256_GCM_SHA384,
    CipherSuite::CHACHA20_POLY1305_SHA256,
];

#[derive(Clone, Copy)]
pub struct CipherSuite {
    id: u16,
    algorithm: &'static Algorithm,
    digest_algorithm: &'static digest::Algorithm,
    hmac_algorithm: hmac::Algorithm,
}

impl PartialEq for CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for CipherSuite {}

impl CipherSuite {
    pub const AES_128_GCM_SHA256: Self = Self {
        id: 0x1301,
        algorithm: &AES_128_GCM,
        digest_algorithm: &digest::SHA256,
        hmac_algorithm: HMAC_SHA256,
    };

    pub const AES_256_GCM_SHA384: Self = Self {
        id: 0x1302,
        algorithm: &AES_256_GCM,
        digest_algorithm: &digest::SHA384,
        hmac_algorithm: HMAC_SHA384,
    };

    pub const CHACHA20_POLY1305_SHA256: Self = Self {
        id: 0x1303,
        algorithm: &CHACHA20_POLY1305,
        digest_algorithm: &digest::SHA256,
        hmac_algorithm: HMAC_SHA256,
    };

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::AES_128_GCM_SHA256),
            0x1302 => Some(Self::AES_256_GCM_SHA384),
            0x1303 => Some(Self::CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self.id {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            _ => unreachable!(),
        }
    }

    #[inline]
    pub fn id(&self) -> u16 {
        self.id
    }

    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    #[inline]
    pub fn key_len(&self) -> usize {
        self.algorithm.key_len()
    }

    #[inline]
    pub fn nonce_len(&self) -> usize {
        self.algorithm.nonce_len()
    }

    #[inline]
    pub fn hash_len(&self) -> usize {
        self.digest_algorithm.output_len()
    }

    #[inline]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.digest_algorithm
    }

    #[inline]
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.hmac_algorithm
    }
}

impl std::fmt::Debug for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
