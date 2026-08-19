//! Shadowsocks service context

use std::{io, sync::Arc};

use crate::{
    config::ServerType,
    crypto::CipherKind,
    security::replay::ReplayProtector,
};

/// Service context
#[derive(Debug)]
pub struct Context {
    // Protector against replay attack (AEAD-2022)
    replay_protector: ReplayProtector,
}

/// `Context` for sharing between services
pub type SharedContext = Arc<Context>;

impl Context {
    /// Create a new `Context` for `Client` or `Server`
    pub fn new(config_type: ServerType) -> Self {
        Self {
            replay_protector: ReplayProtector::new(config_type),
        }
    }

    /// Create a new `Context` shared
    pub fn new_shared(config_type: ServerType) -> SharedContext {
        SharedContext::new(Self::new(config_type))
    }

    /// Check if nonce exist or not (for generating unique nonces)
    #[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
    #[inline(always)]
    fn check_nonce_and_set(&self, method: CipherKind, nonce: &[u8]) -> bool {
        self.replay_protector.check_nonce_and_set(method, nonce)
    }

    /// Generate nonce (IV or SALT)
    pub fn generate_nonce(&self, method: CipherKind, nonce: &mut [u8], unique: bool) {
        if nonce.is_empty() {
            return;
        }

        #[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
        loop {
            use crate::crypto::utils::random_iv_or_salt;

            random_iv_or_salt(nonce);

            // Salt already exists, generate a new one.
            if unique && self.check_nonce_and_set(method, nonce) {
                continue;
            }

            break;
        }

        #[cfg(not(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022")))]
        if !nonce.is_empty() {
            let _ = unique;
            panic!("{method} don't know how to generate nonce");
        }
    }

    /// Check nonce replay (AEAD-2022)
    pub fn check_nonce_replay(&self, method: CipherKind, nonce: &[u8]) -> io::Result<()> {
        if nonce.is_empty() {
            return Ok(());
        }

        #[cfg(feature = "aead-cipher-2022")]
        if method.is_aead_2022() {
            if self.replay_protector.check_nonce_and_set(method, nonce) {
                return Err(io::Error::other("detected repeated nonce (iv/salt)"));
            }
            return Ok(());
        }

        let _ = method;
        let _ = nonce;
        Ok(())
    }
}
