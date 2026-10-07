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

    /// Generate nonce (IV or SALT)
    pub fn generate_nonce(&self, method: CipherKind, nonce: &mut [u8]) {
        if nonce.is_empty() {
            return;
        }

        #[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
        {
            use crate::crypto::utils::random_iv_or_salt;
            let _ = method;
            // Outgoing salts are random and are not stored in the replay cache.
            random_iv_or_salt(nonce);
        }

        #[cfg(not(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022")))]
        if !nonce.is_empty() {
            panic!("{method} don't know how to generate nonce");
        }
    }

    /// Check nonce replay (AEAD-2022)
    pub fn check_nonce_replay(&self, method: CipherKind, nonce: &[u8]) -> io::Result<()> {
        if nonce.is_empty() {
            return Ok(());
        }

        self.replay_protector.check_nonce_and_set(method, nonce)
    }
}
