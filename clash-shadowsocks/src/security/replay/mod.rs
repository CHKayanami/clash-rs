use std::fmt;

#[cfg(feature = "aead-cipher-2022")]
use quick_cache::sync::Cache;

use crate::{config::ServerType, crypto::CipherKind};

/// A protector against replay attack (AEAD 2022)
pub struct ReplayProtector {
    // AEAD 2022 specific filter.
    // AEAD 2022 TCP protocol has a timestamp, which can already reject most of the replay requests,
    // so we only need to remember nonce that are in the valid time range
    #[cfg(feature = "aead-cipher-2022")]
    nonce_set: Cache<Vec<u8>, ()>,
}

impl fmt::Debug for ReplayProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayProtector").finish()
    }
}

impl ReplayProtector {
    /// Create a new ReplayProtector
    #[allow(unused_variables)]
    pub fn new(config_type: ServerType) -> Self {
        Self {
            #[cfg(feature = "aead-cipher-2022")]
            nonce_set: Cache::new(16384),
        }
    }

    /// Check if nonce exist or not
    #[inline(always)]
    pub fn check_nonce_and_set(&self, method: CipherKind, nonce: &[u8]) -> bool {
        // Plain cipher doesn't have a nonce
        // Always treated as non-duplicated
        if nonce.is_empty() {
            return false;
        }

        #[cfg(feature = "aead-cipher-2022")]
        if method.is_aead_2022() {
            if self.nonce_set.contains_key(nonce) {
                return true;
            }
            self.nonce_set.insert(nonce.to_vec(), ());
            return false;
        }

        let _ = method;
        false
    }
}
