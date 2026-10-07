use crate::config::internal::listener::InboundUser;
use shadowsocks::{
    config::{ServerUser, ServerUserManager},
    crypto::CipherKind,
};
use std::{collections::HashMap, io, sync::Arc};

pub(super) struct Authentication {
    method: CipherKind,
    multi_user: bool,
    pub manager: Option<Arc<ServerUserManager>>,
    pub index: Arc<HashMap<Vec<u8>, Arc<str>>>,
}

impl Authentication {
    pub fn new(method: CipherKind, users: &[InboundUser]) -> io::Result<Self> {
        let mut auth = Self {
            method,
            multi_user: false,
            manager: None,
            index: Arc::new(HashMap::new()),
        };
        auth.update(users)?;
        Ok(auth)
    }

    // Build a complete snapshot before publishing it. Once enabled, multi-user
    // authentication stays enabled even when the last user is removed.
    pub fn update(&mut self, users: &[InboundUser]) -> io::Result<()> {
        let multi_user = self.multi_user || !users.is_empty();
        if !multi_user {
            return Ok(());
        }
        let key_len = match self.method {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => 16,
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => 32,
            _ => return Err(io::Error::other(
                "cipher does not support multi-user authentication",
            )),
        };
        let mut manager = ServerUserManager::new();
        let mut index = HashMap::new();
        for entry in users {
            let user = ServerUser::with_encoded_key(&entry.name, &entry.password)
                .map_err(|_| io::Error::other(format!(
                    "invalid Shadowsocks user key for '{}'", entry.name,
                )))?;
            if user.key().len() != key_len {
                return Err(io::Error::other(format!(
                    "Shadowsocks user '{}' requires a {key_len}-byte key",
                    entry.name,
                )));
            }
            if index.insert(user.key().to_vec(), Arc::from(user.name()))
                .is_some()
            {
                return Err(io::Error::other("duplicate Shadowsocks user key"));
            }
            manager.add_user(user);
        }
        self.manager = Some(Arc::new(manager));
        self.index = Arc::new(index);
        self.multi_user = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    fn user(length: usize) -> InboundUser {
        InboundUser {
            name: "test-user".into(),
            password: STANDARD.encode(vec![7; length]),
        }
    }

    #[test]
    fn multi_user_updates_are_transactional_and_never_fall_back() {
        let mut auth = Authentication::new(
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM, &[user(32)],
        ).unwrap();
        let manager = auth.manager.clone().unwrap();
        assert!(auth.update(&[user(16)]).is_err());
        let invalid = InboundUser { name: "invalid".into(), password: "!!!".into() };
        assert!(auth.update(&[user(32), invalid]).is_err());
        assert!(auth.update(&[user(32), user(32)]).is_err());
        assert!(Arc::ptr_eq(&manager, auth.manager.as_ref().unwrap()));
        auth.update(&[]).unwrap();
        assert!(auth.manager.is_some());
        assert_eq!(auth.manager.as_ref().unwrap().users_iter().count(), 0);
        assert!(auth.index.is_empty());
    }

    #[test]
    fn validates_cipher_key_length_and_initial_single_user_mode() {
        assert!(Authentication::new(CipherKind::AES_256_GCM, &[user(32)]).is_err());
        assert!(Authentication::new(
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305, &[user(32)],
        ).is_err());
        assert!(Authentication::new(
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM, &[user(16)],
        ).is_ok());
        assert!(Authentication::new(
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM, &[user(32)],
        ).is_err());
        let mut auth = Authentication::new(
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM, &[],
        ).unwrap();
        assert!(auth.manager.is_none());
        auth.update(&[user(32)]).unwrap();
        auth.update(&[]).unwrap();
        assert!(auth.manager.is_some());
    }
}
