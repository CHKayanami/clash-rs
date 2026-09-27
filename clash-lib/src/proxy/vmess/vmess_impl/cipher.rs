use aes_gcm::Aes128Gcm;
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;

use crate::common::crypto::AeadCipherHelper;

#[allow(clippy::large_enum_variant)]
pub enum VmessSecurity {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl VmessSecurity {
    #[inline(always)]
    pub fn overhead_len(&self) -> usize {
        16
    }

    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        12
    }
}

pub(crate) struct AeadCipher {
    pub security: VmessSecurity,
    nonce: [u8; 32],
    iv: Bytes,
    count: u32,
}

impl AeadCipher {
    pub fn new(iv: &[u8], security: VmessSecurity) -> Self {
        Self {
            security,
            nonce: [0u8; 32],
            iv: Bytes::copy_from_slice(iv),
            count: 0,
        }
    }

    pub fn decrypt_inplace(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.len() < self.security.overhead_len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VMess AEAD chunk is shorter than its authentication tag",
            ));
        }
        let mut nonce = self.nonce;
        nonce[..2].copy_from_slice(&self.next_count()?.to_be_bytes());
        let security = &self.security;
        let iv = &self.iv;

        nonce[2..12].copy_from_slice(&iv[2..12]);

        let nonce = &nonce[..security.nonce_len()];
        match security {
            VmessSecurity::Aes128Gcm(cipher) => {
                let dec =
                    cipher.decrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
                if let Err(err) = dec {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        err.to_string(),
                    ));
                }
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                let dec =
                    cipher.decrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
                if let Err(err) = dec {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        err.to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn encrypt_inplace(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut nonce = self.nonce;
        nonce[..2].copy_from_slice(&self.next_count()?.to_be_bytes());
        let security = &self.security;
        let iv = &self.iv;

        nonce[2..12].copy_from_slice(&iv[2..12]);

        let nonce = &nonce[..security.nonce_len()];
        match security {
            VmessSecurity::Aes128Gcm(cipher) => {
                cipher.encrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                cipher.encrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
            }
        }

        Ok(())
    }

    fn next_count(&mut self) -> std::io::Result<u16> {
        let count = u16::try_from(self.count).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VMess AEAD chunk counter exhausted",
            )
        })?;
        self.count += 1;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> AeadCipher {
        AeadCipher::new(
            &[0; 16],
            VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&[0; 16])),
        )
    }

    #[test]
    fn rejects_short_aead_chunk() {
        let mut cipher = cipher();
        let err = cipher.decrypt_inplace(&mut [0; 15]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(cipher.count, 0);
    }

    #[test]
    fn refuses_to_reuse_aead_nonce() {
        let mut cipher = cipher();
        cipher.count = u16::MAX as u32;
        cipher.encrypt_inplace(&mut [0; 16]).unwrap();
        let err = cipher.encrypt_inplace(&mut [0; 16]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(cipher.count, u16::MAX as u32 + 1);
    }
}
