//! Cryptographic primitives for handshake and framed traffic.

use std::io;
use aes::{Aes256, cipher::{BlockCipherEncrypt, KeyInit as _}};
use boring::aead::{AeadCtx, Algorithm};
use boring_sys::{X25519, X25519_keypair};

use super::{KDF_CTR, NONCE_LEN, TAG_LEN};
use super::raw_blake3::derive_key as derive_raw_key;

pub(super) fn x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut public = [0u8; 32];
    let mut private = [0u8; 32];
    // SAFETY: both output arrays provide exactly 32 writable bytes.
    unsafe { X25519_keypair(public.as_mut_ptr(), private.as_mut_ptr()) };
    (public, private)
}

pub(super) fn x25519(private: &[u8; 32], public: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let mut shared = [0u8; 32];
    // SAFETY: all three arrays are live, nonoverlapping 32-byte buffers.
    let ok = unsafe { X25519(shared.as_mut_ptr(), private.as_ptr(), public.as_ptr()) };
    anyhow::ensure!(ok == 1, "invalid VLESS Encryption X25519 public key");
    Ok(shared)
}

pub(super) fn encode_length(length: usize) -> [u8; 2] {
    (length as u16).to_be_bytes()
}

pub(super) fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
    derive_raw_key(context, material)
}

#[cfg(target_arch = "x86_64")]
pub(super) fn aes_gcm_hardware_available() -> bool {
    std::is_x86_feature_detected!("aes")
        && std::is_x86_feature_detected!("pclmulqdq")
        && std::is_x86_feature_detected!("sse4.1")
        && std::is_x86_feature_detected!("ssse3")
}

#[cfg(target_arch = "aarch64")]
pub(super) fn aes_gcm_hardware_available() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn aes_gcm_hardware_available() -> bool {
    false
}

pub(super) struct AesCtr {
    cipher: Aes256,
    counter: [u8; 16],
    block: [u8; 16],
    used: usize,
}

impl AesCtr {
    pub(super) fn new(material: &[u8], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes256::new_from_slice(&derive_key(KDF_CTR, material))
                .expect("AES-256 key length"),
            counter: *iv,
            block: [0; 16],
            used: 16,
        }
    }

    pub(super) fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == self.block.len() {
                let mut block = aes::cipher::Block::<Aes256>::default();
                block.copy_from_slice(&self.counter);
                self.cipher.encrypt_block(&mut block);
                self.block.copy_from_slice(&block);
                self.used = 0;
                for counter_byte in self.counter.iter_mut().rev() {
                    let (next, overflow) = counter_byte.overflowing_add(1);
                    *counter_byte = next;
                    if !overflow {
                        break;
                    }
                }
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

pub(super) struct StreamAead {
    cipher: AeadCtx,
    pub(super) nonce: [u8; NONCE_LEN],
}

impl StreamAead {
    pub(super) fn new(context: &[u8], key: &[u8], use_aes: bool) -> anyhow::Result<Self> {
        Ok(Self {
            cipher: AeadCtx::new_default_tag(
                &if use_aes { Algorithm::aes_256_gcm() } else { Algorithm::chacha20_poly1305() },
                &derive_key(context, key),
            )?,
            nonce: [0; NONCE_LEN],
        })
    }

    pub(super) fn seal(&mut self, plaintext: &[u8], aad: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.next_nonce();
        let start = output.len();
        output.extend_from_slice(plaintext);
        output.resize(output.len() + TAG_LEN, 0);
        let (body, tag) = output[start..].split_at_mut(plaintext.len());
        self.cipher.seal_in_place(&nonce, body, tag, aad)
            .map(|_| ())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "VLESS Encryption seal failed"))
    }

    pub(super) fn open(&mut self, ciphertext: &mut [u8], aad: &[u8]) -> io::Result<usize> {
        let nonce = self.next_nonce();
        self.open_with_nonce(&nonce, ciphertext, aad)
    }

    pub(super) fn open_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &mut [u8],
        aad: &[u8],
    ) -> io::Result<usize> {
        let length = ciphertext.len().checked_sub(TAG_LEN)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated VLESS Encryption tag"))?;
        let (body, tag) = ciphertext.split_at_mut(length);
        self.cipher.open_in_place(nonce, body, tag, aad)
            .map(|()| length)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS Encryption authentication failed",
                )
            })
    }

    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        for byte in self.nonce.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
        self.nonce
    }
}
