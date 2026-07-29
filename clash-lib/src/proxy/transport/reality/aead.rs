use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use std::io::{self, Error, ErrorKind};

use super::cipher_suite::CipherSuite;
use super::common::strip_content_type_with_padding;

pub struct AeadKey(LessSafeKey);

impl AeadKey {
    pub fn new(cipher_suite: CipherSuite, key: &[u8]) -> io::Result<Self> {
        let algorithm = cipher_suite.algorithm();
        let expected_len = cipher_suite.key_len();

        if key.len() != expected_len {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Invalid key length for {:?}: {} (expected {})",
                    cipher_suite,
                    key.len(),
                    expected_len
                ),
            ));
        }

        let unbound = UnboundKey::new(algorithm, key).map_err(|e| {
            Error::new(ErrorKind::InvalidInput, format!("Invalid key: {:?}", e))
        })?;

        Ok(Self(LessSafeKey::new(unbound)))
    }

    #[inline]
    pub fn seal_in_place(
        &self,
        buf: &mut Vec<u8>,
        iv: &[u8],
        seq: u64,
        aad: &[u8],
    ) -> io::Result<()> {
        let nonce = Self::make_nonce(iv, seq)?;
        self.0
            .seal_in_place_append_tag(nonce, Aad::from(aad), buf)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Encryption failed: {:?}", e),
                )
            })
    }

    #[inline]
    pub fn open_in_place_slice<'a>(
        &self,
        buf: &'a mut [u8],
        iv: &[u8],
        seq: u64,
        aad: &[u8],
    ) -> io::Result<&'a mut [u8]> {
        let nonce = Self::make_nonce(iv, seq)?;
        self.0
            .open_in_place(nonce, Aad::from(aad), buf)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Decryption failed: {:?}", e),
                )
            })
    }

    #[inline]
    pub fn open(
        &self,
        ciphertext: &[u8],
        iv: &[u8],
        seq: u64,
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut buf = ciphertext.to_vec();
        let plaintext = self.open_in_place_slice(&mut buf, iv, seq, aad)?;
        let plaintext_len = plaintext.len();
        buf.truncate(plaintext_len);
        Ok(buf)
    }

    fn make_nonce(iv: &[u8], seq: u64) -> io::Result<Nonce> {
        if iv.len() != 12 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid IV length: {} (expected 12)", iv.len()),
            ));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(iv);

        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_bytes[i];
        }

        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|e| {
            Error::new(ErrorKind::InvalidInput, format!("Invalid nonce: {:?}", e))
        })
    }
}

pub fn decrypt_handshake_message(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    seq: u64,
    ciphertext: &[u8],
    record_len: u16,
) -> io::Result<Vec<u8>> {
    let aad = [
        0x17, // ApplicationData
        0x03,
        0x03, // TLS 1.2 version
        (record_len >> 8) as u8,
        (record_len & 0xff) as u8,
    ];

    let aead_key = AeadKey::new(cipher_suite, key)?;
    let mut plaintext = aead_key.open(ciphertext, iv, seq, &aad)?;

    let _ = strip_content_type_with_padding(&mut plaintext)?;

    Ok(plaintext)
}
