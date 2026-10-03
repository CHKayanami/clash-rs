//! VLESS Encryption: parsed options, handshake runtime and framed IO.
//! Adapted from honk (GPL-3.0-only).

mod client;
mod crypto;
mod options;
mod raw_blake3;
mod stream;

pub use stream::EncryptionStream;

pub(crate) use client::EncryptionClient;
pub(crate) use options::EncryptionOptions;

const X25519_KEY_LEN: usize = 32;
const MLKEM_PUBLIC_KEY_LEN: usize = 1184;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;
const SHARED_SECRET_LEN: usize = 32;
const PFS_CLIENT_KEY_LEN: usize = MLKEM_PUBLIC_KEY_LEN + X25519_KEY_LEN;
const PFS_SERVER_KEY_LEN: usize = MLKEM_CIPHERTEXT_LEN + X25519_KEY_LEN;
const TICKET_LEN: usize = 16;
const IV_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const FRAME_HEADER_LEN: usize = 5;
const MAX_FRAME_PLAINTEXT: usize = 8192;
const MAX_FRAME_CIPHERTEXT: usize = 16_640;
const MAX_NONCE: [u8; NONCE_LEN] = [u8::MAX; NONCE_LEN];
const KDF_CTR: &[u8] = b"VLESS";
