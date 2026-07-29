use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement;
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};

#[derive(Debug)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidCiphertextLength,
    EncryptionFailed,
    DecryptionFailed,
    EcdhFailed,
    HkdfFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::InvalidNonceLength => write!(f, "Invalid nonce length"),
            CryptoError::InvalidCiphertextLength => {
                write!(f, "Invalid ciphertext length")
            }
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::EcdhFailed => write!(f, "ECDH key exchange failed"),
            CryptoError::HkdfFailed => write!(f, "HKDF derivation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CryptoError> for std::io::Error {
    fn from(err: CryptoError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
    }
}

pub fn perform_ecdh(
    private_key: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let my_private_key =
        agreement::PrivateKey::from_private_key(&agreement::X25519, private_key)
            .map_err(|_| CryptoError::EcdhFailed)?;

    let peer_public_key =
        agreement::UnparsedPublicKey::new(&agreement::X25519, public_key.as_ref());

    let mut shared_secret = [0u8; 32];
    agreement::agree(
        &my_private_key,
        peer_public_key,
        CryptoError::EcdhFailed,
        |key_material| {
            shared_secret.copy_from_slice(key_material);
            Ok(())
        },
    )?;

    Ok(shared_secret)
}

pub fn derive_auth_key(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], CryptoError> {
    debug_assert_eq!(salt.len(), 20, "salt must be exactly 20 bytes");
    let salt = Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(shared_secret);
    let info_pieces = [info];
    let okm = prk
        .expand(&info_pieces, HKDF_SHA256)
        .map_err(|_| CryptoError::HkdfFailed)?;
    let mut auth_key = [0u8; 32];
    okm.fill(&mut auth_key)
        .map_err(|_| CryptoError::HkdfFailed)?;
    Ok(auth_key)
}

pub fn encrypt_session_id(
    plaintext: &[u8; 16],
    auth_key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
) -> Result<[u8; 32], CryptoError> {
    debug_assert_eq!(nonce.len(), 12, "nonce must be exactly 12 bytes");
    let unbound_key = UnboundKey::new(&AES_256_GCM, auth_key)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let sealing_key = LessSafeKey::new(unbound_key);

    let nonce_obj = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| CryptoError::InvalidNonceLength)?;

    let aad_obj = Aad::from(aad);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce_obj, aad_obj, &mut in_out)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    if in_out.len() != 32 {
        return Err(CryptoError::EncryptionFailed);
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&in_out);
    Ok(result)
}
