use shadowsocks::crypto::CipherKind;
use std::io;

pub mod inbound;
pub mod outbound;

pub(crate) fn map_cipher(cipher: &str) -> std::io::Result<CipherKind> {
    let lower = cipher.to_lowercase();
    match lower.as_str() {
        "aes-128-gcm" => Ok(CipherKind::AES_128_GCM),
        "aes-256-gcm" => Ok(CipherKind::AES_256_GCM),
        "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(CipherKind::CHACHA20_POLY1305),
        "xchacha20-ietf-poly1305" | "xchacha20-poly1305" => Ok(CipherKind::XCHACHA20_POLY1305),

        "2022-blake3-aes-128-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_128_GCM),
        "2022-blake3-aes-256-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_256_GCM),
        "2022-blake3-chacha20-ietf-poly1305" | "2022-blake3-chacha20-poly1305" => {
            Ok(CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305)
        }

        "rc4-md5" => Ok(CipherKind::SS_RC4_MD5),
        "dummy" | "none" | "plain" => Ok(CipherKind::NONE),
        _ => lower
            .parse::<CipherKind>()
            .map_err(|e| io::Error::other(format!("unsupported cipher '{cipher}': {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_cipher_aliases_and_case() {
        assert_eq!(map_cipher("AES-256-GCM").unwrap(), CipherKind::AES_256_GCM);
        assert_eq!(map_cipher("chacha20-poly1305").unwrap(), CipherKind::CHACHA20_POLY1305);
        assert_eq!(map_cipher("2022-blake3-chacha20-poly1305").unwrap(), CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305);
        assert_eq!(map_cipher("NONE").unwrap(), CipherKind::NONE);
        assert!(map_cipher("invalid-cipher-name").is_err());
    }
}


