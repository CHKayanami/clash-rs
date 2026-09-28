use base64::{Engine, engine::general_purpose::STANDARD};

pub(crate) struct KeyBytes(pub [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                let decoded_key =
                    hex::decode(s).map_err(|_| "Illegal character in key")?;
                internal.copy_from_slice(&decoded_key);
            }
            43 | 44 => {
                // Try to parse as base64
                let decoded_key =
                    STANDARD.decode(s).map_err(|_| "Illegal character in key")?;
                if decoded_key.len() == internal.len() {
                    internal[..].copy_from_slice(&decoded_key);
                } else {
                    return Err("Illegal character in key");
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}

#[cfg(test)]
mod tests {
    use super::KeyBytes;

    #[test]
    fn invalid_key_is_rejected() {
        assert!("?".repeat(44).parse::<KeyBytes>().is_err());
        assert!("é".repeat(32).parse::<KeyBytes>().is_err());
    }
}
