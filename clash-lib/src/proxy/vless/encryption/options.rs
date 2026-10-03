//! Immutable, validated VLESS Encryption parameters.

use std::{fmt, sync::Arc};
use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD}};
use blake3::hash as blake3_hash;
use boring::mlkem::{Algorithm as MlKemAlgorithm, MlKemPublicKey};

use super::{MLKEM_CIPHERTEXT_LEN, MLKEM_PUBLIC_KEY_LEN, X25519_KEY_LEN};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum XorMode {
    Native,
    XorPub,
    Random,
}

impl XorMode {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "native" => Ok(Self::Native),
            "xorpub" => Ok(Self::XorPub),
            "random" => Ok(Self::Random),
            _ => anyhow::bail!("unsupported VLESS Encryption mode '{value}'"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PaddingSpec {
    pub(super) probability: u8,
    pub(super) min: usize,
    pub(super) max: usize,
}

pub(super) enum AuthKey {
    X25519 {
        public: [u8; X25519_KEY_LEN],
        hash: [u8; 32],
    },
    MlKem {
        public: MlKemPublicKey,
        hash: [u8; 32],
    },
}

impl AuthKey {
    pub(super) fn ciphertext_len(&self) -> usize {
        match self {
            Self::X25519 { .. } => X25519_KEY_LEN,
            Self::MlKem { .. } => MLKEM_CIPHERTEXT_LEN,
        }
    }

    pub(super) fn public_bytes(&self) -> &[u8] {
        match self {
            Self::X25519 { public, .. } => public,
            Self::MlKem { public, .. } => public.as_bytes(),
        }
    }

    pub(super) fn hash(&self) -> &[u8; 32] {
        match self {
            Self::X25519 { hash, .. } | Self::MlKem { hash, .. } => hash,
        }
    }
}

pub(crate) struct EncryptionOptions {
    pub(super) auth_keys: Vec<AuthKey>,
    pub(super) relays_len: usize,
    pub(super) mode: XorMode,
    pub(super) allow_0rtt: bool,
    pub(super) padding_lengths: Vec<PaddingSpec>,
    pub(super) padding_gaps: Vec<PaddingSpec>,
}

impl fmt::Debug for EncryptionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionOptions")
            .field("auth_keys", &self.auth_keys.len())
            .field("mode", &self.mode)
            .field("allow_0rtt", &self.allow_0rtt)
            .finish_non_exhaustive()
    }
}

impl EncryptionOptions {
    pub(crate) fn parse(value: &str) -> anyhow::Result<Arc<Self>> {
        let mut parts = value.split('.');
        let protocol = parts.next().unwrap_or_default();
        anyhow::ensure!(
            protocol == "mlkem768x25519plus",
            "unsupported VLESS Encryption protocol '{protocol}'"
        );
        let mode = XorMode::parse(parts.next().unwrap_or_default())?;
        let rtt = parts.next().unwrap_or_default();
        anyhow::ensure!(
            rtt == "0rtt" || rtt == "1rtt",
            "unsupported VLESS Encryption RTT mode '{rtt}'"
        );

        let mut padding_parts = Vec::new();
        let mut auth_keys = Vec::new();
        let mut saw_key = false;
        for part in parts {
            let decoded = decode_base64url(part);
            if !saw_key && !matches!(decoded.as_ref().map(Vec::len), Some(32 | 1184)) {
                padding_parts.push(part);
                continue;
            }
            saw_key = true;
            let raw = decoded.with_context(|| "invalid VLESS Encryption public key")?;
            let hash = *blake3_hash(&raw).as_bytes();
            match raw.len() {
                X25519_KEY_LEN => auth_keys.push(AuthKey::X25519 {
                    public: raw.try_into().expect("checked X25519 key length"),
                    hash,
                }),
                MLKEM_PUBLIC_KEY_LEN => auth_keys.push(AuthKey::MlKem {
                    public: MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, &raw)
                        .context("invalid ML-KEM-768 public key")?,
                    hash,
                }),
                len => anyhow::bail!(
                    "invalid VLESS Encryption public key length {len} (expected 32 or 1184)"
                ),
            }
        }
        anyhow::ensure!(
            !auth_keys.is_empty(),
            "VLESS Encryption requires at least one server public key"
        );
        let (padding_lengths, padding_gaps) = parse_padding(&padding_parts)?;
        let relays_len = auth_keys.iter().map(AuthKey::ciphertext_len).sum::<usize>()
            + (auth_keys.len() - 1) * 32;
        Ok(Arc::new(Self {
            auth_keys,
            relays_len,
            mode,
            allow_0rtt: rtt == "0rtt",
            padding_lengths,
            padding_gaps,
        }))
    }

}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

fn parse_padding(parts: &[&str]) -> anyhow::Result<(Vec<PaddingSpec>, Vec<PaddingSpec>)> {
    if parts.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut lengths = Vec::new();
    let mut gaps = Vec::new();
    let mut total_max = 0usize;
    for (index, part) in parts.iter().enumerate() {
        let values: Vec<_> = part.split('-').collect();
        anyhow::ensure!(
            values.len() == 3,
            "invalid VLESS Encryption padding parameter '{part}'"
        );
        let spec = PaddingSpec {
            probability: values[0].parse().context("invalid padding probability")?,
            min: values[1].parse().context("invalid padding minimum")?,
            max: values[2].parse().context("invalid padding maximum")?,
        };
        anyhow::ensure!(spec.probability <= 100, "padding probability exceeds 100");
        anyhow::ensure!(spec.min <= spec.max, "padding minimum exceeds maximum");
        if index == 0 {
            anyhow::ensure!(
                spec.probability == 100 && spec.min >= 35,
                "first VLESS Encryption padding must be certain and at least 35 bytes"
            );
        }
        if index % 2 == 0 {
            anyhow::ensure!(spec.max <= 65_553, "padding length exceeds 65553 bytes");
            total_max = total_max.checked_add(spec.max)
                .context("total VLESS Encryption padding overflow")?;
            anyhow::ensure!(total_max <= 65_553,
                "total VLESS Encryption padding exceeds 65553 bytes");
            lengths.push(spec);
        } else {
            gaps.push(spec);
        }
    }
    Ok((lengths, gaps))
}
