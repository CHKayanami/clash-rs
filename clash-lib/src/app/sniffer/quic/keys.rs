use aes::Aes128;
use aes_gcm::{Aes128Gcm, KeyInit};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;

use super::{
    QUIC_VERSION_1, QUIC_VERSION_2, QUIC_VERSION_2_DRAFT,
    QUIC_VERSION_DRAFT29, QUIC_V1_SALT, QUIC_V2_SALT, QUIC_DRAFT29_SALT,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct InitialId {
    version: u32,
    dcid: [u8; 20],
    length: u8,
}

impl InitialId {
    pub(super) fn new(version: u32, dcid: &[u8]) -> Option<Self> {
        if dcid.len() > 20 { return None; }
        let mut bytes = [0; 20];
        bytes[..dcid.len()].copy_from_slice(dcid);
        Some(Self { version, dcid: bytes, length: dcid.len() as u8 })
    }

    pub(super) fn from_packet(data: &[u8]) -> Option<Self> {
        if data.len() < 6 || data[0] & 0xc0 != 0xc0 { return None; }
        let version = u32::from_be_bytes(data[1..5].try_into().ok()?);
        let packet_type = (data[0] & 0x30) >> 4;
        let expected = match version {
            QUIC_VERSION_1 | QUIC_VERSION_DRAFT29 => 0,
            QUIC_VERSION_2 | QUIC_VERSION_2_DRAFT => 1,
            _ => return None,
        };
        if packet_type != expected { return None; }
        Self::new(version, data.get(6..6 + usize::from(data[5]))?)
    }
}

pub(super) struct InitialKeys {
    pub(super) id: InitialId,
    pub(super) hp: Aes128,
    pub(super) gcm: Aes128Gcm,
    pub(super) iv: [u8; 12],
}

impl InitialKeys {
    pub(super) fn new(id: InitialId) -> Self {
        let v2 = matches!(id.version, QUIC_VERSION_2 | QUIC_VERSION_2_DRAFT);
        let salt = match id.version {
            QUIC_VERSION_DRAFT29 => &QUIC_DRAFT29_SALT,
            QUIC_VERSION_2 | QUIC_VERSION_2_DRAFT => &QUIC_V2_SALT,
            _ => &QUIC_V1_SALT,
        };
        let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(salt).unwrap();
        mac.update(&id.dcid[..usize::from(id.length)]);
        let initial: [u8; 32] = mac.finalize().into_bytes().into();
        let client = expand_label::<32>(&initial, b"client in");
        let (key_label, iv_label, hp_label) = if v2 {
            (b"quicv2 key".as_slice(), b"quicv2 iv".as_slice(), b"quicv2 hp".as_slice())
        } else {
            (b"quic key".as_slice(), b"quic iv".as_slice(), b"quic hp".as_slice())
        };
        let key = expand_label::<16>(&client, key_label);
        let hp = expand_label::<16>(&client, hp_label);
        Self {
            id,
            hp: Aes128::new_from_slice(&hp).unwrap(),
            gcm: Aes128Gcm::new_from_slice(&key).unwrap(),
            iv: expand_label::<12>(&client, iv_label),
        }
    }
}

// All Initial outputs fit in one SHA-256 block. Feed the TLS HKDF label
// directly into HMAC rather than constructing intermediate heap buffers.
fn expand_label<const N: usize>(secret: &[u8; 32], label: &[u8]) -> [u8; N] {
    assert!(N <= 32);
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(secret).unwrap();
    mac.update(&(N as u16).to_be_bytes());
    mac.update(&[(6 + label.len()) as u8]);
    mac.update(b"tls13 ");
    mac.update(label);
    mac.update(&[0, 1]); // Empty context, followed by the HKDF block counter.
    let output = mac.finalize().into_bytes();
    let mut result = [0; N];
    result.copy_from_slice(&output[..N]);
    result
}
