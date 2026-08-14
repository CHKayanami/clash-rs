/// QUIC Initial packet decryptor and TLS 1.3 ClientHello SNI extractor.
/// Supports RFC 9000/9001 (QUIC v1), RFC 9369 (QUIC v2), and draft-29.

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit as AesKeyInit};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::tls::parse_client_hello_handshake;

const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x7b, 0x23, 0x23, 0x34, 0x79, 0x18, 0x85, 0x5d, 0xd5,
    0x19, 0xd2, 0xa8, 0x7d, 0x56, 0x48, 0x60, 0x93, 0x76, 0xb8,
];

const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xc9, 0xbf, 0x09, 0x9a, 0x22,
];

const QUIC_DRAFT29_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
    0x86, 0xf1, 0x9c, 0x3f, 0xe1, 0xce, 0x46, 0xb1, 0x35, 0xd4,
];

pub fn parse_quic_sni(data: &[u8]) -> Option<String> {
    if data.len() < 40 {
        return None;
    }

    let first_byte = data[0];
    // Must be Long Header (0x80) and have Fixed Bit (0x40)
    if (first_byte & 0x80) == 0 || (first_byte & 0x40) == 0 {
        return None;
    }

    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    if version == 0 {
        // Version negotiation packet, not an Initial packet
        return None;
    }

    let (salt, is_v2) = match version {
        0x00000001 => (&QUIC_V1_SALT[..], false),
        0x709a50c4 => (&QUIC_V2_SALT[..], true),
        0xff00001d => (&QUIC_DRAFT29_SALT[..], false),
        _ => return None,
    };

    // Packet type for Initial packet:
    // QUIC v1 & draft-29: (first_byte & 0x30) >> 4 == 0x00
    // QUIC v2: (first_byte & 0x30) >> 4 == 0x01
    let packet_type = (first_byte & 0x30) >> 4;
    if is_v2 {
        if packet_type != 0x01 {
            return None;
        }
    } else if packet_type != 0x00 {
        return None;
    }

    let mut pos = 5;
    if pos >= data.len() {
        return None;
    }

    // DCID length & DCID
    let dcil = data[pos] as usize;
    pos += 1;
    if pos + dcil > data.len() {
        return None;
    }
    let dcid = &data[pos..pos + dcil];
    pos += dcil;

    // SCID length & SCID
    if pos >= data.len() {
        return None;
    }
    let scil = data[pos] as usize;
    pos += 1;
    if pos + scil > data.len() {
        return None;
    }
    pos += scil;

    // Token length & Token
    let (token_len, varint_len) = read_varint(&data[pos..])?;
    pos += varint_len;
    if pos + (token_len as usize) > data.len() {
        return None;
    }
    pos += token_len as usize;

    // Length of packet (Packet Number + AEAD payload + Tag)
    let (payload_len, varint_len) = read_varint(&data[pos..])?;
    pos += varint_len;
    let pn_offset = pos;
    let total_len = pn_offset + (payload_len as usize);

    if data.len() < total_len || pn_offset + 4 + 16 > data.len() {
        return None;
    }

    // Derive Initial Secrets
    let initial_secret = hkdf_extract(salt, dcid);
    let (client_label, key_label, iv_label, hp_label) = if is_v2 {
        (b"quicv2 client in".as_slice(), b"quicv2 key".as_slice(), b"quicv2 iv".as_slice(), b"quicv2 hp".as_slice())
    } else {
        (b"client in".as_slice(), b"quic key".as_slice(), b"quic iv".as_slice(), b"quic hp".as_slice())
    };

    let client_initial_secret = hkdf_expand_label(&initial_secret, client_label, &[], 32);
    let key = hkdf_expand_label(&client_initial_secret, key_label, &[], 16);
    let iv = hkdf_expand_label(&client_initial_secret, iv_label, &[], 12);
    let hp_key = hkdf_expand_label(&client_initial_secret, hp_label, &[], 16);

    // Header protection removal
    // Sample is 16 bytes starting 4 bytes after pn_offset
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > total_len {
        return None;
    }
    let sample = &data[sample_offset..sample_offset + 16];

    let cipher = Aes128::new_from_slice(&hp_key).ok()?;
    let mut mask = [0u8; 16];
    mask.copy_from_slice(sample);
    cipher.encrypt_block((&mut mask).into());

    let unmasked_first_byte = first_byte ^ (mask[0] & 0x0f);
    let pn_len = ((unmasked_first_byte & 0x03) + 1) as usize;
    if pn_offset + pn_len > total_len {
        return None;
    }

    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[i] = data[pn_offset + i] ^ mask[1 + i];
    }

    // Prepare AAD & Nonce
    let mut aad = data[..pn_offset + pn_len].to_vec();
    aad[0] = unmasked_first_byte;
    for i in 0..pn_len {
        aad[pn_offset + i] = pn_bytes[i];
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&iv);
    for i in 0..pn_len {
        nonce_bytes[12 - pn_len + i] ^= pn_bytes[i];
    }

    // Decrypt AES-128-GCM payload
    let ciphertext = &data[pn_offset + pn_len..total_len];
    let gcm = Aes128Gcm::new_from_slice(&key).ok()?;
    let nonce = aes_gcm::aead::Nonce::<Aes128Gcm>::try_from(&nonce_bytes[..]).ok()?;
    let plaintext = gcm.decrypt(&nonce, Payload { msg: ciphertext, aad: &aad }).ok()?;

    // Parse QUIC Frames in decrypted payload
    extract_sni_from_quic_frames(&plaintext)
}

fn extract_sni_from_quic_frames(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos < data.len() {
        let (frame_type, varint_len) = read_varint(&data[pos..])?;
        pos += varint_len;

        match frame_type {
            0x00 => {
                // PADDING
                while pos < data.len() && data[pos] == 0 {
                    pos += 1;
                }
            }
            0x01 => {
                // PING
            }
            0x06 => {
                // CRYPTO frame: offset (varint), length (varint), data
                let (offset, var_len1) = read_varint(&data[pos..])?;
                pos += var_len1;
                let (crypto_len, var_len2) = read_varint(&data[pos..])?;
                pos += var_len2;

                let crypto_len = crypto_len as usize;
                if pos + crypto_len > data.len() {
                    return None;
                }

                if offset == 0 {
                    let crypto_data = &data[pos..pos + crypto_len];
                    if let Some(sni) = parse_client_hello_handshake(crypto_data) {
                        return Some(sni);
                    }
                }
                pos += crypto_len;
            }
            _ => {
                // Other frames - cannot safely determine length of unknown frames without full frame parser
                break;
            }
        }
    }

    None
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    let prefix = (first & 0xc0) >> 6;
    match prefix {
        0 => Some((first as u64, 1)),
        1 => {
            if data.len() < 2 {
                return None;
            }
            let val = (((first & 0x3f) as u64) << 8) | (data[1] as u64);
            Some((val, 2))
        }
        2 => {
            if data.len() < 4 {
                return None;
            }
            let val = (((first & 0x3f) as u64) << 24)
                | ((data[1] as u64) << 16)
                | ((data[2] as u64) << 8)
                | (data[3] as u64);
            Some((val, 4))
        }
        3 => {
            if data.len() < 8 {
                return None;
            }
            let val = (((first & 0x3f) as u64) << 56)
                | ((data[1] as u64) << 48)
                | ((data[2] as u64) << 40)
                | ((data[3] as u64) << 32)
                | ((data[4] as u64) << 24)
                | ((data[5] as u64) << 16)
                | ((data[6] as u64) << 8)
                | (data[7] as u64);
            Some((val, 8))
        }
        _ => unreachable!(),
    }
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC salt");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand(prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(okm_len);
    let mut t = Vec::new();
    let mut counter = 1u8;
    while okm.len() < okm_len {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("HMAC prk");
        if !t.is_empty() {
            mac.update(&t);
        }
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        let take = std::cmp::min(t.len(), okm_len - okm.len());
        okm.extend_from_slice(&t[..take]);
        counter += 1;
    }
    okm
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    let full_label = [b"tls13 ", label].concat();
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_parsing() {
        assert_eq!(read_varint(&[0x25]), Some((37, 1)));
        assert_eq!(read_varint(&[0x7b, 0xbd]), Some((15293, 2)));
        assert_eq!(read_varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494878333, 4)));
    }

    #[test]
    fn test_non_quic_packet() {
        let data = [0u8; 50];
        assert_eq!(parse_quic_sni(&data), None);
    }

    #[test]
    fn test_quic_v1_initial_sni_extraction() {
        let server_name = "quic.cloudflare.com";
        let tls_record = crate::app::sniffer::tests::build_tls_client_hello(server_name);
        let client_hello = &tls_record[5..];

        // Build CRYPTO frame: Type 0x06, offset 0x00, length (varint), data
        let mut crypto_frame = Vec::new();
        crypto_frame.push(0x06); // Type
        crypto_frame.push(0x00); // Offset 0
        crypto_frame.extend_from_slice(&((client_hello.len() as u16) | 0x4000).to_be_bytes()); // Length (2-byte varint)
        crypto_frame.extend_from_slice(client_hello);

        // Pad to at least 64 bytes
        while crypto_frame.len() < 64 {
            crypto_frame.push(0x00); // Padding
        }

        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let initial_secret = hkdf_extract(&QUIC_V1_SALT, &dcid);
        let client_initial_secret = hkdf_expand_label(&initial_secret, b"client in", &[], 32);
        let key = hkdf_expand_label(&client_initial_secret, b"quic key", &[], 16);
        let iv = hkdf_expand_label(&client_initial_secret, b"quic iv", &[], 12);
        let hp_key = hkdf_expand_label(&client_initial_secret, b"quic hp", &[], 16);

        let pn = 1u32;
        let pn_len = 4usize;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv);
        nonce[11] ^= 1;

        let payload_len = pn_len + crypto_frame.len() + 16; // 16 for GCM tag

        let mut header = Vec::new();
        header.push(0xc0 | ((pn_len - 1) as u8)); // Long header, Initial, 4-byte PN
        header.extend_from_slice(&1u32.to_be_bytes()); // Version 1
        header.push(dcid.len() as u8);
        header.extend_from_slice(&dcid);
        header.push(0x00); // SCID len 0
        header.push(0x00); // Token len 0
        // Length varint (2 bytes)
        header.extend_from_slice(&((payload_len as u16) | 0x4000).to_be_bytes());
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes());

        let gcm = Aes128Gcm::new_from_slice(&key).unwrap();
        let gcm_nonce = aes_gcm::aead::Nonce::<Aes128Gcm>::try_from(&nonce[..]).unwrap();
        let ciphertext = gcm.encrypt(&gcm_nonce, Payload { msg: &crypto_frame, aad: &header }).unwrap();

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);

        // Apply Header Protection
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let cipher = Aes128::new_from_slice(&hp_key).unwrap();
        let mut mask = [0u8; 16];
        mask.copy_from_slice(sample);
        cipher.encrypt_block((&mut mask).into());

        packet[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }

        let parsed = parse_quic_sni(&packet);
        assert_eq!(parsed, Some("quic.cloudflare.com".to_string()));
    }
}
