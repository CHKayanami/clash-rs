use aes::cipher::BlockCipherEncrypt;
use aes_gcm::{Aes128Gcm, aead::{Aead, Nonce, Payload}};

use super::{
    CryptoReassembly, QUIC_VERSION_1, QUIC_VERSION_2,
    QUIC_VERSION_2_DRAFT, QUIC_VERSION_DRAFT29,
    keys::{InitialId, InitialKeys},
};
use crate::app::sniffer::tls::parse_client_hello_handshake;

/// Decrypts all Initial packets in a UDP datagram and extracts all CRYPTO frame fragments as `(offset, data)`.
pub(super) fn decrypt_initial_datagram(
    data: &[u8], keys: &mut Option<InitialKeys>,
    mut collect: impl FnMut(u64, &[u8]),
) -> bool {
    let mut found = false;
    let identity = InitialId::from_packet(data);
    let mut offset = 0;

    while offset < data.len() {
        let remaining = &data[offset..];
        if remaining.len() < 7 {
            break;
        }

        let first_byte = remaining[0];
        // Long Header bit (0x80) and Fixed bit (0x40)
        if (first_byte & 0x80) == 0 || (first_byte & 0x40) == 0 {
            break;
        }

        let version = u32::from_be_bytes([
            remaining[1],
            remaining[2],
            remaining[3],
            remaining[4],
        ]);
        if version == 0 {
            // Version negotiation packet
            break;
        }

        let is_v2 = match version {
            QUIC_VERSION_1 | QUIC_VERSION_DRAFT29 => false,
            QUIC_VERSION_2 | QUIC_VERSION_2_DRAFT => true,
            _ => break,
        };

        // Packet type check
        let packet_type = (first_byte & 0x30) >> 4;
        if is_v2 {
            if packet_type != 0x01 {
                break;
            }
        } else if packet_type != 0x00 {
            break;
        }

        let mut pos = 5;
        if pos >= remaining.len() {
            break;
        }

        // DCID
        let dcil = remaining[pos] as usize;
        pos += 1;
        if dcil > 20 || pos + dcil > remaining.len() {
            break;
        }
        let dcid = &remaining[pos..pos + dcil];
        pos += dcil;

        // SCID
        if pos >= remaining.len() {
            break;
        }
        let scil = remaining[pos] as usize;
        pos += 1;
        if scil > 20 || pos + scil > remaining.len() {
            break;
        }
        pos += scil;

        // Token
        let Some((token_len, varint_len)) = read_varint(&remaining[pos..]) else {
            break;
        };
        pos += varint_len;
        if pos + (token_len as usize) > remaining.len() {
            break;
        }
        pos += token_len as usize;

        // Payload Length (Packet Number + AEAD payload + Tag)
        let Some((payload_len, varint_len)) = read_varint(&remaining[pos..]) else {
            break;
        };
        pos += varint_len;
        let pn_offset = pos;
        let total_len = pn_offset + (payload_len as usize);

        if remaining.len() < total_len || pn_offset + 4 + 16 > total_len {
            break;
        }

        let Some(id) = InitialId::new(version, dcid) else { break; };
        if Some(id) != identity { break; }
        if keys.as_ref().is_none_or(|keys| keys.id != id) {
            *keys = Some(InitialKeys::new(id));
        }
        let keys = keys.as_ref().unwrap();

        // Header Protection Removal
        let sample_offset = pn_offset + 4;
        if sample_offset + 16 > total_len {
            break;
        }
        let sample = &remaining[sample_offset..sample_offset + 16];

        let mut mask = [0u8; 16];
        mask.copy_from_slice(sample);
        keys.hp.encrypt_block((&mut mask).into());

        let unmasked_first_byte = first_byte ^ (mask[0] & 0x0f);
        let pn_len = ((unmasked_first_byte & 0x03) + 1) as usize;
        if pn_offset + pn_len > total_len {
            break;
        }

        let mut pn_bytes = [0u8; 4];
        for i in 0..pn_len {
            pn_bytes[i] = remaining[pn_offset + i] ^ mask[1 + i];
        }

        // Prepare AAD & Nonce
        let mut aad = remaining[..pn_offset + pn_len].to_vec();
        aad[0] = unmasked_first_byte;
        for i in 0..pn_len {
            aad[pn_offset + i] = pn_bytes[i];
        }

        let mut nonce_bytes = keys.iv;
        for i in 0..pn_len {
            nonce_bytes[12 - pn_len + i] ^= pn_bytes[i];
        }

        // Decrypt AES-128-GCM payload
        let ciphertext = &remaining[pn_offset + pn_len..total_len];
        let nonce =
            match Nonce::<Aes128Gcm>::try_from(&nonce_bytes[..]) {
                Ok(n) => n,
                Err(_) => break,
            };

        if let Ok(plaintext) = keys.gcm.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        ) {
            found |= collect_crypto_frames(&plaintext, &mut collect);
        }

        offset += total_len;
    }

    found
}

/// Collect CRYPTO frames from decrypted QUIC payload.
fn collect_crypto_frames(data: &[u8], collect: &mut impl FnMut(u64, &[u8])) -> bool {
    let mut found = false;
    let mut pos = 0;
    while pos < data.len() {
        let Some((frame_type, varint_len)) = read_varint(&data[pos..]) else {
            break;
        };
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
            0x02 | 0x03 => {
                // ACK frame
                let Some((_, l1)) = read_varint(&data[pos..]) else {
                    break;
                };
                pos += l1;
                let Some((_, l2)) = read_varint(&data[pos..]) else {
                    break;
                };
                pos += l2;
                let Some((range_count, l3)) = read_varint(&data[pos..]) else {
                    break;
                };
                pos += l3;
                let Some((_, l4)) = read_varint(&data[pos..]) else {
                    break;
                };
                pos += l4;
                for _ in 0..range_count {
                    let Some((_, l5)) = read_varint(&data[pos..]) else {
                        return found;
                    };
                    pos += l5;
                    let Some((_, l6)) = read_varint(&data[pos..]) else {
                        return found;
                    };
                    pos += l6;
                }
                if frame_type == 0x03 {
                    // ECN
                    for _ in 0..3 {
                        let Some((_, l)) = read_varint(&data[pos..]) else {
                            return found;
                        };
                        pos += l;
                    }
                }
            }
            0x06 => {
                // CRYPTO frame: offset (varint), length (varint), data
                let Some((offset, var_len1)) = read_varint(&data[pos..]) else {
                    break;
                };
                pos += var_len1;
                let Some((crypto_len, var_len2)) = read_varint(&data[pos..]) else {
                    break;
                };
                pos += var_len2;

                let crypto_len = crypto_len as usize;
                if pos + crypto_len > data.len() {
                    break;
                }

                let crypto_data = &data[pos..pos + crypto_len];
                collect(offset, crypto_data);
                found = true;
                pos += crypto_len;
            }
            0x1c | 0x1d => {
                // CONNECTION_CLOSE
                let Some((_, l1)) = read_varint(&data[pos..]) else {
                    break;
                };
                pos += l1;
                if frame_type == 0x1c {
                    let Some((_, l2)) = read_varint(&data[pos..]) else {
                        break;
                    };
                    pos += l2;
                }
                let Some((reason_len, l3)) = read_varint(&data[pos..]) else {
                    break;
                };
                pos += l3 + (reason_len as usize);
            }
            _ => {
                // Unknown frame in Initial packet
                break;
            }
        }
    }
    found
}

/// Extract TLS SNI from a single QUIC datagram.
pub fn parse_quic_sni(data: &[u8]) -> Option<String> {
    let mut reassembly = CryptoReassembly::new();
    if !decrypt_initial_datagram(data, &mut None, |offset, chunk| {
        reassembly.insert(offset, chunk);
    }) { return None; }
    parse_client_hello_handshake(reassembly.assembled())
}

pub(super) fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
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

