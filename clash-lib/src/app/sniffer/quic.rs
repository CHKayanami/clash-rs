/// QUIC Initial packet decryptor and TLS 1.3 ClientHello SNI extractor.
/// Supports RFC 9000/9001 (QUIC v1), RFC 9369 (QUIC v2), and draft-29.
use std::collections::BTreeMap;

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit as AesKeyInit};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::tls::parse_client_hello_handshake;

pub const QUIC_VERSION_1: u32 = 0x00000001;
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;
pub const QUIC_VERSION_2_DRAFT: u32 = 0x709a50c4;
pub const QUIC_VERSION_DRAFT29: u32 = 0xff00001d;

/// RFC 9001 §5.2 initial salt (QUIC v1)
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4,
    0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369 §3.3 initial salt (QUIC v2)
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e,
    0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

/// draft-29 initial salt
const QUIC_DRAFT29_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c,
    0x3f, 0xe1, 0xce, 0x46, 0xb1, 0x35, 0xd4,
];

/// Upper bound on the reassembled CRYPTO stream (ClientHello is typically < 4 KiB).
const MAX_CRYPTO_STREAM: usize = 64 * 1024;

/// Stream reassembly for QUIC CRYPTO frames.
#[derive(Debug, Clone, Default)]
pub struct CryptoReassembly {
    fragments: BTreeMap<u64, Vec<u8>>,
    assembled: Vec<u8>,
    overflowed: bool,
}

impl CryptoReassembly {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, offset: u64, data: &[u8]) {
        if self.overflowed || data.is_empty() {
            return;
        }

        let assembled_len = self.assembled.len() as u64;

        if offset < assembled_len {
            let skip = (assembled_len - offset) as usize;
            if skip >= data.len() {
                return;
            }
            self.insert(assembled_len, &data[skip..]);
            return;
        }

        self.fragments.insert(offset, data.to_vec());

        while let Some((&frag_offset, _)) = self.fragments.iter().next() {
            let cur_len = self.assembled.len() as u64;
            if frag_offset > cur_len {
                break;
            }

            let (_, frag_data) = self.fragments.remove_entry(&frag_offset).unwrap();
            let overlap = (cur_len - frag_offset) as usize;
            if overlap < frag_data.len() {
                let to_append = &frag_data[overlap..];
                if self.assembled.len() + to_append.len() > MAX_CRYPTO_STREAM {
                    self.overflowed = true;
                    self.assembled.clear();
                    self.fragments.clear();
                    return;
                }
                self.assembled.extend_from_slice(to_append);
            }
        }
    }

    pub fn assembled(&self) -> &[u8] {
        &self.assembled
    }

    pub fn is_overflowed(&self) -> bool {
        self.overflowed
    }
}

/// Decrypts all Initial packets in a UDP datagram and extracts all CRYPTO frame fragments as `(offset, data)`.
pub fn decrypt_initial_datagram(data: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut fragments = Vec::new();
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

        let (salt, is_v2) = match version {
            QUIC_VERSION_1 => (&QUIC_V1_SALT[..], false),
            QUIC_VERSION_2 | QUIC_VERSION_2_DRAFT => (&QUIC_V2_SALT[..], true),
            QUIC_VERSION_DRAFT29 => (&QUIC_DRAFT29_SALT[..], false),
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
        if pos + dcil > remaining.len() {
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
        if pos + scil > remaining.len() {
            break;
        }
        pos += scil;

        // Token
        let (token_len, varint_len) = read_varint(&remaining[pos..])?;
        pos += varint_len;
        if pos + (token_len as usize) > remaining.len() {
            break;
        }
        pos += token_len as usize;

        // Payload Length (Packet Number + AEAD payload + Tag)
        let (payload_len, varint_len) = read_varint(&remaining[pos..])?;
        pos += varint_len;
        let pn_offset = pos;
        let total_len = pn_offset + (payload_len as usize);

        if remaining.len() < total_len || pn_offset + 4 + 16 > total_len {
            break;
        }

        // Derive Initial Secrets
        let initial_secret = hkdf_extract(salt, dcid);
        let (client_label, key_label, iv_label, hp_label) = if is_v2 {
            (
                b"quicv2 client in".as_slice(),
                b"quicv2 key".as_slice(),
                b"quicv2 iv".as_slice(),
                b"quicv2 hp".as_slice(),
            )
        } else {
            (
                b"client in".as_slice(),
                b"quic key".as_slice(),
                b"quic iv".as_slice(),
                b"quic hp".as_slice(),
            )
        };

        let client_initial_secret =
            hkdf_expand_label(&initial_secret, client_label, &[], 32);
        let key = hkdf_expand_label(&client_initial_secret, key_label, &[], 16);
        let iv = hkdf_expand_label(&client_initial_secret, iv_label, &[], 12);
        let hp_key = hkdf_expand_label(&client_initial_secret, hp_label, &[], 16);

        // Header Protection Removal
        let sample_offset = pn_offset + 4;
        if sample_offset + 16 > total_len {
            break;
        }
        let sample = &remaining[sample_offset..sample_offset + 16];

        let cipher = match Aes128::new_from_slice(&hp_key) {
            Ok(c) => c,
            Err(_) => break,
        };
        let mut mask = [0u8; 16];
        mask.copy_from_slice(sample);
        cipher.encrypt_block((&mut mask).into());

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

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&iv);
        for i in 0..pn_len {
            nonce_bytes[12 - pn_len + i] ^= pn_bytes[i];
        }

        // Decrypt AES-128-GCM payload
        let ciphertext = &remaining[pn_offset + pn_len..total_len];
        let gcm = match Aes128Gcm::new_from_slice(&key) {
            Ok(g) => g,
            Err(_) => break,
        };
        let nonce =
            match aes_gcm::aead::Nonce::<Aes128Gcm>::try_from(&nonce_bytes[..]) {
                Ok(n) => n,
                Err(_) => break,
            };

        if let Ok(plaintext) = gcm.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        ) {
            collect_crypto_frames(&plaintext, &mut fragments);
        }

        offset += total_len;
    }

    if fragments.is_empty() {
        None
    } else {
        Some(fragments)
    }
}

/// Collect CRYPTO frames from decrypted QUIC payload.
fn collect_crypto_frames(data: &[u8], out: &mut Vec<(u64, Vec<u8>)>) {
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
                        return;
                    };
                    pos += l5;
                    let Some((_, l6)) = read_varint(&data[pos..]) else {
                        return;
                    };
                    pos += l6;
                }
                if frame_type == 0x03 {
                    // ECN
                    for _ in 0..3 {
                        let Some((_, l)) = read_varint(&data[pos..]) else {
                            return;
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
                out.push((offset, crypto_data.to_vec()));
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
}

/// Extract TLS SNI from a single QUIC datagram.
pub fn parse_quic_sni(data: &[u8]) -> Option<String> {
    let fragments = decrypt_initial_datagram(data)?;
    let mut reassembly = CryptoReassembly::new();
    for (offset, chunk) in fragments {
        reassembly.insert(offset, &chunk);
    }
    parse_client_hello_handshake(reassembly.assembled())
}

/// Outcome of feeding one datagram to the QUIC sniffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicSniffOutcome {
    /// Not a QUIC Initial packet, or flow is suppressed by DCID negative cache.
    NotQuic,
    /// Successfully decrypted QUIC Initial, but ClientHello spans across fragments/packets not all received yet.
    Incomplete,
    /// ClientHello is complete, but carries no SNI or was bypassed.
    CompleteNoDomain,
    /// SNI successfully extracted.
    Domain(String),
}

impl QuicSniffOutcome {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::CompleteNoDomain | Self::Domain(_))
    }

    pub fn into_domain(self) -> Option<String> {
        match self {
            Self::Domain(domain) => Some(domain),
            _ => None,
        }
    }
}

/// Key identifying a UDP flow: (src_addr, dst_addr)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpFlowKey {
    pub src: std::net::SocketAddr,
    pub dst: std::net::SocketAddr,
}

const SNIFFER_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const NO_SNI_THRESHOLD: u32 = 3;
const FAILED_DCID_TTL: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_INITIAL_SNIFF_PACKETS: u32 = 8;

struct SnifferSession {
    domain: Option<String>,
    packets_seen: u32,
    error_count: u32,
    crypto: CryptoReassembly,
    done: bool,
    expires_at: std::time::Instant,
}

impl SnifferSession {
    fn new() -> Self {
        Self {
            domain: None,
            packets_seen: 0,
            error_count: 0,
            crypto: CryptoReassembly::new(),
            done: false,
            expires_at: std::time::Instant::now() + SNIFFER_TTL,
        }
    }

    fn is_expired(&self, now: std::time::Instant) -> bool {
        now > self.expires_at
    }
}

/// Pool of packet sniffers with DCID negative caching and multi-packet ClientHello reassembly.
pub struct PacketSnifferPool {
    sessions:
        parking_lot::Mutex<std::collections::HashMap<UdpFlowKey, SnifferSession>>,
    failed_dcids: parking_lot::Mutex<
        std::collections::HashMap<UdpFlowKey, std::time::Instant>,
    >,
}

impl Default for PacketSnifferPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSnifferPool {
    pub fn new() -> Self {
        Self {
            sessions: parking_lot::Mutex::new(std::collections::HashMap::new()),
            failed_dcids: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn is_dcid_failed(&self, key: &UdpFlowKey, now: std::time::Instant) -> bool {
        if let Some(&expires_at) = self.failed_dcids.lock().get(key) {
            if now < expires_at {
                return true;
            }
        }
        false
    }

    pub fn mark_dcid_failed(
        &self,
        key: UdpFlowKey,
        now: std::time::Instant,
        ttl: std::time::Duration,
    ) {
        let mut failed = self.failed_dcids.lock();
        if failed.len() > 4096 {
            failed.retain(|_, expires_at| now < *expires_at);
        }
        failed.insert(key, now + ttl);
    }

    /// Feed a UDP datagram to the QUIC sniffer for the flow.
    pub fn feed_quic_datagram(
        &self,
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
        data: &[u8],
    ) -> QuicSniffOutcome {
        let key = UdpFlowKey { src, dst };
        let now = std::time::Instant::now();

        if self.is_dcid_failed(&key, now) {
            return QuicSniffOutcome::NotQuic;
        }

        // Decrypt fragments from datagram
        let fragments = decrypt_initial_datagram(data);

        let mut sessions = self.sessions.lock();
        if sessions.len() > 4096 {
            sessions.retain(|_, s| !s.is_expired(now));
        }

        let session = sessions.entry(key).or_insert_with(SnifferSession::new);

        if session.done {
            return session
                .domain
                .clone()
                .map(QuicSniffOutcome::Domain)
                .unwrap_or(QuicSniffOutcome::CompleteNoDomain);
        }

        session.packets_seen += 1;
        if session.packets_seen > MAX_INITIAL_SNIFF_PACKETS {
            drop(sessions);
            self.mark_dcid_failed(key, now, FAILED_DCID_TTL);
            return QuicSniffOutcome::NotQuic;
        }

        let fragments = match fragments {
            Some(f) => f,
            None => {
                session.error_count += 1;
                let failed = session.error_count >= NO_SNI_THRESHOLD;
                if failed {
                    session.done = true;
                }
                drop(sessions);
                if failed {
                    self.mark_dcid_failed(key, now, FAILED_DCID_TTL);
                }
                return QuicSniffOutcome::NotQuic;
            }
        };

        for (offset, chunk) in fragments {
            session.crypto.insert(offset, &chunk);
        }

        if session.crypto.is_overflowed() {
            session.done = true;
            drop(sessions);
            self.mark_dcid_failed(key, now, FAILED_DCID_TTL);
            return QuicSniffOutcome::CompleteNoDomain;
        }

        let assembled = session.crypto.assembled();
        if let Some(domain) = parse_client_hello_handshake(assembled) {
            session.domain = Some(domain.clone());
            session.done = true;
            return QuicSniffOutcome::Domain(domain);
        }

        // If we have received the ClientHello header, check if we need more bytes
        if assembled.len() >= 4 && assembled[0] == 0x01 {
            let handshake_len = ((assembled[1] as usize) << 16)
                | ((assembled[2] as usize) << 8)
                | (assembled[3] as usize);
            if assembled.len() < 4 + handshake_len {
                // ClientHello not yet complete: waiting for further packets
                return QuicSniffOutcome::Incomplete;
            }
        }

        // Handshake body was complete or invalid, but no SNI was found
        session.done = true;
        drop(sessions);
        self.mark_dcid_failed(key, now, std::time::Duration::from_secs(10));
        QuicSniffOutcome::CompleteNoDomain
    }
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

fn hkdf_expand_label(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
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
    fn test_crypto_reassembly_out_of_order() {
        let mut reassembly = CryptoReassembly::new();
        let part1 = b"Hello, ";
        let part2 = b"World!";
        reassembly.insert(7, part2);
        assert_eq!(reassembly.assembled(), b"");
        reassembly.insert(0, part1);
        assert_eq!(reassembly.assembled(), b"Hello, World!");
    }

    #[test]
    fn test_rfc9001_appendix_a2_vector() {
        // RFC 9001 Appendix A.2 standard vector: Client Initial packet with DCID 0x8394c8f03e515708
        // Server Name inside ClientHello is "example.com"
        let hex = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";
        let mut packet = Vec::new();
        for i in (0..hex.len()).step_by(2) {
            packet.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
        }

        let parsed = parse_quic_sni(&packet);
        assert_eq!(parsed, Some("example.com".to_string()));
    }

    #[test]
    fn test_quic_sniffer_pool_state_machine_and_negative_cache() {
        let pool = PacketSnifferPool::new();
        let src: std::net::SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let dst: std::net::SocketAddr = "8.8.8.8:443".parse().unwrap();
        let key = UdpFlowKey { src, dst };

        // 1. Send garbage packet -> NotQuic
        let garbage = [0u8; 40];
        let outcome = pool.feed_quic_datagram(src, dst, &garbage);
        assert_eq!(outcome, QuicSniffOutcome::NotQuic);
        assert!(!pool.is_dcid_failed(&key, std::time::Instant::now()));

        // 2. Fail 3 times -> DCID negative cache triggered
        for _ in 0..2 {
            pool.feed_quic_datagram(src, dst, &garbage);
        }
        assert!(pool.is_dcid_failed(&key, std::time::Instant::now()));

        // 3. Subsequent attempts return NotQuic immediately without decrypting
        let outcome = pool.feed_quic_datagram(src, dst, &garbage);
        assert_eq!(outcome, QuicSniffOutcome::NotQuic);
    }

    #[test]
    fn test_quic_sniffer_pool_valid_packet() {
        let pool = PacketSnifferPool::new();
        let src: std::net::SocketAddr = "10.0.0.2:12345".parse().unwrap();
        let dst: std::net::SocketAddr = "8.8.8.8:443".parse().unwrap();

        let hex = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";
        let mut packet = Vec::new();
        for i in (0..hex.len()).step_by(2) {
            packet.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
        }

        let outcome = pool.feed_quic_datagram(src, dst, &packet);
        assert_eq!(outcome, QuicSniffOutcome::Domain("example.com".to_string()));
    }
}
