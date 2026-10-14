/// QUIC Initial packet decryptor and TLS 1.3 ClientHello SNI extractor.
/// Supports RFC 9000/9001 (QUIC v1), RFC 9369 (QUIC v2), and draft-29.
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::{AtomicU64, Ordering}},
};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

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

mod reassembly;
mod keys;
mod decrypt;

pub use reassembly::CryptoReassembly;
pub use decrypt::parse_quic_sni;
use decrypt::decrypt_initial_datagram;
use keys::{InitialId, InitialKeys};

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

#[inline]
pub fn is_grease_version(version: u32) -> bool {
    (version & 0x0f0f_0f0f) == 0x0a0a_0a0a
}

/// Key identifying a UDP flow: (src_addr, dst_addr)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpFlowKey {
    pub src: std::net::SocketAddr,
    pub dst: std::net::SocketAddr,
}

const SNIFFER_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const NO_SNI_THRESHOLD: u32 = 3;
const FAILED_DCID_TTL: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_INITIAL_SNIFF_PACKETS: u32 = 8;
const MAX_FAILED_DCIDS: usize = 4096;
const TARGET_FAILED_DCIDS: usize = 3072;
const MAX_SESSIONS: usize = 4096;
const TARGET_SESSIONS: usize = 3072;

struct SnifferSession {
    domain: Option<String>,
    packets_seen: u32,
    error_count: u32,
    crypto: CryptoReassembly,
    identity: Option<InitialId>,
    keys: Option<InitialKeys>,
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
            identity: None,
            keys: None,
            done: false,
            expires_at: std::time::Instant::now() + SNIFFER_TTL,
        }
    }

    fn finish(&mut self) {
        self.done = true;
        self.crypto = CryptoReassembly::new();
        self.keys = None;
    }

    fn is_expired(&self, now: std::time::Instant) -> bool {
        now > self.expires_at
    }
}

/// Pool of packet sniffers with DCID negative caching and multi-packet ClientHello reassembly.
pub struct PacketSnifferPool {
    sessions: DashMap<UdpFlowKey, Arc<Mutex<SnifferSession>>>,
    failed_dcids: DashMap<UdpFlowKey, Instant>,
    sessions_eviction_lock: Mutex<()>,
    failed_dcids_eviction_lock: Mutex<()>,
    cleanup_epoch: Instant,
    next_cleanup_ms: AtomicU64,
}

impl Default for PacketSnifferPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSnifferPool {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            failed_dcids: DashMap::new(),
            sessions_eviction_lock: Mutex::new(()),
            failed_dcids_eviction_lock: Mutex::new(()),
            cleanup_epoch: Instant::now(),
            next_cleanup_ms: AtomicU64::new(SNIFFER_TTL.as_millis() as u64),
        }
    }

    pub fn sessions_len(&self) -> usize {
        self.sessions.len()
    }

    pub fn failed_dcids_len(&self) -> usize {
        self.failed_dcids.len()
    }

    pub fn is_dcid_failed(&self, key: &UdpFlowKey, now: Instant) -> bool {
        if let Some(expires_at) = self.failed_dcids.get(key) {
            if now < *expires_at {
                return true;
            }
        }
        false
    }

    pub fn mark_dcid_failed(
        &self,
        key: UdpFlowKey,
        now: Instant,
        ttl: Duration,
    ) {
        // Fast path: if key already exists, update in-place without triggering eviction.
        if let Some(mut entry) = self.failed_dcids.get_mut(&key) {
            *entry.value_mut() = now + ttl;
            return;
        }

        // Slow path: inserting a new key.
        // Synchronize under eviction_lock to ensure atomic capacity check and insertion under concurrency.
        let _guard = self.failed_dcids_eviction_lock.lock();

        // Double check
        if let Some(mut entry) = self.failed_dcids.get_mut(&key) {
            *entry.value_mut() = now + ttl;
            return;
        }

        if self.failed_dcids.len() >= MAX_FAILED_DCIDS {
            self.failed_dcids.retain(|_, expires_at| now < *expires_at);
            if self.failed_dcids.len() >= MAX_FAILED_DCIDS {
                let to_evict = (self.failed_dcids.len() + 1).saturating_sub(TARGET_FAILED_DCIDS);
                let mut evicted = 0;
                self.failed_dcids.retain(|_, _| {
                    if evicted < to_evict {
                        evicted += 1;
                        false
                    } else {
                        true
                    }
                });
            }
        }
        self.failed_dcids.insert(key, now + ttl);
    }

    fn claim_cleanup(&self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.cleanup_epoch)
            .as_millis().try_into().unwrap_or(u64::MAX);
        // This atomic only schedules scans. The maps and flow locks protect data,
        // so publishing the next deadline needs no acquire/release ordering.
        let next = self.next_cleanup_ms.load(Ordering::Relaxed);
        elapsed >= next && self.next_cleanup_ms.compare_exchange(
            next,
            elapsed.saturating_add(SNIFFER_TTL.as_millis() as u64),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ).is_ok()
    }

    fn prune_expired(&self, now: Instant) {
        if !self.claim_cleanup(now) { return; }
        self.sessions.retain(|_, session| {
            // Busy flows are retained for the next cleanup pass.
            session.try_lock().is_none_or(|s| !s.is_expired(now))
        });
        self.failed_dcids.retain(|_, expires_at| now < *expires_at);
    }

    /// Feed a UDP datagram to the QUIC sniffer for the flow.
    pub fn feed_quic_datagram(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
    ) -> QuicSniffOutcome {
        let key = UdpFlowKey { src, dst };
        let now = Instant::now();

        self.prune_expired(now);
        let identity = InitialId::from_packet(data);
        if self.is_dcid_failed(&key, now) {
            let existing = self.sessions.get(&key)
                .map(|entry| Arc::clone(entry.value()));
            let changed = existing.is_some_and(|entry| {
                identity.is_some() && entry.lock().identity != identity
            });
            if !changed { return QuicSniffOutcome::NotQuic; }
            self.failed_dcids.remove(&key);
        }

        let session = if let Some(s) = self.sessions.get(&key) {
            Arc::clone(s.value())
        } else {
            let _guard = self.sessions_eviction_lock.lock();
            let s = if let Some(s) = self.sessions.get(&key) {
                Arc::clone(s.value())
            } else {
                if self.sessions.len() >= MAX_SESSIONS {
                    self.sessions.retain(|_, s| {
                        s.try_lock().is_none_or(|s| !s.is_expired(now))
                    });
                    if self.sessions.len() >= MAX_SESSIONS {
                        let to_evict =
                            (self.sessions.len() + 1).saturating_sub(TARGET_SESSIONS);
                        let mut evicted = 0;
                        self.sessions.retain(|_, _| {
                            if evicted < to_evict {
                                evicted += 1;
                                false
                            } else {
                                true
                            }
                        });
                    }
                }
                let entry = self.sessions.entry(key).or_insert_with(|| {
                    Arc::new(Mutex::new(SnifferSession::new()))
                });
                Arc::clone(entry.value())
            };
            drop(_guard);
            s
        };

        // Crypto work holds only the flow lock, never a DashMap shard lock.
        let mut session = session.lock();
        if session.is_expired(now)
            || identity.is_some() && session.identity != identity
        {
            *session = SnifferSession::new();
            session.identity = identity;
        }

        if session.done && session.identity == identity {
            return session
                .domain
                .clone()
                .map(QuicSniffOutcome::Domain)
                .unwrap_or(QuicSniffOutcome::CompleteNoDomain);
        }

        session.packets_seen += 1;
        if session.packets_seen > MAX_INITIAL_SNIFF_PACKETS {
            session.finish();
            drop(session);
            self.mark_dcid_failed(key, now, FAILED_DCID_TTL);
            return QuicSniffOutcome::NotQuic;
        }

        let SnifferSession { crypto, keys, .. } = &mut *session;
        let decrypted = decrypt_initial_datagram(data, keys, |offset, chunk| {
            crypto.insert(offset, chunk);
        });
        if !decrypted {
            session.error_count += 1;
            let failed = session.error_count >= NO_SNI_THRESHOLD;
            if failed { session.finish(); }
            drop(session);
            if failed { self.mark_dcid_failed(key, now, FAILED_DCID_TTL); }
            return QuicSniffOutcome::NotQuic;
        }

        if session.crypto.is_overflowed() {
            session.finish();
            drop(session);
            self.mark_dcid_failed(key, now, FAILED_DCID_TTL);
            return QuicSniffOutcome::CompleteNoDomain;
        }

        let assembled = session.crypto.assembled();
        if let Some(domain) = parse_client_hello_handshake(assembled) {
            session.domain = Some(domain.clone());
            session.finish();
            return QuicSniffOutcome::Domain(domain);
        }

        // Out-of-order CRYPTO frames or a split handshake header need more data.
        if assembled.len() < 4 {
            return QuicSniffOutcome::Incomplete;
        }

        // If we have received the ClientHello header, check if we need more bytes
        if assembled[0] == 0x01 {
            let handshake_len = ((assembled[1] as usize) << 16)
                | ((assembled[2] as usize) << 8)
                | (assembled[3] as usize);
            if assembled.len() < 4 + handshake_len {
                // ClientHello not yet complete: waiting for further packets
                return QuicSniffOutcome::Incomplete;
            }
        }

        // Handshake body was complete or invalid, but no SNI was found
        session.finish();
        drop(session);
        self.mark_dcid_failed(key, now, Duration::from_secs(10));
        QuicSniffOutcome::CompleteNoDomain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::Aes128;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    use aes_gcm::{Aes128Gcm, aead::{Aead, Nonce, Payload}};
    use super::decrypt::read_varint;

    use crate::app::sniffer::tests::build_tls_client_hello;

    // Encrypt with the independently published RFC 9369 Appendix A.1 keys.
    // This exercises v2 decryption without deriving the test keys with production code.
    fn v2_initial(offset: u16, crypto: &[u8]) -> Vec<u8> {
        let key = [
            0x8b, 0x1a, 0x0b, 0xc1, 0x21, 0x28, 0x42, 0x90,
            0xa2, 0x9e, 0x09, 0x71, 0xb5, 0xcd, 0x04, 0x5d,
        ];
        let iv = [
            0x91, 0xf7, 0x3e, 0x23, 0x51, 0xd8,
            0xfa, 0x91, 0x66, 0x0e, 0x90, 0x9f,
        ];
        let hp_key = [
            0x45, 0xb9, 0x5e, 0x15, 0x23, 0x5d, 0x6f, 0x45,
            0xa6, 0xb1, 0x9c, 0xbc, 0xb0, 0x29, 0x4b, 0xa9,
        ];
        let mut plaintext = vec![0x06];
        plaintext.extend_from_slice(&(offset | 0x4000).to_be_bytes());
        plaintext.extend_from_slice(&((crypto.len() as u16) | 0x4000).to_be_bytes());
        plaintext.extend_from_slice(crypto);
        plaintext.resize(1162, 0);

        // DCID and packet number match the RFC keys and nonce.
        let mut packet = vec![
            0xd3, 0x6b, 0x33, 0x43, 0xcf, 0x08,
            0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
        ];
        let mut nonce = iv;
        nonce[11] ^= 2;
        let gcm = Aes128Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::<Aes128Gcm>::try_from(&nonce[..]).unwrap();
        let ciphertext = gcm.encrypt(
            &nonce, Payload { msg: &plaintext, aad: &packet },
        ).unwrap();
        packet.extend_from_slice(&ciphertext);
        let mut mask = [0; 16];
        mask.copy_from_slice(&packet[22..38]);
        let cipher = Aes128::new_from_slice(&hp_key).unwrap();
        cipher.encrypt_block((&mut mask).into());
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..4 {
            packet[18 + i] ^= mask[1 + i];
        }
        packet
    }

    #[test]
    fn test_v2_initial_with_rfc9369_keys() {
        let hello = build_tls_client_hello("example.com");
        let packet = v2_initial(0, &hello[5..]);
        assert_eq!(parse_quic_sni(&packet), Some("example.com".to_string()));
    }

    #[test]
    fn test_quic_pool_incomplete_handshake_header() {
        let hello = build_tls_client_hello("example.com");
        let hello = &hello[5..];
        let src = "192.0.2.1:12345".parse().unwrap();
        let dst = "192.0.2.2:443".parse().unwrap();
        for split in 1..=3 {
            for tail_first in [false, true] {
                let pool = PacketSnifferPool::new();
                let head = v2_initial(0, &hello[..split]);
                let tail = v2_initial(split as u16, &hello[split..]);
                let (first, second) = if tail_first {
                    (tail, head)
                } else {
                    (head, tail)
                };
                assert_eq!(
                    pool.feed_quic_datagram(src, dst, &first),
                    QuicSniffOutcome::Incomplete,
                );
                assert!(!pool.is_dcid_failed(
                    &UdpFlowKey { src, dst }, Instant::now(),
                ));
                assert_eq!(
                    pool.feed_quic_datagram(src, dst, &second),
                    QuicSniffOutcome::Domain("example.com".to_string()),
                );
            }
        }
    }

    #[test]
    fn test_crypto_reassembly_shorter_retransmission() {
        let mut reassembly = CryptoReassembly::new();
        reassembly.insert(4, b"efghijkl");
        reassembly.insert(4, b"efgh");
        reassembly.insert(0, b"abcd");
        assert_eq!(reassembly.assembled(), b"abcdefghijkl");

        // A longer retransmission must still extend the buffered fragment.
        let mut reassembly = CryptoReassembly::new();
        reassembly.insert(4, b"efgh");
        reassembly.insert(4, b"efghijkl");
        reassembly.insert(0, b"abcd");
        assert_eq!(reassembly.assembled(), b"abcdefghijkl");
    }

    #[test]
    fn terminal_flow_releases_crypto_and_checks_connection_identity() {
        let pool = PacketSnifferPool::new();
        let src = "192.0.2.1:12345".parse().unwrap();
        let dst = "192.0.2.2:443".parse().unwrap();
        let key = UdpFlowKey { src, dst };
        let hello = build_tls_client_hello("example.com");
        let packet = v2_initial(0, &hello[5..]);
        let expected = QuicSniffOutcome::Domain("example.com".to_string());
        assert_eq!(pool.feed_quic_datagram(src, dst, &packet), expected);
        {
            let entry = pool.sessions.get(&key).unwrap();
            let session = entry.lock();
            assert!(session.done);
            assert!(session.crypto.assembled().is_empty());
            assert!(session.keys.is_none());
        }
        // A terminal flow can reuse its result without decrypting the payload.
        let mut corrupt = packet.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(pool.feed_quic_datagram(src, dst, &corrupt), expected);
        corrupt[6] ^= 1;
        assert_eq!(pool.feed_quic_datagram(src, dst, &corrupt), QuicSniffOutcome::NotQuic);
        {
            let entry = pool.sessions.get(&key).unwrap();
            let session = entry.lock();
            assert!(!session.done);
            assert!(session.domain.is_none());
        }
        assert_eq!(pool.feed_quic_datagram(src, dst, &packet), expected);
    }

    #[test]
    fn incomplete_flow_reuses_keys_and_prunes_expired_state() {
        let pool = PacketSnifferPool::new();
        let src = "192.0.2.1:12345".parse().unwrap();
        let dst = "192.0.2.2:443".parse().unwrap();
        let key = UdpFlowKey { src, dst };
        let hello = build_tls_client_hello("example.com");
        let head = v2_initial(0, &hello[5..7]);
        assert_eq!(pool.feed_quic_datagram(src, dst, &head), QuicSniffOutcome::Incomplete);
        {
            let entry = pool.sessions.get(&key).unwrap();
            let session = entry.lock();
            assert!(session.keys.is_some());
            assert_eq!(session.crypto.assembled(), &hello[5..7]);
        }
        let tail = v2_initial(2, &hello[7..]);
        assert_eq!(pool.feed_quic_datagram(src, dst, &tail),
            QuicSniffOutcome::Domain("example.com".to_string()));
        let now = Instant::now() + SNIFFER_TTL + Duration::from_secs(1);
        pool.mark_dcid_failed(key, Instant::now(), FAILED_DCID_TTL);
        pool.prune_expired(now);
        assert!(pool.sessions.is_empty());
        assert!(pool.failed_dcids.is_empty());
    }

    #[test]
    fn cleanup_deadline_preserves_scan_interval() {
        let pool = PacketSnifferPool::new();
        let start = pool.cleanup_epoch;
        assert!(!pool.claim_cleanup(start + SNIFFER_TTL - Duration::from_millis(1)));
        assert!(pool.claim_cleanup(start + SNIFFER_TTL));
        assert!(!pool.claim_cleanup(start + SNIFFER_TTL));
        assert!(!pool.claim_cleanup(start + SNIFFER_TTL * 2 - Duration::from_millis(1)));
        assert!(pool.claim_cleanup(start + SNIFFER_TTL * 2));
    }

    #[test]
    fn concurrent_cleanup_claims_have_one_winner() {
        use std::{sync::Barrier, thread};

        let pool = Arc::new(PacketSnifferPool::new());
        let barrier = Arc::new(Barrier::new(8));
        let now = pool.cleanup_epoch + SNIFFER_TTL;
        let mut handles = Vec::new();
        for _ in 0..8 {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                usize::from(pool.claim_cleanup(now))
            }));
        }
        let winners: usize = handles.into_iter()
            .map(|handle| handle.join().unwrap()).sum();
        assert_eq!(winners, 1);
    }

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

    #[test]
    fn test_quic_sniffer_pool_capacity_limit_and_batch_eviction() {
        let pool = PacketSnifferPool::new();
        let now = std::time::Instant::now();

        // 1. Fill failed_dcids beyond 4096
        for i in 0..4100 {
            let key = UdpFlowKey {
                src: format!("10.0.0.1:{}", 1024 + (i % 60000)).parse().unwrap(),
                dst: format!("8.8.8.{}:443", (i / 60000) + 1).parse().unwrap(),
            };
            pool.mark_dcid_failed(key, now, std::time::Duration::from_secs(60));
        }

        // Hard capacity guaranteed <= 4096 (evicted to 3071 + 4 = 3075)
        assert!(pool.failed_dcids_len() <= 4096);
        assert_eq!(pool.failed_dcids_len(), 3075);

        // 2. Fill sessions beyond 4096
        let garbage = [0u8; 40];
        for i in 0..4100 {
            let src = format!("10.0.0.2:{}", 1024 + (i % 60000)).parse().unwrap();
            let dst = format!("8.8.8.{}:443", (i / 60000) + 1).parse().unwrap();
            pool.feed_quic_datagram(src, dst, &garbage);
        }
        assert!(pool.sessions_len() <= 4096);
        assert_eq!(pool.sessions_len(), 3075);
    }

    #[test]
    fn test_quic_sniffer_pool_existing_key_does_not_evict() {
        let pool = PacketSnifferPool::new();
        let now = std::time::Instant::now();

        // 1. Fill failed_dcids exactly to 4096
        for i in 0..4096 {
            let key = UdpFlowKey {
                src: format!("10.0.0.1:{}", 1024 + (i % 60000)).parse().unwrap(),
                dst: format!("8.8.8.{}:443", (i / 60000) + 1).parse().unwrap(),
            };
            pool.mark_dcid_failed(key, now, std::time::Duration::from_secs(60));
        }
        assert_eq!(pool.failed_dcids_len(), 4096);

        // Updating an existing failed DCID key must NOT trigger eviction
        let existing_key = UdpFlowKey {
            src: "10.0.0.1:1024".parse().unwrap(),
            dst: "8.8.8.1:443".parse().unwrap(),
        };
        for _ in 0..10 {
            pool.mark_dcid_failed(existing_key, now, std::time::Duration::from_secs(60));
            assert_eq!(pool.failed_dcids_len(), 4096);
        }

        // 2. Fill sessions exactly to 4096
        let garbage = [0u8; 40];
        for i in 0..4096 {
            let src = format!("10.0.0.2:{}", 1024 + (i % 60000)).parse().unwrap();
            let dst = format!("8.8.8.{}:443", (i / 60000) + 1).parse().unwrap();
            pool.feed_quic_datagram(src, dst, &garbage);
        }
        assert_eq!(pool.sessions_len(), 4096);

        // Subsequent datagrams for an existing flow session must NOT trigger eviction
        let existing_src = "10.0.0.2:1024".parse().unwrap();
        let existing_dst = "8.8.8.1:443".parse().unwrap();
        for _ in 0..10 {
            pool.feed_quic_datagram(existing_src, existing_dst, &garbage);
            assert_eq!(pool.sessions_len(), 4096);
        }
    }

    #[test]
    fn test_quic_sniffer_pool_concurrent_hard_capacity_limit() {
        use std::sync::Arc;

        let pool = Arc::new(PacketSnifferPool::new());
        let mut handles = Vec::new();

        // 10 threads concurrently inserting into failed_dcids and sessions
        for thread_idx in 0..10 {
            let pool_clone = pool.clone();
            handles.push(std::thread::spawn(move || {
                let now = Instant::now();
                let garbage = [0u8; 40];
                for i in 0..500 {
                    let port = 1024 + (thread_idx * 500 + i) as u16;
                    let key = UdpFlowKey {
                        src: format!("10.0.0.1:{}", port).parse().unwrap(),
                        dst: "8.8.8.8:443".parse().unwrap(),
                    };
                    pool_clone.mark_dcid_failed(key, now, Duration::from_secs(60));
                    assert!(pool_clone.failed_dcids_len() <= 4096);

                    let src = format!("10.0.0.2:{}", port).parse().unwrap();
                    let dst = "8.8.8.8:443".parse().unwrap();
                    pool_clone.feed_quic_datagram(src, dst, &garbage);
                    assert!(pool_clone.sessions_len() <= 4096);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert!(pool.failed_dcids_len() <= 4096);
        assert!(pool.sessions_len() <= 4096);
    }
}
