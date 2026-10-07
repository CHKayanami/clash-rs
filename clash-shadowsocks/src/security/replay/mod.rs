use std::{fmt, io};

#[cfg(feature = "aead-cipher-2022")]
mod nonce;
#[cfg(feature = "aead-cipher-2022")]
use nonce::Nonces;

use crate::{config::ServerType, crypto::CipherKind};

/// A protector against replay attack (AEAD 2022)
pub struct ReplayProtector {
    // AEAD 2022 specific filter.
    // AEAD 2022 TCP protocol has a timestamp, which can already reject most of the replay requests,
    // so we only need to remember nonce that are in the valid time range
    #[cfg(feature = "aead-cipher-2022")]
    nonce_set: Nonces,
}

impl fmt::Debug for ReplayProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayProtector").finish()
    }
}

impl ReplayProtector {
    /// Create a new ReplayProtector
    #[allow(unused_variables)]
    pub fn new(config_type: ServerType) -> Self {
        Self {
            #[cfg(feature = "aead-cipher-2022")]
            nonce_set: Nonces::default(),
        }
    }

    /// Check and retain incoming salts for the complete protocol replay window.
    pub fn check_nonce_and_set(&self, method: CipherKind, nonce: &[u8]) -> io::Result<()> {
        if nonce.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "aead-cipher-2022")]
        if method.is_aead_2022() {
            return self.nonce_set.check_and_set(nonce);
        }
        let _ = method;
        Ok(())
    }
}

#[cfg(feature = "aead-cipher-2022")]
const UDP_REPLAY_WINDOW_SIZE: u64 = 1024;
#[cfg(feature = "aead-cipher-2022")]
const UDP_REPLAY_RING_BLOCKS: usize = 32;
#[cfg(feature = "aead-cipher-2022")]
const UDP_REPLAY_BLOCK_MASK: u64 = (UDP_REPLAY_RING_BLOCKS - 1) as u64;

#[cfg(feature = "aead-cipher-2022")]
#[derive(Debug, Clone)]
pub struct PacketWindow {
    highest: Option<u64>,
    bitmap: [u64; UDP_REPLAY_RING_BLOCKS],
}

#[cfg(feature = "aead-cipher-2022")]
impl Default for PacketWindow {
    fn default() -> Self {
        Self {
            highest: None,
            bitmap: [0; UDP_REPLAY_RING_BLOCKS],
        }
    }
}

#[cfg(feature = "aead-cipher-2022")]
impl PacketWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_set(&mut self, packet_id: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(packet_id);
            self.set(packet_id);
            return false;
        };

        if packet_id > highest {
            let current_block = highest >> 6;
            let target_block = packet_id >> 6;
            let diff = target_block - current_block;
            if diff >= UDP_REPLAY_RING_BLOCKS as u64 {
                self.bitmap.fill(0);
            } else {
                for d in 1..=diff {
                    let block = ((current_block + d) & UDP_REPLAY_BLOCK_MASK) as usize;
                    self.bitmap[block] = 0;
                }
            }
            self.highest = Some(packet_id);
            self.set(packet_id);
            return false;
        }

        if highest - packet_id >= UDP_REPLAY_WINDOW_SIZE || self.contains(packet_id) {
            return true;
        }

        self.set(packet_id);
        false
    }

    #[inline]
    fn index(packet_id: u64) -> (usize, u64) {
        let block = ((packet_id >> 6) & UDP_REPLAY_BLOCK_MASK) as usize;
        let mask = 1_u64 << (packet_id & 63);
        (block, mask)
    }

    #[inline]
    fn contains(&self, packet_id: u64) -> bool {
        let (word, mask) = Self::index(packet_id);
        self.bitmap[word] & mask != 0
    }

    #[inline]
    fn set(&mut self, packet_id: u64) {
        let (word, mask) = Self::index(packet_id);
        self.bitmap[word] |= mask;
    }
}

#[cfg(all(test, feature = "aead-cipher-2022"))]
mod tests {
    use super::{PacketWindow, ReplayProtector};
    use crate::{config::ServerType, crypto::CipherKind};
    use std::{sync::{Barrier, atomic::{AtomicUsize, Ordering}}, thread};

    #[test]
    fn concurrent_nonce_replays_are_accepted_only_once() {
        let protector = ReplayProtector::new(ServerType::Server);
        let barrier = Barrier::new(8);
        let accepted: Vec<_> = (0..128).map(|_| AtomicUsize::new(0)).collect();
        thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for (round, count) in accepted.iter().enumerate() {
                        let mut nonce = [0_u8; 32];
                        nonce[..8].copy_from_slice(&(round as u64).to_be_bytes());
                        barrier.wait();
                        if protector.check_nonce_and_set(
                            CipherKind::AEAD2022_BLAKE3_AES_256_GCM, &nonce,
                        ).is_ok() {
                            count.fetch_add(1, Ordering::Relaxed);
                        }
                        barrier.wait();
                    }
                });
            }
        });
        for count in accepted {
            assert_eq!(count.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn udp_window_rejects_duplicates_and_old_packets() {
        let mut window = PacketWindow::new();
        assert!(!window.check_and_set(10));
        assert!(window.check_and_set(10));
        assert!(!window.check_and_set(9));
        assert!(window.check_and_set(9));
        assert!(!window.check_and_set(1034));
        assert!(window.check_and_set(10));
    }

    #[test]
    fn udp_window_accepts_out_of_order_packets_once() {
        let mut window = PacketWindow::new();
        assert!(!window.check_and_set(100));
        assert!(!window.check_and_set(98));
        assert!(!window.check_and_set(99));
        assert!(window.check_and_set(98));
    }

    #[test]
    fn udp_window_advances_across_blocks_and_handles_out_of_order() {
        let mut window = PacketWindow::new();
        assert!(!window.check_and_set(63));
        assert!(!window.check_and_set(65));
        assert!(!window.check_and_set(60));
        assert!(window.check_and_set(60));
        assert!(!window.check_and_set(200));
        assert!(!window.check_and_set(150));
        assert!(window.check_and_set(150));
        assert!(!window.check_and_set(66));
        assert!(window.check_and_set(66));
    }
}
