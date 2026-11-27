use std::{
    collections::{HashMap, hash_map::Entry},
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};

use super::{Address, ParsedPacket};

const MAX_INCOMPLETE_PACKETS: usize = 64;
const MAX_PACKET_SIZE: usize = u16::MAX as usize;
const DEFAULT_GC_LIFETIME: Duration = Duration::from_secs(10);

struct IncompletePacket {
    created: Instant,
    frag_total: u8,
    address: Option<Address>,
    fragments: Vec<Option<Bytes>>,
    received: usize,
    size: usize,
}

impl IncompletePacket {
    fn new(created: Instant, frag_total: u8) -> Self {
        Self {
            created,
            frag_total,
            address: None,
            fragments: vec![None; frag_total as usize],
            received: 0,
            size: 0,
        }
    }

    fn reset(&mut self, created: Instant, frag_total: u8) {
        self.created = created;
        self.frag_total = frag_total;
        self.address = None;
        self.fragments = vec![None; frag_total as usize];
        self.received = 0;
        self.size = 0;
    }
}

pub struct FragmentReassembler {
    packets: HashMap<u16, IncompletePacket>,
    gc_lifetime: Duration,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new(DEFAULT_GC_LIFETIME)
    }
}

impl FragmentReassembler {
    pub fn new(gc_lifetime: Duration) -> Self {
        Self {
            packets: HashMap::new(),
            gc_lifetime,
        }
    }

    pub fn accept(&mut self, packet: ParsedPacket) -> Option<(Address, Bytes)> {
        let ParsedPacket {
            pkt_id,
            frag_total,
            frag_id,
            addr,
            payload,
            ..
        } = packet;
        if frag_total == 0 || frag_id >= frag_total {
            return None;
        }
        if frag_total == 1 {
            return (frag_id == 0 && addr != Address::None)
                .then_some((addr, payload));
        }
        if (frag_id == 0) == (addr == Address::None) {
            return None;
        }

        let now = Instant::now();
        let is_full = self.packets.len() >= MAX_INCOMPLETE_PACKETS;
        let mut entry = match self.packets.entry(pkt_id) {
            Entry::Occupied(occ) => occ,
            Entry::Vacant(vac) => {
                if !is_full {
                    vac.insert_entry(IncompletePacket::new(now, frag_total))
                } else {
                    drop(vac);
                    if !self.gc_lifetime.is_zero() {
                        self.expire_at(now, self.gc_lifetime);
                    }
                    if self.packets.len() >= MAX_INCOMPLETE_PACKETS
                        && let Some(oldest) = self
                            .packets
                            .iter()
                            .min_by_key(|(_, value)| value.created)
                            .map(|(key, _)| *key)
                    {
                        self.packets.remove(&oldest);
                    }
                    match self.packets.entry(pkt_id) {
                        Entry::Vacant(vac) => {
                            vac.insert_entry(IncompletePacket::new(now, frag_total))
                        }
                        Entry::Occupied(occ) => occ,
                    }
                }
            }
        };

        let state = entry.get_mut();
        // Preserve legacy `gc_lifetime == 0` semantics: fragments arriving
        // between GC ticks can still reassemble, while `expire_stale()` clears
        // incomplete entries on each GC tick.
        if !self.gc_lifetime.is_zero()
            && now.saturating_duration_since(state.created) >= self.gc_lifetime
        {
            state.reset(now, frag_total);
        } else if state.frag_total != frag_total {
            return None;
        }
        let slot = &mut state.fragments[frag_id as usize];
        if slot.is_some() {
            return None;
        }
        if state.size + payload.len() > MAX_PACKET_SIZE {
            entry.remove();
            return None;
        }
        state.size += payload.len();
        state.received += 1;
        if frag_id == 0 {
            state.address = Some(addr);
        }
        *slot = Some(payload);
        if state.received != frag_total as usize {
            return None;
        }

        let complete = entry.remove();
        let mut combined = BytesMut::with_capacity(complete.size);
        for fragment in complete.fragments {
            combined.extend_from_slice(&fragment?);
        }
        Some((complete.address?, combined.freeze()))
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn expire_stale(&mut self) {
        self.expire(self.gc_lifetime);
    }

    pub fn expire(&mut self, lifetime: Duration) {
        self.expire_at(Instant::now(), lifetime);
    }

    fn expire_at(&mut self, now: Instant, lifetime: Duration) {
        self.packets.retain(|_, packet| {
            now.saturating_duration_since(packet.created) < lifetime
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::tuic::proto::{decode_packet_frame, packet_fragments};
    use std::net::Ipv4Addr;

    #[test]
    fn reassembles_out_of_order_native_datagrams() {
        let address = Address::IPv4(Ipv4Addr::LOCALHOST, 53);
        let payload = vec![42; 3000];
        let frames: Vec<_> = packet_fragments(7, 9, &address, &payload, 1200)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(frames.len() > 1);
        assert!(frames.iter().all(|frame| frame.len() <= 1200));

        let mut reassembler = FragmentReassembler::default();
        for frame in frames.iter().skip(1).rev() {
            assert!(
                reassembler
                    .accept(decode_packet_frame(frame.clone()).unwrap())
                    .is_none()
            );
        }
        let complete = reassembler
            .accept(decode_packet_frame(frames[0].clone()).unwrap())
            .unwrap();
        assert_eq!(complete.0, address);
        assert_eq!(complete.1.as_ref(), payload.as_slice());
    }

    #[test]
    fn rejects_invalid_fragment_metadata() {
        let address = Address::IPv4(Ipv4Addr::LOCALHOST, 53);
        let mut frame = decode_packet_frame(
            super::super::encode_single_packet(7, 9, &address, b"part").unwrap(),
        )
        .unwrap();
        frame.frag_total = 0;
        assert!(FragmentReassembler::default().accept(frame).is_none());
    }

    #[test]
    fn enforces_per_session_pending_limit_and_resets_expired_entries() {
        let address = Address::IPv4(Ipv4Addr::LOCALHOST, 53);
        let payload = vec![7u8; 2500];
        let mut reassembler = FragmentReassembler::new(Duration::from_secs(10));

        for pkt_id in 0..(MAX_INCOMPLETE_PACKETS as u16 + 10) {
            let frames: Vec<_> =
                packet_fragments(1, pkt_id, &address, &payload, 1200)
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
            assert!(
                reassembler
                    .accept(decode_packet_frame(frames[0].clone()).unwrap())
                    .is_none()
            );
        }
        assert_eq!(reassembler.packets.len(), MAX_INCOMPLETE_PACKETS);

        // Use an exact 2-fragment payload so both control and expiry assertions
        // test whether fragment 0 survived until fragment 1 arrived.
        let two_frag_payload = vec![9u8; 1500];
        let frames: Vec<_> =
            packet_fragments(1, 5, &address, &two_frag_payload, 1200)
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
        assert_eq!(frames.len(), 2);

        // Control: with a live lifetime, fragment 0 + fragment 1 reassemble.
        let mut live = FragmentReassembler::new(Duration::from_secs(10));
        assert!(
            live.accept(decode_packet_frame(frames[0].clone()).unwrap())
                .is_none()
        );
        let completed = live
            .accept(decode_packet_frame(frames[1].clone()).unwrap())
            .expect("non-expired 2-fragment packet must reassemble");
        assert_eq!(completed.0, address);
        assert_eq!(completed.1.as_ref(), two_frag_payload.as_slice());

        // Positive lifetime expiry: once `gc_lifetime` elapses, fragment 1
        // resets the expired fragment 0 instead of completing with it.
        use std::thread::sleep;
        let mut expiring = FragmentReassembler::new(Duration::from_millis(15));
        assert!(
            expiring
                .accept(decode_packet_frame(frames[0].clone()).unwrap())
                .is_none()
        );
        sleep(Duration::from_millis(25));
        assert!(
            expiring
                .accept(decode_packet_frame(frames[1].clone()).unwrap())
                .is_none(),
            "expired fragment 0 must be reset instead of completing with fragment 1"
        );

        // Zero lifetime preserves legacy behavior: fragments arriving before a
        // GC tick still reassemble, while `expire_stale()` clears partial state.
        let mut zero_life = FragmentReassembler::new(Duration::ZERO);
        assert!(
            zero_life
                .accept(decode_packet_frame(frames[0].clone()).unwrap())
                .is_none()
        );
        let zero_completed = zero_life
            .accept(decode_packet_frame(frames[1].clone()).unwrap())
            .expect("gc_lifetime=0 must still reassemble fragments before GC tick");
        assert_eq!(zero_completed.0, address);
        assert_eq!(zero_completed.1.as_ref(), two_frag_payload.as_slice());

        assert!(
            zero_life
                .accept(decode_packet_frame(frames[0].clone()).unwrap())
                .is_none()
        );
        assert!(!zero_life.is_empty());
        zero_life.expire_stale();
        assert!(zero_life.is_empty());
    }
}
