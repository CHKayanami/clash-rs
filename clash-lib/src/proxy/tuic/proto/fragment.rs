use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};

use super::{Address, ParsedPacket};

const MAX_INCOMPLETE_PACKETS: usize = 1024;
const MAX_PACKET_SIZE: usize = u16::MAX as usize;

struct IncompletePacket {
    created: Instant,
    frag_total: u8,
    address: Option<Address>,
    fragments: Vec<Option<Bytes>>,
    received: usize,
    size: usize,
}

#[derive(Default)]
pub struct FragmentReassembler {
    packets: HashMap<(u16, u16), IncompletePacket>,
}

impl FragmentReassembler {
    pub fn accept(&mut self, packet: ParsedPacket) -> Option<(Address, Bytes)> {
        let ParsedPacket {
            assoc_id,
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

        let key = (assoc_id, pkt_id);
        if !self.packets.contains_key(&key) {
            if self.packets.len() >= MAX_INCOMPLETE_PACKETS
                && let Some(oldest) = self
                    .packets
                    .iter()
                    .min_by_key(|(_, value)| value.created)
                    .map(|(key, _)| *key)
            {
                self.packets.remove(&oldest);
            }
            self.packets.insert(
                key,
                IncompletePacket {
                    created: Instant::now(),
                    frag_total,
                    address: None,
                    fragments: vec![None; frag_total as usize],
                    received: 0,
                    size: 0,
                },
            );
        }
        let state = self.packets.get_mut(&key)?;
        if state.frag_total != frag_total {
            return None;
        }
        let slot = &mut state.fragments[frag_id as usize];
        if slot.is_some() {
            return None;
        }
        if state.size + payload.len() > MAX_PACKET_SIZE {
            self.packets.remove(&key);
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

        let complete = self.packets.remove(&key)?;
        let mut combined = BytesMut::with_capacity(complete.size);
        for fragment in complete.fragments {
            combined.extend_from_slice(&fragment?);
        }
        Some((complete.address?, combined.freeze()))
    }

    pub fn expire(&mut self, lifetime: Duration) {
        self.packets
            .retain(|_, packet| packet.created.elapsed() < lifetime);
    }

    pub fn remove_association(&mut self, assoc_id: u16) {
        self.packets.retain(|(id, _), _| *id != assoc_id);
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
}
