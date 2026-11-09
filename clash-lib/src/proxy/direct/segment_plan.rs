//! Group only a contiguous, same-peer prefix. Completion remains measured in
//! logical datagrams even when one kernel message carries the whole prefix.
use crate::proxy::{datagram::batch::MAX_DIRECT_BATCH_PACKETS, utils::udp_batch::DatagramSlice};

pub(super) fn prefix(packets: &[DatagramSlice<'_>]) -> Option<(usize, usize)> {
    let first = packets.first()?;
    let size = first.payload.len();
    if !first.header.is_empty() || size == 0 || size > u16::MAX as usize { return None; }
    let mut count = 1;
    let mut length = size;
    for packet in packets.iter().skip(1).take(MAX_DIRECT_BATCH_PACKETS - 1) {
        if !packet.header.is_empty() || packet.destination != first.destination
            || packet.payload.is_empty() || packet.payload.len() > size
            || length + packet.payload.len() > 65507 { break; }
        length += packet.payload.len(); count += 1;
        if packet.payload.len() < size { break; }
    }
    (count >= 2).then_some((count, size))
}

#[derive(Clone, Copy, Default)]
pub(super) struct Group { pub start: usize, pub count: usize, pub size: Option<usize> }
pub(super) fn groups(packets: &[DatagramSlice<'_>], output: &mut [Group; MAX_DIRECT_BATCH_PACKETS]) -> (usize, bool) {
    assert!(!packets.is_empty() && packets.len() <= MAX_DIRECT_BATCH_PACKETS);
    let (mut offset, mut count, mut segmented) = (0, 0, false);
    while offset < packets.len() {
        let (length, size) = match prefix(&packets[offset..]) {
            Some((length, size)) => { segmented = true; (length, Some(size)) },
            None => (1, None),
        };
        output[count] = Group { start: offset, count: length, size };
        count += 1; offset += length;
    }
    (count, segmented)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grouping_preserves_empty_packets_peers_and_protocol_headers() {
        let a = "127.0.0.1:1000".parse().unwrap();
        let b = "127.0.0.1:1001".parse().unwrap();
        let mut packets = (0..4).map(|_| DatagramSlice { header: &[], payload: b"same", destination: a }).collect::<Vec<_>>();
        assert_eq!(prefix(&packets), Some((4, 4)));
        packets[2].destination = b;
        assert_eq!(prefix(&packets), Some((2, 4)));
        packets[1].payload = b"";
        assert_eq!(prefix(&packets), None);
        packets[1].payload = b"same"; packets[0].header = b"encrypted-header";
        assert_eq!(prefix(&packets), None);
        packets[0].header = &[]; packets[0].payload = b"different-length";
        assert_eq!(prefix(&packets), Some((2, 16)));
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    #[test]
    fn multiple_peers_short_tail_and_empty_datagrams_have_exact_completion_prefixes() {
        let a = "127.0.0.1:1000".parse().unwrap();
        let b = "127.0.0.1:1001".parse().unwrap();
        let packets = [(a, &b"abcd"[..]), (a, &b"abcd"[..]), (a, &b"x"[..]),
            (b, &b"abcd"[..]), (b, &b"abcd"[..]), (b, &b""[..])]
            .map(|(destination, payload)| DatagramSlice { destination, payload, header: &[] });
        let mut output = [Group::default(); MAX_DIRECT_BATCH_PACKETS];
        let (count, segmented) = groups(&packets, &mut output);
        assert!(segmented); assert_eq!(count, 3);
        assert_eq!((output[0].start, output[0].count, output[0].size), (0, 3, Some(4)));
        assert_eq!((output[1].start, output[1].count, output[1].size), (3, 2, Some(4)));
        assert_eq!((output[2].start, output[2].count, output[2].size), (5, 1, None));
        assert_eq!(output[..2].iter().map(|g| g.count).sum::<usize>(), 5);
    }
}
