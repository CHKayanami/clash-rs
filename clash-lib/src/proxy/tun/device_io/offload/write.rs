//! Construct borrowed scatter/gather frames independently of platform syscalls.
use std::io::{self, IoSlice};
use super::{HEADER_LEN, transmit_header, udp};
use super::super::{DEVICE_BATCH, frame::Frame};

pub(in crate::proxy::tun::device_io) struct WriteFrame<'a> {
    virtio: [u8; HEADER_LEN],
    header: [u8; 68],
    header_len: usize,
    payloads: [&'a [u8]; DEVICE_BATCH],
    pub count: usize,
}
impl<'a> WriteFrame<'a> {
    pub fn new<P: Frame>(packets: &'a [P], udp_gso: bool, mtu: usize) -> io::Result<Self> {
        assert!(!packets.is_empty() && packets.len() <= DEVICE_BATCH);
        let mut frame = Self { virtio: [0; HEADER_LEN], header: [0; 68], header_len: 0,
            payloads: [&[]; DEVICE_BATCH], count: 1 };
        if let Some((header, payload)) = packets[0].parts() {
            if packets[0].udp_segmentation().is_some() && !udp_gso {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "UDP GSO is not supported by device"));
            }
            if !matches!(header.len(), 28 | 48) { return Err(super::invalid("invalid UDP header size")); }
            frame.header[..header.len()].copy_from_slice(header); frame.header_len = header.len();
            frame.payloads[0] = payload;
            let original = packets[0].udp_segmentation().map(usize::from);
            let size = original.unwrap_or(payload.len());
            let mut length = payload.len();
            let mut segments = if size > 0 { length.div_ceil(size) } else { 0 };
            if udp_gso && size > 0 && length % size == 0 {
                for packet in &packets[1..] {
                    let Some((next, data)) = packet.parts() else { break; };
                    let next_size = packet.udp_segmentation().map(usize::from);
                    if next.len() != header.len() || data.is_empty()
                        || next_size.is_some_and(|next| next != size)
                        || (next_size.is_none() && data.len() > size)
                        || header.len() + length + data.len() > 65535
                        || segments + data.len().div_ceil(size) > 64
                        || next[next.len() - 8..next.len() - 4] != header[header.len() - 8..header.len() - 4]
                        || (header.len() == 28 && (next[12..20] != header[12..20]
                            || next[..2] != header[..2] || next[4..10] != header[4..10]))
                        || (header.len() == 48 && (next[8..40] != header[8..40]
                            || next[..4] != header[..4] || next[6..8] != header[6..8])) { break; }
                    frame.payloads[frame.count] = data; frame.count += 1;
                    length += data.len(); segments += data.len().div_ceil(size);
                    // A short final logical datagram cannot precede another group.
                    if data.len() % size != 0 { break; }
                }
            }
            frame.virtio = udp::parts_header(&mut frame.header[..frame.header_len], length,
                if frame.count > 1 { Some(size) } else { packets[0].udp_segmentation().map(usize::from) },
                packets[0].udp_partial() || frame.count > 1, mtu)?;
        } else if let Some(size) = packets[0].udp_segmentation() {
            if !udp_gso { return Err(io::Error::new(io::ErrorKind::Unsupported, "UDP GSO is not supported by device")); }
            frame.virtio = udp::transmit_header(packets[0].as_ref(), size, mtu)?;
            frame.payloads[0] = packets[0].as_ref();
        } else if packets[0].tcp_segmentation().is_none() && udp_gso
            && let Some(group) = udp::group(packets, &mut frame.header)
            && group.header_len + group.payload_len <= mtu {
            frame.virtio = group.virtio;
            frame.header_len = group.header_len;
            frame.count = group.count;
            for (target, packet) in frame.payloads.iter_mut().zip(&packets[..group.count]) {
                *target = &packet.as_ref()[group.header_len..];
                debug_assert_eq!(target.len(), group.payload_len);
            }
        } else {
            frame.virtio = transmit_header(packets[0].as_ref(), packets[0].tcp_segmentation())?;
            frame.payloads[0] = packets[0].as_ref();
        }
        Ok(frame)
    }

    pub fn vectors(&self) -> [IoSlice<'_>; DEVICE_BATCH + 2] {
        let mut vectors = [IoSlice::new(&[]); DEVICE_BATCH + 2];
        vectors[0] = IoSlice::new(&self.virtio);
        let start = if self.header_len > 0 {
            vectors[1] = IoSlice::new(&self.header[..self.header_len]); 2
        } else { 1 };
        for (target, payload) in vectors[start..].iter_mut().zip(&self.payloads[..self.count]) {
            *target = IoSlice::new(payload);
        }
        vectors
    }
    pub fn vector_count(&self) -> usize { self.count + if self.header_len > 0 { 2 } else { 1 } }
    pub fn length(&self) -> usize {
        HEADER_LEN + self.header_len + self.payloads[..self.count].iter().map(|data| data.len()).sum::<usize>()
    }
}
