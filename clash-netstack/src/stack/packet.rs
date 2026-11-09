//! Packet ownership for contiguous ingress and scatter/gather UDP output.
use bytes::{Bytes, BytesMut};
use std::{io, ops::{Deref, Range}, sync::{Arc, OnceLock}};

#[derive(Debug, Clone, Copy)]
enum Segmentation { Tcp(u16), Udp(u16) }

#[derive(Debug, Clone)]
pub struct Packet {
    data: Bytes,
    split: Option<Arc<SplitPacket>>,
    segmentation: Option<Segmentation>,
    rx_checksum_verified: bool,
    udp_partial: bool,
    backing_capacity: usize,
}

#[derive(Debug, Clone)]
struct SplitPacket {
    header: [u8; 48],
    header_len: usize,
    payload: Bytes,
    contiguous: OnceLock<Bytes>,
}
impl SplitPacket {
    fn contiguous(&self) -> &Bytes {
        self.contiguous.get_or_init(|| {
            let mut bytes = BytesMut::with_capacity(self.header_len + self.payload.len());
            bytes.extend_from_slice(&self.header[..self.header_len]);
            bytes.extend_from_slice(&self.payload);
            bytes.freeze()
        })
    }
}

impl Packet {
    #[inline]
    pub fn new(data: impl Into<Bytes>) -> Self {
        Packet {
            data: data.into(),
            split: None,
            segmentation: None,
            rx_checksum_verified: false,
            udp_partial: false,
            backing_capacity: 0,
        }
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        match &self.split { Some(split) => split.contiguous().as_ref(), None => self.data.as_ref() }
    }

    /// Keep a small protocol header separate from an owned payload. Native
    /// scatter/gather writers borrow both; contiguous consumers materialize
    /// once. All owners survive until the complete device write finishes.
    pub fn from_parts(header: &[u8], payload: Bytes) -> io::Result<Self> {
        if header.len() > 48 || header.len() + payload.len() > 65535 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid split IP packet size"));
        }
        let mut bytes = [0; 48]; bytes[..header.len()].copy_from_slice(header);
        let mut packet = Self::new(Bytes::new());
        packet.split = Some(Arc::new(SplitPacket { header: bytes, header_len: header.len(), payload,
            contiguous: OnceLock::new() }));
        Ok(packet)
    }
    pub fn parts(&self) -> Option<(&[u8], &[u8])> {
        self.split.as_ref().map(|split| (&split.header[..split.header_len], split.payload.as_ref()))
    }
    pub fn len(&self) -> usize {
        self.split.as_ref().map_or(self.data.len(), |split| split.header_len + split.payload.len())
    }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
    /// Release a shared receive slab before retaining this packet across a wait.
    /// The header remains separate; only a non-unique payload is compacted.
    pub fn compact_payload(&mut self) {
        if let Some(split) = &mut self.split {
            let split = Arc::make_mut(split);
            if !split.payload.is_unique() { split.payload = Bytes::copy_from_slice(&split.payload); }
        }
    }
    /// Storage retained by this packet, including reusable device headroom.
    pub fn backing_capacity(&self) -> usize { self.backing_capacity.max(self.len()) }

    /// Describe an owned receive allocation so small queued datagrams can be
    /// compacted without unnecessarily copying packets from small buffers.
    pub fn with_backing_capacity(mut self, capacity: usize) -> Self {
        self.backing_capacity = capacity;
        self
    }

    /// Extract a payload without pinning a disproportionately large receive
    /// allocation in a downstream datagram queue.
    pub fn into_payload(self, range: Range<usize>) -> Bytes {
        if self.backing_capacity() > 4096 && range.len() < self.backing_capacity() / 4 {
            Bytes::copy_from_slice(&self.data()[range])
        } else { self.into_bytes().slice(range) }
    }

    /// Segment size for a TCP frame whose checksum is completed by the device.
    pub fn tcp_segmentation(&self) -> Option<u16> {
        match self.segmentation { Some(Segmentation::Tcp(size)) => Some(size), _ => None }
    }

    pub fn with_partial_udp_checksum(mut self) -> Self { self.udp_partial = true; self }
    pub fn udp_checksum_partial(&self) -> bool { self.udp_partial }
    pub fn udp_segmentation(&self) -> Option<u16> {
        match self.segmentation { Some(Segmentation::Udp(size)) => Some(size), _ => None }
    }

    /// Attach validated UDP L4 segmentation metadata to an aggregate IP frame.
    pub fn with_udp_segmentation(mut self, size: u16) -> Self {
        self.segmentation = Some(Segmentation::Udp(size));
        self
    }

    pub(crate) fn with_tcp_segmentation(mut self, size: u16) -> Self {
        self.segmentation = Some(Segmentation::Tcp(size));
        self
    }

    /// Trust transport checksums only after validating kernel offload metadata.
    /// IP headers and TCP structure are still checked by the protocol driver.
    pub fn with_verified_rx_checksum(mut self) -> Self {
        self.rx_checksum_verified = true;
        self
    }

    pub(crate) fn rx_checksum_verified(&self) -> bool { self.rx_checksum_verified }

    /// Raw IP bytes. Offload callers must retain segmentation metadata separately.
    #[inline]
    pub fn into_bytes(self) -> Bytes {
        match self.split { Some(split) => split.contiguous().clone(), None => self.data }
    }
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] { self.data() }
}

impl Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &[u8] { self.data() }
}

impl From<Bytes> for Packet {
    fn from(data: Bytes) -> Self {
        Packet::new(data)
    }
}

impl From<Vec<u8>> for Packet {
    fn from(data: Vec<u8>) -> Self {
        let capacity = data.capacity();
        Packet::new(Bytes::from(data)).with_backing_capacity(capacity)
    }
}

impl From<&'static [u8]> for Packet {
    fn from(data: &'static [u8]) -> Self {
        Packet::new(Bytes::from_static(data))
    }
}

impl From<bytes::BytesMut> for Packet {
    fn from(data: bytes::BytesMut) -> Self {
        let capacity = data.capacity();
        Packet::new(data.freeze()).with_backing_capacity(capacity)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_payload_is_borrowed_until_contiguous_access_and_clones_compact_independently() {
        let slab = Bytes::from(vec![0x5a; 128 * 1024]);
        let payload = slab.slice(20..120);
        let pointer = payload.as_ptr();
        let packet = Packet::from_parts(&[0x45; 28], payload).unwrap();
        assert_eq!(packet.len(), 128);
        assert_eq!(packet.parts().unwrap().1.as_ptr(), pointer);
        let mut retained = packet.clone();
        retained.compact_payload();
        assert_ne!(retained.parts().unwrap().1.as_ptr(), pointer);
        assert_eq!(packet.parts().unwrap().1.as_ptr(), pointer);
        assert_eq!(&retained.data()[28..], &[0x5a; 100]);
        assert_eq!(packet.into_bytes().len(), 128);
    }
}
