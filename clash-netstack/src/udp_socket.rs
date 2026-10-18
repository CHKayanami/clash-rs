use crate::Packet;
use bytes::BytesMut;
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// Single-pass, zero-allocation fast parser for IPv4 and IPv6 UDP packets.
///
/// Returns `(src_addr, dst_addr, payload_range_in_bytes)`.
pub fn parse_udp_packet(
    data: &[u8],
) -> Option<(SocketAddr, SocketAddr, std::ops::Range<usize>)> {
    if data.is_empty() {
        return None;
    }
    let version = data[0] >> 4;
    match version {
        4 => {
            if data.len() < 20 {
                return None;
            }
            let ihl = (data[0] & 0x0f) as usize * 4;
            if ihl < 20 || data.len() < ihl {
                return None;
            }
            if data[9] != 17 {
                // Not UDP (protocol 17)
                return None;
            }
            let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            let packet_len = data.len().min(total_len);
            if packet_len < ihl + 8 {
                return None;
            }
            let src_ip =
                std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
            let dst_ip =
                std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);

            let udp_slice = &data[ihl..packet_len];
            let src_port = u16::from_be_bytes([udp_slice[0], udp_slice[1]]);
            let dst_port = u16::from_be_bytes([udp_slice[2], udp_slice[3]]);
            let udp_len = u16::from_be_bytes([udp_slice[4], udp_slice[5]]) as usize;
            if udp_len < 8 {
                return None;
            }

            let payload_start = ihl + 8;
            let payload_end = (ihl + udp_len).min(packet_len);
            if payload_start > payload_end {
                return None;
            }

            Some((
                SocketAddr::new(src_ip.into(), src_port),
                SocketAddr::new(dst_ip.into(), dst_port),
                payload_start..payload_end,
            ))
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            if data[6] != 17 {
                // Not direct UDP
                return None;
            }
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&data[8..24]);
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&data[24..40]);
            let src_ip = std::net::Ipv6Addr::from(src_bytes);
            let dst_ip = std::net::Ipv6Addr::from(dst_bytes);

            let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
            let packet_len = data.len().min(40 + payload_len);
            if packet_len < 48 {
                return None;
            }

            let udp_slice = &data[40..packet_len];
            let src_port = u16::from_be_bytes([udp_slice[0], udp_slice[1]]);
            let dst_port = u16::from_be_bytes([udp_slice[2], udp_slice[3]]);
            let udp_len = u16::from_be_bytes([udp_slice[4], udp_slice[5]]) as usize;
            if udp_len < 8 {
                return None;
            }

            let payload_start = 48;
            let payload_end = (40 + udp_len).min(packet_len);
            if payload_start > payload_end {
                return None;
            }

            Some((
                SocketAddr::new(src_ip.into(), src_port),
                SocketAddr::new(dst_ip.into(), dst_port),
                payload_start..payload_end,
            ))
        }
        _ => None,
    }
}

pub struct UdpPacket {
    pub data: Packet,
    /// src of the packet
    pub local_addr: SocketAddr,
    /// dst of the packet
    pub remote_addr: SocketAddr,
}

impl std::fmt::Debug for UdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("data_len", &self.data().len())
            .finish()
    }
}

impl<T> From<(T, SocketAddr, SocketAddr)> for UdpPacket
where
    T: Into<Packet>,
{
    fn from((data, local_addr, remote_addr): (T, SocketAddr, SocketAddr)) -> Self {
        UdpPacket {
            data: data.into(),
            local_addr,
            remote_addr,
        }
    }
}

impl UdpPacket {
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

pub struct UdpSocket {
    inbound: mpsc::Receiver<UdpPacket>,
    outbound: mpsc::Sender<Packet>,
}

impl UdpSocket {
    pub fn new(
        inbound: mpsc::Receiver<UdpPacket>,
        outbound: mpsc::Sender<Packet>,
    ) -> Self {
        Self { inbound, outbound }
    }

    pub fn split(self) -> (SplitRead, SplitWrite) {
        let read = SplitRead { recv: self.inbound };
        let write = SplitWrite {
            send: self.outbound,
        };
        (read, write)
    }
}

pub struct SplitRead {
    recv: mpsc::Receiver<UdpPacket>,
}

impl SplitRead {
    /// Receive a single UDP packet.
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        self.recv.recv().await
    }

    /// Receive multiple UDP packets in a batch to minimize async scheduling overhead.
    pub async fn recv_many(
        &mut self,
        buffer: &mut Vec<UdpPacket>,
        limit: usize,
    ) -> usize {
        self.recv.recv_many(buffer, limit).await
    }
}

#[derive(Clone)]
pub struct SplitWrite {
    send: mpsc::Sender<Packet>,
}

impl SplitWrite {
    pub async fn send(&mut self, packet: UdpPacket) -> Result<(), std::io::Error> {
        let packet = encode_packet(&packet)?;
        match self.send.try_send(packet) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(std::io::Error::other("packet outbound channel closed"))
            }
        }
    }

    /// Reserve packet-based queue capacity once for the ready batch. Invalid
    /// packets are reported after the independent valid packets are submitted;
    /// excess packets are dropped, matching the single-packet UDP policy.
    pub fn send_batch(&mut self, packets: &[UdpPacket]) -> Result<usize, std::io::Error> {
        let count = packets.len();
        if count == 0 {
            return if self.send.is_closed() {
                Err(std::io::Error::other("packet outbound channel closed"))
            } else { Ok(0) };
        }
        let mut permits = match self.send.try_reserve_many(count) {
            Ok(permits) => Some(permits),
            // Partial capacity or competing senders must not lose the batch.
            // Keep the bulk fast path, then reserve individually under pressure.
            Err(mpsc::error::TrySendError::Full(_)) => None,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(std::io::Error::other("packet outbound channel closed"));
            }
        };
        let mut sent = 0;
        let mut error = None;
        let mut permit = None;
        for packet in packets {
            if permit.is_none() {
                permit = permits.as_mut().and_then(Iterator::next);
                if permit.is_none() {
                    match self.send.try_reserve() {
                        Ok(reserved) => permit = Some(reserved),
                        Err(mpsc::error::TrySendError::Full(_)) => break,
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            return Err(std::io::Error::other("packet outbound channel closed"));
                        }
                    }
                }
            }
            match encode_packet(packet) {
                Ok(packet) => { permit.take().unwrap().send(packet); sent += 1; }
                Err(err) => { error.get_or_insert(err); }
            }
        }
        error.map_or(Ok(sent), Err)
    }
}

fn encode_packet(packet: &UdpPacket) -> Result<Packet, std::io::Error> {
    let payload = packet.data.data();
    let is_v4 = match (&packet.local_addr, &packet.remote_addr) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => true,
        (SocketAddr::V6(_), SocketAddr::V6(_)) => false,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP socket only supports homogeneous IPv4 and IPv6",
            ));
        }
    };

    let ip_hdr_len = if is_v4 { 20 } else { 40 };
    let udp_hdr_len = 8;
    let total_len = ip_hdr_len + udp_hdr_len + payload.len();

    if total_len > 65535 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "packet exceeds max IP packet length",
        ));
    }

    let mut buf = BytesMut::with_capacity(total_len);

    if is_v4 {
        let SocketAddr::V4(src) = packet.local_addr else {
            unreachable!()
        };
        let SocketAddr::V4(dst) = packet.remote_addr else {
            unreachable!()
        };

        // 1. Write IPv4 header (20 bytes)
        let mut ip_hdr = [0u8; 20];
        ip_hdr[0] = 0x45; // Version 4, IHL 5
        ip_hdr[1] = 0; // DSCP / ECN
        ip_hdr[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip_hdr[4..6].copy_from_slice(&0u16.to_be_bytes()); // Identification
        ip_hdr[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags (DF)
        ip_hdr[8] = 64; // TTL
        ip_hdr[9] = 17; // Protocol (UDP)
        ip_hdr[12..16].copy_from_slice(&src.ip().octets());
        ip_hdr[16..20].copy_from_slice(&dst.ip().octets());
        let ip_csum = compute_ipv4_checksum(&ip_hdr);
        ip_hdr[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // 2. Write UDP header (8 bytes)
        let udp_len = (udp_hdr_len + payload.len()) as u16;
        let mut udp_hdr = [0u8; 8];
        udp_hdr[0..2].copy_from_slice(&src.port().to_be_bytes());
        udp_hdr[2..4].copy_from_slice(&dst.port().to_be_bytes());
        udp_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
        let udp_csum = compute_udp_checksum_v4(
            &src.ip().octets(),
            &dst.ip().octets(),
            &udp_hdr[..6],
            payload,
        );
        udp_hdr[6..8].copy_from_slice(&udp_csum.to_be_bytes());

        buf.extend_from_slice(&ip_hdr);
        buf.extend_from_slice(&udp_hdr);
        buf.extend_from_slice(payload);
    } else {
        let SocketAddr::V6(src) = packet.local_addr else {
            unreachable!()
        };
        let SocketAddr::V6(dst) = packet.remote_addr else {
            unreachable!()
        };

        // 1. Write IPv6 header (40 bytes)
        let mut ip_hdr = [0u8; 40];
        ip_hdr[0] = 0x60; // Version 6
        let udp_len = (udp_hdr_len + payload.len()) as u16;
        ip_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes()); // Payload Length
        ip_hdr[6] = 17; // Next Header (UDP)
        ip_hdr[7] = 64; // Hop Limit
        ip_hdr[8..24].copy_from_slice(&src.ip().octets());
        ip_hdr[24..40].copy_from_slice(&dst.ip().octets());

        // 2. Write UDP header (8 bytes)
        let mut udp_hdr = [0u8; 8];
        udp_hdr[0..2].copy_from_slice(&src.port().to_be_bytes());
        udp_hdr[2..4].copy_from_slice(&dst.port().to_be_bytes());
        udp_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
        let udp_csum = compute_udp_checksum_v6(
            &src.ip().octets(),
            &dst.ip().octets(),
            &udp_hdr[..6],
            payload,
        );
        udp_hdr[6..8].copy_from_slice(&udp_csum.to_be_bytes());

        buf.extend_from_slice(&ip_hdr);
        buf.extend_from_slice(&udp_hdr);
        buf.extend_from_slice(payload);
    }

    Ok(Packet::new(buf.freeze()))
}

fn compute_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn compute_udp_checksum_v4(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    udp_hdr_first_6: &[u8],
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header (12 bytes)
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 17u32; // Protocol UDP
    let udp_len = (8 + payload.len()) as u16;
    sum += udp_len as u32;

    // UDP header first 6 bytes (src_port, dst_port, length)
    sum += u16::from_be_bytes([udp_hdr_first_6[0], udp_hdr_first_6[1]]) as u32;
    sum += u16::from_be_bytes([udp_hdr_first_6[2], udp_hdr_first_6[3]]) as u32;
    sum += u16::from_be_bytes([udp_hdr_first_6[4], udp_hdr_first_6[5]]) as u32;

    // Payload
    let mut chunks = payload.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if res == 0 { 0xffff } else { res }
}

fn compute_udp_checksum_v6(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    udp_hdr_first_6: &[u8],
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src_ip (16), dst_ip (16), udp_len (4), next_hdr (4)
    for chunk in src_ip.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst_ip.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let udp_len = (8 + payload.len()) as u32;
    sum += udp_len >> 16;
    sum += udp_len & 0xffff;
    sum += 17u32; // Next header UDP

    // UDP header first 6 bytes
    sum += u16::from_be_bytes([udp_hdr_first_6[0], udp_hdr_first_6[1]]) as u32;
    sum += u16::from_be_bytes([udp_hdr_first_6[2], udp_hdr_first_6[3]]) as u32;
    sum += u16::from_be_bytes([udp_hdr_first_6[4], udp_hdr_first_6[5]]) as u32;

    // Payload
    let mut chunks = payload.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !(sum as u16);
    if res == 0 { 0xffff } else { res }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use bytes::Bytes;
    use smoltcp::wire::{IpAddress, UdpPacket as WireUdpPacket};

    #[tokio::test]
    async fn batches_preserve_empty_packets_addresses_and_checksums() {
        for (source, target, header_len) in [
            ("127.0.0.1:1234", "127.0.0.2:5678", 20),
            ("[::1]:1234", "[::2]:5678", 40),
        ] {
            let source: SocketAddr = source.parse().unwrap();
            let target: SocketAddr = target.parse().unwrap();
            let (send, mut receive) = mpsc::channel(4);
            let mut writer = SplitWrite { send };
            let packets = [
                UdpPacket::from((Bytes::new(), source, target)),
                UdpPacket::from((Bytes::from_static(b"odd"), source, target)),
            ];
            assert_eq!(writer.send_batch(&packets).unwrap(), 2);
            for expected in &packets {
                let packet = receive.recv().await.unwrap();
                let raw = packet.data();
                let (src, dst, payload) = parse_udp_packet(raw).unwrap();
                assert_eq!((src, dst), (source, target));
                assert_eq!(&raw[payload], expected.data());
                let udp = WireUdpPacket::new_checked(&raw[header_len..]).unwrap();
                assert!(udp.verify_checksum(&IpAddress::from(source.ip()), &IpAddress::from(target.ip())));
                if header_len == 20 { assert_eq!(compute_ipv4_checksum(&raw[..20]), 0); }
            }
        }
    }

    #[tokio::test]
    async fn batches_keep_packet_capacity_and_do_not_block_on_full_queue() {
        let (send, mut receive) = mpsc::channel(2);
        let mut writer = SplitWrite { send };
        let packets: Vec<_> = (0..4).map(|i| UdpPacket::from((
            Bytes::from(vec![i]), "127.0.0.1:1".parse().unwrap(), "127.0.0.2:2".parse().unwrap(),
        ))).collect();
        assert_eq!(writer.send_batch(&packets).unwrap(), 2);
        assert_eq!(writer.send_batch(&packets).unwrap(), 0);
        for expected in &packets[..2] {
            let packet = receive.recv().await.unwrap();
            let (_, _, payload) = parse_udp_packet(packet.data()).unwrap();
            assert_eq!(&packet.data()[payload], expected.data());
        }
        drop(receive);
        assert!(writer.send_batch(&packets).is_err());
    }

    #[tokio::test]
    async fn competing_reservations_keep_available_batch_prefix() {
        let (send, mut receive) = mpsc::channel(4);
        let competing = send.clone();
        let _held = competing.try_reserve_many(2).unwrap();
        let mut writer = SplitWrite { send };
        let packets: Vec<_> = (0..4).map(|i| UdpPacket::from((
            Bytes::from(vec![i]), "127.0.0.1:1".parse().unwrap(), "127.0.0.2:2".parse().unwrap(),
        ))).collect();
        assert_eq!(writer.send_batch(&packets).unwrap(), 2);
        for expected in &packets[..2] {
            let packet = receive.try_recv().unwrap();
            let (_, _, payload) = parse_udp_packet(packet.data()).unwrap();
            assert_eq!(&packet.data()[payload], expected.data());
        }
        assert!(receive.try_recv().is_err());
    }

    #[tokio::test]
    async fn invalid_packet_does_not_discard_valid_batch_suffix() {
        let (send, mut receive) = mpsc::channel(2);
        let mut writer = SplitWrite { send };
        let valid = || UdpPacket::from((Bytes::from_static(b"ok"),
            "127.0.0.1:1".parse().unwrap(), "127.0.0.2:2".parse().unwrap()));
        let invalid = UdpPacket::from((Bytes::new(),
            "127.0.0.1:1".parse().unwrap(), "[::1]:2".parse().unwrap()));
        assert!(writer.send_batch(&[valid(), invalid, valid()]).is_err());
        assert!(receive.try_recv().is_ok());
        assert!(receive.try_recv().is_ok());
        assert!(receive.try_recv().is_err());
    }
}
