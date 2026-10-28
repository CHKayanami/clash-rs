use crate::Packet;
use bytes::BytesMut;
use std::{io, net::SocketAddr, task::{Context, Poll}};
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
            // No reassembly is performed here. Neither first fragments (MF)
            // nor later fragments may be interpreted as whole UDP datagrams.
            if u16::from_be_bytes([data[6], data[7]]) & 0x3fff != 0 { return None; }
            let packet_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            if packet_len > data.len() || packet_len < ihl + 8 {
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
            if udp_len < 8 || udp_len > packet_len - ihl {
                return None;
            }

            let payload_start = ihl + 8;
            let payload_end = ihl + udp_len;
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
            let packet_len = 40 + payload_len;
            if packet_len > data.len() || packet_len < 48 {
                return None;
            }

            let udp_slice = &data[40..packet_len];
            let src_port = u16::from_be_bytes([udp_slice[0], udp_slice[1]]);
            let dst_port = u16::from_be_bytes([udp_slice[2], udp_slice[3]]);
            let udp_len = u16::from_be_bytes([udp_slice[4], udp_slice[5]]) as usize;
            if udp_len < 8 || udp_len > payload_len {
                return None;
            }

            let payload_start = 48;
            let payload_end = 40 + udp_len;
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
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        self.recv.poll_recv(cx)
    }

    pub fn poll_recv_many(&mut self, cx: &mut Context<'_>,
        buffer: &mut Vec<UdpPacket>, limit: usize) -> Poll<usize> {
        self.recv.poll_recv_many(cx, buffer, limit)
    }

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

/// Successful submissions and deliberate congestion drops form one prefix.
/// An error, if present, refers to the packet immediately after that prefix.
pub struct UdpSendResult {
    pub sent: usize,
    pub dropped: usize,
    pub error: Option<io::Error>,
}

#[derive(Clone)]
pub struct SplitWrite {
    send: mpsc::Sender<Packet>,
}

impl SplitWrite {
    /// Submit without waiting; a saturated queue deliberately drops the packet.
    /// The async signature is retained for compatibility and does not yield.
    /// A closed outbound channel returns `io::ErrorKind::BrokenPipe`.
    pub async fn send(&mut self, packet: UdpPacket) -> io::Result<()> {
        let packet = encode_packet(&packet)?;
        match self.send.try_send(packet) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "packet outbound channel closed"))
            }
        }
    }

    /// Submit a contiguous prefix, stopping at the first invalid packet.
    /// Queue saturation drops the unsubmitted suffix without blocking reads.
    /// `sent + dropped` packets are consumed; an error belongs to the next one.
    pub fn send_batch(&mut self, packets: &[UdpPacket]) -> UdpSendResult {
        let mut result = UdpSendResult { sent: 0, dropped: 0, error: None };
        if self.send.is_closed() {
            result.error = Some(io::Error::new(io::ErrorKind::BrokenPipe, "packet outbound channel closed"));
            return result;
        }
        if packets.is_empty() { return result; }
        let mut permits = self.send.try_reserve_many(packets.len()).ok();
        for (index, packet) in packets.iter().enumerate() {
            let permit = match permits.as_mut().and_then(Iterator::next) {
                Some(permit) => permit,
                None => match self.send.try_reserve() {
                    Ok(permit) => permit,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        result.dropped = packets.len() - index;
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        result.error = Some(io::Error::new(io::ErrorKind::BrokenPipe, "packet outbound channel closed"));
                        break;
                    }
                },
            };
            match encode_packet(packet) {
                Ok(packet) => { permit.send(packet); result.sent += 1; }
                Err(error) => { result.error = Some(error); break; }
            }
        }
        result
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
            let result = writer.send_batch(&packets);
            assert_eq!((result.sent, result.dropped), (2, packets.len() - 2));
            assert!(result.error.is_none());
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
        let result = writer.send_batch(&packets);
        assert_eq!((result.sent, result.dropped), (2, 2));
        assert!(result.error.is_none());
        let result = writer.send_batch(&packets);
        assert_eq!((result.sent, result.dropped), (0, 4));
        assert!(result.error.is_none());
        for expected in &packets[..2] {
            let packet = receive.recv().await.unwrap();
            let (_, _, payload) = parse_udp_packet(packet.data()).unwrap();
            assert_eq!(&packet.data()[payload], expected.data());
        }
        drop(receive);
        assert_eq!(writer.send_batch(&packets).error.unwrap().kind(), io::ErrorKind::BrokenPipe);
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
        let result = writer.send_batch(&packets);
        assert_eq!((result.sent, result.dropped), (2, 2));
        assert!(result.error.is_none());
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
        let packets = [valid(), invalid, valid()];
        let result = writer.send_batch(&packets);
        assert_eq!((result.sent, result.dropped), (1, 0));
        assert_eq!(result.error.unwrap().kind(), io::ErrorKind::InvalidInput);
        assert!(receive.try_recv().is_ok());
        assert!(receive.try_recv().is_err());
        // Consume the successful prefix and invalid packet before retrying.
        let result = writer.send_batch(&packets[2..]);
        assert_eq!((result.sent, result.dropped), (1, 0));
        assert!(result.error.is_none());
        assert!(receive.try_recv().is_ok());
        assert!(receive.try_recv().is_err());
    }

    fn wire(ipv6: bool) -> Vec<u8> {
        let (source, target) = if ipv6 { ("[::1]:1", "[::2]:2") }
            else { ("127.0.0.1:1", "127.0.0.2:2") };
        encode_packet(&UdpPacket::from((Bytes::from_static(b"payload"),
            source.parse().unwrap(), target.parse().unwrap()))).unwrap().data().to_vec()
    }

    #[test]
    fn rejects_fragments_and_truncated_datagrams_without_clamping() {
        for flags in [0x2000u16, 1, 0x2001] {
            let mut packet = wire(false);
            packet[6..8].copy_from_slice(&flags.to_be_bytes());
            assert!(parse_udp_packet(&packet).is_none());
        }
        for ipv6 in [false, true] {
            let original = wire(ipv6);
            let header = if ipv6 { 40 } else { 20 };
            for size in 0..original.len() {
                assert!(parse_udp_packet(&original[..size]).is_none(), "accepted truncated packet: {ipv6}/{size}");
            }
            for length in [0u16, 7, 16, u16::MAX] {
                let mut packet = original.clone();
                packet[header + 4..header + 6].copy_from_slice(&length.to_be_bytes());
                assert!(parse_udp_packet(&packet).is_none(), "accepted UDP length {length}");
            }
            let mut padded = original.clone();
            padded.extend_from_slice(b"padding");
            let (_, _, payload) = parse_udp_packet(&padded).unwrap();
            assert_eq!(&padded[payload], b"payload");
        }
        let mut ipv6 = wire(true);
        ipv6[6] = 44; // Fragment header is not handled by this fast parser.
        assert!(parse_udp_packet(&ipv6).is_none());
    }

    #[tokio::test]
    async fn malformed_input_does_not_stop_following_valid_udp() {
        use futures::SinkExt;
        use tokio::time::{timeout, Duration};
        let (stack, _listener, udp) = crate::NetStack::new();
        let (mut sink, _output) = stack.split();
        let (mut reader, _writer) = udp.split();
        let valid = wire(false);
        sink.send(Packet::new(valid[..27].to_vec())).await.unwrap();
        let mut fragment = valid.clone();
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        sink.send(Packet::new(fragment)).await.unwrap();
        sink.send(Packet::new(valid)).await.unwrap();
        let packet = timeout(Duration::from_secs(1), reader.recv()).await.unwrap().unwrap();
        assert_eq!(packet.data(), b"payload");
        assert!(timeout(Duration::from_millis(10), reader.recv()).await.is_err());
    }

}
