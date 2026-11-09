use std::{cell::RefCell, net::{Ipv4Addr, Ipv6Addr}, sync::Arc};

use bytes::BytesMut;
use tokio::time::Instant;
use smoltcp::wire::IpProtocol;
#[cfg(test)]
use smoltcp::wire::{Ipv4Packet, Ipv6Packet};
use tracing::debug;
use clash_netstack::{Packet, PacketHeaders, UdpPacket};

use crate::app::dispatcher::udp::association::direct::{DirectPath, Upload, UploadCache};
use super::system_stack::{SystemTcpNat, process_system_tcp_packet};

pub(super) struct PacketDispatcher {
    pub enable_tcp: bool,
    pub system_tcp: bool,
    pub ipv4: Option<(Ipv4Addr, Ipv4Addr, u16)>,
    pub ipv6: Option<(Ipv6Addr, Ipv6Addr, u16)>,
    pub nat: Arc<SystemTcpNat>,
    pub direct: Arc<DirectPath>,
    pub uploads: RefCell<UploadCache>,
}

pub(super) enum Dispatch {
    Stack(Packet, IpProtocol),
    Udp(UdpPacket),
    Direct(Upload),
    Split(Packet),
    Reply(BytesMut),
    Drop,
}

impl PacketDispatcher {
    pub(super) fn prepare_frame(&self, packet: Packet, now: Instant) -> Dispatch {
        let Some(headers) = PacketHeaders::new(packet.data()) else { return Dispatch::Drop; };
        let protocol = headers.protocol();
        let udp = headers.udp();
        if protocol == IpProtocol::Tcp {
            if !self.enable_tcp { return Dispatch::Drop; }
            // Native TCP retains the device allocation and checksum metadata.
            if !self.system_tcp { return Dispatch::Stack(packet, protocol); }
            let bytes = packet.into_bytes();
            let mut packet = bytes.try_into_mut().unwrap_or_else(|bytes| BytesMut::from(bytes.as_ref()));
            if process_system_tcp_packet(&mut packet, self.ipv4, self.ipv6, &self.nat) == Some(true) {
                return Dispatch::Reply(packet);
            }
            debug!("dropping TUN TCP packet rejected by system NAT");
            return Dispatch::Drop;
        }
        match self.direct.upload_parsed(packet, udp.clone(), &mut self.uploads.borrow_mut(), now) {
            Ok(Some(upload)) => Dispatch::Direct(upload),
            Ok(None) => Dispatch::Drop,
            Err(packet) if packet.udp_segmentation().is_some() => Dispatch::Split(packet),
            Err(packet) => match udp {
                Some((source, destination, payload)) => Dispatch::Udp(UdpPacket {
                    data: Packet::new(packet.into_payload(payload)),
                    local_addr: source, remote_addr: destination,
                }),
                None => Dispatch::Stack(packet, protocol),
            },
        }
    }

    #[cfg(test)]
    pub(super) fn prepare(&self, packet: BytesMut) -> Dispatch {
        self.prepare_frame(Packet::from(packet), Instant::now())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::{net::IpAddr, time::Duration};
    use futures::StreamExt;
    use bytes::Bytes;
    use smoltcp::wire::{IpAddress, TcpPacket, TcpSeqNumber};
    use tokio::time::timeout;
    use clash_netstack::NetStack;
    use super::super::packet_queue;

    #[tokio::test]
    async fn tcp_switch_controls_both_ip_versions_and_stack_modes() {
        for enable_tcp in [false, true] {
            for system_tcp in [false, true] {
                for ipv6 in [false, true] {
                    let (stack, mut listener, _udp) = NetStack::new_with_protocols(enable_tcp && !system_tcp, enable_tcp);
                    let (mut sink, _output) = stack.split();
                    let (replies, mut receiver) = packet_queue::channel();
                    let nat = Arc::new(SystemTcpNat::new());
                    let dispatcher = PacketDispatcher {
                        enable_tcp, system_tcp, nat: nat.clone(), direct: super::super::datagram::direct_path(None), uploads: Default::default(),
                        ipv4: Some((Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2), 1234)),
                        ipv6: Some(("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap(), 1234)),
                    };
                    match dispatcher.prepare(tcp_syn(ipv6)) {
                        Dispatch::Stack(packet, protocol) => sink.send_checked_packet(packet, protocol).unwrap(),
                        Dispatch::Udp(_) => panic!("no UDP in protocol-switch test"),
                        Dispatch::Reply(packet) => replies.send(packet).await.unwrap(),
                        Dispatch::Drop => {},
                        Dispatch::Split(_) => panic!("no aggregate in protocol-switch test"),
                        Dispatch::Direct(_) => panic!("no established direct route in protocol-switch test"),
                    }
                    if !enable_tcp {
                        assert!(listener.is_none());
                        assert!(receiver.try_recv().is_err());
                        assert!(nat.lookup_back(10000).is_none());
                    } else if system_tcp {
                        assert!(listener.is_none());
                        let packet = receiver.try_recv().expect("system TCP must enter the TUN reply queue");
                        if ipv6 {
                            let ip = Ipv6Packet::new_checked(&packet.bytes[..]).unwrap();
                            assert_eq!(ip.dst_addr(), "fd00::1".parse::<Ipv6Addr>().unwrap());
                        } else {
                            let ip = Ipv4Packet::new_checked(&packet.bytes[..]).unwrap();
                            assert_eq!(ip.dst_addr(), Ipv4Addr::new(198, 18, 0, 1));
                        }
                        assert!(nat.lookup_back(10000).is_some());
                    } else {
                        let stream = timeout(Duration::from_secs(1), listener.as_mut().unwrap().next())
                            .await.unwrap().expect("smoltcp must accept TCP when enabled");
                        assert_eq!(stream.local_addr().port(), 23456);
                        assert_eq!(stream.remote_addr().port(), 443);
                        assert!(receiver.try_recv().is_err());
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn udp_route_miss_keeps_checked_payload_and_addresses() {
        let dispatcher = PacketDispatcher {
            enable_tcp: true, system_tcp: false, ipv4: None, ipv6: None,
            nat: Arc::new(SystemTcpNat::new()),
            direct: super::super::datagram::direct_path(None), uploads: Default::default(),
        };
        for (source, destination) in [
            ("192.0.2.1:1234", "198.51.100.1:53"),
            ("[2001:db8::1]:1234", "[2001:db8::2]:53"),
        ] {
            let source = source.parse().unwrap();
            let destination = destination.parse().unwrap();
            let frame = UdpPacket::from((Bytes::from_static(b"query"), source, destination)).encode().unwrap();
            let Dispatch::Udp(packet) = dispatcher.prepare_frame(frame, Instant::now()) else {
                panic!("unregistered UDP must enter the ordinary route");
            };
            assert_eq!(packet.local_addr, source);
            assert_eq!(packet.remote_addr, destination);
            assert_eq!(packet.data.data(), b"query");
        }
    }

    pub(in crate::proxy::tun) fn tcp_syn(ipv6: bool) -> BytesMut {
        let (source, destination, offset): (IpAddr, IpAddr, usize) = if ipv6 {
            ("2001:db8::2".parse().unwrap(), "2001:db8::3".parse().unwrap(), 40)
        } else {
            ("192.0.2.2".parse().unwrap(), "198.51.100.2".parse().unwrap(), 20)
        };
        let mut bytes = BytesMut::zeroed(offset + 20);
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
                ip.set_version(4);
                ip.set_header_len(20);
                ip.set_total_len(40);
                ip.set_next_header(IpProtocol::Tcp);
                ip.set_hop_limit(64);
                ip.set_src_addr(source);
                ip.set_dst_addr(destination);
                ip.fill_checksum();
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
                ip.set_version(6);
                ip.set_payload_len(20);
                ip.set_next_header(IpProtocol::Tcp);
                ip.set_hop_limit(64);
                ip.set_src_addr(source);
                ip.set_dst_addr(destination);
            }
            _ => unreachable!(),
        }
        let mut tcp = TcpPacket::new_unchecked(&mut bytes[offset..]);
        tcp.set_src_port(23456);
        tcp.set_dst_port(443);
        tcp.set_header_len(20);
        tcp.set_seq_number(TcpSeqNumber(1));
        tcp.set_syn(true);
        tcp.set_window_len(65535);
        tcp.fill_checksum(&IpAddress::from(source), &IpAddress::from(destination));
        bytes
    }
}
