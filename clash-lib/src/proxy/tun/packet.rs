use std::{net::{Ipv4Addr, Ipv6Addr}, sync::Arc};

use bytes::BytesMut;
use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};
use tracing::debug;
use clash_netstack::{Packet, StackSplitSink};

use crate::Error;
use super::{packet_queue::Sender, system_stack::{SystemTcpNat, process_system_tcp_packet}};

pub(super) struct PacketDispatcher {
    pub enable_tcp: bool,
    pub system_tcp: bool,
    pub ipv4: Option<(Ipv4Addr, Ipv4Addr, u16)>,
    pub ipv6: Option<(Ipv6Addr, Ipv6Addr, u16)>,
    pub nat: Arc<SystemTcpNat>,
    pub replies: Sender,
}

impl PacketDispatcher {
    pub async fn dispatch(&self, mut packet: BytesMut, stack: &mut StackSplitSink) -> Result<(), Error> {
        if self.enable_tcp && !self.system_tcp {
            stack.send_packet(Packet::from(packet))?;
            return Ok(());
        }
        let is_tcp = match IpVersion::of_packet(&packet) {
            Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(&packet[..])
                .is_ok_and(|ip| ip.next_header() == IpProtocol::Tcp),
            Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet[..])
                .is_ok_and(|ip| ip.next_header() == IpProtocol::Tcp),
            Err(_) => false,
        };
        if is_tcp {
            if !self.enable_tcp { return Ok(()); }
            if self.system_tcp {
                if process_system_tcp_packet(&mut packet, self.ipv4, self.ipv6, &self.nat) == Some(true) {
                    self.replies.send(packet).await?;
                } else {
                    debug!("dropping TUN TCP packet rejected by system NAT");
                }
                return Ok(());
            }
        }
        stack.send_packet(Packet::from(packet))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::IpAddr, time::Duration};
    use futures::StreamExt;
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
                        enable_tcp, system_tcp, nat: nat.clone(), replies,
                        ipv4: Some((Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2), 1234)),
                        ipv6: Some(("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap(), 1234)),
                    };
                    dispatcher.dispatch(tcp_syn(ipv6), &mut sink).await.unwrap();
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

    fn tcp_syn(ipv6: bool) -> BytesMut {
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
