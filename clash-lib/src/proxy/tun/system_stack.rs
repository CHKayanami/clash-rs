use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use smoltcp::wire::{
    IpAddress, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet,
    TcpPacket,
};
use tracing::{debug, error, trace};

pub struct TcpSession {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub last_active: RwLock<Instant>,
}

pub struct SystemTcpNat {
    port_index: AtomicU16,
    addr_map: RwLock<HashMap<SocketAddr, u16>>,
    port_map: RwLock<HashMap<u16, Arc<TcpSession>>>,
}

impl Default for SystemTcpNat {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemTcpNat {
    pub fn new() -> Self {
        Self {
            port_index: AtomicU16::new(10000),
            addr_map: RwLock::new(HashMap::new()),
            port_map: RwLock::new(HashMap::new()),
        }
    }

    pub fn lookup(&self, source: SocketAddr, destination: SocketAddr) -> u16 {
        {
            let addr_map = self.addr_map.read();
            if let Some(&port) = addr_map.get(&source) {
                let port_map = self.port_map.read();
                if let Some(session) = port_map.get(&port) {
                    *session.last_active.write() = Instant::now();
                    return port;
                }
            }
        }

        let mut addr_map = self.addr_map.write();
        let mut port_map = self.port_map.write();

        // Double check after acquiring write locks
        if let Some(&port) = addr_map.get(&source) {
            if let Some(session) = port_map.get(&port) {
                *session.last_active.write() = Instant::now();
                return port;
            }
        }

        // Allocate a new port in range 10000..65535
        let mut attempts = 0;
        let mut port;
        loop {
            let next = self.port_index.fetch_add(1, Ordering::Relaxed);
            port = if next < 10000 || next > 65500 {
                self.port_index.store(10001, Ordering::Relaxed);
                10000
            } else {
                next
            };

            if !port_map.contains_key(&port) {
                break;
            }
            attempts += 1;
            if attempts > 55535 {
                // If completely full, evict oldest or replace
                break;
            }
        }

        let session = Arc::new(TcpSession {
            source,
            destination,
            last_active: RwLock::new(Instant::now()),
        });

        addr_map.insert(source, port);
        port_map.insert(port, session);
        port
    }

    pub fn lookup_back(&self, port: u16) -> Option<Arc<TcpSession>> {
        let port_map = self.port_map.read();
        let session = port_map.get(&port)?.clone();
        *session.last_active.write() = Instant::now();
        Some(session)
    }

    pub fn cleanup_timeout(&self, timeout: Duration) {
        let now = Instant::now();
        let mut addr_map = self.addr_map.write();
        let mut port_map = self.port_map.write();

        port_map.retain(|_port, session| {
            let last = *session.last_active.read();
            if now.duration_since(last) > timeout {
                addr_map.remove(&session.source);
                false
            } else {
                true
            }
        });
    }
}

/// Rewrites IPv4/TCP headers in-place for System NAT.
/// Returns Some(true) if the packet was rewritten and should be written back to TUN.
pub fn process_ipv4_tcp(
    packet: &mut [u8],
    server_addr: Ipv4Addr,
    client_addr: Ipv4Addr,
    listener_port: u16,
    nat: &SystemTcpNat,
) -> Option<bool> {
    let ip_hdr_len = {
        let ipv4 = Ipv4Packet::new_checked(&packet[..]).ok()?;
        if ipv4.next_header() != IpProtocol::Tcp {
            return None;
        }
        ipv4.header_len() as usize
    };

    if packet.len() < ip_hdr_len + 20 {
        return None;
    }

    let (ip_slice, tcp_slice) = packet.split_at_mut(ip_hdr_len);
    let mut ipv4 = Ipv4Packet::new_unchecked(ip_slice);
    let mut tcp = TcpPacket::new_checked(tcp_slice).ok()?;

    let src_ip: Ipv4Addr = ipv4.src_addr().into();
    let dst_ip: Ipv4Addr = ipv4.dst_addr().into();
    let src_port = tcp.src_port();
    let dst_port = tcp.dst_port();

    let server_v4_repr = Ipv4Address::from(server_addr);
    let client_v4_repr = Ipv4Address::from(client_addr);

    if src_ip == server_addr && src_port == listener_port {
        // Inbound: OS Kernel -> Client
        let session = nat.lookup_back(dst_port)?;
        let orig_dst_ip = match session.destination.ip() {
            IpAddr::V4(v4) => Ipv4Address::from(v4),
            _ => return None,
        };
        let orig_src_ip = match session.source.ip() {
            IpAddr::V4(v4) => Ipv4Address::from(v4),
            _ => return None,
        };

        ipv4.set_src_addr(orig_dst_ip);
        tcp.set_src_port(session.destination.port());
        ipv4.set_dst_addr(orig_src_ip);
        tcp.set_dst_port(session.source.port());
    } else {
        // Outbound: Client -> External Target
        if dst_ip.is_broadcast() || dst_ip.is_multicast() {
            return None;
        }

        let source = SocketAddr::new(IpAddr::V4(src_ip), src_port);
        let destination = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
        let nat_port = nat.lookup(source, destination);

        ipv4.set_src_addr(client_v4_repr);
        tcp.set_src_port(nat_port);
        ipv4.set_dst_addr(server_v4_repr);
        tcp.set_dst_port(listener_port);
    }

    // Recompute IP & TCP checksums
    ipv4.fill_checksum();
    let src_addr_repr = IpAddress::Ipv4(ipv4.src_addr());
    let dst_addr_repr = IpAddress::Ipv4(ipv4.dst_addr());
    tcp.fill_checksum(&src_addr_repr, &dst_addr_repr);

    Some(true)
}

/// Rewrites IPv6/TCP headers in-place for System NAT.
/// Returns Some(true) if the packet was rewritten and should be written back to TUN.
pub fn process_ipv6_tcp(
    packet: &mut [u8],
    server_addr: Ipv6Addr,
    client_addr: Ipv6Addr,
    listener_port6: u16,
    nat: &SystemTcpNat,
) -> Option<bool> {
    let ip_hdr_len = {
        let ipv6 = Ipv6Packet::new_checked(&packet[..]).ok()?;
        if ipv6.next_header() != IpProtocol::Tcp {
            return None;
        }
        ipv6.header_len()
    };

    if packet.len() < ip_hdr_len + 20 {
        return None;
    }

    let (ip_slice, tcp_slice) = packet.split_at_mut(ip_hdr_len);
    let mut ipv6 = Ipv6Packet::new_unchecked(ip_slice);
    let mut tcp = TcpPacket::new_checked(tcp_slice).ok()?;

    let src_ip: Ipv6Addr = ipv6.src_addr().into();
    let dst_ip: Ipv6Addr = ipv6.dst_addr().into();
    let src_port = tcp.src_port();
    let dst_port = tcp.dst_port();

    let server_v6_repr = Ipv6Address::from(server_addr);
    let client_v6_repr = Ipv6Address::from(client_addr);

    if src_ip == server_addr && src_port == listener_port6 {
        // Inbound: OS Kernel -> Client
        let session = nat.lookup_back(dst_port)?;
        let orig_dst_ip = match session.destination.ip() {
            IpAddr::V6(v6) => Ipv6Address::from(v6),
            _ => return None,
        };
        let orig_src_ip = match session.source.ip() {
            IpAddr::V6(v6) => Ipv6Address::from(v6),
            _ => return None,
        };

        ipv6.set_src_addr(orig_dst_ip);
        tcp.set_src_port(session.destination.port());
        ipv6.set_dst_addr(orig_src_ip);
        tcp.set_dst_port(session.source.port());
    } else {
        // Outbound: Client -> External Target
        if dst_ip.is_multicast() {
            return None;
        }

        let source = SocketAddr::new(IpAddr::V6(src_ip), src_port);
        let destination = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);
        let nat_port = nat.lookup(source, destination);

        ipv6.set_src_addr(client_v6_repr);
        tcp.set_src_port(nat_port);
        ipv6.set_dst_addr(server_v6_repr);
        tcp.set_dst_port(listener_port6);
    }

    // Recompute TCP checksum
    let src_addr_repr = IpAddress::Ipv6(ipv6.src_addr());
    let dst_addr_repr = IpAddress::Ipv6(ipv6.dst_addr());
    tcp.fill_checksum(&src_addr_repr, &dst_addr_repr);

    Some(true)
}

/// Dispatches an IP packet to either IPv4 or IPv6 TCP NAT translation.
pub fn process_system_tcp_packet(
    packet: &mut [u8],
    v4_info: Option<(Ipv4Addr, Ipv4Addr, u16)>,
    v6_info: Option<(Ipv6Addr, Ipv6Addr, u16)>,
    nat: &SystemTcpNat,
) -> Option<bool> {
    match IpVersion::of_packet(packet).ok()? {
        IpVersion::Ipv4 => {
            let (server, client, port) = v4_info?;
            process_ipv4_tcp(packet, server, client, port, nat)
        }
        IpVersion::Ipv6 => {
            let (server, client, port) = v6_info?;
            process_ipv6_tcp(packet, server, client, port, nat)
        }
    }
}

/// Starts the system TCP listener loop for `stack: system`.
pub async fn start_system_tcp_listener(
    tcp_listener: tokio::net::TcpListener,
    nat: Arc<SystemTcpNat>,
    dispatcher: Arc<crate::app::dispatcher::Dispatcher>,
    resolver: crate::app::dns::ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: crate::config::internal::config::DnsHijack,
    strict_route: bool,
    exclude_routes: Arc<Vec<ipnet::IpNet>>,
) {
    loop {
        match tcp_listener.accept().await {
            Ok((stream, peer_addr)) => {
                let nat_port = peer_addr.port();
                let Some(session) = nat.lookup_back(nat_port) else {
                    debug!("system stack: unknown incoming TCP connection from {peer_addr}");
                    continue;
                };

                let source = session.source;
                let destination = session.destination;
                trace!("system stack: accepted connection {source} -> {destination}");

                let dispatcher = dispatcher.clone();
                let resolver = resolver.clone();
                let dns_hijack = dns_hijack.clone();
                let exclude_routes = exclude_routes.clone();

                tokio::spawn(async move {
                    crate::proxy::tun::stream::handle_inbound_stream(
                        stream,
                        source,
                        destination,
                        dispatcher,
                        resolver,
                        so_mark,
                        dns_hijack,
                        strict_route,
                        exclude_routes,
                    )
                    .await;
                });
            }
            Err(e) => {
                error!("system stack: TCP listener accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr};

    #[test]
    fn test_system_tcp_nat_lookup() {
        let nat = SystemTcpNat::new();
        let src: SocketAddr = "192.168.1.100:54321".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();

        let port1 = nat.lookup(src, dst);
        assert!(port1 >= 10000);

        let port2 = nat.lookup(src, dst);
        assert_eq!(port1, port2);

        let session = nat.lookup_back(port1).expect("session must exist");
        assert_eq!(session.source, src);
        assert_eq!(session.destination, dst);
    }

    #[test]
    fn test_system_ipv4_tcp_bidirectional_rewrite() {
        let nat = SystemTcpNat::new();
        let server_addr = Ipv4Addr::new(198, 18, 0, 1);
        let client_addr = Ipv4Addr::new(198, 18, 0, 2);
        let listener_port = 54321;

        let client_src = Ipv4Address::new(10, 0, 0, 5);
        let target_dst = Ipv4Address::new(1, 1, 1, 1);
        let client_port = 12345;
        let target_port = 80;

        // 1. Build an outbound client -> target TCP SYN packet
        let mut packet = vec![0u8; 40];
        let ip_repr = Ipv4Repr {
            src_addr: client_src,
            dst_addr: target_dst,
            next_header: IpProtocol::Tcp,
            payload_len: 20,
            hop_limit: 64,
        };
        let tcp_repr = TcpRepr {
            src_port: client_port,
            dst_port: target_port,
            control: TcpControl::Syn,
            seq_number: smoltcp::wire::TcpSeqNumber(100),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };

        ip_repr.emit(&mut Ipv4Packet::new_unchecked(&mut packet[..20]), &smoltcp::phy::ChecksumCapabilities::default());
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut packet[20..]),
            &IpAddress::Ipv4(client_src),
            &IpAddress::Ipv4(target_dst),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );

        // 2. Process outbound packet (Client -> Target)
        let res = process_ipv4_tcp(&mut packet, server_addr, client_addr, listener_port, &nat);
        assert_eq!(res, Some(true));

        let rewritten_ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
        let rewritten_tcp = TcpPacket::new_checked(&packet[20..]).unwrap();

        assert_eq!(rewritten_ip.src_addr(), Ipv4Address::from(client_addr));
        assert_eq!(rewritten_ip.dst_addr(), Ipv4Address::from(server_addr));
        let nat_port = rewritten_tcp.src_port();
        assert_eq!(rewritten_tcp.dst_port(), listener_port);
        assert!(nat_port >= 10000);

        // 3. Build return packet from OS kernel (Server -> Client nat_port)
        let mut reply_packet = vec![0u8; 40];
        let reply_ip_repr = Ipv4Repr {
            src_addr: Ipv4Address::from(server_addr),
            dst_addr: Ipv4Address::from(client_addr),
            next_header: IpProtocol::Tcp,
            payload_len: 20,
            hop_limit: 64,
        };
        let reply_tcp_repr = TcpRepr {
            src_port: listener_port,
            dst_port: nat_port,
            control: TcpControl::Syn,
            seq_number: smoltcp::wire::TcpSeqNumber(500),
            ack_number: Some(smoltcp::wire::TcpSeqNumber(101)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };

        reply_ip_repr.emit(&mut Ipv4Packet::new_unchecked(&mut reply_packet[..20]), &smoltcp::phy::ChecksumCapabilities::default());
        reply_tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut reply_packet[20..]),
            &IpAddress::Ipv4(Ipv4Address::from(server_addr)),
            &IpAddress::Ipv4(Ipv4Address::from(client_addr)),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );

        // 4. Process return packet (Server -> Client)
        let res_reply = process_ipv4_tcp(&mut reply_packet, server_addr, client_addr, listener_port, &nat);
        assert_eq!(res_reply, Some(true));

        let restored_ip = Ipv4Packet::new_checked(&reply_packet[..]).unwrap();
        let restored_tcp = TcpPacket::new_checked(&reply_packet[20..]).unwrap();

        assert_eq!(restored_ip.src_addr(), target_dst);
        assert_eq!(restored_ip.dst_addr(), client_src);
        assert_eq!(restored_tcp.src_port(), target_port);
        assert_eq!(restored_tcp.dst_port(), client_port);
    }
}
