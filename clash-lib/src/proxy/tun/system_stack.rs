use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock,
    },
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use smoltcp::wire::{
    IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet,
    TcpPacket,
};

static START_TIME: LazyLock<Instant> = LazyLock::new(Instant::now);

#[inline]
fn current_monotonic_us() -> u64 {
    START_TIME.elapsed().as_micros() as u64
}

struct TcpSession {
    source: SocketAddr,
    destination: SocketAddr,
    last_active_us: AtomicU64,
}

impl TcpSession {
    fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            source,
            destination,
            last_active_us: AtomicU64::new(current_monotonic_us()),
        }
    }

    #[inline]
    fn touch(&self) {
        self.last_active_us
            .store(current_monotonic_us(), Ordering::Relaxed);
    }

    #[inline]
    fn last_active_us(&self) -> u64 {
        self.last_active_us.load(Ordering::Relaxed)
    }
}

const FIRST_NAT_PORT: u16 = 10000;
const LAST_NAT_PORT: u16 = 65500;
const NAT_PORT_COUNT: usize = (LAST_NAT_PORT - FIRST_NAT_PORT + 1) as usize;

#[derive(Default)]
struct NatState {
    next_port: u16,
    addresses: HashMap<(SocketAddr, SocketAddr), u16>,
    ports: HashMap<u16, TcpSession>,
}

pub struct SystemTcpNat {
    // Both indexes form one invariant. A hot lookup takes one read lock;
    // insert/expiry update both indexes under the same write lock.
    state: RwLock<NatState>,
}

impl Default for SystemTcpNat {
    fn default() -> Self { Self::new() }
}

impl SystemTcpNat {
    pub fn new() -> Self {
        Self { state: RwLock::new(NatState {
            next_port: FIRST_NAT_PORT, ..Default::default()
        }) }
    }

    pub fn lookup(&self, source: SocketAddr, destination: SocketAddr) -> Option<u16> {
        let key = (source, destination);
        {
            let state = self.state.read();
            if let Some(port) = state.addresses.get(&key) {
                state.ports[port].touch();
                return Some(*port);
            }
        }
        let mut state = self.state.write();
        if let Some(port) = state.addresses.get(&key) {
            state.ports[port].touch();
            return Some(*port);
        }
        if state.ports.len() == NAT_PORT_COUNT { return None; }
        loop {
            let port = state.next_port;
            state.next_port = if port == LAST_NAT_PORT { FIRST_NAT_PORT } else { port + 1 };
            if state.ports.contains_key(&port) { continue; }
            state.addresses.insert(key, port);
            state.ports.insert(port, TcpSession::new(source, destination));
            return Some(port);
        }
    }

    pub fn lookup_back(&self, port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let state = self.state.read();
        let session = state.ports.get(&port)?;
        session.touch();
        Some((session.source, session.destination))
    }

    pub fn cleanup_timeout(&self, timeout: Duration) {
        let now = current_monotonic_us();
        let timeout_us = timeout.as_micros() as u64;
        let mut state = self.state.write();
        let NatState { addresses, ports, .. } = &mut *state;
        ports.retain(|_, session| {
            let expired = now.saturating_sub(session.last_active_us()) > timeout_us;
            if timeout.is_zero() || expired {
                addresses.remove(&(session.source, session.destination));
                false
            } else { true }
        });
    }
}

// RFC 1624: adjust only changed header words. Payload bytes are never scanned,
// and an invalid incoming checksum is not silently repaired by NAT.
fn replace_checksum(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    debug_assert_eq!(old.len(), new.len());
    debug_assert_eq!(old.len() % 2, 0);
    let mut sum = u32::from(!checksum);
    for (old, new) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        sum += u32::from(!u16::from_be_bytes([old[0], old[1]]));
        sum += u32::from(u16::from_be_bytes([new[0], new[1]]));
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
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
    let original_tcp_checksum = tcp.checksum();

    let server_v4_repr = Ipv4Address::from(server_addr);
    let client_v4_repr = Ipv4Address::from(client_addr);

    if src_ip == server_addr && src_port == listener_port {
        // Inbound: OS Kernel -> Client
        let (source, destination) = nat.lookup_back(dst_port)?;
        let orig_dst_ip = match destination.ip() {
            IpAddr::V4(v4) => Ipv4Address::from(v4),
            _ => return None,
        };
        let orig_src_ip = match source.ip() {
            IpAddr::V4(v4) => Ipv4Address::from(v4),
            _ => return None,
        };

        ipv4.set_src_addr(orig_dst_ip);
        tcp.set_src_port(destination.port());
        ipv4.set_dst_addr(orig_src_ip);
        tcp.set_dst_port(source.port());
    } else {
        // Outbound: Client -> External Target
        if dst_ip.is_broadcast() || dst_ip.is_multicast() {
            return None;
        }

        let source = SocketAddr::new(IpAddr::V4(src_ip), src_port);
        let destination = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
        let nat_port = nat.lookup(source, destination)?;

        ipv4.set_src_addr(client_v4_repr);
        tcp.set_src_port(nat_port);
        ipv4.set_dst_addr(server_v4_repr);
        tcp.set_dst_port(listener_port);
    }

    let checksum = replace_checksum(ipv4.checksum(), &src_ip.octets(), &ipv4.src_addr().octets());
    ipv4.set_checksum(replace_checksum(checksum, &dst_ip.octets(), &ipv4.dst_addr().octets()));
    let checksum = replace_checksum(original_tcp_checksum, &src_ip.octets(), &ipv4.src_addr().octets());
    let checksum = replace_checksum(checksum, &dst_ip.octets(), &ipv4.dst_addr().octets());
    let checksum = replace_checksum(checksum, &src_port.to_be_bytes(), &tcp.src_port().to_be_bytes());
    tcp.set_checksum(replace_checksum(checksum, &dst_port.to_be_bytes(), &tcp.dst_port().to_be_bytes()));

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
    let original_tcp_checksum = tcp.checksum();

    let server_v6_repr = Ipv6Address::from(server_addr);
    let client_v6_repr = Ipv6Address::from(client_addr);

    if src_ip == server_addr && src_port == listener_port6 {
        // Inbound: OS Kernel -> Client
        let (source, destination) = nat.lookup_back(dst_port)?;
        let orig_dst_ip = match destination.ip() {
            IpAddr::V6(v6) => Ipv6Address::from(v6),
            _ => return None,
        };
        let orig_src_ip = match source.ip() {
            IpAddr::V6(v6) => Ipv6Address::from(v6),
            _ => return None,
        };

        ipv6.set_src_addr(orig_dst_ip);
        tcp.set_src_port(destination.port());
        ipv6.set_dst_addr(orig_src_ip);
        tcp.set_dst_port(source.port());
    } else {
        // Outbound: Client -> External Target
        if dst_ip.is_multicast() {
            return None;
        }

        let source = SocketAddr::new(IpAddr::V6(src_ip), src_port);
        let destination = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);
        let nat_port = nat.lookup(source, destination)?;

        ipv6.set_src_addr(client_v6_repr);
        tcp.set_src_port(nat_port);
        ipv6.set_dst_addr(server_v6_repr);
        tcp.set_dst_port(listener_port6);
    }

    let checksum = replace_checksum(original_tcp_checksum, &src_ip.octets(), &ipv6.src_addr().octets());
    let checksum = replace_checksum(checksum, &dst_ip.octets(), &ipv6.dst_addr().octets());
    let checksum = replace_checksum(checksum, &src_port.to_be_bytes(), &tcp.src_port().to_be_bytes());
    tcp.set_checksum(replace_checksum(checksum, &dst_port.to_be_bytes(), &tcp.dst_port().to_be_bytes()));

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

#[cfg(test)]
#[path = "system_stack_tests.rs"]
mod tests;
