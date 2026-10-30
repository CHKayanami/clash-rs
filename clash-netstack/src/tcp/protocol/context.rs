//! Minimal L3 context for transparent TCP endpoints, without Interface/SocketSet.
use smoltcp::{time::Instant, wire::{IpAddress, IpCidr}};

#[derive(Debug)]
pub struct Context {
    now: Instant,
    mtu: usize,
    addresses: Vec<IpCidr>,
    any_ip: bool,
}

impl Context {
    /// Create an IP-only transparent endpoint context. Passive connections may
    /// use any unicast local address; active opens need an explicit source.
    pub fn new(mtu: usize) -> Self {
        Self { now: Instant::ZERO, mtu, addresses: Vec::new(), any_ip: true }
    }

    pub(crate) fn now(&self) -> Instant { self.now }
    pub(crate) fn set_now(&mut self, now: Instant) { self.now = now; }
    pub(crate) fn ip_mtu(&self) -> usize { self.mtu }
    #[cfg(not(test))]
    pub(crate) fn random_u32(&mut self) -> u32 { rand::random() }

    pub(crate) fn has_ip_addr(&self, address: IpAddress) -> bool {
        self.any_ip || self.addresses.iter().any(|cidr| cidr.address() == address)
    }

    pub(crate) fn get_source_address(&self, destination: &IpAddress) -> Option<IpAddress> {
        self.addresses.iter().map(IpCidr::address)
            .find(|address| address.version() == destination.version())
    }

    #[cfg(test)]
    pub(crate) fn set_ip_addrs(&mut self, addresses: Vec<IpCidr>) { self.addresses = addresses; }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self { any_ip: false, addresses: vec![
            IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24),
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ], ..Self::new(1500) }
    }
}
