use smoltcp::{iface::{Config, Interface, SocketSet}, phy::Device, time::Instant,
    wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv6Address}};
use tokio::sync::mpsc;

use crate::{Packet, link::device::SinglePacketDevice};

pub(crate) fn new_interface<D: Device>(device: &mut D) -> Interface {
    let mut config =
        Config::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(
        config,
        device,
        Instant::now(),
    );
    iface.set_any_ip(true);
    iface.update_ip_addrs(|ip_addrs| {
        let _ = ip_addrs.push(IpCidr::new(
            Ipv4Address::new(10, 0, 0, 1).into(),
            24,
        ));
        let _ = ip_addrs.push(IpCidr::new(
            Ipv6Address::new(0x0, 0xfac, 0, 0, 0, 0, 0, 1).into(),
            64,
        ));
    });

    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1))
        .expect("Failed to add default IPv4 route");
    iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(
            0x0, 0xfac, 0, 0, 0, 0, 0, 1,
        ))
        .expect("Failed to add default IPv6 route");
    iface
}

/// ICMP requires no TCP sockets, accept queue or background polling task.
/// Constructed only when an ICMP packet reaches a stack with TCP disabled.
pub(crate) struct IcmpResponder {
    iface: Interface,
    sockets: SocketSet<'static>,
    mtu: usize,
}

impl IcmpResponder {
    pub(crate) fn new(outbound: &mpsc::Sender<Packet>, mtu: usize) -> Self {
        let mut device = SinglePacketDevice::new(None, outbound, mtu);
        Self { iface: new_interface(&mut device), sockets: SocketSet::new(vec![]), mtu }
    }

    pub(crate) fn respond(&mut self, packet: Packet, outbound: &mpsc::Sender<Packet>) {
        let mut device = SinglePacketDevice::new(Some(packet), outbound, self.mtu);
        self.iface.poll(Instant::now(), &mut device, &mut self.sockets);
    }
}
