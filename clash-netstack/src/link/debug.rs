use smoltcp::wire::{IpVersion, Ipv4Packet, Ipv6Packet, PrettyPrinter};
use tracing::{Level, enabled, trace};

pub(crate) fn trace_ip_packet(message: &str, packet: &[u8]) {
    if !enabled!(Level::TRACE) { return; }
    match IpVersion::of_packet(packet) {
        Ok(IpVersion::Ipv4) => trace!(
            "{}: {}", message, PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
        ),
        Ok(IpVersion::Ipv6) => trace!(
            "{}: {}", message, PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
        ),
        _ => {},
    }
}
