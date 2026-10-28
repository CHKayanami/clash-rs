mod adapter;
use adapter::TunDatagram;
use std::{sync::Arc, time::Duration};
use ipnet::IpNet;
use tracing::{debug, warn};
use clash_netstack::UdpSocket;
use crate::{
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver,
        net::get_default_outbound_interface},
    config::internal::config::DnsHijack,
    session::{Network, Session, Type},
};

pub(crate) async fn handle_inbound_datagram(
    socket: UdpSocket,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: DnsHijack,
    udp_timeout: Option<u64>,
    strict_route: bool,
    exclude_routes: Arc<Vec<IpNet>>,
) {
    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        iface: get_default_outbound_interface(),
        so_mark,
        udp_timeout: udp_timeout.map(Duration::from_secs),
        ..Default::default()
    };
    let (datagram, finished) = TunDatagram::new(
        socket, resolver, dns_hijack, strict_route, exclude_routes,
    );
    // The dispatcher owns both directions and the adapter's DNS tasks. Dropping
    // the close sender on cancellation stops that entire inbound namespace.
    let closer = dispatcher.dispatch_datagram(sess, Box::new(datagram)).await;
    debug!("tun UDP ready");
    let _ = finished.await;
    let _ = closer.send(0);
    warn!("TUN UDP dispatcher stopped");
}
