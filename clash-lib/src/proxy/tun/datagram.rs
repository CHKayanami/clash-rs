use crate::app::dns::query::IngressProfile;
use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
        net::get_default_outbound_interface,
    },
    proxy::datagram::UdpPacket,
    session::{Network, Session, Type},
};
use std::sync::Arc;
use tracing::{debug, trace, warn};
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use super::device_io::DEVICE_BATCH;

const MAX_PENDING_DNS: usize = 256;

pub(crate) async fn handle_inbound_datagram(
    socket: watfaq_netstack::UdpSocket,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: crate::config::internal::config::DnsHijack,
    udp_timeout: Option<u64>,
    strict_route: bool,
    exclude_routes: Arc<Vec<ipnet::IpNet>>,
) {
    // tun i/o
    // lr: app packets went into tun will be accessed from lr
    // ls: packet written into ls will go back to app from tun
    let (mut lr, mut ls) = socket.split();
    let ls_dns = ls.clone(); // for dns hijack
    let resolver_dns = resolver.clone(); // for dns hijack

    // dispatcher <-> tun communications
    // l_tx: dispatcher write packet responded from remote proxy
    // l_rx: in fut1 items are forwarded to ls
    let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(2048);

    // forward packets from tun to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(2048);

    // for dispatcher - the dispatcher would receive packets from this channel,
    // which is from the stack and send back packets to this channel, which
    // is to the tun
    let udp_stream = TunDatagram::new(l_tx, d_rx);

    let default_outbound = get_default_outbound_interface();
    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        iface: default_outbound.inspect(|x| {
            debug!("selecting outbound interface: {:?} for tun UDP traffic", x);
        }),
        so_mark,
        udp_timeout: udp_timeout.map(std::time::Duration::from_secs),
        ..Default::default()
    };

    let closer = dispatcher
        .dispatch_datagram(sess, Box::new(udp_stream))
        .await;

    // dispatcher -> tun
    let mut fut1 = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut reply_batch = Vec::with_capacity(DEVICE_BATCH);
        let mut packets = Vec::with_capacity(DEVICE_BATCH);
        while l_rx.recv_many(&mut reply_batch, DEVICE_BATCH).await > 0 {
            for packet in reply_batch.drain(..) {
                let (Some(source), Some(destination)) = (
                    packet.src_addr.try_into_socket_addr(), packet.dst_addr.try_into_socket_addr(),
                ) else { warn!("tun drop reply with non-IP address"); continue; };
                packets.push((packet.data, source, destination).into());
            }
            match ls.send_batch(&packets) {
                Ok(sent) if sent < packets.len() => {
                    debug!("TUN UDP reply queue full: submitted {sent}/{} packets", packets.len());
                }
                Err(error) => warn!("failed to send UDP batch to netstack: {error}"),
                _ => {}
            }
            packets.clear();
        }
    }));

    // tun -> dispatcher
    let mut fut2 = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut batch = Vec::with_capacity(DEVICE_BATCH);
        let mut dns_queries = JoinSet::new();
        'outer: loop {
            batch.clear();
            let count = tokio::select! {
                count = lr.recv_many(&mut batch, DEVICE_BATCH) => count,
                Some(result) = dns_queries.join_next(), if !dns_queries.is_empty() => {
                    if let Err(error) = result { warn!("TUN DNS task failed: {error}"); }
                    continue;
                }
            };
            if count == 0 {
                break 'outer;
            }

            'read_packet: for watfaq_netstack::UdpPacket {
                data,
                local_addr,
                remote_addr,
            } in batch.drain(..)
            {
                if remote_addr.ip().is_multicast() {
                    continue;
                }

                if strict_route
                    && exclude_routes.iter().any(|net| net.contains(&remote_addr.ip()))
                {
                    trace!(
                        "strict-route: dropping tun UDP packet to excluded subnet: {:?}",
                        remote_addr
                    );
                    continue 'read_packet;
                }

                let pkt = UdpPacket {
                    data: data.into_bytes(),
                    src_addr: local_addr.into(),
                    dst_addr: remote_addr.into(),
                    inbound_user: None,
                };

                trace!("tun -> dispatcher: {:?}", pkt);

                if dns_hijack.is_hijacked(Network::Udp, &remote_addr) {
                    trace!("got dns packet: {:?}, returning from Clash DNS server", pkt);
                    // Bound admission, not only resolver execution: otherwise
                    // queued DNS tasks can retain unlimited packet buffers.
                    while let Some(result) = dns_queries.try_join_next() {
                        if let Err(error) = result { warn!("TUN DNS task failed: {error}"); }
                    }
                    if dns_queries.len() >= MAX_PENDING_DNS {
                        debug!("TUN DNS concurrency limit reached, dropping query");
                        continue 'read_packet;
                    }
                    let mut ls_dns = ls_dns.clone();
                    let resolver = resolver_dns.clone();
                    dns_queries.spawn(async move {
                        match exchange_with_resolver(
                            &resolver, pkt.data,
                            IngressProfile::Udp { advertised_size: 512 },
                            Some(local_addr.ip()),
                        ).await {
                            Ok(resp) => {
                                let _ = ls_dns
                                    .send((resp, remote_addr, local_addr).into())
                                    .await;
                            }
                            Err(e) => {
                                warn!("failed to exchange dns packet: {}", e);
                            }
                        }
                    });
                    // don't forward dns packet to dispatcher
                    continue 'read_packet;
                }

                match d_tx.try_send(pkt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(pkt)) => {
                        if let Err(e) = d_tx.send(pkt).await {
                            warn!("failed to send udp packet to proxy: {}", e);
                            break 'outer;
                        }
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        warn!("dispatcher channel closed, stopping tun -> dispatcher");
                        break 'outer;
                    }
                }
            }
        }

        closer.send(0).ok();
    }));

    debug!("tun UDP ready");

    // If one direction stops, dropping the guards cancels the other and its
    // owned DNS tasks, releasing channels and packet buffers on shutdown.
    tokio::select! {
        result = &mut fut1 => {
            if let Err(error) = result { warn!("TUN UDP reply task failed: {error}"); }
        }
        result = &mut fut2 => {
            if let Err(error) = result { warn!("TUN UDP ingress task failed: {error}"); }
        }
    }
}

pub use crate::proxy::datagram::ChannelDatagram as TunDatagram;
