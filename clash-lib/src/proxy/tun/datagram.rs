use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
        net::DEFAULT_OUTBOUND_INTERFACE,
    },
    // common::errors::new_io_error,
    proxy::datagram::UdpPacket,
    session::{Network, Session, Type},
};
use std::sync::Arc;
use tracing::{debug, trace, warn};

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

    let default_outbound = DEFAULT_OUTBOUND_INTERFACE.read().await;
    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        iface: default_outbound.clone().inspect(|x| {
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
    let fut1 = tokio::spawn(async move {
        let mut reply_batch = Vec::with_capacity(32);
        while l_rx.recv_many(&mut reply_batch, 32).await > 0 {
            for UdpPacket {
                data,
                src_addr,
                dst_addr,
                ..
            } in reply_batch.drain(..)
            {
                let Some(src_sock_addr) = src_addr.try_into_socket_addr() else {
                    warn!("tun drop packet: src_addr is not a valid socket addr");
                    continue;
                };
                let Some(dst_sock_addr) = dst_addr.try_into_socket_addr() else {
                    warn!("tun drop packet: dst_addr is not a valid socket addr");
                    continue;
                };
                if let Err(e) = ls
                    .send(
                        (
                            data,
                            src_sock_addr,
                            dst_sock_addr,
                        )
                            .into(),
                    )
                    .await
                {
                    warn!("failed to send udp packet to netstack: {}", e);
                }
            }
        }
    });

    // tun -> dispatcher
    let fut2 = tokio::spawn(async move {
        let mut batch = Vec::with_capacity(32);
        'outer: loop {
            batch.clear();
            let count = lr.recv_many(&mut batch, 32).await;
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
                    let mut ls_dns = ls_dns.clone();
                    let resolver = resolver_dns.clone();
                    tokio::spawn(async move {
                        match exchange_with_resolver(&resolver, &pkt.data, true).await {
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
    });

    debug!("tun UDP ready");

    let _ = futures::future::join(fut1, fut2).await;
}

pub use crate::proxy::datagram::ChannelDatagram as TunDatagram;
