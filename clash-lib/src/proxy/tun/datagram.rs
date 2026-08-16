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
) {
    // tun i/o
    // lr: app packets went into tun will be accessed from lr
    // ls: packet written into ls will go back to app from tun
    let (mut lr, mut ls) = socket.split();
    let mut ls_dns = ls.clone(); // for dns hijack
    let resolver_dns = resolver.clone(); // for dns hijack

    // dispatcher <-> tun communications
    // l_tx: dispatcher write packet responded from remote proxy
    // l_rx: in fut1 items are forwarded to ls
    let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(512);

    // forward packets from tun to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(512);

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
        ..Default::default()
    };

    let closer = dispatcher
        .dispatch_datagram(sess, Box::new(udp_stream))
        .await;

    // dispatcher -> tun
    let fut1 = tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            trace!("tun <- dispatcher: {:?}", pkt);
            let Some(src_addr) = pkt.src_addr.clone().try_into_socket_addr() else {
                warn!("tun drop packet: src_addr is not a valid socket addr: {:?}", pkt.src_addr);
                continue;
            };
            let Some(dst_addr) = pkt.dst_addr.clone().try_into_socket_addr() else {
                warn!("tun drop packet: dst_addr is not a valid socket addr: {:?}", pkt.dst_addr);
                continue;
            };
            if let Err(e) = ls
                .send(
                    (
                        pkt.data,
                        src_addr,
                        dst_addr,
                    )
                        .into(),
                )
                .await
            {
                warn!("failed to send udp packet to netstack: {}", e);
            }
        }
    });

    // tun -> dispatcher
    let fut2 = tokio::spawn(async move {
        'read_packet: while let Some(watfaq_netstack::UdpPacket {
            data,
            local_addr,
            remote_addr,
        }) = lr.recv().await
        {
            if remote_addr.ip().is_multicast() {
                continue;
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

                match hickory_proto::op::Message::from_vec(&pkt.data) {
                    Ok(msg) => {
                        let mut send_response =
                            async |msg: hickory_proto::op::Message,
                                   pkt: &UdpPacket| {
                                match msg.to_vec() {
                                    Ok(data) => {
                                        let Some(dst_addr) = pkt.dst_addr.clone().try_into_socket_addr() else {
                                            warn!("dns hijack drop: dst_addr is not a valid socket addr");
                                            return;
                                        };
                                        let Some(src_addr) = pkt.src_addr.clone().try_into_socket_addr() else {
                                            warn!("dns hijack drop: src_addr is not a valid socket addr");
                                            return;
                                        };
                                        if let Err(e) = ls_dns
                                            .send(
                                                (
                                                    data,
                                                    dst_addr,
                                                    src_addr,
                                                )
                                                    .into(),
                                            )
                                            .await
                                        {
                                            warn!(
                                                "failed to send udp packet to \
                                                 netstack: {}",
                                                e
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "failed to serialize dns response: {}",
                                            e
                                        );
                                    }
                                }
                            };

                        trace!("hijack dns request: {:?}", msg);

                        let mut resp =
                            match exchange_with_resolver(&resolver_dns, &msg, true)
                                .await
                            {
                                Ok(resp) => resp,
                                Err(e) => {
                                    warn!("failed to exchange dns message: {}", e);
                                    continue 'read_packet;
                                }
                            };

                        // TODO: figure out where the message id got lost
                        resp.metadata.id = msg.metadata.id;
                        trace!("hijack dns response: {:?}", resp);

                        send_response(resp, &pkt).await;
                    }
                    Err(e) => {
                        warn!(
                            "failed to parse dns packet: {}, putting it back to \
                             stack",
                            e
                        );
                    }
                };

                // don't forward dns packet to dispatcher
                continue 'read_packet;
            }

            match d_tx.send(pkt).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("failed to send udp packet to proxy: {}", e);
                }
            }
        }

        closer.send(0).ok();
    });

    debug!("tun UDP ready");

    let _ = futures::future::join(fut1, fut2).await;
}

pub use crate::proxy::datagram::ChannelDatagram as TunDatagram;
