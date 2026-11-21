use std::{future::Future, io, net::SocketAddr, sync::Arc};

use tokio::{net::UdpSocket, pin, time::{Instant, MissedTickBehavior, interval_at}};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info_span, warn};

use super::{Dispatcher, ReplyTarget, RouteShards, UdpQueueLimits, shards::UdpRouteIngress};
use crate::{proxy::utils::transparent_reply::{ReplySockets, SWEEP_INTERVAL}, session::Session};

const TRANSPARENT_QUEUE_LIMITS: UdpQueueLimits = UdpQueueLimits {
    per_route_shard: 256,
    warn_on_drop: true,
};

impl Dispatcher {
    pub(crate) async fn dispatch_transparent_udp<F, Fut>(
        &self,
        sess: Session,
        receive: F,
        create_reply_socket: impl Fn(SocketAddr) -> io::Result<UdpSocket> + Send + Sync + 'static,
    ) where
        F: FnOnce(UdpRouteIngress) -> Fut + Send,
        Fut: Future<Output = ()> + Send,
    {
        let span = info_span!("dispatch_datagram", trace_id = sess.id, inbound = ?sess.typ);
        async move {
            let sockets = Arc::new(ReplySockets::new(create_reply_socket));
            let closed = CancellationToken::new();
            let _close_workers = closed.clone().drop_guard();
            let replies = ReplyTarget::Transparent { sockets: sockets.clone(), closed };
            let (ctx, mut closed_flows) = self.udp_dispatch_context(
                &sess, replies, #[cfg(feature = "tun")] None,
            );
            let shards = RouteShards::spawn(
                sess, ctx, self.sniffer.clone(), self.allow_quic.clone(),
                TRANSPARENT_QUEUE_LIMITS,
            );
            let mut sweep = interval_at(Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
            sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let receive = receive(shards.ingress.clone());
            pin!(receive);
            loop {
                tokio::select! {
                    _ = &mut receive => {
                        warn!("transparent UDP receive loop ended");
                        break;
                    }
                    flow = closed_flows.recv() => match flow {
                        Some(flow) => shards.flow_closed(flow),
                        None => {
                            warn!("transparent UDP flow notifications closed");
                            break;
                        }
                    },
                    _ = sweep.tick() => sockets.sweep(),
                }
            }
        }.instrument(span).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use bytes::Bytes;
    use parking_lot::Mutex;
    use tokio::{spawn, sync::oneshot, task::id, time::{sleep, timeout}};

    use crate::{
        app::dispatcher::udp::tests::test_dispatcher,
        proxy::{OutboundType, datagram::UdpPacket},
        session::Network,
    };

    #[tokio::test]
    async fn transparent_udp_shared_association_replies_directly_for_both_targets() {
        let dispatcher = test_dispatcher(OutboundType::Direct).await;
        let servers = [
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        ];
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reply_sockets = [
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        ];
        let source = client.local_addr().unwrap();
        let destinations = servers.each_ref().map(|server| server.local_addr().unwrap());
        let reply_addresses = reply_sockets.each_ref().map(|socket| socket.local_addr().unwrap());
        let (stop, stopped) = oneshot::channel();
        let worker = spawn({
            let dispatcher = dispatcher.clone();
            let reply_sockets = Mutex::new(reply_sockets.map(Some));
            async move {
                let receive_task = id();
                dispatcher.dispatch_transparent_udp(
                    Session { network: Network::Udp, ..Session::default() },
                    move |ingress| async move {
                        assert!(ingress.send_batch(destinations.map(|destination| UdpPacket::new(
                            Bytes::from_static(b"request"), source.into(), destination.into(),
                        ))));
                        let _ = stopped.await;
                    },
                    move |reply_source| {
                        assert_ne!(id(), receive_task);
                        let index = destinations.iter().position(|addr| *addr == reply_source).unwrap();
                        Ok(reply_sockets.lock()[index].take().unwrap())
                    },
                ).await;
            }
        });

        timeout(Duration::from_secs(2), async {
            let mut buffer = [0; 32];
            let (len, outbound) = servers[0].recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..len], b"request");
            let (len, other_outbound) = servers[1].recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..len], b"request");
            assert_eq!(outbound, other_outbound, "both targets share the outbound association");
            for (index, (server, reply_addr)) in servers.iter().zip(reply_addresses).enumerate() {
                let reply = [index as u8];
                server.send_to(&reply, outbound).await.unwrap();
                let (len, from) = client.recv_from(&mut buffer).await.unwrap();
                assert_eq!((&buffer[..len], from), (&reply[..], reply_addr));
            }
            stop.send(()).unwrap();
            worker.await.unwrap();
            while !dispatcher.manager.active_connections_snapshot().is_empty() {
                sleep(Duration::from_millis(1)).await;
            }
        }).await.unwrap();
    }
}
