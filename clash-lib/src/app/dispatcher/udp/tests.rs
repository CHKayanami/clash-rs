use crate::{common::io::datagram_relay::{relay, RelayContext},
    proxy::{AnyOutboundDatagram, OutboundDatagram}};
use tracing::warn;
use crate::app::dns::ClashResolver;
use futures::{Sink, Stream};
use std::{io, task::{Context, Poll}};
use super::*;
use crate::app::dispatcher::udp::association::tests::inert_flow as test_flow;

/// Flush remains pending until the test releases a token, independently of reads.
#[derive(Debug)]
struct BackpressuredDatagram {
    replies: tokio::sync::mpsc::Receiver<UdpPacket>,
    permits: tokio::sync::mpsc::Receiver<()>,
    sent: tokio::sync::mpsc::Sender<UdpPacket>,
    staged: Option<UdpPacket>,
    started: tokio::sync::mpsc::Sender<()>,
    fail_first: bool,
}

impl Stream for BackpressuredDatagram {
    type Item = UdpPacket;
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<UdpPacket>> {
        self.replies.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for BackpressuredDatagram {
    type Error = io::Error;
    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        assert!(
            self.staged.is_none(),
            "send restarted before flush completed"
        );
        Poll::Ready(Ok(()))
    }
    fn start_send(
        mut self: Pin<&mut Self>,
        packet: UdpPacket,
    ) -> Result<(), Self::Error> {
        assert!(self.staged.replace(packet).is_none());
        self.started.try_send(()).unwrap();
        Ok(())
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.staged.is_none() {
            return Poll::Ready(Ok(()));
        }
        futures::ready!(self.permits.poll_recv(cx))
            .expect("permit channel closed");
        let packet = self.staged.take().unwrap();
        if self.fail_first {
            self.fail_first = false;
            return Poll::Ready(Err(io::Error::other(
                "test send failure",
            )));
        }
        self.sent.try_send(packet).unwrap();
        Poll::Ready(Ok(()))
    }
    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

#[tokio::test]
async fn unsplit_relay_reads_during_backpressure_and_retains_sends() {
    check_unsplit_backpressure(false).await;
}

#[tokio::test]
async fn unsplit_relay_continues_after_send_error() {
    check_unsplit_backpressure(true).await;
}

async fn check_unsplit_backpressure(fail_first: bool) {
    let (outgoing_tx, outgoing_rx) = tokio::sync::mpsc::channel(4);
    let (reply_tx, reply_rx) = tokio::sync::mpsc::channel(4);
    let (permit_tx, permit_rx) = tokio::sync::mpsc::channel(4);
    let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(4);
    let (received_tx, mut received_rx) = tokio::sync::mpsc::channel(4);
    let (count_tx, mut count_rx) = tokio::sync::mpsc::channel(4);
    let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(4);
    let destination: SocksAddr =
        "127.0.0.1:12345".parse::<SocketAddr>().unwrap().into();
    let expected_destination = destination.clone();
    for data in [b"first".as_slice(), b"second".as_slice()] {
        outgoing_tx
            .send(UdpPacket {
                data: bytes::Bytes::copy_from_slice(data),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    drop(outgoing_tx);
    let relay = tokio::spawn(async move {
        relay_datagram(
            AnyOutboundDatagram::dynamic(BackpressuredDatagram {
                replies: reply_rx,
                permits: permit_rx,
                sent: sent_tx,
                staged: None,
                started: started_tx,
                fail_first,
            }),
            outgoing_rx,
            &destination,
            |len| count_tx.try_send(len).unwrap(),
            |packet| {
                received_tx.try_send(packet).unwrap();
                true
            },
        )
        .await;
    });
    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .unwrap()
        .unwrap();
    // No flush tokens: replies must still progress, and upload accounting
    // must wait for actual completion rather than start_send.
    reply_tx
        .send(UdpPacket {
            data: bytes::Bytes::from_static(b"reply"),
            ..Default::default()
        })
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), received_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.data.as_ref(), b"reply");
    assert!(count_rx.try_recv().is_err());
    assert!(!relay.is_finished());
    permit_tx.send(()).await.unwrap();
    permit_tx.send(()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    let first = sent_rx.recv().await.unwrap();
    assert_eq!(first.dst_addr, expected_destination);
    if fail_first {
        assert_eq!(first.data.as_ref(), b"second");
        assert_eq!(count_rx.recv().await, Some(6));
    } else {
        assert_eq!(first.data.as_ref(), b"first");
        assert_eq!(sent_rx.recv().await.unwrap().data.as_ref(), b"second");
        assert_eq!(count_rx.recv().await, Some(5));
        assert_eq!(count_rx.recv().await, Some(6));
    }
    assert!(sent_rx.recv().await.is_none());
    assert!(count_rx.recv().await.is_none());
}
use crate::app::dispatcher::StatisticsManager;
use crate::app::dns::MockClashResolver;
use crate::app::outbound::manager::OutboundManager;
use crate::app::router::Router;
use crate::proxy::{OutboundNode, loadbalance, selector};
use crate::proxy::mocks::MockDummyProxyProvider;
use crate::app::remote_content_manager::ProxyManager;
use crate::proxy::direct::Handler as DirectHandler;
use crate::proxy::reject::Handler as RejectHandler;
use crate::session::{Network, Type};
use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use tokio::net::UdpSocket;

#[test]
fn reverse_lookup_rejects_unmapped_fake_ip() {
    let fake_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
    let mut resolver = MockClashResolver::new();
    resolver.expect_fake_ip_enabled().return_const(true);
    resolver
        .expect_is_fake_ip()
        .returning(move |ip| ip == fake_ip);
    resolver.expect_reverse_lookup().return_const(None);
    let resolver: Arc<dyn ClashResolver> = Arc::new(resolver);

    let dst = SocksAddr::Ip(SocketAddr::new(fake_ip, 443));
    assert_eq!(reverse_lookup(&resolver, &dst, false), None);
}

#[tokio::test]
async fn closed_relay_returns_packet_for_reconnect() {
    let flow = test_flow();

    let src = SocksAddr::Ip("127.0.0.1:12345".parse().unwrap());
    let dst = SocksAddr::Domain("example.com".into(), 443);
    let packet =
        UdpPacket::new(Bytes::from_static(b"hello"), src.clone(), dst.clone());

    let returned = forward_to_remote(&flow, packet, 42)
        .expect("closed relay must return the packet");
    assert_eq!(returned.data, Bytes::from_static(b"hello"));
    assert_eq!(returned.src_addr, src);
    assert_eq!(returned.dst_addr, dst);
}

#[tokio::test]
async fn dropping_connecting_session_aborts_establish_task() {
    struct NotifyOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for NotifyOnDrop {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
    let establish_handle = tokio::spawn(async move {
        let _notify = NotifyOnDrop(Some(dropped_tx));
        let _ = started_tx.send(());
        std::future::pending::<()>().await;
    });
    started_rx.await.unwrap();

    let mut delay_queue = DelayQueue::new();
    let delay_key = delay_queue.insert(
        UdpQueueEvent::Connecting(
            (
                "127.0.0.1:12345".parse().unwrap(),
                SocksAddr::Domain("example.com".into(), 443), None,
            ),
            42,
        ),
        CONNECTING_SESSION_TIMEOUT,
    );
    let connecting = ConnectingSession {
        id: 42,
        delay_key,
        packets: Vec::new(),
        establish_handle,
    };

    drop(connecting);
    tokio::time::timeout(Duration::from_secs(1), dropped_rx)
        .await
        .expect("aborted establish task was not dropped")
        .unwrap();
}

#[tokio::test]
async fn active_session_retains_global_capacity_permit_until_drop() {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.clone().acquire_owned().await.unwrap();
    let mut delay_queue = DelayQueue::new();
    let delay_key = delay_queue.insert(
        UdpQueueEvent::SessionIdle((
            "127.0.0.1:12345".parse().unwrap(),
            SocksAddr::Domain("example.com".into(), 443), None,
        )),
        Duration::from_secs(60),
    );

    let session = OutboundSession {
        id: 42,
        dest: SocksAddr::Domain("example.com".into(), 443),
        flow: test_flow(),
        delay_key,
        idle_deadline: Instant::now() + Duration::from_secs(60),
        scheduled_deadline: Instant::now() + Duration::from_secs(60),
        last_upload: Instant::now(),
        reply_activity: Arc::new(ReplyActivity::new()),
        _capacity_permit: permit,
        upload_count: 1,
        is_short_flow: false,
    };

    assert_eq!(semaphore.available_permits(), 0);
    drop(session);
    assert_eq!(semaphore.available_permits(), 1);
}

#[tokio::test]
async fn active_session_defers_timer_reset_until_its_scheduled_deadline() {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.acquire_owned().await.unwrap();
    let mut delay_queue = DelayQueue::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let delay_key = delay_queue.insert_at(
        UdpQueueEvent::SessionIdle((
            "127.0.0.1:12345".parse().unwrap(),
            SocksAddr::Ip("1.1.1.1:53".parse().unwrap()), None,
        )),
        deadline,
    );
    let mut session = OutboundSession {
        id: 42,
        dest: SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
        flow: test_flow(),
        delay_key,
        idle_deadline: deadline,
        scheduled_deadline: deadline,
        last_upload: Instant::now(),
        reply_activity: Arc::new(ReplyActivity::new()),
        _capacity_permit: permit,
        upload_count: 1,
        is_short_flow: true,
    };

    let queued_deadline = delay_queue.deadline(&session.delay_key);
    session.refresh_idle(&mut delay_queue, Duration::from_secs(60));
    assert_eq!(delay_queue.deadline(&session.delay_key), queued_deadline);
    assert!(session.idle_deadline > session.scheduled_deadline);

    session.refresh_idle(&mut delay_queue, Duration::from_secs(1));
    assert!(delay_queue.deadline(&session.delay_key) < queued_deadline);
    assert_eq!(session.idle_deadline, session.scheduled_deadline);
}

#[tokio::test(start_paused = true)]
async fn reply_activity_obeys_latest_direction_and_short_flow_timeout() {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.acquire_owned().await.unwrap();
    let mut delay_queue = DelayQueue::new();
    let now = Instant::now();
    let delay_key = delay_queue.insert_at(
        UdpQueueEvent::SessionIdle((
            "127.0.0.1:12345".parse().unwrap(),
            SocksAddr::Ip("1.1.1.1:53".parse().unwrap()), None,
        )),
        now + FAST_RESPONSE_TIMEOUT,
    );
    let mut session = OutboundSession {
        id: 42,
        dest: SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
        flow: test_flow(),
        delay_key,
        idle_deadline: now + SHORT_FLOW_INIT_TIMEOUT,
        scheduled_deadline: now + FAST_RESPONSE_TIMEOUT,
        last_upload: now,
        reply_activity: Arc::new(ReplyActivity::new()),
        _capacity_permit: permit,
        upload_count: 1,
        is_short_flow: true,
    };
    let timeout = Duration::from_secs(60);
    assert_eq!(session.latest_idle_deadline(timeout), now + SHORT_FLOW_INIT_TIMEOUT);

    tokio::time::advance(Duration::from_secs(1)).await;
    session.reply_activity.record();
    assert_eq!(session.latest_idle_deadline(timeout), Instant::now() + FAST_RESPONSE_TIMEOUT);

    tokio::time::advance(Duration::from_secs(1)).await;
    session.refresh_idle(&mut delay_queue, SHORT_FLOW_INIT_TIMEOUT);
    assert_eq!(session.latest_idle_deadline(timeout), Instant::now() + SHORT_FLOW_INIT_TIMEOUT);

    // Once uploads promote the flow, later replies use the normal timeout.
    session.is_short_flow = false;
    tokio::time::advance(Duration::from_secs(1)).await;
    session.reply_activity.record();
    assert_eq!(session.latest_idle_deadline(timeout), Instant::now() + timeout);
}

#[test]
fn test_short_flow_ports() {
    assert!(is_short_flow_port(53));
    assert!(is_short_flow_port(123));
    assert!(is_short_flow_port(5353));
    assert!(!is_short_flow_port(3478));
    assert!(!is_short_flow_port(5349));
    assert!(!is_short_flow_port(443));
    assert!(!is_short_flow_port(80));
}

#[derive(Debug)]
struct MockInboundDatagram {
    rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    tx: tokio::sync::mpsc::Sender<UdpPacket>,
}

impl futures::Stream for MockInboundDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl futures::Sink<UdpPacket> for MockInboundDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.tx
            .try_send(item)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

fn test_provider(handler: OutboundNode) -> Arc<MockDummyProxyProvider> {
    let mut provider = MockDummyProxyProvider::new();
    let proxies = Arc::new(vec![handler]);
    provider.expect_proxies().returning(move || proxies.clone());
    provider.expect_touch().return_const(());
    Arc::new(provider)
}

#[tokio::test]
async fn selector_reject_is_detected_before_connecting() {
    let reject = OutboundNode::protocol(Arc::new(RejectHandler::new("REJECT")));
    let selector = OutboundNode::group(Arc::new(selector::Handler::new(
        selector::HandlerOptions { name: "reject-group".into(), ..Default::default() },
        vec![test_provider(reject.clone())],
        None,
    ).await));
    assert_eq!(selector.proto(), OutboundType::Selector);
    assert_eq!(effective_outbound_type(&selector).await, OutboundType::Reject);
    assert_eq!(effective_outbound_type(&reject).await, OutboundType::Reject);
}

async fn test_dispatcher(proto: OutboundType) -> Arc<Dispatcher> {
    let direct_handler: OutboundNode =
        OutboundNode::protocol(Arc::new(DirectHandler::new("DIRECT")));
    test_dispatcher_with_leaf(proto, direct_handler).await
}

async fn test_dispatcher_with_leaf(
    proto: OutboundType,
    direct_handler: OutboundNode,
) -> Arc<Dispatcher> {
    let mut mock_resolver = MockClashResolver::new();
    mock_resolver.expect_fake_ip_enabled().returning(|| false);
    mock_resolver.expect_is_fake_ip().returning(|_| false);
    mock_resolver.expect_cached_for().returning(|_| None);
    mock_resolver
        .expect_resolve_v4()
        .returning(|_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
    mock_resolver.expect_resolve().returning(|_, _| {
        Ok(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
    });
    let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

    let handler = match proto {
        OutboundType::Selector => {
            let inner = selector::Handler::new(
                selector::HandlerOptions {
                    name: "inner".into(),
                    udp: true,
                    ..Default::default()
                },
                vec![test_provider(direct_handler)],
                None,
            ).await;
            OutboundNode::group(Arc::new(selector::Handler::new(
                selector::HandlerOptions {
                    name: "outer".into(),
                    udp: true,
                    ..Default::default()
                },
                vec![test_provider(OutboundNode::group(Arc::new(inner)))],
                None,
            ).await))
        }
        OutboundType::LoadBalance => OutboundNode::group(Arc::new(loadbalance::Handler::new(
            loadbalance::HandlerOptions {
                name: "balance".into(),
                udp: true,
                ..Default::default()
            },
            vec![test_provider(direct_handler)],
            ProxyManager::new(resolver.clone(), None),
        ))),
        OutboundType::Direct => direct_handler,
        _ => unreachable!(),
    };
    let mut handlers = HashMap::new();
    handlers.insert("DIRECT".to_string(), handler);
    let outbound_manager = Arc::new(OutboundManager::new_for_test(handlers));

    let router = Arc::new(
        Router::new(
            vec![],
            HashMap::new(),
            resolver.clone(),
            None,
            None,
            None,
            None,
            None,
            "".to_string(),
        )
        .await
        .unwrap(),
    );

    let manager = StatisticsManager::new();
    Arc::new(Dispatcher::new(
        outbound_manager,
        router,
        resolver,
        RunMode::Direct,
        manager,
        None,
        None,
        true,
    ))
}

#[tokio::test]
async fn inbound_backpressure_does_not_block_upstream_or_close() {
    check_inbound_backpressure(true).await;
}

#[tokio::test]
async fn inbound_backpressure_does_not_block_expiration() {
    check_inbound_backpressure(false).await;
}

#[tokio::test]
async fn downstream_only_activity_keeps_session_alive_until_idle() {
    let dispatcher = test_dispatcher(OutboundType::Direct).await;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = SocksAddr::Ip(server.local_addr().unwrap());
    let source: SocketAddr = "127.0.0.1:54324".parse().unwrap();
    let sess = Session {
        network: Network::Udp,
        source,
        destination: destination.clone(),
        udp_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };
    let (client_tx, inbound_rx) = tokio::sync::mpsc::channel(4);
    let (inbound_tx, mut client_rx) = tokio::sync::mpsc::channel(4);
    let _closer = dispatcher.dispatch_datagram(sess, Box::new(
        MockInboundDatagram { rx: inbound_rx, tx: inbound_tx },
    )).await;
    client_tx.send(UdpPacket::new(
        Bytes::from_static(b"request"), SocksAddr::Ip(source), destination,
    )).await.unwrap();
    let mut buf = [0u8; 64];
    let (_, outbound_addr) = tokio::time::timeout(
        Duration::from_secs(2), server.recv_from(&mut buf),
    ).await.unwrap().unwrap();
    let session_id = dispatcher.manager.active_connections_snapshot()[0].id;

    // Cross the initial idle deadline without any additional upstream packet.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        server.send_to(b"reply", outbound_addr).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
            .await.unwrap().unwrap();
        assert_eq!(reply.data.as_ref(), b"reply");
        assert_eq!(dispatcher.manager.active_connections_snapshot()[0].id, session_id);
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while dispatcher.udp_session_semaphore.available_permits()
            != MAX_GLOBAL_UDP_SESSIONS
            || !dispatcher.manager.active_connections_snapshot().is_empty()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("downstream activity must expire after replies stop");
}

async fn check_inbound_backpressure(explicit_close: bool) {
    let dispatcher = test_dispatcher(OutboundType::Direct).await;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = SocksAddr::Ip(server.local_addr().unwrap());
    let source: SocketAddr = "127.0.0.1:54323".parse().unwrap();
    let sess = Session {
        network: Network::Udp,
        source,
        destination: destination.clone(),
        udp_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };
    let (client_tx, client_rx) = tokio::sync::mpsc::channel(4);
    let (_permit_tx, permit_rx) = tokio::sync::mpsc::channel(4);
    let (sent_tx, _sent_rx) = tokio::sync::mpsc::channel(4);
    let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(4);
    let closer = dispatcher.dispatch_datagram(sess, Box::new(
        BackpressuredDatagram {
            replies: client_rx,
            permits: permit_rx,
            sent: sent_tx,
            staged: None,
            started: started_tx,
            fail_first: false,
        },
    )).await;
    let packet = UdpPacket::new(
        Bytes::from_static(b"request"),
        SocksAddr::Ip(source),
        destination,
    );
    client_tx.send(packet.clone()).await.unwrap();
    let mut buf = [0u8; 64];
    let (_, outbound_addr) = tokio::time::timeout(
        Duration::from_secs(2), server.recv_from(&mut buf),
    ).await.unwrap().unwrap();
    server.send_to(b"reply", outbound_addr).await.unwrap();
    // The inbound sink has accepted the reply, but its flush is blocked.
    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await.unwrap().unwrap();

    client_tx.send(packet).await.unwrap();
    let (len, _) = tokio::time::timeout(
        Duration::from_secs(2), server.recv_from(&mut buf),
    ).await.unwrap().unwrap();
    assert_eq!(&buf[..len], b"request");
    if explicit_close {
        closer.send(0).unwrap();
        tokio::time::timeout(Duration::from_secs(2), client_tx.closed())
            .await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while dispatcher.udp_session_semaphore.available_permits()
            != MAX_GLOBAL_UDP_SESSIONS
            || !dispatcher.manager.active_connections_snapshot().is_empty()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("blocked inbound must not retain expired or closed sessions");
}

#[tokio::test]
async fn test_dispatcher_full_cone_relay_preserves_peer_source_address_end_to_end() {
    check_full_cone_relay(OutboundType::Direct).await;
}

#[tokio::test]
async fn proxy_shared_association_keeps_flow_fast_path_and_group_selection() {
    use crate::app::dispatcher::udp::association::tests::{outbound, request, reply};

    for proto in [OutboundType::Direct, OutboundType::Selector, OutboundType::LoadBalance] {
        let (leaf, connects, mut servers) = outbound();
        let dispatcher = test_dispatcher_with_leaf(proto, OutboundNode::Protocol(leaf)).await;
        let source: SocketAddr = "127.0.0.1:54328".parse().unwrap();
        let a: SocksAddr = "127.0.0.1:30001".parse::<SocketAddr>().unwrap().into();
        let b: SocksAddr = "127.0.0.1:30002".parse::<SocketAddr>().unwrap().into();
        let sess = Session {
            network: Network::Udp, typ: Type::Socks5,
            source, destination: a.clone(), ..Default::default()
        };
        let (client_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
        let (inbound_tx, mut client_rx) = tokio::sync::mpsc::channel(16);
        let _close = dispatcher.dispatch_datagram(sess, Box::new(MockInboundDatagram {
            rx: inbound_rx, tx: inbound_tx,
        })).await;
        client_tx.send(UdpPacket::new(Bytes::from_static(b"a"), source.into(), a.clone()))
            .await.unwrap();
        let mut server = tokio::time::timeout(Duration::from_secs(2), servers.recv())
            .await.unwrap().unwrap();
        assert_eq!(request(&mut server).await.dst_addr, a);
        client_tx.send(UdpPacket::new(Bytes::from_static(b"b"), source.into(), b.clone()))
            .await.unwrap();
        assert_eq!(request(&mut server).await.dst_addr, b);
        // Revisit A after B attaches: a shared relay must not pin sends to B.
        client_tx.send(UdpPacket::new(Bytes::from_static(b"a-again"), source.into(), a.clone()))
            .await.unwrap();
        assert_eq!(request(&mut server).await.dst_addr, a);
        assert_eq!(connects.load(Ordering::Relaxed), 1);
        let peer: SocksAddr = "127.0.0.2:31000".parse::<SocketAddr>().unwrap().into();
        for remote in [&b, &a, &peer] {
            reply(&mut server, remote, b"reply").await;
            let packet = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
                .await.unwrap().unwrap();
            assert_eq!(&packet.src_addr, remote);
            assert_eq!(packet.dst_addr, SocksAddr::Ip(source));
        }
    }
}

#[tokio::test]
async fn nested_selector_direct_preserves_peer_source() {
    check_full_cone_relay(OutboundType::Selector).await;
}

#[tokio::test]
async fn loadbalance_direct_preserves_peer_source() {
    check_full_cone_relay(OutboundType::LoadBalance).await;
}

async fn check_full_cone_relay(proto: OutboundType) {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer_socket.local_addr().unwrap();

    let dispatcher = test_dispatcher(proto).await;

    let client_src: SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let sess = Session {
        network: Network::Udp,
        typ: Type::Socks5,
        source: client_src,
        destination: SocksAddr::Ip(server_addr),
        ..Default::default()
    };

    let (client_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
    let (inbound_tx, mut client_rx) = tokio::sync::mpsc::channel(16);

    let inbound = Box::new(MockInboundDatagram {
        rx: inbound_rx,
        tx: inbound_tx,
    });

    let _close_tx = dispatcher.dispatch_datagram(sess, inbound).await;

    // 1. Client sends UDP to Server via Dispatcher
    client_tx
        .send(UdpPacket {
            data: Bytes::from_static(b"hello-server"),
            src_addr: SocksAddr::Ip(client_src),
            dst_addr: SocksAddr::Ip(server_addr),
            ..Default::default()
        })
        .await
        .unwrap();

    // 2. Server receives packet from Direct Outbound socket
    let mut buf = [0u8; 1024];
    let (n, direct_outbound_addr) =
        tokio::time::timeout(
            Duration::from_secs(2), server_socket.recv_from(&mut buf),
        ).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"hello-server");

    // 3. A third-party peer sends an unsolicited hole-punching UDP packet to Direct Outbound
    peer_socket
        .send_to(b"peer-hole-punch", direct_outbound_addr)
        .await
        .unwrap();

    // 4. Client receives packet from Dispatcher
    let peer_reply =
        tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
            .await
            .expect("timeout waiting for peer reply")
            .expect("channel closed");

    assert_eq!(peer_reply.data.as_ref(), b"peer-hole-punch");
    // CRITICAL: Full-Cone unsolicited peer packet's source address MUST be preserved
    // as the actual physical address of the peer, NOT rewritten to server_addr!
    assert_eq!(peer_reply.src_addr, SocksAddr::Ip(peer_addr));
    assert_eq!(peer_reply.dst_addr, SocksAddr::Ip(client_src));

    // 5. Server also replies normally
    server_socket
        .send_to(b"server-reply", direct_outbound_addr)
        .await
        .unwrap();

    let server_reply =
        tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
            .await
            .expect("timeout waiting for server reply")
            .expect("channel closed");

    assert_eq!(server_reply.data.as_ref(), b"server-reply");
    // Normal reply from server should have source matching server_addr
    assert_eq!(server_reply.src_addr, SocksAddr::Ip(server_addr));
    assert_eq!(server_reply.dst_addr, SocksAddr::Ip(client_src));
}

#[tokio::test]
async fn test_dispatcher_fake_ip_relay_restores_fake_ip_source_address() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let fake_ip = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 5)),
        server_addr.port(),
    );

    let direct_handler: OutboundNode =
        OutboundNode::protocol(Arc::new(DirectHandler::new("DIRECT")));
    let mut mock_resolver = MockClashResolver::new();
    mock_resolver.expect_fake_ip_enabled().returning(|| true);
    mock_resolver.expect_is_fake_ip().returning(|ip| {
        ip == std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 5))
    });
    mock_resolver
        .expect_reverse_lookup()
        .returning(|_| Some("fake.domain.com".to_string()));
    mock_resolver.expect_cached_for().returning(|_| None);
    mock_resolver
        .expect_resolve_v4()
        .returning(move |_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
    mock_resolver.expect_resolve().returning(move |_, _| {
        Ok(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
    });
    let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

    let mut handlers = HashMap::new();
    handlers.insert("DIRECT".to_string(), direct_handler);
    let outbound_manager = Arc::new(OutboundManager::new_for_test(handlers));

    let router = Arc::new(
        Router::new(
            vec![],
            HashMap::new(),
            resolver.clone(),
            None,
            None,
            None,
            None,
            None,
            "".to_string(),
        )
        .await
        .unwrap(),
    );

    let manager = StatisticsManager::new();
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager,
        router,
        resolver,
        RunMode::Direct,
        manager,
        None,
        None,
        true,
    ));

    let client_src: SocketAddr = "127.0.0.1:54322".parse().unwrap();
    let sess = Session {
        network: Network::Udp,
        typ: Type::Socks5,
        source: client_src,
        destination: SocksAddr::Ip(fake_ip),
        ..Default::default()
    };

    let (client_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
    let (inbound_tx, mut client_rx) = tokio::sync::mpsc::channel(16);

    let inbound = Box::new(MockInboundDatagram {
        rx: inbound_rx,
        tx: inbound_tx,
    });

    let _close_tx = dispatcher.dispatch_datagram(sess, inbound).await;

    // 1. Client sends UDP to Fake-IP via Dispatcher
    client_tx
        .send(UdpPacket {
            data: Bytes::from_static(b"hello-fake-ip"),
            src_addr: SocksAddr::Ip(client_src),
            dst_addr: SocksAddr::Ip(fake_ip),
            ..Default::default()
        })
        .await
        .unwrap();

    // 2. Server receives packet from Direct Outbound socket
    let mut buf = [0u8; 1024];
    let (n, direct_outbound_addr) =
        server_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello-fake-ip");

    // 3. Server replies back with its physical server_addr
    server_socket
        .send_to(b"reply-from-real-server", direct_outbound_addr)
        .await
        .unwrap();

    // 4. Client receives reply, source address MUST be restored to fake_ip, NOT server_addr!
    let reply = tokio::time::timeout(Duration::from_secs(2), client_rx.recv())
        .await
        .expect("timeout waiting for server reply")
        .expect("channel closed");

    assert_eq!(reply.data.as_ref(), b"reply-from-real-server");
    assert_eq!(reply.src_addr, SocksAddr::Ip(fake_ip));
    assert_eq!(reply.dst_addr, SocksAddr::Ip(client_src));
}
#[tokio::test]
async fn wide_inbound_shards_keep_client_sockets_and_replies_separate() {
    let dispatcher = test_dispatcher(OutboundType::Direct).await;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination: SocksAddr = server.local_addr().unwrap().into();
    let (client_tx, incoming) = tokio::sync::mpsc::channel(16);
    let (replies, mut client_rx) = tokio::sync::mpsc::channel(16);
    let _close = dispatcher.dispatch_datagram(Session { network: Network::Udp,
        ..Session::default() }, Box::new(MockInboundDatagram { rx: incoming, tx: replies })).await;
    let mut sockets = Vec::new();
    for port in 23456..23460 {
        let source: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
        client_tx.send(UdpPacket::new(Bytes::from_static(b"request"), source.into(), destination.clone())).await.unwrap();
        let mut buf = [0; 32];
        let (_, socket) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await.unwrap().unwrap();
        assert!(!sockets.contains(&socket)); sockets.push(socket);
        server.send_to(b"reply", socket).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(2), client_rx.recv()).await.unwrap().unwrap();
        assert_eq!(packet.dst_addr, SocksAddr::Ip(source));
    }
}

#[tokio::test]
async fn flow_cache_and_replies_preserve_user_identity() {
    use crate::app::dispatcher::udp::association::tests::{outbound, request, reply};
    let (leaf, count, mut servers) = outbound();
    let dispatcher = test_dispatcher_with_leaf(OutboundType::Direct, OutboundNode::Protocol(leaf)).await;
    let source: SocketAddr = "127.0.0.1:23456".parse().unwrap();
    let destination: SocksAddr = "127.0.0.1:30001".parse::<SocketAddr>().unwrap().into();
    let (client_tx, incoming) = tokio::sync::mpsc::channel(16);
    let (replies, mut client_rx) = tokio::sync::mpsc::channel(16);
    let _close = dispatcher.dispatch_datagram(Session { network: Network::Udp,
        source, ..Session::default() }, Box::new(MockInboundDatagram { rx: incoming, tx: replies })).await;
    let mut live_servers = Vec::new();
    for user in ["user-a", "user-b"] {
        let mut packet = UdpPacket::new(Bytes::from_static(b"request"), source.into(), destination.clone());
        packet.inbound_user = Some(Arc::from(user));
        client_tx.send(packet).await.unwrap();
        let mut server = tokio::time::timeout(Duration::from_secs(2), servers.recv()).await.unwrap().unwrap();
        request(&mut server).await;
        reply(&mut server, &destination, b"reply").await;
        let packet = tokio::time::timeout(Duration::from_secs(2), client_rx.recv()).await.unwrap().unwrap();
        assert_eq!(packet.inbound_user.as_deref(), Some(user));
        live_servers.push(server);
    }
    assert_eq!(count.load(Ordering::Relaxed), 2);
}

async fn relay_datagram<D, W, R>(
    datagram: D,
    outgoing: tokio::sync::mpsc::Receiver<UdpPacket>,
    destination: &SocksAddr,
    on_sent: W,
    on_received: R,
) where
    D: OutboundDatagram<UdpPacket>,
    W: FnMut(usize),
    R: FnMut(UdpPacket) -> bool,
{
    struct FlowRelay<'a, W, R> {
        outgoing: tokio::sync::mpsc::Receiver<UdpPacket>,
        destination: &'a SocksAddr,
        on_sent: W,
        on_received: R,
    }

    impl<W: FnMut(usize), R: FnMut(UdpPacket) -> bool> RelayContext
        for FlowRelay<'_, W, R>
    {
        fn poll_outgoing(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Option<UdpPacket>> {
            self.outgoing.poll_recv(cx).map(|packet| packet.map(|mut packet| {
                if packet.dst_addr != *self.destination {
                    packet.dst_addr = self.destination.clone();
                }
                packet
            }))
        }

        fn sent(&mut self, result: io::Result<usize>) -> bool {
            match result {
                Ok(len) => (self.on_sent)(len),
                Err(err) => warn!("failed to send packet to remote: {err:?}"),
            }
            true
        }

        fn received(&mut self, packet: UdpPacket) -> bool {
            (self.on_received)(packet)
        }
    }

    relay(datagram, FlowRelay { outgoing, destination, on_sent, on_received }).await;
}


#[tokio::test]
async fn connected_packet_batches_do_not_starve_expiration_or_close() {
    check_busy_route_control(false).await;
}

#[tokio::test]
async fn sharded_packet_batches_do_not_starve_expiration_or_close() {
    check_busy_route_control(true).await;
}

async fn check_busy_route_control(wide: bool) {
    let dispatcher = test_dispatcher(OutboundType::Direct).await;
    let idle_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let busy_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let idle_destination: SocksAddr = idle_server.local_addr().unwrap().into();
    let busy_destination: SocksAddr = busy_server.local_addr().unwrap().into();
    let source: SocketAddr = "127.0.0.1:54330".parse().unwrap();
    let (client_tx, incoming) = tokio::sync::mpsc::channel(64);
    let (replies, _client_rx) = tokio::sync::mpsc::channel(64);
    let close = dispatcher.dispatch_datagram(Session {
        network: Network::Udp, source: if wide { SocketAddr::from(([0, 0, 0, 0], 0)) } else { source },
        udp_timeout: Some(Duration::from_millis(100)), ..Session::default()
    }, Box::new(MockInboundDatagram { rx: incoming, tx: replies })).await;
    client_tx.send(UdpPacket::new(Bytes::from_static(b"idle"), source.into(), idle_destination)).await.unwrap();
    let mut buf = [0; 32];
    tokio::time::timeout(Duration::from_secs(2), idle_server.recv_from(&mut buf)).await.unwrap().unwrap();
    let idle_id = dispatcher.manager.active_connections_snapshot()[0].id;
    let busy_packet = UdpPacket::new(Bytes::from_static(b"busy"), source.into(), busy_destination);
    client_tx.send(busy_packet.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), busy_server.recv_from(&mut buf)).await.unwrap().unwrap();
    let busy_id = dispatcher.manager.active_connections_snapshot().iter().find(|flow| flow.id != idle_id).unwrap().id;
    let _drain = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut buf = [0; 32];
        while busy_server.recv_from(&mut buf).await.is_ok() {}
    }));
    let producer = AbortOnDropHandle::new(tokio::spawn(async move {
        while client_tx.send(busy_packet.clone()).await.is_ok() {}
    }));
    tokio::time::timeout(Duration::from_secs(2), async {
        while dispatcher.manager.active_connections_snapshot().iter().any(|flow| flow.id == idle_id) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await.expect("idle flow must expire while another flow keeps the input busy");
    dispatcher.manager.close(busy_id);
    tokio::time::timeout(Duration::from_secs(2), async {
        while dispatcher.manager.active_connections_snapshot().iter().any(|flow| flow.id == busy_id) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await.expect("manager closure must be processed during sustained input");
    close.send(0).unwrap();
    tokio::time::timeout(Duration::from_secs(2), producer).await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while dispatcher.manager.traffic_summary().4 != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await.unwrap();
}
