use super::*;
use bytes::{BufMut, Bytes, BytesMut};
use futures::StreamExt;
use std::{net::IpAddr, sync::atomic::{AtomicUsize, Ordering}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex}, time::timeout};
use crate::{
    app::dns::MockClashResolver,
    proxy::{AnyStream, OutboundType, mocks::MockDummyOutboundHandler, trojan::OutboundDatagramTrojan,
        transport::uot::OutboundDatagramUotV2},
    session::Network,
};

mod regressions;

fn resolver() -> ThreadSafeDNSResolver {
    let mut dns = MockClashResolver::new();
    dns.expect_is_fake_ip().returning(|_| false);
    Arc::new(dns)
}
fn session(port: u16) -> Session {
    Session { network: Network::Udp, typ: Type::Socks5,
        source: "127.0.0.1:23456".parse().unwrap(),
        destination: SocketAddr::from(([127, 0, 0, 1], port)).into(), ..Session::default() }
}

struct Fixture {
    pool: Arc<UdpAssociationPool>,
    replies: mpsc::Receiver<UdpPacket>,
    events: mpsc::UnboundedReceiver<FlowClosed>,
    manager: Arc<Manager>,
}
impl Fixture {
    fn new(timeout: Duration) -> Self {
        let (replies, rx) = mpsc::channel(64);
        let (closed_flows, events) = mpsc::unbounded_channel();
        let manager = Manager::new();
        let pool = UdpAssociationPool::new(AssociationConfig {
            replies, closed_flows, manager: manager.clone(), allow_quic: Arc::new(AtomicBool::new(true)),
            timeout, capacity: Arc::new(Semaphore::new(64)),
        });
        Self { pool, replies: rx, events, manager }
    }
    async fn connect(&self, outbound: &ProtocolOutbound, sess: &Session) -> UdpFlow {
        self.pool.connect(outbound, sess, resolver(), Arc::new(TrackerInfo::new(sess, None))).await.unwrap()
    }
    async fn receive(&mut self) -> UdpPacket {
        timeout(Duration::from_secs(2), self.replies.recv()).await.unwrap().unwrap()
    }
}
fn send(flow: &UdpFlow, data: &'static [u8]) {
    flow.try_send(UdpPacket::new(Bytes::from_static(data), SocksAddr::any_ipv4(), SocksAddr::any_ipv4())).unwrap();
}
fn slot_count(pool: &UdpAssociationPool) -> usize {
    pool.slots.iter().map(|shard| shard.lock().len()).sum()
}

/// A closed lease for dispatcher timer and reconnect tests; no physical I/O.
pub(crate) fn inert_flow() -> UdpFlow {
    let sess = session(30001);
    let manager = Manager::new();
    let (events, _) = mpsc::unbounded_channel();
    let (outgoing, _) = mpsc::channel(1);
    let (control, _) = mpsc::channel(1);
    UdpFlow {
        state: Arc::new(FlowState { id: sess.id, source: sess.source, target: sess.destination.clone(),
            original: sess.destination.clone(), aliases: vec![], tracker: Arc::new(TrackerInfo::new(&sess, None)),
            activity: Arc::new(ReplyActivity::new()), closed: AtomicBool::new(false), events,
            _guard: TrackGuard::new(sess.id, manager), }),
        association: Arc::new(Association { id: 0, outgoing, control, chain: vec![], task: tokio::spawn(std::future::pending()) }),
    }
}

pub(crate) fn outbound() -> (ProtocolOutbound, Arc<AtomicUsize>, mpsc::Receiver<DuplexStream>) {
    let (tx, rx) = mpsc::channel(16);
    let count = Arc::new(AtomicUsize::new(0));
    let connects = count.clone();
    let mut handler = MockDummyOutboundHandler::new();
    handler.expect_name().return_const("test-proxy".to_owned());
    handler.expect_proto().return_const(OutboundType::Trojan);
    handler.expect_connect_datagram().returning(move |sess, _| {
        connects.fetch_add(1, Ordering::Relaxed);
        sess.push_chain("test-proxy");
        let (client, server) = duplex(128);
        tx.try_send(server).unwrap();
        Ok(AnyOutboundDatagram::new(OutboundDatagramTrojan::new(AnyStream::new(client))))
    });
    (Arc::new(handler).into(), count, rx)
}

pub(crate) async fn request(stream: &mut DuplexStream) -> UdpPacket {
    timeout(Duration::from_secs(2), async {
        let target = SocksAddr::read_from(stream).await.unwrap();
        let len = stream.read_u16().await.unwrap();
        assert_eq!(stream.read_u16().await.unwrap(), 0x0d0a);
        let mut data = vec![0; usize::from(len)];
        stream.read_exact(&mut data).await.unwrap();
        UdpPacket::new(Bytes::from(data), SocksAddr::any_ipv4(), target)
    }).await.unwrap()
}

pub(crate) async fn reply(stream: &mut DuplexStream, source: &SocksAddr, data: &[u8]) {
    let mut frame = BytesMut::new();
    source.write_buf(&mut frame);
    frame.put_u16(data.len() as u16);
    frame.put_slice(b"\r\n");
    frame.put_slice(data);
    timeout(Duration::from_secs(2), stream.write_all(&frame)).await.unwrap().unwrap();
}


#[tokio::test]
async fn shared_association_preserves_targets_and_unsolicited_sources() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, mut servers) = outbound();
    let first = session(30001);
    let second = session(30002);
    let (a, b) = tokio::join!(fixture.connect(&outbound, &first), fixture.connect(&outbound, &second));
    assert_eq!(count.load(Ordering::Relaxed), 1);
    let mut server = servers.recv().await.unwrap();
    send(&a, b"first");
    assert_eq!(request(&mut server).await.dst_addr, first.destination);
    send(&b, b"second");
    assert_eq!(request(&mut server).await.dst_addr, second.destination);
    let peer: SocksAddr = "127.0.0.2:31000".parse::<SocketAddr>().unwrap().into();
    reply(&mut server, &peer, b"punch").await;
    let packet = fixture.receive().await;
    assert_eq!(packet.src_addr, peer);
    assert_eq!(packet.dst_addr, SocksAddr::Ip(first.source));
    assert_eq!(a.state.tracker.download_total(), 0);
    assert_eq!(b.state.tracker.download_total(), 0);
    reply(&mut server, &first.destination, b"known").await;
    fixture.receive().await;
    assert_eq!(a.state.tracker.download_total(), 5);
    drop((a, b));
    reply(&mut server, &peer, b"no-live-flow").await;
    assert_eq!(fixture.receive().await.src_addr, peer);
    assert_eq!(slot_count(&fixture.pool), 1);
    drop(fixture);
    let mut buf = [0; 1];
    assert_eq!(timeout(Duration::from_secs(2), server.read(&mut buf)).await.unwrap().unwrap(), 0);
}

#[tokio::test]
async fn association_idle_lifetime_is_independent_of_flow_and_unknown_replies() {
    let mut fixture = Fixture::new(Duration::from_millis(150));
    let (outbound, count, mut servers) = outbound();
    let a = fixture.connect(&outbound, &session(30001)).await;
    let mut server = servers.recv().await.unwrap();
    send(&a, b"first"); request(&mut server).await;
    drop(a);
    let peer = SocksAddr::try_from(("192.0.2.3".to_owned(), 9000)).unwrap();
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(60)).await;
        reply(&mut server, &peer, b"keep-alive").await;
        fixture.receive().await;
    }
    let b = fixture.connect(&outbound, &session(30002)).await;
    assert_eq!(count.load(Ordering::Relaxed), 1);
    timeout(Duration::from_secs(2), fixture.events.recv()).await.unwrap().unwrap();
    assert!(b.state.is_closed());
    let c = fixture.connect(&outbound, &session(30003)).await;
    assert_eq!(count.load(Ordering::Relaxed), 2);
    drop(c);
}

#[tokio::test]
async fn shared_association_reads_and_registers_during_send_backpressure() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, mut servers) = outbound();
    let first = session(30001);
    let a = fixture.connect(&outbound, &first).await;
    let mut server = servers.recv().await.unwrap();
    a.try_send(UdpPacket::new(Bytes::from(vec![7; 1024]), SocksAddr::any_ipv4(), first.destination.clone())).unwrap();
    let second = session(30002);
    let b = fixture.connect(&outbound, &second).await;
    reply(&mut server, &second.destination, b"incoming").await;
    assert_eq!(fixture.receive().await.data, Bytes::from_static(b"incoming"));
    assert_eq!(a.state.tracker.upload_total(), 0);
    assert_eq!(request(&mut server).await.data.len(), 1024);
    timeout(Duration::from_secs(2), async {
        while a.state.tracker.upload_total() == 0 { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 1);
    drop(b);
}

#[tokio::test]
async fn shared_association_isolates_client_user_leaf_and_namespace() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, _servers) = outbound();
    let a = fixture.connect(&outbound, &session(30001)).await;
    let mut other = session(30002); other.source.set_port(23457);
    let b = fixture.connect(&outbound, &other).await;
    other = session(30002); other.inbound_user = Some(Arc::from("test-user"));
    let c = fixture.connect(&outbound, &other).await;
    let second = Fixture::new(Duration::from_secs(60));
    let d = second.connect(&outbound, &session(30002)).await;
    let (leaf, leaf_count, _leaf_servers) = self::outbound();
    let e = fixture.connect(&leaf, &session(30002)).await;
    assert_eq!(count.load(Ordering::Relaxed), 4);
    assert_eq!(leaf_count.load(Ordering::Relaxed), 1);
    drop((a, b, c, d, e));
}

fn fake_resolver() -> ThreadSafeDNSResolver {
    let mut dns = MockClashResolver::new();
    dns.expect_is_fake_ip().returning(|ip| matches!(ip, IpAddr::V4(ip) if ip.octets()[..2] == [198, 18]));
    dns.expect_resolve().times(0);
    Arc::new(dns)
}
fn fake_session(port: u16) -> Session {
    let mut sess = session(port);
    sess.destination = SocksAddr::Domain(Arc::from("fake.example"), port);
    sess.orig_destination = Some(SocketAddr::from(([198, 18, 0, 5], port)).into());
    sess
}

#[tokio::test]
async fn fake_ip_restoration_survives_route_expiration_without_guessing_unknown_sources() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, _, mut servers) = outbound();
    let mut first = fake_session(30001);
    first.resolved_ip = Some("127.0.0.1".parse().unwrap());
    let a = fixture.pool.connect(&outbound, &first, fake_resolver(), Arc::new(TrackerInfo::new(&first, None))).await.unwrap();
    let mut server = servers.recv().await.unwrap();
    send(&a, b"fake");
    let target = request(&mut server).await.dst_addr;
    drop(a);
    reply(&mut server, &target, b"known").await;
    assert_eq!(fixture.receive().await.src_addr, first.orig_destination.unwrap());
    let peer: SocksAddr = "127.0.0.2:30001".parse::<SocketAddr>().unwrap().into();
    reply(&mut server, &peer, b"unknown").await;
    assert_eq!(fixture.receive().await.src_addr, peer);
}

#[tokio::test]
async fn unresolved_fake_ip_keeps_remote_dns_and_private_association() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, _servers) = outbound();
    let first = fake_session(30001); let second = fake_session(30002);
    let a = fixture.pool.connect(&outbound, &first, fake_resolver(), Arc::new(TrackerInfo::new(&first, None))).await.unwrap();
    let b = fixture.pool.connect(&outbound, &second, fake_resolver(), Arc::new(TrackerInfo::new(&second, None))).await.unwrap();
    assert!(!Arc::ptr_eq(&a.association, &b.association));
    assert_eq!(count.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn conflicting_logical_alias_cannot_overwrite_a_persistent_binding() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, mut servers) = outbound();
    let first = session(30001);
    let a = fixture.connect(&outbound, &first).await;
    send(&a, b"real");
    let mut server = servers.recv().await.unwrap(); request(&mut server).await;
    drop(a);
    let mut second = fake_session(30001); second.resolved_ip = Some("127.0.0.1".parse().unwrap());
    let b = fixture.pool.connect(&outbound, &second, fake_resolver(), Arc::new(TrackerInfo::new(&second, None))).await.unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 2);
    assert_eq!(second.proxy_chain.snapshot(), vec!["test-proxy"]);
    reply(&mut server, &first.destination, b"real-reply").await;
    assert_eq!(fixture.receive().await.src_addr, first.destination);
    drop(b);
}

#[tokio::test]
async fn fixed_target_transport_is_private() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let (tx, _servers) = mpsc::channel(2);
    let mut handler = MockDummyOutboundHandler::new();
    handler.expect_connect_datagram().times(2).returning(move |sess, _| {
        let (client, server) = duplex(128); tx.try_send(server).unwrap();
        Ok(AnyOutboundDatagram::new(OutboundDatagramUotV2::new(AnyStream::new(client), sess.destination.clone())))
    });
    let outbound: ProtocolOutbound = Arc::new(handler).into();
    let a = fixture.connect(&outbound, &session(30001)).await;
    let b = fixture.connect(&outbound, &session(30002)).await;
    assert!(!Arc::ptr_eq(&a.association, &b.association));
}

#[tokio::test]
async fn fake_ip_cannot_be_used_as_a_resolved_target() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, _) = outbound();
    let mut first = fake_session(30001); first.resolved_ip = Some("198.18.0.6".parse().unwrap());
    let result = fixture.pool.connect(&outbound, &first, fake_resolver(), Arc::new(TrackerInfo::new(&first, None))).await;
    let Err(err) = result else { panic!("Fake-IP must be rejected"); };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn association_close_notifies_all_routes_and_allows_rebuild() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, mut servers) = outbound();
    let a = fixture.connect(&outbound, &session(30001)).await;
    let b = fixture.connect(&outbound, &session(30002)).await;
    drop(servers.recv().await.unwrap());
    let first = timeout(Duration::from_secs(2), fixture.events.recv()).await.unwrap().unwrap();
    let second = timeout(Duration::from_secs(2), fixture.events.recv()).await.unwrap().unwrap();
    assert_ne!(first.id, second.id);
    assert!(a.state.is_closed() && b.state.is_closed());
    let c = fixture.connect(&outbound, &session(30003)).await;
    assert_eq!(count.load(Ordering::Relaxed), 2);
    assert_eq!(slot_count(&fixture.pool), 1);
    drop(c);
}

#[tokio::test]
async fn uot_packet_mode_uses_the_same_direct_reply_path() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (tx, mut rx) = mpsc::channel(2);
    let mut handler = MockDummyOutboundHandler::new();
    handler.expect_connect_datagram().times(1).returning(move |_, _| {
        let (client, server) = duplex(128); tx.try_send(server).unwrap();
        Ok(AnyOutboundDatagram::new(OutboundDatagramUotV2::packet_mode(AnyStream::new(client))))
    });
    let outbound: ProtocolOutbound = Arc::new(handler).into();
    let first = session(30001); let second = session(30002);
    let a = fixture.connect(&outbound, &first).await; let b = fixture.connect(&outbound, &second).await;
    let mut server = OutboundDatagramUotV2::packet_mode(AnyStream::new(rx.recv().await.unwrap()));
    send(&a, b"a"); assert_eq!(server.next().await.unwrap().src_addr, first.destination);
    send(&b, b"b"); assert_eq!(server.next().await.unwrap().src_addr, second.destination);
    let peer = SocksAddr::try_from(("192.0.2.3".to_owned(), 9000)).unwrap();
    use futures::SinkExt;
    server.send(UdpPacket::new(Bytes::from_static(b"punch"), SocksAddr::any_ipv4(), peer.clone())).await.unwrap();
    assert_eq!(fixture.receive().await.src_addr, peer);
}

#[tokio::test]
async fn association_and_flow_statistics_count_user_bytes_once() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, _, mut servers) = outbound();
    let mut first = session(30001); first.inbound_user = Some(Arc::from("test-user"));
    let mut second = session(30002); second.inbound_user = first.inbound_user.clone();
    let a = fixture.connect(&outbound, &first).await;
    let b = fixture.connect(&outbound, &second).await;
    let mut server = servers.recv().await.unwrap();
    send(&a, b"first"); request(&mut server).await;
    send(&b, b"second"); request(&mut server).await;
    let peer = SocksAddr::try_from(("192.0.2.3".to_owned(), 9000)).unwrap();
    reply(&mut server, &first.destination, b"known").await; fixture.receive().await;
    reply(&mut server, &peer, b"unknown").await; fixture.receive().await;
    let snapshot = serde_json::to_value(fixture.manager.snapshot()).unwrap();
    assert_eq!(snapshot["connections"].as_array().unwrap().len(), 2);
    let mut keys: Vec<_> = snapshot.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["connections", "downloadTotal", "memory", "uploadTotal"]);
    assert_eq!(snapshot["uploadTotal"], 11);
    assert_eq!(snapshot["downloadTotal"], 12);
    assert_eq!(fixture.manager.active_connections_snapshot().len(), 2);
    assert_eq!(fixture.manager.traffic_summary().4, 2);
    assert_eq!(a.state.tracker.download_total(), 5);
    assert_eq!(b.state.tracker.download_total(), 0);
    let user = fixture.manager.drain_user_stats().await;
    assert_eq!(user["test-user"].upload, 11);
    assert_eq!(user["test-user"].download, 12);
    assert!(fixture.manager.drain_user_stats().await.is_empty());
    fixture.manager.close(a.state.id);
    assert_eq!(timeout(Duration::from_secs(2), fixture.events.recv()).await.unwrap().unwrap().id, a.state.id);
    drop(a);
    send(&b, b"alive"); request(&mut server).await;
    fixture.manager.close_all();
    assert_eq!(timeout(Duration::from_secs(2), fixture.events.recv()).await.unwrap().unwrap().id, b.state.id);
    assert!(b.is_closed());
}

#[tokio::test]
async fn failed_dial_does_not_leave_an_empty_slot() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let mut handler = MockDummyOutboundHandler::new();
    handler.expect_connect_datagram().returning(|_, _| Err(io::Error::other("test dial error")));
    let outbound: ProtocolOutbound = Arc::new(handler).into();
    let first = session(30001);
    assert!(fixture.pool.connect(&outbound, &first, resolver(), Arc::new(TrackerInfo::new(&first, None))).await.is_err());
    assert_eq!(slot_count(&fixture.pool), 0);
}

#[tokio::test]
async fn capacity_is_reserved_before_dial_and_shared_routes_can_reuse_it() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, _servers) = outbound();
    let a = fixture.connect(&outbound, &session(30001)).await;
    fixture.pool.config.capacity.close();
    let b = fixture.connect(&outbound, &session(30002)).await;
    assert!(Arc::ptr_eq(&a.association, &b.association));
    let mut other = session(30003); other.source.set_port(23457);
    let result = fixture.pool.connect(&outbound, &other, resolver(), Arc::new(TrackerInfo::new(&other, None))).await;
    let Err(err) = result else { panic!("new association must respect capacity"); };
    assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(count.load(Ordering::Relaxed), 1);
    assert_eq!(slot_count(&fixture.pool), 1);
}

#[tokio::test]
async fn cancelled_dial_releases_the_slot_and_capacity_reservation() {
    use tokio::net::TcpListener;
    use crate::proxy::socks::outbound::{Handler, HandlerOptions};
    let fixture = Fixture::new(Duration::from_secs(60));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outbound: ProtocolOutbound = Arc::new(Handler::new(HandlerOptions {
        name: "test-socks".to_owned(), server: "127.0.0.1".to_owned(),
        port: listener.local_addr().unwrap().port(), ..Default::default()
    }, None)).into();
    let pool = fixture.pool.clone();
    let task = tokio::spawn(async move {
        let sess = session(30001);
        pool.connect(&outbound, &sess, resolver(), Arc::new(TrackerInfo::new(&sess, None))).await
    });
    let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept()).await.unwrap().unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), 5);
    task.abort();
    assert!(matches!(task.await, Err(err) if err.is_cancelled()));
    assert_eq!(slot_count(&fixture.pool), 0);
    assert_eq!(fixture.pool.config.capacity.available_permits(), 64);
}

#[tokio::test]
async fn native_association_survives_an_oversized_datagram() {
    use crate::proxy::direct::Handler;
    use tokio::net::UdpSocket;
    let fixture = Fixture::new(Duration::from_secs(60));
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut sess = session(30001); sess.destination = server.local_addr().unwrap().into();
    let outbound: ProtocolOutbound = Arc::new(Handler::new("test-direct")).into();
    let flow = fixture.connect(&outbound, &sess).await;
    flow.try_send(UdpPacket::new(Bytes::from(vec![0; 70000]), SocksAddr::any_ipv4(), sess.destination.clone())).unwrap();
    send(&flow, b"valid");
    let mut buf = [0; 32];
    let (len, _) = timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..len], b"valid");
    assert!(!flow.is_closed());
}


#[tokio::test]
async fn shared_alias_tracks_sender_switch_registration_and_owner_removal() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, mut servers) = outbound();
    let first = session(30001);
    let a = fixture.connect(&outbound, &first).await;
    let mut server = servers.recv().await.unwrap();
    for _ in 0..2 {
        send(&a, b"a"); request(&mut server).await;
        reply(&mut server, &first.destination, b"a").await; fixture.receive().await;
    }
    let b = fixture.connect(&outbound, &session(30001)).await;
    send(&a, b"a"); request(&mut server).await;
    reply(&mut server, &first.destination, b"a").await; fixture.receive().await;
    assert_eq!(a.state.tracker.download_total(), 3);
    assert_eq!(b.state.tracker.download_total(), 0);
    send(&b, b"b"); request(&mut server).await;
    reply(&mut server, &first.destination, b"b").await; fixture.receive().await;
    assert_eq!(b.state.tracker.download_total(), 1);
    let c = fixture.connect(&outbound, &session(30001)).await;
    fixture.manager.close(b.state.id);
    assert_eq!(timeout(Duration::from_secs(2), fixture.events.recv()).await.unwrap().unwrap().id, b.state.id);
    send(&a, b"a"); request(&mut server).await;
    fixture.manager.close(a.state.id);
    assert_eq!(timeout(Duration::from_secs(2), fixture.events.recv()).await.unwrap().unwrap().id, a.state.id);
    reply(&mut server, &first.destination, b"c").await; fixture.receive().await;
    assert_eq!(c.state.tracker.download_total(), 1);
    assert_eq!(count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn late_and_unknown_replies_are_counted_without_flow_trackers() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, _, mut servers) = outbound();
    let mut sess = session(30001);
    sess.inbound_user = Some(Arc::from("test-user"));
    let flow = fixture.connect(&outbound, &sess).await;
    let association = flow.association.clone();
    let mut server = servers.recv().await.unwrap();
    send(&flow, b"a"); request(&mut server).await;
    drop(flow);
    timeout(Duration::from_secs(2), async {
        while fixture.manager.traffic_summary().4 != 0 { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert!(fixture.manager.active_connections_snapshot().is_empty());
    let unknown = SocksAddr::try_from(("192.0.2.3".to_owned(), 9000)).unwrap();
    reply(&mut server, &sess.destination, b"late").await;
    assert_eq!(fixture.receive().await.src_addr, sess.destination);
    reply(&mut server, &unknown, b"unknown").await;
    assert_eq!(fixture.receive().await.src_addr, unknown);
    let snapshot = serde_json::to_value(fixture.manager.snapshot()).unwrap();
    assert!(snapshot["connections"].as_array().unwrap().is_empty());
    assert_eq!(snapshot["uploadTotal"], 1);
    assert_eq!(snapshot["downloadTotal"], 11);
    let stats = fixture.manager.drain_user_stats().await;
    assert_eq!(stats["test-user"].upload, 1);
    assert_eq!(stats["test-user"].download, 11);
    fixture.manager.close_all();
    timeout(Duration::from_secs(2), async {
        while !association.outgoing.is_closed() { tokio::task::yield_now().await; }
    }).await.expect("close_all must stop an association with no tracked flows");
    assert!(fixture.manager.drain_user_stats().await.is_empty());
    assert!(fixture.manager.closed_flows_snapshot().await.keys().all(|key| key.dst_port == 30001));
}

#[tokio::test]
async fn shared_routes_can_register_before_an_earlier_registration_is_acknowledged() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, _servers) = outbound();
    let first = session(30001);
    let slot = fixture.pool.slot(AssociationKey { outbound: outbound.identity(),
        source: first.source, inbound: first.typ, user: None, interface: None,
        mark: first.so_mark, isolated: None }, &outbound);
    let (outgoing, _packets) = mpsc::channel(64);
    let (control, mut commands) = mpsc::channel(64);
    *slot.association.lock().await = Some(Arc::new(Association {
        id: 0, outgoing, control, chain: vec!["test-proxy".to_owned()], task: tokio::spawn(std::future::pending()),
    }));
    let pool = fixture.pool.clone();
    let leaf = outbound.clone();
    let pending = tokio::spawn(async move {
        pool.connect(&leaf, &first, resolver(), Arc::new(TrackerInfo::new(&first, None))).await
    });
    let Registration { reply: first_ack, .. } = timeout(Duration::from_secs(2), commands.recv()).await.unwrap().unwrap();
    let pool = fixture.pool.clone();
    let second = tokio::spawn(async move {
        let sess = session(30002);
        pool.connect(&outbound, &sess, resolver(), Arc::new(TrackerInfo::new(&sess, None))).await
    });
    let Registration { reply: second_ack, .. } = timeout(Duration::from_secs(2), commands.recv()).await
        .expect("registration must not hold the slot lock while waiting for acknowledgment").unwrap();
    assert!(second_ack.send(Ok(())).is_ok());
    let second = timeout(Duration::from_secs(2), second).await.unwrap().unwrap().unwrap();
    assert!(first_ack.send(Ok(())).is_ok());
    let first = pending.await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&first.association, &second.association));
    assert_eq!(count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn native_targets_reject_fake_ips_even_without_a_fake_original_address() {
    use crate::proxy::direct::Handler;
    let fixture = Fixture::new(Duration::from_secs(60));
    let fake: IpAddr = "192.0.2.99".parse().unwrap();
    let outbound: ProtocolOutbound = Arc::new(Handler::new("test-direct")).into();
    for destination in [SocksAddr::Domain("example.test".into(), 80), SocksAddr::Ip(SocketAddr::new(fake, 80))] {
        let mut dns = MockClashResolver::new();
        dns.expect_is_fake_ip().returning(move |ip| ip == fake);
        if destination.is_domain() { dns.expect_resolve().returning(move |_, _| Ok(Some(fake))); }
        let sess = Session { destination, ..session(30001) };
        let result = fixture.pool.connect(&outbound, &sess, Arc::new(dns), Arc::new(TrackerInfo::new(&sess, None))).await;
        let Err(err) = result else { panic!("Fake-IP must not reach physical UDP I/O"); };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
    assert_eq!(slot_count(&fixture.pool), 0);
}

#[tokio::test]
async fn sender_cache_is_invalidated_by_registration_during_pending_flush() {
    let mut fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, _, mut servers) = outbound();
    let first = session(30001);
    let a = fixture.connect(&outbound, &first).await;
    let mut server = servers.recv().await.unwrap();
    a.try_send(UdpPacket::new(Bytes::from(vec![b'a'; 1024]), SocksAddr::any_ipv4(), SocksAddr::any_ipv4())).unwrap();
    tokio::task::yield_now().await;
    let b = fixture.connect(&outbound, &session(30001)).await;
    assert_eq!(a.state.tracker.upload_total(), 0);
    assert_eq!(request(&mut server).await.data.len(), 1024);
    timeout(Duration::from_secs(2), async {
        while a.state.tracker.upload_total() == 0 { tokio::task::yield_now().await; }
    }).await.unwrap();
    send(&a, b"follow"); request(&mut server).await;
    reply(&mut server, &first.destination, b"reply").await; fixture.receive().await;
    assert_eq!(a.state.tracker.download_total(), 5);
    assert_eq!(b.state.tracker.download_total(), 0);
}
