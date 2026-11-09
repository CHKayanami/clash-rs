use super::*;
use bytes::{Bytes, BytesMut};
use std::{io::ErrorKind, sync::atomic::AtomicBool, task::Poll};
use tokio::sync::Semaphore;
use tokio::{net::UdpSocket, sync::mpsc, time::{Duration, timeout}};
use tokio_util::sync::PollSender;
use clash_netstack::UdpPacket as StackPacket;
use crate::{app::{dispatcher::{Manager, TrackerInfo}, dns::{MockClashResolver, ThreadSafeDNSResolver}, net::notify_network_change},
    proxy::{ProtocolOutbound, direct::Handler}, session::{Network, Session, Type}};
use super::super::{AssociationConfig, UdpAssociationPool};
use super::super::super::replies;

fn resolver() -> ThreadSafeDNSResolver {
    let mut dns = MockClashResolver::new();
    dns.expect_is_fake_ip().returning(|_| false);
    Arc::new(dns)
}

fn session(destination: SocketAddr) -> Session {
    Session { network: Network::Udp, typ: Type::Tun, source: "127.0.0.1:23456".parse().unwrap(),
        destination: destination.into(), ..Default::default() }
}
fn packet(sess: &Session, payload: &'static [u8]) -> BytesMut {
    let SocksAddr::Ip(destination) = sess.orig_destination.as_ref().unwrap_or(&sess.destination) else { panic!("IP packet destination"); };
    let ip = StackPacket::from((Bytes::from_static(payload), sess.source, *destination)).encode().unwrap();
    BytesMut::from(ip.data())
}

// The test owner has external I/O endpoints. Production TUN uploads/replies
// are passed directly to/from Engine and never use these fixture channels.
fn drive(path: Arc<DirectPath>, replies: mpsc::Sender<Vec<UdpPacket>>)
    -> (mpsc::Sender<Upload>, tokio_util::task::AbortOnDropHandle<()>) {
    let mut engine = path.take_engine().unwrap();
    let (incoming, mut uploads) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        let mut replies = PollSender::new(replies);
        futures::future::poll_fn(move |cx| {
            let mut progress = engine.poll(cx, Instant::now());
            let mut batch = Vec::new();
            for _ in 0..16 {
                match uploads.poll_recv(cx) {
                    Poll::Ready(Some(upload)) => { batch.push(upload); progress = true; },
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            engine.upload_batch(cx, &mut batch, Instant::now());
            progress |= engine.poll(cx, Instant::now());
            for _ in 0..16 {
                match replies.poll_reserve(cx) {
                    Poll::Ready(Ok(())) => {},
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
                let Some(group) = engine.take_reply() else { replies.abort_send(); break; };
                if replies.send_item(vec![group.packet]).is_err() { return Poll::Ready(()); }
                progress = true;
            }
            if progress { cx.waker().wake_by_ref(); }
            Poll::Pending
        }).await;
    });
    (incoming, tokio_util::task::AbortOnDropHandle::new(task))
}
async fn upload(path: &DirectPath, owner: &mpsc::Sender<Upload>, packet: BytesMut) -> Result<(), BytesMut> {
    match path.upload_frame(Packet::from(packet), &mut UploadCache::default(), Instant::now()) {
        Ok(Some(upload)) => { owner.send(upload).await.unwrap(); Ok(()) },
        Ok(None) => Ok(()),
        Err(packet) => Err(BytesMut::from(packet.data())),
    }
}

#[tokio::test]
#[serial_test::serial(tun_network_changes)]
async fn direct_data_keeps_fullcone_mapping_and_releases_weak_upload_cache() {
    let manager = Manager::new();
    let (target, mut returned) = mpsc::channel(1);
    let path = DirectPath::integrated(None);
    let (incoming, _owner) = drive(path.clone(), target);
    let (fallback, mut fallback_rx) = replies::channel(64);
    let (events, _closed) = mpsc::unbounded_channel();
    let pool = UdpAssociationPool::new(AssociationConfig { replies: fallback, direct: Some(path.clone()),
        closed_flows: events, manager: manager.clone(), allow_quic: Arc::new(AtomicBool::new(true)),
        timeout: Duration::from_secs(60), capacity: Arc::new(Semaphore::new(64)) });
    let outbound: ProtocolOutbound = Arc::new(Handler::new("DIRECT")).into();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let unknown = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = session(first.local_addr().unwrap());
    let b = session(second.local_addr().unwrap());
    let flow_a = pool.connect(&outbound, &a, resolver(), Arc::new(TrackerInfo::new(&a, None))).await.unwrap();
    let flow_b = pool.connect(&outbound, &b, resolver(), Arc::new(TrackerInfo::new(&b, None))).await.unwrap();
    assert!(Arc::ptr_eq(&flow_a.association, &flow_b.association));
    assert!(upload(&path, &incoming, packet(&a, b"not-yet-handed-off")).await.is_err());
    flow_a.enable_direct_upload();
    flow_b.enable_direct_upload();
    let mut buffer = [0; 64];
    assert!(upload(&path, &incoming, packet(&a, b"fast-a")).await.is_ok());
    let (n, peer_a) = timeout(Duration::from_secs(2), first.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..n], b"fast-a");
    assert!(upload(&path, &incoming, packet(&b, b"fast-b")).await.is_ok());
    let (_, peer_b) = timeout(Duration::from_secs(2), second.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(peer_a, peer_b);
    unknown.send_to(b"punch", peer_a).await.unwrap();
    let batch = timeout(Duration::from_secs(2), returned.recv()).await.unwrap().unwrap();
    assert_eq!(batch[0].src_addr, SocksAddr::Ip(unknown.local_addr().unwrap()));
    assert_eq!(batch[0].dst_addr, SocksAddr::Ip(a.source));
    assert_eq!(batch[0].data.as_ref(), b"punch");
    assert!(timeout(Duration::from_millis(10), fallback_rx.recv()).await.is_err());
    // Capacity pressure at the direct destination must not block upload.
    for _ in 0..32 { first.send_to(b"backlog", peer_a).await.unwrap(); }
    assert!(upload(&path, &incoming, packet(&a, b"upload-with-replies-blocked")).await.is_ok());
    let (n, _) = timeout(Duration::from_secs(2), first.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..n], b"upload-with-replies-blocked");
    let key = (a.source, first.local_addr().unwrap());
    path.uploads.get_mut(&key).unwrap().generation = network_generation().wrapping_sub(1);
    assert!(upload(&path, &incoming, packet(&a, b"stale-network")).await.is_err());
    assert!(!path.uploads.contains_key(&key));
    let key_b = (b.source, second.local_addr().unwrap());
    assert!(path.uploads.contains_key(&key_b));
    drop(flow_b);
    assert!(!path.uploads.contains_key(&key_b));
    assert!(upload(&path, &incoming, packet(&b, b"expired-flow")).await.is_err());
    let association = flow_a.association.clone();
    // Old physical mappings close on a network change, even if reply output
    // is blocked and no further native socket event arrives.
    notify_network_change();
    timeout(Duration::from_secs(2), async {
        while !association.task.is_finished() { tokio::task::yield_now().await; }
    }).await.unwrap();
    manager.close_all();
    drop(flow_a);
}

#[tokio::test]
#[serial_test::serial(tun_network_changes)]
async fn fake_ip_upload_and_reply_use_the_established_projection() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let real = server.local_addr().unwrap();
    let fake = SocketAddr::new("198.18.0.5".parse().unwrap(), 443);
    let manager = Manager::new();
    let (target, mut returned) = mpsc::channel(1);
    let path = DirectPath::integrated(None);
    let (incoming, _owner) = drive(path.clone(), target);
    let (fallback, _fallback_rx) = replies::channel(64);
    let (events, _closed) = mpsc::unbounded_channel();
    let allow_quic = Arc::new(AtomicBool::new(true));
    let pool = UdpAssociationPool::new(AssociationConfig { replies: fallback, direct: Some(path.clone()),
        closed_flows: events, manager: manager.clone(), allow_quic: allow_quic.clone(),
        timeout: Duration::from_secs(60), capacity: Arc::new(Semaphore::new(64)) });
    let outbound: ProtocolOutbound = Arc::new(Handler::new("DIRECT")).into();
    let mut sess = session(fake);
    sess.destination = SocksAddr::Domain("test.invalid".into(), real.port());
    sess.orig_destination = Some(fake.into());
    sess.resolved_ip = Some(real.ip());
    let mut dns = MockClashResolver::new();
    dns.expect_is_fake_ip().returning(move |ip| ip == fake.ip());
    dns.expect_resolve().returning(move |_, _| Ok(Some(real.ip())));
    let flow = pool.connect(&outbound, &sess, Arc::new(dns), Arc::new(TrackerInfo::new(&sess, None))).await.unwrap();
    flow.enable_direct_upload();
    assert!(upload(&path, &incoming, packet(&sess, b"fake-request")).await.is_ok());
    let mut buffer = [0; 64];
    let (_, peer) = timeout(Duration::from_secs(2), server.recv_from(&mut buffer)).await.unwrap().unwrap();
    server.send_to(b"fake-reply", peer).await.unwrap();
    let batch = timeout(Duration::from_secs(2), returned.recv()).await.unwrap().unwrap();
    assert_eq!(batch[0].src_addr, SocksAddr::Ip(fake));
    assert_eq!(batch[0].dst_addr, SocksAddr::Ip(sess.source));
    assert!(flow.state.tracker.upload_total() > 0);
    assert_eq!(flow.state.tracker.download_total(), 10);
    let previous_upload = flow.state.activity.latest_upload();
    allow_quic.store(false, Ordering::Relaxed);
    assert!(upload(&path, &incoming, packet(&sess, b"blocked-quic")).await.is_ok());
    assert_eq!(flow.state.activity.latest_upload(), previous_upload);
    assert!(timeout(Duration::from_millis(20), server.recv_from(&mut buffer)).await.is_err());
    manager.close_all();
}

#[tokio::test]
#[serial_test::serial(tun_network_changes)]
async fn segmented_upload_preserves_boundaries_and_counts_partial_progress_once() {
    let manager = Manager::new();
    let (returned, _returned) = mpsc::channel(1);
    let path = DirectPath::integrated(None);
    let (incoming, _owner) = drive(path.clone(), returned);
    let (fallback, _fallback) = replies::channel(64);
    let (events, _events) = mpsc::unbounded_channel();
    let pool = UdpAssociationPool::new(AssociationConfig { replies: fallback, direct: Some(path.clone()),
        closed_flows: events, manager: manager.clone(), allow_quic: Arc::new(AtomicBool::new(true)),
        timeout: Duration::from_secs(60), capacity: Arc::new(Semaphore::new(64)) });
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sess = session(server.local_addr().unwrap());
    let outbound: ProtocolOutbound = Arc::new(Handler::new("DIRECT")).into();
    let flow = pool.connect(&outbound, &sess, resolver(), Arc::new(TrackerInfo::new(&sess, None))).await.unwrap();
    flow.enable_direct_upload();
    let mut data = Vec::new();
    for marker in 0..33u8 { data.extend_from_slice(&[marker; 32]); }
    data.extend_from_slice(&[99; 7]);
    let packet = StackPacket::from((Bytes::from(data.clone()), sess.source, server.local_addr().unwrap()))
        .encode_segments(32).unwrap();
    let upload = path.upload_frame(packet, &mut UploadCache::default(), Instant::now()).unwrap().unwrap();
    incoming.send(upload).await.unwrap();
    let mut received = [0u8; 64];
    for marker in 0..33u8 {
        let (count, _) = timeout(Duration::from_secs(2), server.recv_from(&mut received)).await.unwrap().unwrap();
        assert_eq!(&received[..count], &[marker; 32]);
    }
    let (count, _) = timeout(Duration::from_secs(2), server.recv_from(&mut received)).await.unwrap().unwrap();
    assert_eq!(&received[..count], &[99; 7]);
    assert_eq!(server.try_recv_from(&mut received).unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!(flow.state.tracker.upload_total(), data.len() as u64);
    manager.close_all();
}

#[tokio::test]
#[serial_test::serial(tun_network_changes)]
async fn interleaved_upload_batch_preserves_peer_order_and_flow_totals() {
    let manager = Manager::new();
    let (returned, _returned) = mpsc::channel(1);
    let path = DirectPath::integrated(None);
    let (incoming, _owner) = drive(path.clone(), returned);
    let (fallback, _fallback) = replies::channel(64);
    let (events, _events) = mpsc::unbounded_channel();
    let pool = UdpAssociationPool::new(AssociationConfig { replies: fallback, direct: Some(path.clone()),
        closed_flows: events, manager: manager.clone(), allow_quic: Arc::new(AtomicBool::new(true)),
        timeout: Duration::from_secs(60), capacity: Arc::new(Semaphore::new(64)) });
    let outbound: ProtocolOutbound = Arc::new(Handler::new("DIRECT")).into();
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sa = session(a.local_addr().unwrap());
    let sb = session(b.local_addr().unwrap());
    let fa = pool.connect(&outbound, &sa, resolver(), Arc::new(TrackerInfo::new(&sa, None))).await.unwrap();
    let fb = pool.connect(&outbound, &sb, resolver(), Arc::new(TrackerInfo::new(&sb, None))).await.unwrap();
    fa.enable_direct_upload(); fb.enable_direct_upload();
    assert!(Arc::ptr_eq(&fa.association, &fb.association));
    // Queue a whole burst before yielding, mixing both consecutive and
    // alternating flow owners in the shared association's completion prefix.
    for index in 0..16 {
        let sess = if index < 8 { &sa } else { &sb };
        let frame = StackPacket::from((Bytes::from(vec![index; index as usize + 1]), sess.source,
            if index < 8 { a.local_addr().unwrap() } else { b.local_addr().unwrap() })).encode().unwrap();
        incoming.try_send(path.upload_frame(frame, &mut UploadCache::default(), Instant::now()).unwrap().unwrap()).unwrap();
    }
    let mut buffer = [0u8; 32];
    for (socket, start) in [(&a, 0u8), (&b, 8u8)] {
        for index in start..start + 8 {
            let (length, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
            assert_eq!(&buffer[..length], vec![index; index as usize + 1]);
        }
    }
    assert_eq!(fa.state.tracker.upload_total(), (1..=8).sum::<u64>());
    assert_eq!(fb.state.tracker.upload_total(), (9..=16).sum::<u64>());
    manager.close_all();
}

#[tokio::test]
#[serial_test::serial(tun_network_changes)]
async fn warm_owner_cache_observes_policy_and_close_without_holding_a_flow_lease() {
    let manager = Manager::new();
    let (returned, _returned) = mpsc::channel(1);
    let path = DirectPath::integrated(None);
    let (_incoming, _owner) = drive(path.clone(), returned);
    let (fallback, _fallback) = replies::channel(64);
    let (events, _events) = mpsc::unbounded_channel();
    let allow_quic = Arc::new(AtomicBool::new(true));
    let pool = UdpAssociationPool::new(AssociationConfig { replies: fallback, direct: Some(path.clone()),
        closed_flows: events, manager: manager.clone(), allow_quic: allow_quic.clone(),
        timeout: Duration::from_secs(60), capacity: Arc::new(Semaphore::new(64)) });
    let sess = session("127.0.0.1:443".parse().unwrap());
    let outbound: ProtocolOutbound = Arc::new(Handler::new("DIRECT")).into();
    let flow = pool.connect(&outbound, &sess, resolver(), Arc::new(TrackerInfo::new(&sess, None))).await.unwrap();
    flow.enable_direct_upload();
    let mut cache = UploadCache::default();
    let retained = Arc::strong_count(&flow.state);
    assert!(path.upload_frame(Packet::from(packet(&sess, b"warm")), &mut cache, Instant::now()).unwrap().is_some());
    assert_eq!(Arc::strong_count(&flow.state), retained, "the cache must not retain flow guards");
    // Remove the cold registration without publishing an invalidation: a hot
    // hit must use owner state instead of consulting the shared DashMap.
    path.uploads.remove(&(sess.source, "127.0.0.1:443".parse().unwrap()));
    assert!(path.upload_frame(Packet::from(packet(&sess, b"hot")), &mut cache, Instant::now()).unwrap().is_some());
    allow_quic.store(false, Ordering::Relaxed);
    assert!(path.upload_frame(Packet::from(packet(&sess, b"blocked")), &mut cache, Instant::now()).unwrap().is_none());
    allow_quic.store(true, Ordering::Relaxed);
    flow.state.close();
    assert!(path.upload_frame(Packet::from(packet(&sess, b"closed")), &mut cache, Instant::now()).is_err());
    manager.close_all();
}

#[tokio::test]
#[serial_test::serial(tun_network_changes)]
async fn interleaved_clients_keep_each_sessions_order_and_completion_owner() {
    let manager = Manager::new();
    let (returned, _returned) = mpsc::channel(1);
    let path = DirectPath::integrated(None);
    let (incoming, _owner) = drive(path.clone(), returned);
    let (fallback, _fallback) = replies::channel(64);
    let (events, _closed) = mpsc::unbounded_channel();
    let pool = UdpAssociationPool::new(AssociationConfig { replies: fallback, direct: Some(path.clone()),
        closed_flows: events, manager: manager.clone(), allow_quic: Arc::new(AtomicBool::new(true)),
        timeout: Duration::from_secs(60), capacity: Arc::new(Semaphore::new(64)) });
    let outbound: ProtocolOutbound = Arc::new(Handler::new("DIRECT")).into();
    let mut servers = Vec::new();
    let mut clients = Vec::new();
    let mut flows = Vec::new();
    for index in 0..4 {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = session(server.local_addr().unwrap());
        client.source.set_port(24000 + index);
        let flow = pool.connect(&outbound, &client, resolver(), Arc::new(TrackerInfo::new(&client, None))).await.unwrap();
        flow.enable_direct_upload();
        servers.push(server); clients.push(client); flows.push(flow);
    }
    for sequence in 0..4u8 {
        for (index, client) in clients.iter().enumerate() {
            let SocksAddr::Ip(destination) = client.destination else { unreachable!(); };
            let frame = StackPacket::from((Bytes::from(vec![index as u8, sequence]), client.source, destination)).encode().unwrap();
            incoming.try_send(path.upload_frame(frame, &mut UploadCache::default(), Instant::now()).unwrap().unwrap()).unwrap();
        }
    }
    let mut buffer = [0; 16];
    for (index, server) in servers.iter().enumerate() {
        for sequence in 0..4u8 {
            let (length, _) = timeout(Duration::from_secs(2), server.recv_from(&mut buffer)).await.unwrap().unwrap();
            assert_eq!(&buffer[..length], &[index as u8, sequence]);
        }
        assert_eq!(flows[index].state.tracker.upload_total(), 8);
    }
    manager.close_all();
}

#[tokio::test]
#[serial_test::serial(tun_network_changes)]
async fn unpublished_slot_falls_back_without_evicting_the_route() {
    let manager = Manager::new();
    let path = DirectPath::integrated(None);
    let (target, _returned) = mpsc::channel(1);
    let (incoming, _owner) = drive(path.clone(), target);
    let (fallback, _fallback_rx) = replies::channel(16);
    let (events, _closed) = mpsc::unbounded_channel();
    let pool = UdpAssociationPool::new(AssociationConfig { replies: fallback, direct: Some(path.clone()),
        closed_flows: events, manager: manager.clone(), allow_quic: Arc::new(AtomicBool::new(true)),
        timeout: Duration::from_secs(60), capacity: Arc::new(Semaphore::new(16)) });
    let outbound: ProtocolOutbound = Arc::new(Handler::new("DIRECT")).into();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sess = session(server.local_addr().unwrap());
    let flow = pool.connect(&outbound, &sess, resolver(), Arc::new(TrackerInfo::new(&sess, None))).await.unwrap();
    flow.enable_direct_upload();
    let location = &flow.association.direct.as_ref().unwrap().location;
    let published = location.swap(usize::MAX, Ordering::AcqRel);
    assert_ne!(published, usize::MAX);
    let key = (sess.source, server.local_addr().unwrap());
    let mut cache = UploadCache::default();
    // Both a newly populated cache and a cache hit must return the original
    // frame to the slow path, without removing a still-live registration.
    for _ in 0..2 {
        let frame = Packet::from(packet(&sess, b"pending-owner"));
        let expected = frame.data().to_vec();
        let returned = path.upload_frame(frame, &mut cache, Instant::now()).err().expect("unpublished slot must fall back");
        assert_eq!(returned.data(), expected);
        assert!(path.uploads.contains_key(&key));
        assert!(cache.entries.contains_key(&key));
        let (_, _, payload) = parse_udp_packet(returned.data()).unwrap();
        flow.try_send(UdpPacket::new(Bytes::copy_from_slice(&returned.data()[payload]),
            sess.source.into(), sess.destination.clone())).unwrap();
        let mut buffer = [0; 64];
        let length = timeout(Duration::from_secs(2), server.recv(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(&buffer[..length], b"pending-owner");
    }
    location.store(published, Ordering::Release);
    let frame = Packet::from(packet(&sess, b"ready-owner"));
    let upload = path.upload_frame(frame, &mut cache, Instant::now()).ok().flatten().expect("cached route must become usable");
    assert_eq!(upload.slot, published);
    incoming.send(upload).await.unwrap();
    let mut buffer = [0; 64];
    let length = timeout(Duration::from_secs(2), server.recv(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..length], b"ready-owner");
    manager.close_all();
}
