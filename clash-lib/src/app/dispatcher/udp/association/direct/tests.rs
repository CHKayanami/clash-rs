use super::*;
use bytes::Bytes;
use std::{mem, sync::atomic::AtomicBool};
use tokio::sync::Semaphore;
use tokio::{net::UdpSocket, sync::mpsc, time::{Duration, timeout}};
use tokio_util::sync::PollSender;
use clash_netstack::UdpPacket as StackPacket;
use crate::{app::{dispatcher::{Manager, TrackerInfo}, dns::{MockClashResolver, ThreadSafeDNSResolver}, net::notify_network_change},
    proxy::{ProtocolOutbound, direct::Handler}, session::{Network, Session, Type}};
use super::super::{AssociationConfig, UdpAssociationPool};
use super::super::super::replies;

struct Target(mpsc::Sender<Vec<UdpPacket>>);
struct Writer(PollSender<Vec<UdpPacket>>);
impl ReplyTarget for Target {
    fn writer(&self) -> Box<dyn ReplyWriter> { Box::new(Writer(PollSender::new(self.0.clone()))) }
}
impl ReplyWriter for Writer {
    fn is_closed(&self) -> bool { self.0.is_closed() }
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<bool> { self.0.poll_reserve(cx).map(|v| v.is_ok()) }
    fn send(&mut self, packets: &mut Vec<UdpPacket>) -> io::Result<()> {
        self.0.send_item(mem::take(packets)).map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

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

#[tokio::test]
#[serial_test::serial(tun_network_changes)]
async fn direct_data_keeps_fullcone_mapping_and_releases_weak_upload_cache() {
    let manager = Manager::new();
    let (target, mut returned) = mpsc::channel(1);
    let path = DirectPath::new(Arc::new(Target(target)));
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
    assert!(path.upload(packet(&a, b"not-yet-handed-off")).is_err());
    flow_a.enable_direct_upload();
    flow_b.enable_direct_upload();
    let mut buffer = [0; 64];
    assert!(path.upload(packet(&a, b"fast-a")).is_ok());
    let (n, peer_a) = timeout(Duration::from_secs(2), first.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..n], b"fast-a");
    assert!(path.upload(packet(&b, b"fast-b")).is_ok());
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
    assert!(path.upload(packet(&a, b"upload-with-replies-blocked")).is_ok());
    let (n, _) = timeout(Duration::from_secs(2), first.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..n], b"upload-with-replies-blocked");
    let key = (a.source, first.local_addr().unwrap());
    path.uploads.get_mut(&key).unwrap().generation = network_generation().wrapping_sub(1);
    assert!(path.upload(packet(&a, b"stale-network")).is_err());
    assert!(!path.uploads.contains_key(&key));
    let key_b = (b.source, second.local_addr().unwrap());
    assert!(path.uploads.contains_key(&key_b));
    drop(flow_b);
    assert!(!path.uploads.contains_key(&key_b));
    assert!(path.upload(packet(&b, b"expired-flow")).is_err());
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
    let path = DirectPath::new(Arc::new(Target(target)));
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
    assert!(path.upload(packet(&sess, b"fake-request")).is_ok());
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
    assert!(path.upload(packet(&sess, b"blocked-quic")).is_ok());
    assert_eq!(flow.state.activity.latest_upload(), previous_upload);
    assert!(timeout(Duration::from_millis(20), server.recv_from(&mut buffer)).await.is_err());
    manager.close_all();
}
