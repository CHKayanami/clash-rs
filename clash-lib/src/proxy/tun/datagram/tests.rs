use super::*;
use std::{future::pending, net::SocketAddr, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use bytes::Bytes;
use futures::future::poll_fn;
use tokio::{sync::{mpsc, oneshot}, time::timeout};
use clash_netstack::{Packet, parse_udp_packet};
use crate::{app::dns::{MockClashResolver, query::{DnsName, QType, QueryContext}},
    proxy::utils::test_utils::noop::NoopResolver};

type Input = mpsc::Sender<StackUdpPacket>;
type Output = mpsc::Receiver<Packet>;

fn adapter(resolver: ThreadSafeDNSResolver, capacity: usize, hijack: DnsHijack)
    -> (TunDatagram, Input, Output) {
    let (input, reader) = mpsc::channel(512);
    let (writer, output) = mpsc::channel(capacity);
    let adapter = TunDatagram::new(UdpSocket::new(reader, writer),
        resolver, hijack, false, Arc::new(Vec::new()));
    (adapter, input, output)
}

fn inbound(data: Bytes, port: u16) -> StackUdpPacket {
    (data, "192.0.2.1:1234".parse::<SocketAddr>().unwrap(),
        SocketAddr::from(([198, 51, 100, 1], port))).into()
}

fn reply(data: &[u8]) -> UdpPacket {
    UdpPacket::new(Bytes::copy_from_slice(data), "198.51.100.1:443".parse::<SocketAddr>().unwrap().into(),
        "192.0.2.1:1234".parse::<SocketAddr>().unwrap().into())
}

#[tokio::test]
async fn congested_replies_do_not_block_reads_or_dns() {
    timeout(Duration::from_secs(3), async {
        let mut resolver = MockClashResolver::new();
        resolver.expect_exchange().times(32).returning(|query, _| Ok(query.wire().to_vec()));
        let (mut adapter, input, mut output) = adapter(Arc::new(resolver), 1, DnsHijack::All);
        let writer = adapter.reply_writer();
        let mut invalid = reply(b"domain");
        invalid.dst_addr = SocksAddr::Domain("adapter.test".into(), 1234);
        let mut replies = [reply(b"occupied"), reply(b"drop-one"), invalid, reply(b"drop-two")];
        submit_udp_replies(&writer, &mut replies).unwrap();
        assert!(replies[0].data.is_empty());
        assert_eq!(replies[1].data, b"drop-one"[..]);
        assert_eq!(replies[3].data, b"drop-two"[..]);
        let query = QueryContext::new(DnsName::from_domain("adapter.test").unwrap(), QType::A);
        for _ in 0..32 { input.send(inbound(Bytes::copy_from_slice(query.wire()), 53)).await.unwrap(); }
        input.send(inbound(Bytes::from_static(b"ordinary"), 443)).await.unwrap();
        let mut received = Vec::new();
        poll_fn(|cx| adapter.receive(cx, &mut received)).await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data, b"ordinary"[..]);
        while let Some(result) = adapter.dns.join_next().await { result.unwrap(); }
        let packet = output.try_recv().unwrap();
        let (_, _, range) = parse_udp_packet(packet.data()).unwrap();
        assert_eq!(&packet.data()[range], b"occupied");
        assert!(output.try_recv().is_err());
    }).await.unwrap();
}

#[tokio::test]
async fn reply_errors_preserve_prefix_and_do_not_duplicate_valid_suffix() {
    let (adapter, _input, mut output) = adapter(Arc::new(NoopResolver), 4, DnsHijack::Disabled);
    let mut mismatched = reply(b"wrong-family");
    mismatched.dst_addr = "[::1]:1234".parse::<SocketAddr>().unwrap().into();
    let mut domain = reply(b"domain");
    domain.dst_addr = SocksAddr::Domain("adapter.test".into(), 1234);
    let writer = adapter.reply_writer();
    submit_udp_replies(&writer, &mut [reply(b"first"), mismatched, domain, reply(b"last")])
        .unwrap();
    for expected in [b"first".as_slice(), b"last".as_slice()] {
        let packet = output.try_recv().unwrap();
        let (_, _, range) = parse_udp_packet(packet.data()).unwrap();
        assert_eq!(&packet.data()[range], expected);
    }
    assert!(output.try_recv().is_err());
    drop(output);
    let mut domain = reply(b"closed");
    domain.src_addr = SocksAddr::Domain("adapter.test".into(), 443);
    let error = submit_udp_replies(&writer, &mut [domain]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

struct OnDrop(Arc<AtomicBool>);
impl Drop for OnDrop { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }

#[tokio::test]
async fn pending_dns_is_bounded_and_cancelled_with_adapter() {
    let (mut adapter, input, _output) = adapter(Arc::new(NoopResolver), 4, DnsHijack::All);
    let dropped = Arc::new(AtomicBool::new(false));
    let (started, ready) = oneshot::channel();
    let signal = dropped.clone();
    adapter.dns.spawn(async move {
        let _guard = OnDrop(signal);
        let _ = started.send(());
        pending::<()>().await;
    });
    ready.await.unwrap();
    for _ in 1..MAX_PENDING_DNS { adapter.dns.spawn(pending::<()>()); }
    input.send(inbound(Bytes::from_static(b"not admitted"), 53)).await.unwrap();
    input.send(inbound(Bytes::new(), 443)).await.unwrap();
    let mut packets = Vec::new();
    timeout(Duration::from_secs(1), poll_fn(|cx| adapter.receive(cx, &mut packets)))
        .await.unwrap().unwrap();
    let packet = packets.pop().unwrap();
    assert!(packet.data.is_empty());
    assert_eq!(adapter.dns.len(), MAX_PENDING_DNS);
    drop(adapter);
    timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::Acquire) { tokio::task::yield_now().await; }
    }).await.unwrap();
}

#[tokio::test]
async fn filters_preserve_ipv6_and_shutdown_without_bridge_queues() {
    let (mut adapter, input, _output) = adapter(Arc::new(NoopResolver), 4, DnsHijack::Disabled);
    adapter.strict_route = true;
    adapter.exclude_routes = Arc::new(vec!["198.51.100.0/24".parse().unwrap()]);
    input.send(inbound(Bytes::from_static(b"excluded"), 443)).await.unwrap();
    input.send((Bytes::from_static(b"multicast"), "[::1]:1".parse().unwrap(),
        "[ff02::1]:2".parse().unwrap()).into()).await.unwrap();
    input.send((Bytes::new(), "[::1]:1".parse().unwrap(),
        "[::2]:2".parse().unwrap()).into()).await.unwrap();
    let mut packets = Vec::new();
    timeout(Duration::from_secs(1), poll_fn(|cx| adapter.receive(cx, &mut packets)))
        .await.unwrap().unwrap();
    let packet = packets.pop().unwrap();
    assert!(packet.data.is_empty());
    assert_eq!(packet.src_addr.try_into_socket_addr().unwrap(), "[::1]:1".parse().unwrap());
    drop(input);
    assert!(poll_fn(|cx| adapter.receive(cx, &mut packets)).await.is_none());
    drop(adapter);
}

#[tokio::test]
async fn custom_dns_hijack_port_never_reaches_routing() {
    use crate::config::internal::config::DnsHijackRule;
    let mut resolver = MockClashResolver::new();
    resolver.expect_exchange().once().returning(|query, _| Ok(query.wire().to_vec()));
    let hijack = DnsHijack::Rules(vec![DnsHijackRule::Any { network: Some(Network::Udp), port: 5354 }]);
    let (mut adapter, input, mut output) = adapter(Arc::new(resolver), 4, hijack);
    let query = QueryContext::new(DnsName::from_domain("adapter.test").unwrap(), QType::A);
    input.send(inbound(Bytes::copy_from_slice(query.wire()), 5354)).await.unwrap();
    input.send(inbound(Bytes::from_static(b"ordinary"), 443)).await.unwrap();
    let mut received = Vec::new();
    poll_fn(|cx| adapter.receive(cx, &mut received)).await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].data, b"ordinary"[..]);
    while let Some(result) = adapter.dns.join_next().await { result.unwrap(); }
    let packet = output.recv().await.unwrap();
    let (source, _, _) = parse_udp_packet(packet.data()).unwrap();
    assert_eq!(source.port(), 5354);
}
