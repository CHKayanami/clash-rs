use super::*;
use std::{future::pending, net::SocketAddr, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use bytes::Bytes;
use futures::{SinkExt, StreamExt, future::poll_fn};
use tokio::{sync::mpsc, time::timeout};
use watfaq_netstack::{Packet, parse_udp_packet};
use crate::{app::dns::{MockClashResolver, query::{DnsName, QType, QueryContext}},
    proxy::utils::test_utils::noop::NoopResolver};

type Input = mpsc::Sender<StackUdpPacket>;
type Output = mpsc::Receiver<Packet>;

fn adapter(resolver: ThreadSafeDNSResolver, capacity: usize, hijack: DnsHijack)
    -> (TunDatagram, Input, Output, oneshot::Receiver<()>) {
    let (input, reader) = mpsc::channel(512);
    let (writer, output) = mpsc::channel(capacity);
    let (adapter, finished) = TunDatagram::new(UdpSocket::new(reader, writer),
        resolver, hijack, false, Arc::new(Vec::new()));
    (adapter, input, output, finished)
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
        let (mut adapter, input, mut output, _finished) = adapter(Arc::new(resolver), 1, DnsHijack::All);
        adapter.send(reply(b"occupied")).await.unwrap();
        let mut replies = PacketBatch::default();
        replies.push(reply(b"drop-one")).unwrap();
        replies.push(reply(b"drop-two")).unwrap();
        let result = poll_fn(|cx| adapter.poll_send_batch(cx, &mut replies)).await;
        assert_eq!(result.sent, 2); // Deliberate congestion drops are consumed.
        assert!(result.error.is_none());
        let query = QueryContext::new(DnsName::from_domain("adapter.test").unwrap(), QType::A);
        for _ in 0..32 { input.send(inbound(Bytes::copy_from_slice(query.wire()), 53)).await.unwrap(); }
        input.send(inbound(Bytes::from_static(b"ordinary"), 443)).await.unwrap();
        let mut received = Vec::new();
        poll_fn(|cx| adapter.poll_recv_batch(cx, &mut received)).await.unwrap();
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
    let (mut adapter, _input, mut output, _finished) = adapter(Arc::new(NoopResolver), 4, DnsHijack::Disabled);
    let mut batch = PacketBatch::default();
    batch.push(reply(b"first")).unwrap();
    let mut bad = reply(b"bad");
    bad.dst_addr = "[::1]:1234".parse::<SocketAddr>().unwrap().into();
    batch.push(bad).unwrap();
    batch.push(reply(b"last")).unwrap();
    let result = poll_fn(|cx| adapter.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 1);
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::InvalidInput);
    assert!(!result.fatal);
    batch.complete();
    batch.complete();
    let result = poll_fn(|cx| adapter.poll_send_batch(cx, &mut batch)).await;
    assert_eq!(result.sent, 1);
    assert!(result.error.is_none());
    for expected in [b"first".as_slice(), b"last".as_slice()] {
        let packet = output.try_recv().unwrap();
        let (_, _, range) = parse_udp_packet(packet.data()).unwrap();
        assert_eq!(&packet.data()[range], expected);
    }
    assert!(output.try_recv().is_err());
    drop(output);
    let result = poll_fn(|cx| adapter.poll_send_batch(cx, &mut batch)).await;
    assert!(result.fatal);
    assert_eq!(result.error.unwrap().kind(), io::ErrorKind::BrokenPipe);
}

struct OnDrop(Arc<AtomicBool>);
impl Drop for OnDrop { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }

#[tokio::test]
async fn pending_dns_is_bounded_and_cancelled_with_adapter() {
    let (mut adapter, input, _output, finished) = adapter(Arc::new(NoopResolver), 4, DnsHijack::All);
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
    let packet = timeout(Duration::from_secs(1), adapter.next()).await.unwrap().unwrap();
    assert!(packet.data.is_empty());
    assert_eq!(adapter.dns.len(), MAX_PENDING_DNS);
    drop(adapter);
    assert!(finished.await.is_err());
    timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::Acquire) { tokio::task::yield_now().await; }
    }).await.unwrap();
}

#[tokio::test]
async fn filters_preserve_ipv6_and_shutdown_without_bridge_queues() {
    let (mut adapter, input, _output, finished) = adapter(Arc::new(NoopResolver), 4, DnsHijack::Disabled);
    adapter.strict_route = true;
    adapter.exclude_routes = Arc::new(vec!["198.51.100.0/24".parse().unwrap()]);
    input.send(inbound(Bytes::from_static(b"excluded"), 443)).await.unwrap();
    input.send((Bytes::from_static(b"multicast"), "[::1]:1".parse().unwrap(),
        "[ff02::1]:2".parse().unwrap()).into()).await.unwrap();
    input.send((Bytes::new(), "[::1]:1".parse().unwrap(),
        "[::2]:2".parse().unwrap()).into()).await.unwrap();
    let packet = timeout(Duration::from_secs(1), adapter.next()).await.unwrap().unwrap();
    assert!(packet.data.is_empty());
    assert_eq!(packet.src_addr.try_into_socket_addr().unwrap(), "[::1]:1".parse().unwrap());
    drop(input);
    assert!(adapter.next().await.is_none());
    drop(adapter);
    assert!(finished.await.is_err());
}

#[tokio::test]
async fn sink_errors_do_not_consume_following_batch_packets() {
    for domain_address in [false, true] {
        let (mut adapter, _input, mut output, _finished) = adapter(Arc::new(NoopResolver), 4, DnsHijack::Disabled);
        let mut bad = reply(b"bad");
        bad.dst_addr = if domain_address {
            SocksAddr::Domain("adapter.test".into(), 1234)
        } else {
            "[::1]:1234".parse::<SocketAddr>().unwrap().into()
        };
        let error = Pin::new(&mut adapter).start_send(bad).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        Pin::new(&mut adapter).start_send(reply(b"single")).unwrap();
        // Intentionally mix APIs without flushing the Sink first.
        let mut batch = PacketBatch::default();
        batch.push(reply(b"batch-first")).unwrap();
        batch.push(reply(b"batch-last")).unwrap();
        let result = poll_fn(|cx| adapter.poll_send_batch(cx, &mut batch)).await;
        assert_eq!(result.sent, 2);
        assert!(result.error.is_none());
        assert!(!result.fatal);
        poll_fn(|cx| Pin::new(&mut adapter).poll_flush(cx)).await.unwrap();
        for expected in [b"single".as_slice(), b"batch-first".as_slice(), b"batch-last".as_slice()] {
            let packet = output.try_recv().unwrap();
            let (_, _, range) = parse_udp_packet(packet.data()).unwrap();
            assert_eq!(&packet.data()[range], expected);
        }
        assert!(output.try_recv().is_err());
        drop(output);
        let error = Pin::new(&mut adapter).start_send(reply(b"closed")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}
