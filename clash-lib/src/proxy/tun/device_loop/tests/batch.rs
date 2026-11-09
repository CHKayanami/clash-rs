use tokio::{task::{consume_budget, coop::has_budget_remaining}, time::{Duration, timeout}};
use super::*;

#[tokio::test]
async fn external_batch_preserves_fifo_with_limited_cooperative_budget() {
    tokio::spawn(async {
        let (stack, _, _udp) = NetStack::new_with_protocols(false, false);
        let (sink, stream) = stack.split();
        let (replies, receive) = packet_queue::channel();
        let packets = PacketDispatcher { enable_tcp: false, system_tcp: false, ipv4: None, ipv6: None,
            nat: Arc::new(SystemTcpNat::new()), direct: datagram::direct_path(None), uploads: Default::default() };
        let io = MockIo { input: VecDeque::new(), pending: Vec::new(), written: Arc::default(),
            blocked: Arc::new(AtomicBool::new(true)), wake: Arc::new(AtomicWaker::new()) };
        let mut driver = DeviceLoop::new(io, Protocols { tcp: None, sink, stream }, packets, receive, |_| false);
        for i in 0..DEVICE_BATCH { replies.send(BytesMut::from(&[i as u8][..])).await.unwrap(); }
        tokio::task::yield_now().await;
        // Leave less budget than one packet-at-a-time batch needs. A bulk
        // receive should still collect the complete available batch in FIFO.
        for _ in 0..100 { consume_budget().await; }
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        driver.fill_output(&mut cx).unwrap();
        assert_eq!(driver.output.len(), DEVICE_BATCH);
        for (i, packet) in driver.output.iter().enumerate() { assert_eq!(&packet[..], &[i as u8]); }
        assert!(has_budget_remaining());
    }).await.unwrap();
}

#[tokio::test]
async fn prefetched_and_writing_replies_keep_the_same_byte_budget() {
    let (stack, _, _udp) = NetStack::new_with_protocols(false, false);
    let (sink, stream) = stack.split();
    let (replies, receive) = packet_queue::channel();
    let packets = PacketDispatcher { enable_tcp: false, system_tcp: false, ipv4: None, ipv6: None,
        nat: Arc::new(SystemTcpNat::new()), direct: datagram::direct_path(None), uploads: Default::default() };
    let blocked = Arc::new(AtomicBool::new(true));
    let io = MockIo { input: VecDeque::new(), pending: Vec::new(), written: Arc::default(),
        blocked: blocked.clone(), wake: Arc::new(AtomicWaker::new()) };
    let mut driver = DeviceLoop::new(io, Protocols { tcp: None, sink, stream }, packets, receive, |_| false);
    driver.local.extend((0..DEVICE_BATCH).map(|_| Bytes::from_static(b"local")));
    for _ in 0..DEVICE_BATCH { replies.send(BytesMut::from(&vec![0; 128 * 1024][..])).await.unwrap(); }
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(driver.poll(&mut cx).is_pending());
    assert_eq!(driver.external.len(), DEVICE_BATCH / 2);
    assert_eq!(driver.credits.len(), DEVICE_BATCH / 2);
    assert!(timeout(Duration::from_millis(5), replies.send(BytesMut::from(&b"next"[..]))).await.is_err());
    blocked.store(false, Ordering::Release);
    assert!(!matches!(driver.poll(&mut cx), Poll::Ready(Err(_))));
    assert!(driver.external.is_empty());
    timeout(Duration::from_secs(1), replies.send(BytesMut::from(&vec![0; 4 * 1024 * 1024][..])))
        .await.unwrap().unwrap();
}
