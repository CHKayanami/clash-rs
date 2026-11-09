use clash_netstack::UdpPacket as StackUdpPacket;
use super::*;

#[tokio::test]
async fn saturated_tcp_queues_do_not_stop_udp_uploads() {
    for system_tcp in [false, true] {
        let (tcp, _listener) = TcpDriver::new(1500, 1).unwrap();
        let (stack, _, udp) = NetStack::new_with_protocols(false, true);
        let (sink, stream) = stack.split();
        let (mut udp, _send) = udp.split();
        let (_replies, receive) = packet_queue::channel();
        let packets = PacketDispatcher { enable_tcp: true, system_tcp, ipv6: None,
            ipv4: Some((Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2), 1234)),
            nat: Arc::new(SystemTcpNat::new()), direct: datagram::direct_path(None), uploads: Default::default() };
        let datagram = StackUdpPacket::from((Bytes::from_static(b"upload after congestion"),
            "192.0.2.2:53000".parse().unwrap(), "198.51.100.2:9000".parse().unwrap()))
            .encode().unwrap();
        let mut input: VecDeque<_> = (10000..10128).map(syn).collect();
        input.push_back(BytesMut::from(datagram.data()));
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = MockIo { input, pending: Vec::new(), written: written.clone(),
            blocked: Arc::new(AtomicBool::new(true)), wake: Arc::new(AtomicWaker::new()) };
        let mut driver = DeviceLoop::new(io,
            Protocols { tcp: (!system_tcp).then_some(tcp), sink, stream }, packets, receive, |_| false);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..256 { assert!(!matches!(driver.poll(&mut cx), Poll::Ready(Err(_)))); }
        assert!(driver.io.input.is_empty(), "TCP saturation must not gate device reads");
        assert!(written.lock().unwrap().is_empty(), "the writer must remain blocked");
        let datagram = udp.recv().now_or_never().flatten().expect("UDP upload was starved by TCP");
        assert_eq!(datagram.data.data(), b"upload after congestion");
    }
}

#[tokio::test]
async fn buffered_tcp_bursts_remain_bounded_without_polling() {
    let (mut tcp, _listener) = TcpDriver::new(1500, 1).unwrap();
    for port in 10000..10200 { tcp.receive(syn(port).into()).unwrap(); }
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(!matches!(tcp.poll(&mut cx), Poll::Ready(Err(_))));
    let mut replies = 0;
    for _ in 0..256 {
        if tcp.take_output().is_some() { replies += 1; }
        assert!(!matches!(tcp.poll(&mut cx), Poll::Ready(Err(_))));
    }
    // Only the bounded first ingress batch was admitted, not all 200 SYNs.
    assert_eq!(replies, DEVICE_BATCH);
}
