use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use futures::{FutureExt, StreamExt, task::{AtomicWaker, noop_waker}};
use smoltcp::wire::{IpAddress, Ipv4Packet, TcpPacket};
use clash_netstack::{NetStack, TcpDriver};
use super::*;
use crate::proxy::tun::{datagram, packet::tests::tcp_syn, system_stack::SystemTcpNat};

struct MockIo {
    input: VecDeque<BytesMut>,
    pending: Vec<Packet>,
    written: Arc<Mutex<Vec<Bytes>>>,
    blocked: Arc<AtomicBool>,
    wake: Arc<AtomicWaker>,
}

impl PacketIo for MockIo {
    fn poll_receive(&mut self, _: &mut Context<'_>, packets: &mut Vec<Packet>) -> Poll<io::Result<usize>> {
        match self.input.pop_front() {
            Some(packet) => { packets.push(Packet::from(packet)); Poll::Ready(Ok(1)) },
            None => Poll::Pending,
        }
    }
    fn poll_send(&mut self, cx: &mut Context<'_>, packets: &mut Vec<Packet>, _: &mut Vec<OwnedSemaphorePermit>) -> Poll<io::Result<()>> {
        if self.pending.is_empty() { self.pending.append(packets); }
        self.wake.register(cx.waker());
        if self.blocked.load(Ordering::Acquire) { return Poll::Pending; }
        self.written.lock().unwrap().extend(self.pending.drain(..).map(Packet::into_bytes));
        Poll::Ready(Ok(()))
    }
}

fn syn(port: u16) -> BytesMut {
    let mut packet = tcp_syn(false);
    let mut tcp = TcpPacket::new_unchecked(&mut packet[20..]);
    tcp.set_src_port(port);
    tcp.fill_checksum(&IpAddress::from(Ipv4Addr::new(192, 0, 2, 2)), &IpAddress::from(Ipv4Addr::new(198, 51, 100, 2)));
    packet
}

#[tokio::test]
async fn blocked_write_keeps_tcp_ingress_live_and_never_replays_a_batch() {
    let (tcp, mut listener) = TcpDriver::new(1500, DEVICE_BATCH).unwrap();
    let (stack, _, _udp) = NetStack::new_with_protocols(false, true);
    let (sink, stream) = stack.split();
    let (_replies, receive) = packet_queue::channel();
    let packets = PacketDispatcher { enable_tcp: true, system_tcp: false, ipv4: None, ipv6: None,
        nat: Arc::new(SystemTcpNat::new()), direct: datagram::direct_path(None), uploads: Default::default() };
    let written = Arc::new(Mutex::new(Vec::new()));
    let blocked = Arc::new(AtomicBool::new(true));
    let wake = Arc::new(AtomicWaker::new());
    let io = MockIo { input: [syn(10001), syn(10002)].into(), pending: Vec::new(),
        written: written.clone(), blocked: blocked.clone(), wake: wake.clone() };
    let mut driver = DeviceLoop::new(io, Protocols { tcp: Some(tcp), sink, stream }, packets, receive, |_| false);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..4 { assert!(!matches!(driver.poll(&mut cx), Poll::Ready(Err(_)))); }
    let first = listener.next().now_or_never().unwrap().unwrap();
    let second = listener.next().now_or_never().unwrap().unwrap();
    assert_eq!(first.local_addr().port(), 10001);
    assert_eq!(second.local_addr().port(), 10002);
    assert!(written.lock().unwrap().is_empty());
    blocked.store(false, Ordering::Release);
    wake.wake();
    for _ in 0..4 { assert!(!matches!(driver.poll(&mut cx), Poll::Ready(Err(_)))); }
    let written = written.lock().unwrap();
    assert_eq!(written.len(), 2, "each SYN response must be written exactly once");
    for packet in written.iter() {
        let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack());
    }
}

#[tokio::test]
async fn pending_device_write_holds_external_byte_credits() {
    use tokio::time::{Duration, timeout};
    let (stack, _, _udp) = NetStack::new_with_protocols(false, false);
    let (sink, stream) = stack.split();
    let (replies, receive) = packet_queue::channel();
    let packets = PacketDispatcher { enable_tcp: false, system_tcp: false, ipv4: None, ipv6: None,
        nat: Arc::new(SystemTcpNat::new()), direct: datagram::direct_path(None), uploads: Default::default() };
    let blocked = Arc::new(AtomicBool::new(true));
    let io = MockIo { input: VecDeque::new(), pending: Vec::new(), written: Arc::default(),
        blocked: blocked.clone(), wake: Arc::new(AtomicWaker::new()) };
    let mut driver = DeviceLoop::new(io, Protocols { tcp: None, sink, stream }, packets, receive, |_| false);
    replies.send(BytesMut::from(&vec![0; 4 * 1024 * 1024][..])).await.unwrap();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(driver.poll(&mut cx).is_pending());
    assert!(timeout(Duration::from_millis(5), replies.send(BytesMut::from(&b"next"[..]))).await.is_err());
    blocked.store(false, Ordering::Release);
    assert!(!matches!(driver.poll(&mut cx), Poll::Ready(Err(_))));
    timeout(Duration::from_secs(1), replies.send(BytesMut::from(&b"next"[..]))).await.unwrap().unwrap();
    drop(driver);
    assert!(replies.send(BytesMut::from(&b"closed"[..])).await.is_err());
}

mod saturation;
mod batch;
