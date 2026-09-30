use super::*;
use std::{collections::VecDeque, sync::Arc};

#[derive(Default)]
struct Probe {
    ready_pending: bool,
    flush_pending: bool,
    flush_error: bool,
    ready_error: bool,
    send_error: bool,
    closed: bool,
    sent: Vec<UdpPacket>,
    received: VecDeque<UdpPacket>,
}

struct TestDatagram(Arc<Mutex<Probe>>);

impl Stream for TestDatagram {
    type Item = UdpPacket;
    fn poll_next(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<UdpPacket>> {
        let mut probe = self.0.lock();
        if let Some(packet) = probe.received.pop_front() {
            Poll::Ready(Some(packet))
        } else if probe.closed {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

impl Sink<UdpPacket> for TestDatagram {
    type Error = io::Error;
    fn poll_ready(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut probe = self.0.lock();
        if std::mem::take(&mut probe.ready_error) {
            Poll::Ready(Err(io::Error::other("ready failed")))
        } else if probe.ready_pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        let mut probe = self.0.lock();
        assert!(
            !probe.ready_pending,
            "must poll readiness before start_send"
        );
        if std::mem::take(&mut probe.send_error) {
            return Err(io::Error::other("send failed"));
        }
        probe.sent.push(packet);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let mut probe = self.0.lock();
        if std::mem::take(&mut probe.flush_error) {
            Poll::Ready(Err(io::Error::other("flush failed")))
        } else if probe.flush_pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

fn fixture() -> (ShadowsocksUdpIo, Arc<Mutex<Probe>>, SocketAddr) {
    let probe = Arc::new(Mutex::new(Probe::default()));
    let io = ShadowsocksUdpIo::new(AnyOutboundDatagram::dynamic(TestDatagram(
        probe.clone(),
    )));
    (io, probe, "127.0.0.1:1000".parse().unwrap())
}

fn assert_sent(result: Poll<io::Result<usize>>, expected: usize) {
    assert!(matches!(result, Poll::Ready(Ok(n)) if n == expected));
}

#[test]
fn pending_send_preserves_packet_and_allows_receives() {
    let (io, probe, target) = fixture();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    probe.lock().ready_pending = true;
    assert!(io.poll_send_to(&mut cx, b"request", target).is_pending());
    assert!(probe.lock().sent.is_empty());
    {
        let mut state = probe.lock();
        state.ready_pending = false;
        state.flush_pending = true;
        state.received.push_back(UdpPacket {
            data: Bytes::from_static(b"reply"),
            src_addr: target.into(),
            dst_addr: SocksAddr::any_ipv4(),
            inbound_user: None,
        });
    }
    assert!(io.poll_send_to(&mut cx, b"request", target).is_pending());
    assert!(io.poll_send_to(&mut cx, b"request", target).is_pending());
    assert_eq!(probe.lock().sent.len(), 1);
    let mut bytes = [0; 16];
    let mut received = ReadBuf::new(&mut bytes);
    assert!(matches!(
        io.poll_recv(&mut cx, &mut received),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(received.filled(), b"reply");
    probe.lock().flush_pending = false;
    assert_sent(io.poll_send_to(&mut cx, b"request", target), 7);
    assert_eq!(probe.lock().sent.len(), 1);
}

#[test]
fn cancelled_send_flushes_before_new_destination_or_length() {
    for changed_destination in [false, true] {
        let (io, probe, target) = fixture();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        probe.lock().flush_pending = true;
        assert!(io.poll_send_to(&mut cx, b"old", target).is_pending());
        probe.lock().flush_pending = false;
        let next_target = if changed_destination {
            "127.0.0.1:1001".parse().unwrap()
        } else {
            target
        };
        let next: &[u8] = if changed_destination {
            b"new"
        } else {
            b"longer"
        };
        assert_sent(io.poll_send_to(&mut cx, next, next_target), next.len());
        let state = probe.lock();
        assert_eq!(state.sent.len(), 2);
        assert_eq!(state.sent[0].data, b"old"[..]);
        assert_eq!(state.sent[1].data, next);
        assert_eq!(state.sent[1].dst_addr, next_target.into());
    }
}

#[test]
fn send_errors_clear_state_and_allow_retry() {
    for phase in ["ready", "send", "flush", "pending_flush"] {
        let (io, probe, target) = fixture();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        if phase == "pending_flush" {
            probe.lock().flush_pending = true;
            assert!(io.poll_send_to(&mut cx, b"first", target).is_pending());
        }
        {
            let mut state = probe.lock();
            state.ready_error = phase == "ready";
            state.send_error = phase == "send";
            state.flush_error = phase == "flush" || phase == "pending_flush";
            state.flush_pending = false;
        }
        assert!(matches!(
            io.poll_send_to(&mut cx, b"first", target),
            Poll::Ready(Err(_))
        ));
        assert!(io.state.lock().queued.is_none());
        assert_sent(io.poll_send_to(&mut cx, b"retry", target), 5);
        assert_eq!(probe.lock().sent.last().unwrap().data, b"retry"[..]);
    }
}

#[test]
fn zero_length_pending_send_and_receive_truncation() {
    let (io, probe, target) = fixture();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    probe.lock().flush_pending = true;
    assert!(io.poll_send_to(&mut cx, b"", target).is_pending());
    probe.lock().flush_pending = false;
    assert_sent(io.poll_send_to(&mut cx, b"", target), 0);
    assert_eq!(probe.lock().sent.len(), 1);
    probe.lock().received.push_back(UdpPacket {
        data: Bytes::from_static(b"oversized"),
        src_addr: target.into(),
        dst_addr: SocksAddr::any_ipv4(),
        inbound_user: None,
    });
    let mut bytes = [0; 3];
    let mut received = ReadBuf::new(&mut bytes);
    assert!(matches!(
        io.poll_recv(&mut cx, &mut received),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(received.filled(), b"ove");
    received.clear();
    assert!(io.poll_recv(&mut cx, &mut received).is_pending());
    probe.lock().closed = true;
    assert!(
        matches!(io.poll_recv(&mut cx, &mut received), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
}
