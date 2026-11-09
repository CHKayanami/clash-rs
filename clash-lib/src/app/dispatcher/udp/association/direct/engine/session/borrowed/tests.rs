use super::*;
use std::{future::pending, sync::{Weak, atomic::AtomicBool}, time::Duration};
use futures::task::noop_waker;
use tokio::{net::UdpSocket, sync::{Semaphore, oneshot}};
use clash_netstack::{Packet, UdpPacket as StackUdpPacket, parse_udp_packet};
use crate::proxy::{AnyOutboundDatagram, direct::native::NativeDatagram};
use crate::{app::dispatcher::{Manager, TrackGuard, TrackerInfo,
    udp::{association::{AssociationConfig, Registration, WorkerGuard, task::Task, flow::ReplyActivity}, replies}},
    session::Session as ClientSession};

#[tokio::test]
async fn synchronous_batch_borrows_payload_and_pending_copy_survives_owner_drop() {
    let manager = Manager::new();
    let (events, _events) = mpsc::unbounded_channel();
    let client = ClientSession::default();
    let flow = Arc::new(FlowState { id: 1, source: "192.0.2.1:1234".parse().unwrap(),
        original: "198.51.100.1:9000".parse::<SocketAddr>().unwrap().into(),
        target: "198.51.100.1:9000".parse::<SocketAddr>().unwrap().into(), aliases: Vec::new(),
        tracker: Arc::new(TrackerInfo::new(&client, None)), activity: Arc::new(ReplyActivity::new()),
        closed: Arc::new(AtomicBool::new(false)), events: events.clone(), _guard: TrackGuard::new(1, manager.clone()) });
    let (sender, _receiver) = replies::channel(16);
    let config = AssociationConfig { replies: sender, direct: None, closed_flows: events,
        manager, allow_quic: Arc::new(AtomicBool::new(true)), timeout: Duration::from_secs(60),
        capacity: Arc::new(Semaphore::new(1)) };
    let (commands, receiver) = mpsc::channel(1);
    let mut state = AssociationState::new(receiver, &config, flow.source, None, None, true);
    let (_close, close_rx) = oneshot::channel();
    let (reply, registered) = oneshot::channel();
    commands.send(Registration { state: flow.clone(), close_rx, reply }).await.unwrap();
    let waker = noop_waker();
    assert!(state.poll_control(&mut Context::from_waker(&waker)));
    registered.await.unwrap().unwrap();
    let mut uploads = Vec::new();
    for data in [b"first".as_slice(), b"second".as_slice()] {
        let destination = "198.51.100.1:9000".parse().unwrap();
        let frame: Packet = StackUdpPacket::from((Bytes::copy_from_slice(data), flow.source, destination)).encode().unwrap();
        let (_, _, payload) = parse_udp_packet(frame.data()).unwrap();
        uploads.push(Upload { association: 1, slot: usize::MAX, id: 1, source: flow.source, destination,
            frame, payload, segmentation: None });
    }
    let refs = [&uploads[0], &uploads[1]];
    let mut batch = Batch::new();
    let mut cursor = 0;
    batch.collect(&mut state, &refs, &mut cursor, Instant::now());
    assert_eq!(cursor, 2);
    assert_eq!(batch.owner_count, 1);
    assert_eq!(batch.slices[0].payload.as_ptr(), uploads[0].data().as_ptr());
    // Completing a prefix accounts only actual successful bytes. A concurrent
    // close cannot invalidate the completion's pinned flow owner.
    flow.close();
    batch.complete(&mut state, 1, Instant::now());
    assert_eq!(flow.tracker.upload_total(), 5);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let datagram = NativeDatagram::new(socket).unwrap();
    let datagram = AnyOutboundDatagram::new(Box::new(datagram));
    let (cold, receiver) = mpsc::channel(2);
    let (_task, owner) = Task::owned();
    let (close, _closed) = oneshot::channel();
    let lifetime = DirectLifetime {
        _permit: config.capacity.clone().acquire_owned().await.unwrap(),
        _guard: config.manager.register_udp_association(1, close),
        _cleanup: WorkerGuard(Weak::new(), 1), _owner: owner,
    };
    let mut session = Session::new(1, datagram, state, receiver,
        Box::pin(pending()), lifetime, false);
    // A route worker can queue new data while the borrowed syscall is in
    // progress. Its arrival must not revoke or overtake the admitted suffix.
    cold.send(uploads[0].retain()).await.unwrap();
    batch.retain(&mut session, 1, Instant::now());
    assert!(!session.cold.is_empty());
    assert_eq!(session.sending.len(), 1);
    session.state.sent_batch([6], Instant::now());
    assert_eq!(flow.tracker.upload_total(), 11);
    assert_eq!(session.sending.complete(), 6);
    // The same rule applies after a GSO send completed only its prefix.
    session.retain_admitted(&uploads[1], &flow, 2, Some(2), Instant::now());
    let (group, offset) = session.aggregate.as_ref().unwrap();
    assert_eq!(*offset, 0);
    assert_eq!(&group.packet.data[..], b"cond");
    assert_eq!(group.packet.dst_addr, flow.target);
    let retained = uploads[1].retain();
    assert_ne!(retained.packet.data.as_ptr(), uploads[1].data().as_ptr());
    drop(batch);
    drop(uploads);
    assert_eq!(&retained.packet.data[..], b"second");
}
