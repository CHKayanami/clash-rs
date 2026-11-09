use super::*;
use std::{net::SocketAddr, sync::{Weak, atomic::{AtomicBool, AtomicUsize, Ordering}}, time::Duration};
use futures::{task::noop_waker};
use tokio::{net::UdpSocket, sync::{Semaphore, oneshot}, time::timeout};
use crate::{app::dispatcher::Manager, proxy::{AnyOutboundDatagram, direct::native::NativeDatagram, datagram::batch::MAX_BATCH_PACKETS}};
use super::super::super::{AssociationConfig, DirectLifetime, Outgoing, WorkerGuard, state::AssociationState, task::Task};
use super::super::super::super::replies;

struct Fixture {
    sender: Sender,
    engine: Engine,
    manager: Arc<Manager>,
    cold: Vec<mpsc::Sender<Outgoing>>,
    tasks: Vec<Task>,
    polled: Arc<AtomicUsize>,
}
impl Fixture {
    fn new() -> Self {
        let (sender, engine) = channel(None);
        Self { sender, engine, manager: Manager::new(), cold: Vec::new(), tasks: Vec::new(), polled: Arc::new(AtomicUsize::new(0)) }
    }
    async fn socket(&mut self, id: u64) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (outgoing, cold) = mpsc::channel(64);
        let (_control, commands) = mpsc::channel(64);
        let (reply, _replies) = replies::channel(64);
        let (events, _events) = mpsc::unbounded_channel();
        let capacity = Arc::new(Semaphore::new(1));
        let config = AssociationConfig { replies: reply, direct: None, closed_flows: events,
            manager: self.manager.clone(), allow_quic: Arc::new(AtomicBool::new(true)),
            timeout: Duration::from_secs(60), capacity: capacity.clone() };
        let state = AssociationState::new(commands, &config, "192.0.2.2:1234".parse().unwrap(), None, None, true);
        let (task, owner) = Task::owned();
        let cancel = owner.cancel.clone();
        let (close, closed) = oneshot::channel();
        let guard = self.manager.register_udp_association(id, close);
        let mut closed = Box::pin(async move { tokio::select! { _ = cancel.cancelled() => {}, _ = closed => {} } });
        let polled = self.polled.clone();
        let closed = Box::pin(poll_fn(move |cx| { polled.fetch_add(1, Ordering::Relaxed); closed.as_mut().poll(cx) }));
        let datagram = AnyOutboundDatagram::new(Box::new(NativeDatagram::new(socket).unwrap()));
        let lifetime = DirectLifetime { _permit: capacity.acquire_owned().await.unwrap(), _guard: guard,
            _cleanup: WorkerGuard(Weak::new(), id), _owner: owner };
        self.sender.install(Session::new(id, datagram, state, cold, closed, lifetime, false)).unwrap();
        self.cold.push(outgoing); self.tasks.push(task);
        address
    }
}

#[tokio::test]
async fn busy_direct_io_leaves_the_parent_budget_available_for_tun_output() {
    let mut fixture = Fixture::new();
    let address = fixture.socket(1).await;
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..32 { peer.send_to(&[0x5a; 512], address).await.unwrap(); }
    let (ready, mut output) = mpsc::channel(1);
    ready.try_send(1u8).unwrap();
    tokio::spawn(async move {
        timeout(Duration::from_secs(2), poll_fn(|cx| {
            fixture.engine.poll(cx, Instant::now());
            if fixture.engine.pending_frames == 0 { return Poll::Pending; }
            assert!(tokio::task::coop::has_budget_remaining());
            assert_eq!(output.poll_recv(cx), Poll::Ready(Some(1)));
            assert!(fixture.engine.pending_frames <= MAX_BATCH_PACKETS);
            let group = fixture.engine.take_reply().unwrap();
            assert_eq!(group.packet.data.as_ref(), &[0x5a; 512]);
            assert_eq!(group.packet.dst_addr.to_string(), "192.0.2.2:1234");
            Poll::Ready(())
        })).await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn reply_backpressure_is_bounded_and_cancellation_releases_paused_owners() {
    let mut fixture = Fixture::new();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Each session retains one native receive batch. Its initial size is
    // adaptive on Linux, so populate sessions until the real watermark fills.
    timeout(Duration::from_secs(2), async {
        let mut id = 1;
        while fixture.engine.pending_frames < PENDING_FRAMES {
            let address = fixture.socket(id).await;
            for _ in 0..MAX_BATCH_PACKETS { peer.send_to(&[0x5a; 64], address).await.unwrap(); }
            poll_fn(|cx| {
                fixture.engine.poll(cx, Instant::now());
                if fixture.engine.entries[&id].session.replies.is_empty() { return Poll::Pending; }
                Poll::Ready(())
            }).await;
            id += 1;
        }
        // Install another ready socket after filling the watermark. It must
        // be paused rather than consuming more receive storage.
        let address = fixture.socket(id).await;
        peer.send_to(&[0x5a; 64], address).await.unwrap();
        poll_fn(|cx| {
            fixture.engine.poll(cx, Instant::now());
            if !fixture.engine.blocked.contains_key(&id) { return Poll::Pending; }
            Poll::Ready(())
        }).await;
    }).await.unwrap();
    assert!(fixture.engine.pending_frames <= PENDING_FRAMES + 16);
    assert!(fixture.engine.pending_bytes <= PENDING_BYTES);
    assert!(!fixture.engine.blocked.is_empty() || !fixture.engine.ready.is_empty() || !fixture.engine.local.is_empty());
    for task in &fixture.tasks { task.abort(); }
    timeout(Duration::from_secs(2), poll_fn(|cx| {
        fixture.engine.poll(cx, Instant::now());
        if !fixture.engine.entries.is_empty() { cx.waker().wake_by_ref(); return Poll::Pending; }
        Poll::Ready(())
    })).await.unwrap();
    assert_eq!(fixture.engine.pending_frames, 0);
    assert_eq!(fixture.engine.pending_bytes, 0);
    assert!(fixture.engine.outputs.is_empty());
    assert!(fixture.engine.blocked.is_empty());
    assert!(fixture.tasks.iter().all(Task::is_finished));
}

#[test]
fn an_idle_engine_arms_events_without_consuming_work_or_spinning() {
    let (_sender, mut engine) = channel(None);
    let wake = noop_waker();
    let mut cx = Context::from_waker(&wake);
    for _ in 0..8 { assert!(!engine.poll(&mut cx, Instant::now())); }
}

#[tokio::test]
async fn replies_keep_one_native_batch_contiguous_then_rotate_to_the_next_flow() {
    let mut fixture = Fixture::new();
    let first = fixture.socket(1).await;
    let second = fixture.socket(2).await;
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (address, marker) in [(first, 1u8), (second, 2u8)] {
        for _ in 0..MAX_BATCH_PACKETS { peer.send_to(&[marker; 64], address).await.unwrap(); }
    }
    timeout(Duration::from_secs(2), poll_fn(|cx| {
        fixture.engine.poll(cx, Instant::now());
        if fixture.engine.outputs.len() < 2 { return Poll::Pending; }
        Poll::Ready(())
    })).await.unwrap();
    let first_id = *fixture.engine.outputs.front().unwrap();
    let first_count = fixture.engine.entries[&first_id].session.replies.len().min(MAX_BATCH_PACKETS);
    assert!(first_count > 0);
    let first = fixture.engine.take_reply().unwrap().packet.data[0];
    for _ in 1..first_count {
        assert_eq!(fixture.engine.take_reply().unwrap().packet.data[0], first);
    }
    let second_id = *fixture.engine.outputs.front().unwrap();
    assert_ne!(first_id, second_id);
    let second_count = fixture.engine.entries[&second_id].session.replies.len().min(MAX_BATCH_PACKETS);
    assert!(second_count > 0);
    for _ in 0..second_count {
        assert_ne!(fixture.engine.take_reply().unwrap().packet.data[0], first);
    }
    assert!(fixture.engine.take_reply().is_none());
}

#[tokio::test]
async fn local_service_covers_an_already_queued_external_event() {
    let mut fixture = Fixture::new(); fixture.socket(1).await;
    let wake = noop_waker(); let mut cx = Context::from_waker(&wake);
    fixture.engine.poll(&mut cx, Instant::now());
    fixture.polled.store(0, Ordering::Relaxed);
    fixture.engine.entries[&1].ready.schedule();
    fixture.engine.schedule_local(1);
    fixture.engine.poll(&mut cx, Instant::now());
    assert_eq!(fixture.polled.load(Ordering::Relaxed), 1);
    assert!(fixture.engine.local.is_empty()); assert!(fixture.engine.ready.is_empty());
}

#[tokio::test]
async fn recycled_slot_rejects_the_previous_association() {
    let mut fixture = Fixture::new(); fixture.socket(1).await;
    let wake = noop_waker(); let mut cx = Context::from_waker(&wake);
    fixture.engine.poll(&mut cx, Instant::now());
    let location = fixture.engine.entries[&1].session.location.clone();
    let slot = location.load(Ordering::Acquire);
    fixture.engine.remove(1);
    assert_eq!(location.load(Ordering::Acquire), usize::MAX);
    fixture.socket(2).await;
    fixture.engine.poll(&mut cx, Instant::now());
    assert_eq!(fixture.engine.entries[&2].session.location.load(Ordering::Acquire), slot);
    assert!(fixture.engine.entries.at_mut(slot, 1).is_none());
    assert!(fixture.engine.entries.at_mut(slot, 2).is_some());
}

#[tokio::test]
async fn control_is_rechecked_only_after_a_new_event() {
    let mut fixture = Fixture::new(); fixture.socket(1).await;
    let wake = noop_waker(); let mut cx = Context::from_waker(&wake);
    fixture.engine.poll(&mut cx, Instant::now());
    fixture.polled.store(0, Ordering::Relaxed);
    fixture.engine.schedule_local(1);
    fixture.engine.poll(&mut cx, Instant::now());
    assert_eq!(fixture.polled.load(Ordering::Relaxed), 0);
    fixture.engine.entries[&1].ready.schedule();
    fixture.engine.poll(&mut cx, Instant::now());
    assert_eq!(fixture.polled.load(Ordering::Relaxed), 1);
}
