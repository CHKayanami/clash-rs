use std::{collections::{HashMap, VecDeque}, io, net::SocketAddr, pin::Pin,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, task::{Context, Poll}, time::Duration};
use futures::{Stream, stream::FuturesUnordered, future::BoxFuture};
use tokio::{sync::{mpsc, oneshot}, time::{Instant, Sleep, sleep}};
use tracing::warn;

use crate::{proxy::datagram::{UdpPacket, batch::MAX_BATCH_PACKETS}, session::SocksAddr};
use super::{AssociationConfig, Registration, Outgoing, flow::FlowState, traffic::UdpTraffic, peer::PeerTable};

const CONTROL_BUDGET: usize = 32;
pub(super) struct AssociationState {
    commands: mpsc::Receiver<Registration>,
    flows: HashMap<u64, Arc<FlowState>>,
    peers: PeerTable,
    closing: FuturesUnordered<BoxFuture<'static, u64>>,
    sending: VecDeque<(Arc<FlowState>, usize)>,
    last_sender: Option<Arc<FlowState>>,
    source: SocketAddr,
    allow_quic: Arc<AtomicBool>,
    traffic: UdpTraffic,
    // Reply address projection, not a peer-admission filter.
    force_source: Option<SocksAddr>,
    user: Option<Arc<str>>,
    native: bool,
    timeout: Duration,
    last_active: Instant,
    timer: Pin<Box<Sleep>>,
}

impl AssociationState {
    pub(super) fn new(commands: mpsc::Receiver<Registration>, config: &AssociationConfig,
        source: SocketAddr, user: Option<Arc<str>>, force_source: Option<SocksAddr>, native: bool,
    ) -> Self {
        Self {
            commands, flows: HashMap::new(), peers: PeerTable::default(),
            closing: FuturesUnordered::new(), sending: VecDeque::with_capacity(MAX_BATCH_PACKETS + 1), last_sender: None,
            source, allow_quic: config.allow_quic.clone(),
            traffic: UdpTraffic::new(config.manager.clone(), user.as_ref()), force_source, user, native,
            timeout: config.timeout, last_active: Instant::now(), timer: Box::pin(sleep(config.timeout)),
        }
    }

    pub(super) fn map_received(&mut self, packet: &mut UdpPacket, now: Instant) -> bool {

        self.last_active = now;
        self.traffic.push_download(packet.data.len());
        if let SocksAddr::Ip(addr) = &mut packet.src_addr { addr.set_ip(addr.ip().to_canonical()); }
        // Endpoint-independent filtering: unknown peers are admitted too.
        // This table restores addresses and attributes bytes; it is not an allowlist.
        let (owner, original) = self.peers.reply(&packet.src_addr);
        let flow = owner.and_then(|id| self.flows.get(&id))
            .filter(|flow| !flow.is_closed());
        if let Some(flow) = flow {
            flow.tracker.record_download(packet.data.len());
        }
        let original = self.force_source.as_ref().or(original);
        if let Some(original) = original && packet.src_addr != *original {
            packet.src_addr = original.clone();
        }
        packet.dst_addr = self.source.into();
        packet.inbound_user = self.user.clone();
        // Protocol policy remains separate from NAT filtering.
        if !self.allow_quic.load(Ordering::Relaxed) && packet.src_addr.port() == 443 { return false; }
        if let Some(flow) = flow { flow.activity.record_at(self.last_active); }
        true
    }

    fn remove(&mut self, id: u64) {
        if let Some(flow) = self.flows.remove(&id) {
            flow.close();
            self.last_sender = None;
            self.peers.remove(&flow, &self.flows);
        }
    }

    fn register(&mut self, state: Arc<FlowState>, close_rx: oneshot::Receiver<()>) -> io::Result<()> {
        self.peers.register(&state)?;
        self.last_sender = None;
        let id = state.id;
        self.flows.insert(id, state);
        // One small control future per route, never a forwarding task. Dropped
        // senders (expired routes) also complete and reclaim this registration.
        self.closing.push(Box::pin(async move { let _ = close_rx.await; id }));
        Ok(())
    }
}

impl Drop for AssociationState {
    fn drop(&mut self) {
        for flow in self.flows.values() { flow.close(); }
        for (flow, _) in &self.sending { flow.close(); }
    }
}

impl AssociationState {
    pub(super) fn poll_control(&mut self, cx: &mut Context<'_>) -> bool {
        if self.timer.as_mut().poll(cx).is_ready() {
            let deadline = self.last_active + self.timeout;
            if deadline <= Instant::now() { return false; }
            self.timer.as_mut().reset(deadline);
            let _ = self.timer.as_mut().poll(cx);
        }
        for index in 0..CONTROL_BUDGET {
            if index + 1 == CONTROL_BUDGET { cx.waker().wake_by_ref(); }
            match Pin::new(&mut self.closing).poll_next(cx) {
                Poll::Ready(Some(id)) => self.remove(id),
                _ => break,
            }
        }
        for _ in 0..CONTROL_BUDGET {
            match self.commands.poll_recv(cx) {
                Poll::Ready(Some(Registration { state, close_rx, reply })) => {
                    let id = state.id;
                    let result = self.register(state, close_rx);
                    if reply.send(result).is_err() { self.remove(id); }
                    // Newly pushed close futures must be polled to subscribe
                    // their receivers before this relay becomes idle.
                    cx.waker().wake_by_ref();
                }
                _ => return true,
            }
        }
        cx.waker().wake_by_ref();
        true
    }

    fn select_flow(&mut self, id: u64) -> bool {
        if !self.last_sender.as_ref().is_some_and(|flow| flow.id == id) {
            self.last_sender = self.flows.get(&id).cloned();
        }
        let Some(flow) = self.last_sender.as_ref() else { return false; };
        if flow.is_closed() { self.remove(id); return false; }
        true
    }

    #[cfg(feature = "tun")]
    pub(super) fn direct_flow(&mut self, id: u64, now: Instant) -> Option<Arc<FlowState>> {
        if !self.select_flow(id) { return None; }
        self.last_active = now;
        self.last_sender.clone()
    }

    #[cfg(feature = "tun")]
    pub(super) fn sent_direct(&mut self, flow: &FlowState, bytes: usize, now: Instant) {
        self.last_active = now;
        self.traffic.push_upload(bytes);
        if !flow.is_closed() { self.peers.select_sender(flow); }
        flow.tracker.record_upload(bytes);
    }

    fn queue_sending(sending: &mut VecDeque<(Arc<FlowState>, usize)>, flow: &Arc<FlowState>) {
        if let Some((previous, count)) = sending.back_mut() && previous.id == flow.id {
            *count += 1;
        } else { sending.push_back((flow.clone(), 1)); }
    }

    #[cfg(feature = "tun")]
    pub(super) fn retain_direct(&mut self, flow: &Arc<FlowState>, now: Instant) {
        // This owner passed admission before the syscall. New cold packets or
        // concurrent flow closure cannot revoke an already submitted suffix.
        Self::queue_sending(&mut self.sending, flow);
        self.last_active = now;
    }

    pub(super) fn outgoing(&mut self, outgoing: Outgoing, now: Instant) -> Option<UdpPacket> {
        if !self.select_flow(outgoing.id) { return None; }
        let flow = self.last_sender.as_ref().unwrap();
        let mut packet = outgoing.packet;
        if packet.dst_addr != flow.target { packet.dst_addr = flow.target.clone(); }
        Self::queue_sending(&mut self.sending, flow);
        self.last_active = now;
        Some(packet)
    }

    pub(super) fn sent_part(&mut self, len: usize, now: Instant) {
        let (flow, _) = self.sending.front().expect("queued UDP flow completion");
        self.last_active = now;
        self.traffic.push_upload(len);
        if !flow.is_closed() { self.peers.select_sender(flow); }
        flow.tracker.record_upload(len);
    }
    #[cfg(feature = "tun")]
    pub(super) fn sent_batch(&mut self, lengths: impl IntoIterator<Item = usize>, now: Instant) {
        let mut lengths = lengths.into_iter().peekable();
        while lengths.peek().is_some() {
            let (flow, remaining) = self.sending.front_mut().expect("queued UDP flow completion");
            let mut bytes = 0;
            while *remaining > 0 {
                let Some(length) = lengths.next() else { break; };
                bytes += length; *remaining -= 1;
            }
            self.last_active = now;
            self.traffic.push_upload(bytes);
            if !flow.is_closed() { self.peers.select_sender(flow); }
            flow.tracker.record_upload(bytes);
            if *remaining == 0 { self.sending.pop_front(); }
        }
    }
    pub(super) fn finish_send(&mut self) {
        let (_, remaining) = self.sending.front_mut().expect("queued UDP flow completion");
        *remaining -= 1;
        if *remaining == 0 { self.sending.pop_front(); }
    }
    pub(super) fn send_error(&mut self, error: io::Error) -> bool {
        warn!("UDP association send failed: {error}");
        self.native || matches!(error.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData)
    }
    pub(super) fn sent(&mut self, result: io::Result<usize>, now: Instant) -> bool {
        let keep = match result {
            Ok(len) => { self.sent_part(len, now); true },
            Err(error) => self.send_error(error),
        };
        self.finish_send();
        keep
    }
}

#[cfg(all(test, feature = "tun"))]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;
    use crate::{app::dispatcher::{Manager, TrackGuard, TrackerInfo}, session::Session};
    use super::super::{flow::ReplyActivity, super::replies};

    #[tokio::test]
    async fn partial_batch_and_failed_datagram_keep_completion_owners_aligned() {
        let manager = Manager::new();
        let (events, _events) = mpsc::unbounded_channel();
        let flow = |id| {
            let sess = Session::default();
            Arc::new(FlowState { id, source: "192.0.2.1:1234".parse().unwrap(),
                original: "192.0.2.2:4321".parse::<SocketAddr>().unwrap().into(),
                target: "192.0.2.2:4321".parse::<SocketAddr>().unwrap().into(), aliases: Vec::new(),
                tracker: Arc::new(TrackerInfo::new(&sess, None)), activity: Arc::new(ReplyActivity::new()),
                closed: Arc::new(AtomicBool::new(false)), events: events.clone(), _guard: TrackGuard::new(id, manager.clone()) })
        };
        let a = flow(1);
        let b = flow(2);
        let (sender, _receiver) = replies::channel(16);
        let config = AssociationConfig { replies: sender, direct: None, closed_flows: events,
            manager: manager.clone(), allow_quic: Arc::new(AtomicBool::new(true)),
            timeout: Duration::from_secs(60), capacity: Arc::new(Semaphore::new(1)) };
        let (_commands, commands) = mpsc::channel(1);
        let mut state = AssociationState::new(commands, &config, a.source, None, None, true);
        state.sending.extend([(a.clone(), 3), (b.clone(), 2), (a.clone(), 1)]);
        state.sent_batch([4, 5], Instant::now());
        assert_eq!(a.tracker.upload_total(), 9);
        assert_eq!(state.sending.front().unwrap().1, 1);
        assert!(state.sent(Err(io::Error::from(io::ErrorKind::InvalidInput)), Instant::now()));
        state.sent_batch([6, 7, 8], Instant::now());
        assert_eq!(a.tracker.upload_total(), 17);
        assert_eq!(b.tracker.upload_total(), 13);
        assert!(state.sending.is_empty());
    }
}
