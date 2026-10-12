use std::{collections::HashMap, io, net::SocketAddr, pin::Pin,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, task::{Context, Poll}, time::Duration};
use futures::{Stream, stream::FuturesUnordered, future::BoxFuture};
use tokio::{sync::{mpsc, oneshot}, time::{Instant, Sleep, sleep}};
use tracing::{debug, warn};

use crate::{common::io::datagram_relay::RelayContext, proxy::datagram::UdpPacket, session::SocksAddr};
use super::{AssociationConfig, Control, Outgoing, flow::FlowState, traffic::UdpTraffic};

const CONTROL_BUDGET: usize = 32;
const MAX_PEERS: usize = 16384;

struct Peer {
    original: SocksAddr,
    flow: Option<u64>,
    // The current owner stays inline; only aliases shared by flows allocate.
    other_flows: Vec<u64>,
}

pub(super) struct AssociationRelay {
    packets: mpsc::Receiver<Outgoing>,
    commands: mpsc::Receiver<Control>,
    flows: HashMap<u64, Arc<FlowState>>,
    peers: HashMap<SocksAddr, Peer>,
    closing: FuturesUnordered<BoxFuture<'static, u64>>,
    sending: Option<Arc<FlowState>>,
    last_sender: Option<Arc<FlowState>>,
    sender_cache_valid: bool,
    replies: mpsc::Sender<UdpPacket>,
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

impl AssociationRelay {
    pub(super) fn new(packets: mpsc::Receiver<Outgoing>, commands: mpsc::Receiver<Control>,
        config: &AssociationConfig, source: SocketAddr, user: Option<Arc<str>>,
        force_source: Option<SocksAddr>, native: bool,
    ) -> Self {
        Self {
            packets, commands, flows: HashMap::new(), peers: HashMap::new(),
            closing: FuturesUnordered::new(), sending: None, last_sender: None, sender_cache_valid: false,
            replies: config.replies.clone(), source, allow_quic: config.allow_quic.clone(),
            traffic: UdpTraffic::new(config.manager.clone(), user.as_ref()), force_source, user, native,
            timeout: config.timeout, last_active: Instant::now(), timer: Box::pin(sleep(config.timeout)),
        }
    }

    fn remove(&mut self, id: u64) {
        if let Some(flow) = self.flows.remove(&id) {
            flow.close();
            self.last_sender = None;
            self.sender_cache_valid = false;
            for alias in &flow.aliases {
                if let Some(peer) = self.peers.get_mut(alias) {
                    peer.other_flows.retain(|owner| *owner != id
                        && self.flows.get(owner).is_some_and(|flow| !flow.is_closed()));
                    if peer.flow == Some(id)
                        || peer.flow.is_some_and(|owner| !self.flows.get(&owner).is_some_and(|flow| !flow.is_closed())) {
                        peer.flow = peer.other_flows.pop();
                    }
                }
            }
        }
    }

    fn register(&mut self, state: Arc<FlowState>, close_rx: oneshot::Receiver<()>) -> io::Result<()> {
        if state.aliases.iter().any(|alias| self.peers.get(alias)
            .is_some_and(|peer| peer.original != state.original)) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "ambiguous UDP reply address"));
        }
        let additional = state.aliases.iter().filter(|alias| !self.peers.contains_key(*alias)).count();
        if self.peers.len() + additional > MAX_PEERS {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "UDP reply mapping limit reached"));
        }
        for alias in &state.aliases {
            match self.peers.get_mut(alias) {
                Some(peer) => {
                    if let Some(previous) = peer.flow.replace(state.id) {
                        peer.other_flows.push(previous);
                    }
                },
                None => { self.peers.insert(alias.clone(), Peer {
                    original: state.original.clone(), flow: Some(state.id), other_flows: Vec::new(),
                }); }
            }
        }
        self.last_sender = None;
        self.sender_cache_valid = false;
        let id = state.id;
        self.flows.insert(id, state);
        // One small control future per route, never a forwarding task. Dropped
        // senders (expired routes) also complete and reclaim this registration.
        self.closing.push(Box::pin(async move { let _ = close_rx.await; id }));
        Ok(())
    }
}

impl Drop for AssociationRelay {
    fn drop(&mut self) {
        for flow in self.flows.values() { flow.close(); }
        if let Some(flow) = &self.sending { flow.close(); }
    }
}

impl RelayContext for AssociationRelay {
    fn poll_control(&mut self, cx: &mut Context<'_>) -> bool {
        if self.replies.is_closed() { return false; }
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
                Poll::Ready(Some(Control::Register { state, close_rx, reply })) => {
                    let id = state.id;
                    let result = self.register(state, close_rx);
                    if reply.send(result).is_err() { self.remove(id); }
                }
                Poll::Ready(Some(Control::Remove(id))) => self.remove(id),
                _ => return true,
            }
        }
        cx.waker().wake_by_ref();
        true
    }

    fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<Option<UdpPacket>> {
        for _ in 0..CONTROL_BUDGET {
            match self.packets.poll_recv(cx) {
                Poll::Ready(Some(outgoing)) => {
                    let cached = self.last_sender.as_ref().is_some_and(|flow| flow.id == outgoing.id);
                    let flow = self.last_sender.take().filter(|flow| flow.id == outgoing.id)
                        .or_else(|| self.flows.get(&outgoing.id).cloned());
                    let Some(flow) = flow else { continue; };
                    if flow.is_closed() { self.remove(outgoing.id); continue; }
                    if !cached {
                        for alias in &flow.aliases {
                            if let Some(peer) = self.peers.get_mut(alias) && peer.flow != Some(outgoing.id)
                                && let Some(index) = peer.other_flows.iter().position(|&owner| owner == outgoing.id) {
                                match peer.flow.replace(outgoing.id) {
                                    Some(previous) => peer.other_flows[index] = previous,
                                    None => { peer.other_flows.swap_remove(index); },
                                }
                            }
                        }
                    }
                    // Move the retained state between the send and cache. A
                    // Pending send still owns it, without per-packet Arc churn.
                    self.sending = Some(flow);
                    self.sender_cache_valid = true;
                    self.last_active = Instant::now();
                    return Poll::Ready(Some(outgoing.packet));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn sent(&mut self, result: io::Result<usize>) -> bool {
        let flow = self.sending.take();
        let keep_running = match result {
            Ok(len) => {
                self.last_active = Instant::now();
                self.traffic.push_upload(len);
                if let Some(flow) = &flow {
                    flow.tracker.record_upload(len);
                }
                true
            }
            Err(err) => {
                warn!("UDP association send failed: {err}");
                // An invalid datagram does not invalidate a native socket.
                self.native || matches!(err.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData)
            }
        };
        // Registration/removal while flushing may have changed peer ownership.
        if self.sender_cache_valid && let Some(flow) = flow && !flow.is_closed() {
            self.last_sender = Some(flow);
        }
        keep_running
    }

    fn received(&mut self, mut packet: UdpPacket) -> bool {
        self.last_active = Instant::now();
        self.traffic.push_download(packet.data.len());
        if let SocksAddr::Ip(addr) = &mut packet.src_addr { addr.set_ip(addr.ip().to_canonical()); }
        // Endpoint-independent filtering: unknown peers are admitted too.
        // This table restores addresses and attributes bytes; it is not an allowlist.
        let peer = self.peers.get(&packet.src_addr);
        let flow = peer.and_then(|peer| peer.flow).and_then(|id| self.flows.get(&id))
            .filter(|flow| !flow.is_closed());
        if let Some(flow) = flow {
            flow.tracker.record_download(packet.data.len());
        }
        let original = self.force_source.as_ref().or_else(|| peer.map(|peer| &peer.original));
        if let Some(original) = original && packet.src_addr != *original {
            packet.src_addr = original.clone();
        }
        packet.dst_addr = self.source.into();
        packet.inbound_user = self.user.clone();
        // Protocol policy remains separate from NAT filtering.
        if !self.allow_quic.load(Ordering::Relaxed) && packet.src_addr.port() == 443 { return true; }
        if let Some(flow) = flow { flow.activity.record_at(self.last_active); }
        match self.replies.try_send(packet) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!("UDP inbound reply queue full, dropping packet");
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}
