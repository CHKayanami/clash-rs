//! TUN-owned data shortcuts retain the association's routing and mapping lease.
use std::{io, net::SocketAddr, sync::{Arc, Weak, atomic::{AtomicBool, Ordering}}, task::{Context, Poll}};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::{sync::mpsc::error::TrySendError, time::Instant};
use clash_netstack::parse_udp_packet;
use crate::{app::net::network_generation, proxy::datagram::UdpPacket, session::SocksAddr};
use super::{Association, Outgoing, flow::FlowState};
use super::super::is_short_flow_port;

pub(crate) trait ReplyWriter: Send {
    fn is_closed(&self) -> bool;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<bool>;
    fn send(&mut self, packets: &mut Vec<UdpPacket>) -> io::Result<()>;
}
pub(crate) trait ReplyTarget: Send + Sync {
    fn writer(&self) -> Box<dyn ReplyWriter>;
}

struct Cached {
    id: u64,
    generation: u64,
    allow_quic: Arc<AtomicBool>,
    state: Weak<FlowState>,
    association: Weak<Association>,
}

pub(crate) struct DirectPath {
    target: Arc<dyn ReplyTarget>,
    uploads: DashMap<(SocketAddr, SocketAddr), Cached>,
}

pub(super) struct Registration {
    path: Weak<DirectPath>,
    key: (SocketAddr, SocketAddr),
    id: u64,
    generation: u64,
    allow_quic: Arc<AtomicBool>,
}

impl DirectPath {
    pub(crate) fn new(target: Arc<dyn ReplyTarget>) -> Arc<Self> {
        Arc::new(Self { target, uploads: DashMap::new() })
    }
    pub(super) fn writer(&self) -> Box<dyn ReplyWriter> { self.target.writer() }

    pub(super) fn registration(self: &Arc<Self>, state: &Arc<FlowState>, generation: u64, allow_quic: &Arc<AtomicBool>) -> Option<Registration> {
        let SocksAddr::Ip(destination) = state.original else { return None; };
        // Short-flow promotion and sniff decisions stay in the route owner.
        if is_short_flow_port(destination.port()) || is_short_flow_port(state.target.port()) { return None; }
        let key = (state.source, destination);
        Some(Registration { path: Arc::downgrade(self), key, id: state.id,
            generation, allow_quic: allow_quic.clone() })
    }

    /// A cache hit preserves the established route and only skips packet
    /// transport. The cache is scoped to one TUN inbound/security namespace.
    /// Registration is enabled only after TunDatagram applied the full DNS
    /// hijack/route policy and routing completed sniffing. Hijacked queries on
    /// custom ports never reach registration; this does not rely on port 53.
    pub(crate) fn upload(&self, packet: BytesMut) -> Result<(), BytesMut> {
        let Some((mut source, destination, payload)) = parse_udp_packet(&packet) else { return Err(packet); };
        source.set_ip(source.ip().to_canonical());
        let key = (source, destination);
        let Some((id, generation, allowed, state, association)) = self.uploads.get(&key)
            .map(|entry| (entry.id, entry.generation, destination.port() != 443 || entry.allow_quic.load(Ordering::Relaxed), entry.state.upgrade(), entry.association.upgrade()))
            else { return Err(packet); };
        let live = state.zip(association).filter(|(state, association)|
            generation == network_generation() && !state.is_closed() && !association.outgoing.is_closed());
        let Some((state, association)) = live else {
            self.uploads.remove_if(&key, |_, entry| entry.id == id);
            return Err(packet);
        };
        if !allowed { return Ok(()); }
        // Activity is observed even on congestion drops, as in routes.packet.
        state.activity.record_upload_at(Instant::now());
        match association.outgoing.try_reserve() {
            Ok(permit) => {
                // Small payloads must not pin a large device-read allocation
                // throughout association queuing and native send backpressure.
                let data = if packet.capacity() > 4096 && payload.len() < packet.capacity() / 4 {
                    Bytes::copy_from_slice(&packet[payload])
                } else { packet.freeze().slice(payload) };
                permit.send(Outgoing { id, packet: UdpPacket { data, src_addr: source.into(),
                    dst_addr: destination.into(), inbound_user: None } });
                Ok(())
            }
            Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Closed(_)) => {
                self.uploads.remove_if(&key, |_, entry| entry.id == id);
                Err(packet)
            }
        }
    }
}

impl Registration {
    /// Route establishment flushes its buffered first burst before enabling
    /// direct admission. Creating a lease alone must not bypass that handoff.
    pub(super) fn enable(&self, state: &Arc<FlowState>, association: &Arc<Association>) {
        if let Some(path) = self.path.upgrade() {
            path.uploads.insert(self.key, Cached { id: self.id, generation: self.generation,
                allow_quic: self.allow_quic.clone(), state: Arc::downgrade(state),
                association: Arc::downgrade(association) });
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(path) = self.path.upgrade() {
            path.uploads.remove_if(&self.key, |_, entry| entry.id == self.id);
        }
    }
}

#[cfg(test)]
mod tests;
