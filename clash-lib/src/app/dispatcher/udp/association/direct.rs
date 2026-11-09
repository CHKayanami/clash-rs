//! TUN-owned data shortcuts retain the association's routing and mapping lease.
use std::{collections::{HashMap, hash_map::Entry}, net::SocketAddr, ops::Range, sync::{Arc, Weak, atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}}};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::time::Instant;
use clash_netstack::Packet;
#[cfg(test)]
use clash_netstack::parse_udp_packet;
use crate::{app::net::network_generation, proxy::datagram::UdpPacket, session::SocksAddr};
use super::{Association, Outgoing, flow::{FlowState, ReplyActivity}};
use parking_lot::Mutex;
pub(crate) mod engine;
use super::super::is_short_flow_port;

pub(crate) struct Upload {
    association: u64,
    slot: usize,
    id: u64,
    source: SocketAddr,
    destination: SocketAddr,
    frame: Packet,
    payload: Range<usize>,
    segmentation: Option<u16>,
}

impl Upload {
    fn data(&self) -> &[u8] { &self.frame.data()[self.payload.clone()] }
    // Only retained Pending data crosses into the ordinary owned queue.
    fn retain(&self) -> Outgoing { self.retain_from(0) }
    fn retain_from(&self, offset: usize) -> Outgoing {
        Outgoing { id: self.id, packet: UdpPacket { data: Bytes::copy_from_slice(&self.data()[offset..]),
            src_addr: self.source.into(), dst_addr: self.destination.into(), inbound_user: None } }
    }
}

#[derive(Default)]
pub(crate) struct UploadCache {
    revision: u64,
    entries: HashMap<(SocketAddr, SocketAddr), Live>,
}
struct Live {
    id: u64, generation: u64, allow_quic: Arc<AtomicBool>, closed: Arc<AtomicBool>, activity: Arc<ReplyActivity>,
    association: u64, location: Arc<AtomicUsize>, finished: Arc<AtomicBool>,
}
struct Cached {
    id: u64,
    generation: u64,
    allow_quic: Arc<AtomicBool>,
    state: Weak<FlowState>,
    association: Weak<Association>,
}

pub(crate) struct DirectPath {
    executor: engine::Sender,
    engine: Mutex<Option<engine::Engine>>,
    revision: AtomicU64,
    uploads: DashMap<(SocketAddr, SocketAddr), Cached>,
}

pub(super) struct Lease {
    pub generation: u64,
    pub location: Arc<AtomicUsize>,
}

pub(super) struct Registration {
    path: Weak<DirectPath>,
    key: (SocketAddr, SocketAddr),
    id: u64,
    generation: u64,
    allow_quic: Arc<AtomicBool>,
}

impl DirectPath {
    pub(crate) fn integrated(mtu: Option<usize>) -> Arc<Self> {
        let (executor, engine) = engine::channel(mtu);
        Arc::new(Self { executor, engine: Mutex::new(Some(engine)), revision: AtomicU64::new(1), uploads: DashMap::new() })
    }
    pub(crate) fn take_engine(&self) -> Option<engine::Engine> { self.engine.lock().take() }
    pub(super) fn executor(&self) -> &engine::Sender { &self.executor }

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
    #[cfg(test)]
    pub(crate) fn upload_frame(&self, packet: Packet, cache: &mut UploadCache, now: Instant) -> Result<Option<Upload>, Packet> {
        let parsed = parse_udp_packet(&packet);
        self.upload_parsed(packet, parsed, cache, now)
    }

    pub(crate) fn upload_parsed(&self, packet: Packet,
        parsed: Option<(SocketAddr, SocketAddr, Range<usize>)>, cache: &mut UploadCache, now: Instant) -> Result<Option<Upload>, Packet> {
        let Some((mut source, destination, payload)) = parsed else { return Err(packet); };
        source.set_ip(source.ip().to_canonical());
        let key = (source, destination);
        let revision = self.revision.load(Ordering::Acquire);
        if cache.revision != revision { cache.entries.clear(); cache.revision = revision; }
        let live = match cache.entries.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(slot) => {
                let Some(entry) = self.uploads.get(&key) else { return Err(packet); };
                let Some((state, association)) = entry.state.upgrade().zip(entry.association.upgrade()) else { return Err(packet); };
                let Some(finished) = association.task.completion_flag() else { return Err(packet); };
                slot.insert(Live { id: entry.id, generation: entry.generation,
                    allow_quic: entry.allow_quic.clone(), closed: state.closed.clone(), activity: state.activity.clone(),
                    association: association.id, location: association.direct.as_ref().expect("DIRECT lease").location.clone(), finished })
            },
        };
        if live.generation != network_generation() || live.closed.load(Ordering::Relaxed) || live.finished.load(Ordering::Acquire) {
            let id = live.id; cache.entries.remove(&key);
            self.uploads.remove_if(&key, |_, entry| entry.id == id);
            return Err(packet);
        }
        let slot = live.location.load(Ordering::Acquire);
        // An installed registration is not sufficient: until the owner has
        // published a slot, keep this packet on the ordinary association path.
        // Do not evict the registration/cache; the same lease can become ready.
        if slot == usize::MAX { return Err(packet); }
        if destination.port() == 443 && !live.allow_quic.load(Ordering::Relaxed) { return Ok(None); }
        let (id, association) = (live.id, live.association);
        // Activity is observed even on congestion drops, as in routes.packet.
        live.activity.record_upload_at(now);
        let segmentation = packet.udp_segmentation().filter(|&size| size > 0 && payload.len() > usize::from(size));
        Ok(Some(Upload { association, slot, id, source, destination, payload, segmentation, frame: packet }))
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
            path.revision.fetch_add(1, Ordering::Release);
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(path) = self.path.upgrade() {
            path.uploads.remove_if(&self.key, |_, entry| entry.id == self.id);
            path.revision.fetch_add(1, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests;
