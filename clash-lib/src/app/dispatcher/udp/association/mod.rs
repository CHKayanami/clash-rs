//! UDP routes are leases; one worker owns each physical client association.
mod flow;
mod peer;
mod semantics;
mod lifecycle;
mod traffic;
mod worker;

pub(crate) use lifecycle::{AssociationGuard, AssociationRegistry};
pub(crate) use traffic::UserTrafficCounters;

pub(crate) use flow::{FlowClosed, ReplyActivity, UdpFlow};
use flow::FlowState;
use worker::AssociationRelay;
use semantics::{FlowIsolation, IsolationReason};

use std::{collections::HashMap, io, net::{IpAddr, SocketAddr}, sync::{Arc, Weak, atomic::{AtomicBool, AtomicU64, Ordering}}, time::Duration};
use futures::future::BoxFuture;
use parking_lot::Mutex;
use tokio::{sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot}, task::JoinHandle};

use crate::{
    app::{dns::ThreadSafeDNSResolver, dispatcher::{Manager, TrackGuard, TrackerInfo}},
    session::{Session, SocksAddr, Type, generate_session_id},
};
use crate::common::io::datagram_relay::relay;
use crate::proxy::{DatagramConnector, AnyOutboundDatagram, ProtocolOutbound, datagram::UdpPacket,
    dispatch_datagram};

const QUEUE_CAPACITY: usize = 64;
const POOL_SHARDS: usize = 16;

/// Endpoint-independent mapping within one inbound/outbound security scope.
/// Destinations belong to logical flows and are deliberately absent here.
#[derive(Clone, Hash, PartialEq, Eq)]
struct AssociationKey {
    outbound: usize,
    source: SocketAddr,
    inbound: Type,
    user: Option<Arc<str>>,
    interface: Option<String>,
    mark: Option<u32>,
    isolated: Option<FlowIsolation>,
}

pub(crate) struct AssociationConfig {
    pub replies: mpsc::Sender<UdpPacket>,
    pub closed_flows: mpsc::UnboundedSender<FlowClosed>,
    pub manager: Arc<Manager>,
    pub allow_quic: Arc<AtomicBool>,
    pub timeout: Duration,
    pub capacity: Arc<Semaphore>,
}

/// Scoped to an inbound namespace. Shards affect establishment only; packet
/// processing uses neither the pool lock nor a shared routing-table lock.
pub(crate) struct UdpAssociationPool {
    slots: [Mutex<HashMap<AssociationKey, Arc<Slot>>>; POOL_SHARDS],
    config: AssociationConfig,
}

struct Slot {
    generation: AtomicU64,
    association: AsyncMutex<Option<Arc<Association>>>,
    key: AssociationKey,
    pool: Weak<UdpAssociationPool>,
    _outbound: ProtocolOutbound,
}

struct WorkerGuard(Weak<Slot>, u64);
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if let Some(slot) = self.0.upgrade()
            && slot.generation.load(Ordering::Relaxed) == self.1
            && let Some(pool) = slot.pool.upgrade()
        {
            let mut slots = pool.shard(&slot.key).lock();
            if slot.generation.load(Ordering::Relaxed) == self.1
                && slots.get(&slot.key).is_some_and(|current| Arc::ptr_eq(current, &slot)) {
                slots.remove(&slot.key);
            }
        }
    }
}

/// A cancelled or failed dial must not leave an empty slot in the pool.
struct EmptySlotGuard(Arc<Slot>);
impl Drop for EmptySlotGuard {
    fn drop(&mut self) {
        if let Ok(association) = self.0.association.try_lock()
            && association.is_none()
            && let Some(pool) = self.0.pool.upgrade()
        {
            let mut slots = pool.shard(&self.0.key).lock();
            if slots.get(&self.0.key).is_some_and(|slot| Arc::ptr_eq(slot, &self.0)) {
                slots.remove(&self.0.key);
            }
        }
    }
}

impl UdpAssociationPool {
    pub(crate) fn new(config: AssociationConfig) -> Arc<Self> {
        Arc::new(Self { slots: std::array::from_fn(|_| Mutex::new(HashMap::new())), config })
    }

    fn shard(&self, key: &AssociationKey) -> &Mutex<HashMap<AssociationKey, Arc<Slot>>> {
        // Source port is stable across all target flows from the same client.
        &self.slots[usize::from(key.source.port()) % POOL_SHARDS]
    }

    fn slot(self: &Arc<Self>, key: AssociationKey, outbound: &ProtocolOutbound) -> Arc<Slot> {
        self.shard(&key).lock().entry(key.clone()).or_insert_with(|| Arc::new(Slot {
            generation: AtomicU64::new(0), association: AsyncMutex::new(None), key, pool: Arc::downgrade(self),
            _outbound: outbound.clone(),
        })).clone()
    }

    /// Keep the establishment state behind a single cold-path allocation.
    pub(crate) fn connect<'a>(
        self: &'a Arc<Self>, outbound: &'a ProtocolOutbound, sess: &'a Session,
        resolver: ThreadSafeDNSResolver, tracker: Arc<TrackerInfo>,
    ) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(self.connect_inner(outbound, sess, resolver, tracker, None))
    }

    async fn connect_inner(
        self: &Arc<Self>, outbound: &ProtocolOutbound, sess: &Session,
        resolver: ThreadSafeDNSResolver, tracker: Arc<TrackerInfo>, isolation: Option<IsolationReason>,
    ) -> io::Result<UdpFlow> {
        let original = sess.orig_destination.as_ref().unwrap_or(&sess.destination);
        let fake = original.ip().is_some_and(|ip| resolver.is_fake_ip(ip));
        let direct = matches!(outbound, ProtocolOutbound::Direct(_));
        let mut resolved = sess.resolved_ip;
        if direct && let SocksAddr::Domain(host, _) = &sess.destination {
            resolved = Some(resolver.resolve(host, false).await.map_err(io::Error::other)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "UDP target has no address"))?);
        }
        if resolved.is_some_and(|ip| resolver.is_fake_ip(ip))
            || (direct && resolved.is_none() && sess.destination.ip().is_some_and(|ip| resolver.is_fake_ip(ip))) {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "UDP target resolution returned a Fake-IP"));
        }
        let unresolved_fake = fake && resolved.is_none() && !direct;
        let key = AssociationKey {
            outbound: outbound.identity(), source: sess.source, inbound: sess.typ,
            user: sess.inbound_user.clone(), interface: sess.iface.as_ref().map(|i| i.name.clone()),
            mark: sess.so_mark,
            isolated: FlowIsolation::select(sess.id, isolation, unresolved_fake, sess.source.port()),
        };
        let (association, reused) = loop {
            let slot = self.slot(key.clone(), outbound);
            let _empty = EmptySlotGuard(slot.clone());
            let mut current = slot.association.lock().await;
            // A waiter may hold a slot removed while it awaited the dial lock.
            // Claim the generation under the same shard lock as worker cleanup.
            let live = current.as_ref().filter(|a| !a.outgoing.is_closed());
            let Some(generation) = self.claim(&slot, live.map(|a| a.id)) else { continue; };
            if let Some(association) = live {
                break (association.clone(), true);
            }
            current.take();
            let permit = self.config.capacity.clone().try_acquire_owned()
                .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "UDP association limit reached"))?;
            let datagram = match outbound {
                ProtocolOutbound::Direct(handler) => handler.connect_datagram_unpooled(sess)?,
                _ => outbound.connect_datagram(sess, resolver.clone()).await?,
            };
            if !datagram.supports_multi_target() && slot.key.isolated.is_none() {
                let mut private_key = slot.key.clone();
                private_key.isolated = Some(FlowIsolation::new(sess.id, IsolationReason::FixedTarget));
                self.retire(&slot, generation);
                drop(current);
                let private_slot = self.slot(private_key, outbound);
                return self.install_private(private_slot, datagram, sess, tracker, resolved, unresolved_fake, permit).await;
            }
            let association = self.start(&slot, generation, datagram, sess, unresolved_fake, permit)?;
            *current = Some(association.clone());
            break (association, false);
        };
        let result = self.register(&association, sess, tracker.clone(), resolved, fake || direct).await;
        match result {
            Ok(flow) => {
                if reused { for name in &association.chain { sess.push_chain(name); } }
                Ok(flow)
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists && isolation.is_none() => {
                Box::pin(self.connect_inner(outbound, sess, resolver, tracker, Some(IsolationReason::ConflictingReplyAlias))).await
            }
            Err(err) => Err(err),
        }
    }

    async fn install_private(
        self: &Arc<Self>, slot: Arc<Slot>, datagram: AnyOutboundDatagram,
        sess: &Session, tracker: Arc<TrackerInfo>, resolved: Option<IpAddr>,
        unresolved_fake: bool, permit: OwnedSemaphorePermit,
    ) -> io::Result<UdpFlow> {
        let mut slot = slot;
        loop {
            let _empty = EmptySlotGuard(slot.clone());
            let mut current = slot.association.lock().await;
            let Some(generation) = self.claim(&slot, None) else {
                drop(current);
                let replacement = self.slot(slot.key.clone(), &slot._outbound);
                drop(_empty);
                slot = replacement;
                continue;
            };
            current.take();
            let association = self.start(&slot, generation, datagram, sess, unresolved_fake, permit)?;
            *current = Some(association.clone());
            drop(current);
            return self.register(&association, sess, tracker, resolved, false).await;
        }
    }

    fn claim(&self, slot: &Arc<Slot>, live_generation: Option<u64>) -> Option<u64> {
        let slots = self.shard(&slot.key).lock();
        if !slots.get(&slot.key).is_some_and(|current| Arc::ptr_eq(current, slot)) { return None; }
        let generation = live_generation.unwrap_or_else(generate_session_id);
        slot.generation.store(generation, Ordering::Relaxed);
        Some(generation)
    }

    fn retire(&self, slot: &Arc<Slot>, generation: u64) {
        let mut slots = self.shard(&slot.key).lock();
        if slot.generation.load(Ordering::Relaxed) == generation
            && slots.get(&slot.key).is_some_and(|current| Arc::ptr_eq(current, slot)) {
            slots.remove(&slot.key);
        }
    }

    fn start(self: &Arc<Self>, slot: &Arc<Slot>, id: u64, datagram: AnyOutboundDatagram,
        sess: &Session, unresolved_fake: bool, permit: OwnedSemaphorePermit) -> io::Result<Arc<Association>> {
        let (close_tx, close_rx) = oneshot::channel();
        let guard = self.config.manager.register_udp_association(id, close_tx);
        let (outgoing, packets) = mpsc::channel(QUEUE_CAPACITY);
        let (control, commands) = mpsc::channel(QUEUE_CAPACITY);
        let force_source = (unresolved_fake || !datagram.reports_peer_source()).then(||
            sess.orig_destination.clone().unwrap_or_else(|| sess.destination.clone()));
        let context = AssociationRelay::new(packets, commands, &self.config,
            sess.source, sess.inbound_user.clone(), force_source, datagram.physical_socket().is_some() || matches!(&datagram, AnyOutboundDatagram::Socks5(inner) if inner.has_native_send()));
        let cleanup = WorkerGuard(Arc::downgrade(slot), id);
        let task = dispatch_datagram!(datagram, |inner| tokio::spawn(async move {
            let (_permit, _guard, _cleanup) = (permit, guard, cleanup);
            tokio::select! { _ = relay(inner, context) => {}, _ = close_rx => {} }
        }));
        Ok(Arc::new(Association { id, outgoing, control, chain: sess.proxy_chain.snapshot(), task }))
    }

    async fn register(&self, association: &Arc<Association>, sess: &Session,
        tracker: Arc<TrackerInfo>, resolved: Option<IpAddr>, use_resolved: bool,
    ) -> io::Result<UdpFlow> {
        let target = match (use_resolved, resolved) {
            (true, Some(ip)) => SocksAddr::Ip(SocketAddr::new(ip, sess.destination.port())),
            _ => sess.destination.clone(),
        };
        let mut aliases = vec![target.clone()];
        if sess.destination != target { aliases.push(sess.destination.clone()); }
        if let Some(ip) = resolved {
            let address = SocksAddr::Ip(SocketAddr::new(ip, sess.destination.port()));
            if !aliases.contains(&address) { aliases.push(address); }
        }
        let state = Arc::new(FlowState {
            id: sess.id, source: sess.source, target,
            original: sess.orig_destination.clone().unwrap_or_else(|| sess.destination.clone()),
            aliases, tracker: tracker.clone(), activity: Arc::new(ReplyActivity::new()),
            closed: AtomicBool::new(false), events: self.config.closed_flows.clone(),
            _guard: TrackGuard::new(sess.id, self.config.manager.clone()),
        });
        let (close_tx, close_rx) = oneshot::channel();
        self.config.manager.track(sess.id, tracker, close_tx);
        let (tx, rx) = oneshot::channel();
        association.control.send(Registration { state: state.clone(), close_rx, reply: tx })
            .await.map_err(|_| closed())?;
        rx.await.map_err(|_| closed())??;
        Ok(UdpFlow { state, association: association.clone() })
    }
}

struct Association {
    id: u64,
    outgoing: mpsc::Sender<Outgoing>, control: mpsc::Sender<Registration>,
    chain: Vec<String>, task: JoinHandle<()>,
}
impl Drop for Association { fn drop(&mut self) { self.task.abort(); } }
struct Outgoing { id: u64, packet: UdpPacket }
struct Registration {
    state: Arc<FlowState>, close_rx: oneshot::Receiver<()>, reply: oneshot::Sender<io::Result<()>>,
}
fn closed() -> io::Error { io::Error::new(io::ErrorKind::BrokenPipe, "UDP association closed") }

#[cfg(test)]
pub(crate) mod tests;


pub(crate) struct UdpConnectContext<'a> {
    pub pool: &'a Arc<UdpAssociationPool>,
    pub tracker: &'a Arc<TrackerInfo>,
}

impl DatagramConnector for UdpConnectContext<'_> {
    type Datagram = UdpFlow;

    fn connect<'a>(&'a self, handler: &'a ProtocolOutbound, sess: &'a Session,
        resolver: ThreadSafeDNSResolver,
    ) -> BoxFuture<'a, io::Result<UdpFlow>> {
        self.pool.connect(handler, sess, resolver, self.tracker.clone())
    }
}
