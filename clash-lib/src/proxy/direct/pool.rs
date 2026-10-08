use crate::{
    app::{dns::ThreadSafeDNSResolver, net::OutboundInterface},
    proxy::{datagram::UdpPacket, utils::new_dual_stack_udp_socket},
    session::SocksAddr,
};
use futures::{Sink, Stream, ready, task::AtomicWaker};
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender, channel, error::TrySendError},
    task::JoinHandle,
};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
type SessionId = u64;

#[inline]
fn canonicalize_src(src: SocketAddr) -> SocketAddr {
    match src {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::from((v4, v6.port()))
            } else {
                src
            }
        }
        _ => src,
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub(crate) struct DirectSocketKey {
    pub source: SocketAddr,
    pub iface_name: Option<String>,
    pub so_mark: Option<u32>,
}

const MAX_CONSECUTIVE_RECV_ERRORS: usize = 10;
const MAX_BATCH_RECV_PACKETS: usize = 32;
const MAX_LOGICAL_MAPPINGS: usize = 128;

#[derive(Clone)]
struct SessionSender {
    tx: Sender<UdpPacket>,
    recv_waker: Arc<AtomicWaker>,
}

impl SessionSender {
    fn new(tx: Sender<UdpPacket>) -> Self {
        Self {
            tx,
            recv_waker: Arc::new(AtomicWaker::new()),
        }
    }
}

#[derive(Default)]
pub(crate) struct SocketRoutingTable {
    is_closed: bool,
    /// Active sessions and receive-task closure wakers on this socket.
    sessions: HashMap<SessionId, SessionSender>,
    /// Remote destination index: peer SocketAddr -> SessionId (strictly 1:1)
    dest_to_session: HashMap<SocketAddr, SessionId>,
    /// Tracks which session was most recently active for delivering unsolicited Full-Cone packets
    last_active_session: Option<SessionId>,
}

impl SocketRoutingTable {
    #[inline]
    fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    #[inline]
    pub(crate) fn is_closed(&self) -> bool {
        self.is_closed
    }

    /// Try to register a session on this socket.
    /// Returns false if the socket is closed or if `initial_dst` is already bound to another session.
    fn try_register(
        &mut self,
        session_id: SessionId,
        tx: SessionSender,
        initial_dst: Option<SocketAddr>,
    ) -> bool {
        if self.is_closed {
            return false;
        }
        if let Some(dst) = initial_dst {
            if self.dest_to_session.contains_key(&dst) {
                // Another active session on this socket is already bound to this remote address.
                // Reject so caller can place this session on a distinct socket!
                return false;
            }
            self.dest_to_session.insert(dst, session_id);
        }
        self.sessions.insert(session_id, tx);
        self.last_active_session = Some(session_id);
        true
    }

    /// Try to bind a destination for an existing session (e.g. after domain resolution).
    /// Returns:
    /// - `Ok(())` if successfully bound (or already bound to this session).
    /// - `Err(())` if this destination is already bound to ANOTHER session on this socket.
    fn bind_destination(
        &mut self,
        session_id: SessionId,
        dst: SocketAddr,
    ) -> Result<(), ()> {
        if self.is_closed {
            return Err(());
        }
        if let Some(&owner) = self.dest_to_session.get(&dst) {
            if owner == session_id {
                self.last_active_session = Some(session_id);
                return Ok(());
            } else {
                // Collides with another active session on this socket!
                return Err(());
            }
        }
        self.dest_to_session.insert(dst, session_id);
        self.last_active_session = Some(session_id);
        Ok(())
    }

    /// Select the appropriate session sender for an incoming packet from `peer`.
    fn route(&self, peer: SocketAddr) -> Option<Sender<UdpPacket>> {
        if self.is_closed {
            return None;
        }
        // 1. Exact match on registered remote destination
        if let Some(session_id) = self.dest_to_session.get(&peer) {
            return self.sessions.get(session_id)
                .map(|session| session.tx.clone());
        }

        // 2. Unregistered remote address (Full-Cone NAT behavior)
        // Under Full-Cone NAT, deliver unsolicited packets (such as P2P hole-punching packets)
        // to the active session on this socket.
        self.last_active_session
            .and_then(|id| self.sessions.get(&id).map(|session| session.tx.clone()))
            .or_else(|| {
                self.sessions.values().next().map(|session| session.tx.clone())
            })
    }

    fn on_transmit(&mut self, session_id: SessionId) -> bool {
        if self.is_closed {
            return false;
        }
        self.last_active_session = Some(session_id);
        true
    }

    fn unregister_session(
        &mut self,
        session_id: SessionId,
        registered_dsts: &HashSet<SocketAddr>,
    ) {
        for dst in registered_dsts {
            if self.dest_to_session.get(dst) == Some(&session_id) {
                self.dest_to_session.remove(dst);
            }
        }
        self.sessions.remove(&session_id);
        if self.last_active_session == Some(session_id) {
            self.last_active_session = self.sessions.keys().next().copied();
        }
    }

    fn close(&mut self) {
        self.is_closed = true;
        for session in self.sessions.values() {
            session.recv_waker.wake();
        }
        self.sessions.clear();
        self.dest_to_session.clear();
        self.last_active_session = None;
    }
}

pub(crate) struct DirectSocketEntry {
    pub key: DirectSocketKey,
    pub socket: Arc<UdpSocket>,
    pub local_is_ipv6: bool,
    pub routing: Arc<RwLock<SocketRoutingTable>>,
    pub recv_task: JoinHandle<()>,
}

pub struct DirectDatagramPool {
    entries: RwLock<HashMap<DirectSocketKey, Vec<Arc<DirectSocketEntry>>>>,
}

impl DirectDatagramPool {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    fn create_entry(
        key: &DirectSocketKey,
        iface: Option<&OutboundInterface>,
        pool_weak: Option<Weak<DirectDatagramPool>>,
    ) -> io::Result<DirectSocketEntry> {
        let socket = new_dual_stack_udp_socket(
            iface,
            #[cfg(target_os = "linux")]
            key.so_mark,
        )?;
        let socket = Arc::new(socket);
        let local_is_ipv6 = socket
            .local_addr()
            .map(|addr| addr.is_ipv6())
            .unwrap_or(false);

        let routing = Arc::new(RwLock::new(SocketRoutingTable::default()));

        let socket_recv = socket.clone();
        let routing_recv = routing.clone();
        let key_clone = key.clone();

        let recv_task = tokio::spawn(async move {
            let mut consecutive_recv_errors = 0;
            'receive: loop {
                let mut readiness_error = socket_recv.readable().await.err();
                let mut received_count = 0;
                while received_count < MAX_BATCH_RECV_PACKETS {
                    let received = if let Some(err) = readiness_error.take() {
                        Err(err)
                    } else {
                        super::recv::recv_batch(
                            &socket_recv,
                            MAX_BATCH_RECV_PACKETS - received_count,
                            |data, peer_addr| {
                                let peer = canonicalize_src(peer_addr);
                                let target_tx = routing_recv.read().route(peer);
                                if let Some(tx) = target_tx {
                                    let packet = UdpPacket {
                                        data,
                                        src_addr: SocksAddr::Ip(peer),
                                        dst_addr: SocksAddr::any_ipv4(),
                                        inbound_user: None,
                                    };
                                    if let Err(TrySendError::Full(_)) =
                                        tx.try_send(packet)
                                    {
                                        tracing::trace!(
                                            "Direct pooled UDP downstream buffer full, packet dropped"
                                        );
                                    }
                                }
                            },
                        )
                    };
                    match received {
                        Ok(count) => {
                            consecutive_recv_errors = 0;
                            received_count += count;
                            if count == 0 {
                                break;
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            continue 'receive;
                        }
                        Err(err) => {
                            consecutive_recv_errors += 1;
                            if consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS
                            {
                                tracing::warn!(
                                    "Direct pooled UDP socket reached error limit ({MAX_CONSECUTIVE_RECV_ERRORS}), closing: {err}"
                                );
                                routing_recv.write().close();
                                if let Some(pool) =
                                    pool_weak.and_then(|weak| weak.upgrade())
                                {
                                    pool.cleanup_closed(&key_clone);
                                }
                                break 'receive;
                            }
                            tracing::trace!(
                                "Direct pooled UDP transient recv error: {err}"
                            );
                            tokio::task::yield_now().await;
                            continue 'receive;
                        }
                    }
                }
                // Bound a burst so other sockets and sessions get a turn.
                tokio::task::yield_now().await;
            }
        });

        Ok(DirectSocketEntry {
            key: key.clone(),
            socket,
            local_is_ipv6,
            routing,
            recv_task,
        })
    }

    pub fn connect(
        self: &Arc<Self>,
        mut key: DirectSocketKey,
        iface: Option<&OutboundInterface>,
        destination: SocksAddr,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<PooledDirectDatagram> {
        let base_key = key.clone();
        let initial_loopback = destination.ip().is_some_and(|ip| ip.is_loopback());
        if initial_loopback {
            key.iface_name = None;
        }
        let initial_iface = if initial_loopback { None } else { iface };
        let canon_dst = match destination {
            SocksAddr::Ip(addr) => Some(canonicalize_src(addr)),
            SocksAddr::Domain(..) => None,
        };

        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = channel(64);
        let tx = SessionSender::new(tx);

        // 1. Fast-path: Under read lock, try to find an existing socket that doesn't conflict with canon_dst
        let mut chosen_entry = None;
        {
            let entries_guard = self.entries.read();
            if let Some(list) = entries_guard.get(&key) {
                for candidate in list {
                    let mut routing = candidate.routing.write();
                    if routing.try_register(session_id, tx.clone(), canon_dst) {
                        chosen_entry = Some(candidate.clone());
                        break;
                    }
                }
            }
        }

        let entry = match chosen_entry {
            Some(e) => e,
            None => {
                // 2. Slow-path: Create socket OUTSIDE global write lock
                let pool_weak = Arc::downgrade(self);
                let new_entry = Arc::new(Self::create_entry(
                    &key,
                    initial_iface,
                    Some(pool_weak),
                )?);
                let mut entries_guard = self.entries.write();
                let list = entries_guard.entry(key.clone()).or_default();
                list.retain(|e| !e.routing.read().is_closed());
                let mut registered = false;
                for candidate in list.iter() {
                    let mut routing = candidate.routing.write();
                    if routing.try_register(session_id, tx.clone(), canon_dst) {
                        new_entry.recv_task.abort();
                        registered = true;
                        chosen_entry = Some(candidate.clone());
                        break;
                    }
                }
                if !registered {
                    new_entry.routing.write().try_register(
                        session_id,
                        tx.clone(),
                        canon_dst,
                    );
                    list.push(new_entry.clone());
                    new_entry
                } else {
                    chosen_entry.unwrap()
                }
            }
        };

        let mut registered_dsts = HashSet::new();
        if let Some(canon) = canon_dst {
            registered_dsts.insert(canon);
        }

        let ip_to_logical = HashMap::new();
        Ok(PooledDirectDatagram {
            session_id,
            entry,
            pool: self.clone(),
            base_key,
            resolver,
            iface: iface.cloned(),
            tx,
            registered_dsts,
            retained_entries: Vec::new(),
            last_dst: None,
            rx,
            pkt: None,
            flushed: true,
            pending_dns: None,
            resolved_dst: None,
            ip_to_logical,
        })
    }

    /// Attach a session to another socket. Existing sockets stay registered so
    /// replies to requests already sent from their ports can still arrive.
    fn attach(
        self: &Arc<Self>,
        key: &DirectSocketKey,
        current_entry: &Arc<DirectSocketEntry>,
        session_id: SessionId,
        tx: SessionSender,
        dst: SocketAddr,
        iface: Option<&OutboundInterface>,
    ) -> io::Result<Arc<DirectSocketEntry>> {
        let mut chosen_entry = None;
        {
            let entries_guard = self.entries.read();
            if let Some(list) = entries_guard.get(key) {
                for candidate in list {
                    if Arc::ptr_eq(candidate, current_entry) {
                        continue;
                    }
                    let mut routing = candidate.routing.write();
                    if routing.try_register(session_id, tx.clone(), Some(dst)) {
                        chosen_entry = Some(candidate.clone());
                        break;
                    }
                }
            }
        }

        let new_entry = match chosen_entry {
            Some(e) => e,
            None => {
                let pool_weak = Arc::downgrade(self);
                let fresh_entry =
                    Arc::new(Self::create_entry(key, iface, Some(pool_weak))?);
                let mut entries_guard = self.entries.write();
                let list = entries_guard.entry(key.clone()).or_default();
                list.retain(|e| !e.routing.read().is_closed());
                let mut registered = false;
                for candidate in list.iter() {
                    if Arc::ptr_eq(candidate, current_entry) {
                        continue;
                    }
                    let mut routing = candidate.routing.write();
                    if routing.try_register(session_id, tx.clone(), Some(dst)) {
                        fresh_entry.recv_task.abort();
                        registered = true;
                        chosen_entry = Some(candidate.clone());
                        break;
                    }
                }
                if !registered {
                    fresh_entry.routing.write().try_register(
                        session_id,
                        tx,
                        Some(dst),
                    );
                    list.push(fresh_entry.clone());
                    fresh_entry
                } else {
                    chosen_entry.unwrap()
                }
            }
        };

        Ok(new_entry)
    }

    fn cleanup_closed(&self, key: &DirectSocketKey) {
        let mut entries_guard = self.entries.write();
        if let Some(list) = entries_guard.get_mut(key) {
            list.retain(|e| !e.routing.read().is_closed());
            if list.is_empty() {
                entries_guard.remove(key);
            }
        }
    }

    fn release(&self, key: &DirectSocketKey, entry: &Arc<DirectSocketEntry>) {
        // Fast-path exit: if the socket still has other active sessions, don't acquire global write lock
        if !entry.routing.read().is_empty() {
            return;
        }

        let mut entries_guard = self.entries.write();
        let mut routing = entry.routing.write();
        // Clean up entry whenever it is empty, regardless of whether routing is already closed
        if routing.is_empty() {
            routing.close();
            entry.recv_task.abort();

            if let Some(list) = entries_guard.get_mut(key) {
                list.retain(|e| {
                    !Arc::ptr_eq(e, entry) && !e.routing.read().is_closed()
                });
                if list.is_empty() {
                    entries_guard.remove(key);
                }
            }
        }
    }
}

pub struct PooledDirectDatagram {
    session_id: SessionId,
    entry: Arc<DirectSocketEntry>,
    pool: Arc<DirectDatagramPool>,
    base_key: DirectSocketKey,
    resolver: ThreadSafeDNSResolver,
    iface: Option<OutboundInterface>,
    tx: SessionSender,
    registered_dsts: HashSet<SocketAddr>,
    retained_entries: Vec<(Arc<DirectSocketEntry>, HashSet<SocketAddr>)>,
    last_dst: Option<SocketAddr>,
    rx: Receiver<UdpPacket>,
    pkt: Option<UdpPacket>,
    flushed: bool,
    pending_dns: Option<super::resolve::PendingResolution>,
    resolved_dst: Option<SocketAddr>,
    ip_to_logical: HashMap<SocketAddr, SocksAddr>,
}

impl Drop for PooledDirectDatagram {
    fn drop(&mut self) {
        self.pending_dns = None;
        self.entry
            .routing
            .write()
            .unregister_session(self.session_id, &self.registered_dsts);

        self.pool.release(&self.entry.key, &self.entry);
        for (entry, destinations) in self.retained_entries.drain(..) {
            entry
                .routing
                .write()
                .unregister_session(self.session_id, &destinations);
            self.pool.release(&entry.key, &entry);
        }
    }
}

impl Stream for PooledDirectDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let received = match self.rx.poll_recv(cx) {
            Poll::Ready(packet) => packet,
            Poll::Pending => {
                // Only empty queues need closure notifications. Register before
                // checking so a concurrent receiver exit cannot lose a wakeup.
                self.tx.recv_waker.register(cx.waker());
                if self.entry.routing.read().is_closed()
                    && self.retained_entries.iter().all(|(entry, _)| {
                        entry.routing.read().is_closed()
                    })
                {
                    self.rx.close();
                    // A reply may have arrived since the first poll. Drain it
                    // before ending, even though we still own a sender.
                    ready!(self.rx.poll_recv(cx))
                } else {
                    return Poll::Pending;
                }
            }
        };
        match received {
            Some(mut packet) => {
                // Restore logical domain when the source IP matches a resolved domain target.
                // Full-Cone unsolicited packets from third parties retain their raw physical address.
                if let SocksAddr::Ip(src_ip) = packet.src_addr {
                    let canon_src = canonicalize_src(src_ip);
                    if let Some(logical) = self.ip_to_logical.get(&canon_src) {
                        packet.src_addr = logical.clone();
                    }
                }
                Poll::Ready(Some(packet))
            }
            None => Poll::Ready(None),
        }
    }
}

impl Sink<UdpPacket> for PooledDirectDatagram {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pending_dns = None;
        pin.pkt = Some(item);
        pin.resolved_dst = None;
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            session_id,
            ref mut entry,
            ref pool,
            ref base_key,
            ref tx,
            ref iface,
            ref mut pkt,
            ref resolver,
            ref mut pending_dns,
            ref mut resolved_dst,
            ref mut ip_to_logical,
            ref mut registered_dsts,
            ref mut retained_entries,
            ref mut last_dst,
            ref mut flushed,
            ..
        } = *self;

        let p = pkt
            .as_ref()
            .ok_or_else(|| io::Error::other("no packet to send"))?;

        let (dst, logical_mapping) = match *resolved_dst {
            Some(dst) => {
                let logical = match &p.dst_addr {
                    SocksAddr::Domain(..) => Some(p.dst_addr.clone()),
                    _ => None,
                };
                (dst, logical)
            }
            None => match &p.dst_addr {
                SocksAddr::Ip(addr) => {
                    *pending_dns = None;
                    *resolved_dst = Some(*addr);
                    (*addr, None)
                }
                SocksAddr::Domain(domain, port) => {
                    let is_ipv6 = entry.local_is_ipv6;
                    let addr = ready!(super::resolve::poll_resolve_destination(
                        cx,
                        pending_dns,
                        resolver,
                        domain,
                        *port,
                        is_ipv6,
                    ))?;
                    *resolved_dst = Some(addr);
                    (addr, Some(p.dst_addr.clone()))
                }
            },
        };

        let canon_dst = canonicalize_src(dst);
        let loopback = canon_dst.ip().is_loopback();
        let desired_iface_name = if loopback {
            None
        } else {
            base_key.iface_name.as_deref()
        };
        let desired_iface = if loopback { None } else { iface.as_ref() };

        let active_matches = if entry.key.iface_name.as_deref() == desired_iface_name
        {
            let mut routing = entry.routing.write();
            if *last_dst == Some(canon_dst) {
                routing.on_transmit(session_id)
            } else {
                routing.bind_destination(session_id, canon_dst).is_ok()
            }
        } else {
            false
        };
        if !active_matches {
            let retained_match =
                retained_entries.iter().position(|(candidate, _)| {
                    candidate.key.iface_name.as_deref() == desired_iface_name
                        && candidate
                            .routing
                            .write()
                            .bind_destination(session_id, canon_dst)
                            .is_ok()
                });
            if let Some(index) = retained_match {
                std::mem::swap(entry, &mut retained_entries[index].0);
                std::mem::swap(registered_dsts, &mut retained_entries[index].1);
            } else {
                let mut desired_key = base_key.clone();
                if loopback {
                    desired_key.iface_name = None;
                }
                let new_entry = pool.attach(
                    &desired_key,
                    entry,
                    session_id,
                    tx.clone(),
                    canon_dst,
                    desired_iface,
                )?;
                let previous = std::mem::replace(entry, new_entry);
                let previous_dsts = std::mem::take(registered_dsts);
                if previous_dsts.is_empty() {
                    previous
                        .routing
                        .write()
                        .unregister_session(session_id, &previous_dsts);
                    pool.release(&previous.key, &previous);
                } else {
                    retained_entries.push((previous, previous_dsts));
                }
            }
        }
        if !active_matches || *last_dst != Some(canon_dst) {
            registered_dsts.insert(canon_dst);
        }
        *last_dst = Some(canon_dst);

        let send_dst = match (entry.local_is_ipv6, dst) {
            (true, SocketAddr::V4(v4)) => SocketAddr::V6(SocketAddrV6::new(
                v4.ip().to_ipv6_mapped(),
                v4.port(),
                0,
                0,
            )),
            (_, other) => other,
        };

        match entry.socket.poll_send_to(cx, p.data.as_ref(), send_dst) {
            Poll::Ready(Ok(_)) => {
                *flushed = true;
                *pkt = None;
                *resolved_dst = None;
                if let Some(logical) = logical_mapping {
                    if ip_to_logical.len() < MAX_LOGICAL_MAPPINGS
                        || ip_to_logical.contains_key(&canon_dst)
                    {
                        ip_to_logical.insert(canon_dst, logical);
                    }
                } else {
                    ip_to_logical.remove(&canon_dst);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    fn resolver() -> ThreadSafeDNSResolver {
        Arc::new(MockClashResolver::new())
    }

    #[tokio::test]
    async fn test_closed_sockets_wake_and_drain_stream() {
        use std::sync::atomic::AtomicBool;
        use std::task::{Wake, Waker};

        struct WakeFlag(AtomicBool);
        impl Wake for WakeFlag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let pool = Arc::new(DirectDatagramPool::new());
        let key = DirectSocketKey {
            source: "127.0.0.1:43103".parse().unwrap(),
            iface_name: None,
            so_mark: None,
        };
        let dst = "127.0.0.1:53".parse().unwrap();
        let mut datagram = pool
            .connect(key.clone(), None, SocksAddr::Ip(dst), resolver())
            .unwrap();
        let retained = Arc::new(
            DirectDatagramPool::create_entry(&key, None, None).unwrap(),
        );
        retained.routing.write().try_register(
            datagram.session_id,
            datagram.tx.clone(),
            Some(dst),
        );
        datagram.retained_entries
            .push((retained.clone(), HashSet::from([dst])));

        let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        datagram.tx.tx
            .try_send(UdpPacket::new(
                Bytes::from_static(b"buffered"),
                SocksAddr::Ip(dst),
                SocksAddr::any_ipv4(),
            ))
            .unwrap();
        assert!(matches!(
            Pin::new(&mut datagram).poll_next(&mut cx),
            Poll::Ready(Some(_))
        ));
        datagram.tx.recv_waker.wake();
        assert!(!flag.0.load(Ordering::Relaxed));
        assert!(Pin::new(&mut datagram).poll_next(&mut cx).is_pending());
        datagram.entry.routing.write().close();
        assert!(flag.0.swap(false, Ordering::Relaxed));
        assert!(Pin::new(&mut datagram).poll_next(&mut cx).is_pending());

        datagram.tx.tx
            .try_send(UdpPacket::new(
                Bytes::from_static(b"queued"),
                SocksAddr::Ip(dst),
                SocksAddr::any_ipv4(),
            ))
            .unwrap();
        flag.0.store(false, Ordering::Relaxed);
        retained.routing.write().close();
        assert!(flag.0.load(Ordering::Relaxed));
        let Poll::Ready(Some(packet)) = Pin::new(&mut datagram).poll_next(&mut cx)
        else {
            panic!("queued reply must be drained");
        };
        assert_eq!(packet.data.as_ref(), b"queued");
        assert!(matches!(
            Pin::new(&mut datagram).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[tokio::test]
    async fn test_socket_closed_before_first_receive_poll() {
        let pool = Arc::new(DirectDatagramPool::new());
        let key = DirectSocketKey {
            source: "127.0.0.1:43105".parse().unwrap(),
            iface_name: None,
            so_mark: None,
        };
        let mut datagram = pool
            .connect(
                key,
                None,
                SocksAddr::Ip("127.0.0.1:53".parse().unwrap()),
                resolver(),
            )
            .unwrap();
        // Closure happens before any waker is registered. The cold-path
        // check must still end the stream despite its own sender staying alive.
        datagram.entry.routing.write().close();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(matches!(
            Pin::new(&mut datagram).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[tokio::test]
    async fn test_ip_send_clears_previous_domain_mapping() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = peer.local_addr().unwrap();
        let mut dns = MockClashResolver::new();
        dns.expect_resolve().returning(|_, _| {
            Ok(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))
        });
        dns.expect_resolve_v4().returning(|_, _| {
            Ok(Some(Ipv4Addr::LOCALHOST))
        });
        let pool = Arc::new(DirectDatagramPool::new());
        let domain = SocksAddr::Domain("echo.test".into(), dst.port());
        let key = DirectSocketKey {
            source: "127.0.0.1:43104".parse().unwrap(),
            iface_name: None,
            so_mark: None,
        };
        let mut datagram = pool
            .connect(key, None, domain.clone(), Arc::new(dns))
            .unwrap();
        for destination in [domain, SocksAddr::Ip(dst)] {
            datagram
                .send(UdpPacket::new(
                    Bytes::from_static(b"probe"),
                    SocksAddr::any_ipv4(),
                    destination.clone(),
                ))
                .await
                .unwrap();
            let mut buf = [0u8; 32];
            let (_, return_addr) = peer.recv_from(&mut buf).await.unwrap();
            peer.send_to(b"reply", return_addr).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), datagram.next())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.src_addr, destination);
        }
    }

    #[tokio::test]
    async fn test_burst_replies_cross_batch_boundary() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = peer.local_addr().unwrap();
        let pool = Arc::new(DirectDatagramPool::new());
        let key = DirectSocketKey {
            source: "127.0.0.1:43102".parse().unwrap(),
            iface_name: None,
            so_mark: None,
        };
        let mut datagram = pool
            .connect(key, None, SocksAddr::Ip(dst), resolver())
            .unwrap();
        datagram
            .send(UdpPacket::new(
                Bytes::from_static(b"probe"),
                SocksAddr::any_ipv4(),
                SocksAddr::Ip(dst),
            ))
            .await
            .unwrap();
        let mut buf = [0u8; 32];
        let (_, return_addr) = peer.recv_from(&mut buf).await.unwrap();

        for n in 0..(MAX_BATCH_RECV_PACKETS + 16) {
            peer.send_to(&[n as u8], return_addr).await.unwrap();
        }
        let mut received = vec![false; MAX_BATCH_RECV_PACKETS + 16];
        for _ in 0..received.len() {
            let packet =
                tokio::time::timeout(Duration::from_secs(2), datagram.next())
                    .await
                    .unwrap()
                    .unwrap();
            received[packet.data[0] as usize] = true;
        }
        assert!(received.into_iter().all(|seen| seen));
    }

    #[tokio::test]
    async fn test_delayed_reply_survives_socket_change() {
        let old_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_dst = old_peer.local_addr().unwrap();
        let new_dst = new_peer.local_addr().unwrap();
        let pool = Arc::new(DirectDatagramPool::new());
        let key = DirectSocketKey {
            source: "127.0.0.1:43100".parse().unwrap(),
            iface_name: None,
            so_mark: None,
        };
        let mut changing = pool
            .connect(key.clone(), None, SocksAddr::Ip(old_dst), resolver())
            .unwrap();
        let mut other = pool
            .connect(key, None, SocksAddr::Ip(new_dst), resolver())
            .unwrap();

        changing
            .send(UdpPacket::new(
                Bytes::from_static(b"old"),
                SocksAddr::any_ipv4(),
                SocksAddr::Ip(old_dst),
            ))
            .await
            .unwrap();
        let mut buf = [0u8; 32];
        let (_, old_return_addr) = old_peer.recv_from(&mut buf).await.unwrap();

        other
            .send(UdpPacket::new(
                Bytes::from_static(b"other"),
                SocksAddr::any_ipv4(),
                SocksAddr::Ip(new_dst),
            ))
            .await
            .unwrap();
        let (_, shared_addr) = new_peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(old_return_addr, shared_addr);

        changing
            .send(UdpPacket::new(
                Bytes::from_static(b"new"),
                SocksAddr::any_ipv4(),
                SocksAddr::Ip(new_dst),
            ))
            .await
            .unwrap();
        let (_, changed_addr) = new_peer.recv_from(&mut buf).await.unwrap();
        assert_ne!(changed_addr, old_return_addr);

        old_peer.send_to(b"delayed", old_return_addr).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), changing.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.data.as_ref(), b"delayed");
    }

    #[tokio::test]
    async fn test_domain_resolving_to_loopback_uses_unbound_socket() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = peer.local_addr().unwrap();
        let pool = Arc::new(DirectDatagramPool::new());
        let mut dns = MockClashResolver::new();
        dns.expect_resolve()
            .returning(|_, _| Ok(Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))));
        dns.expect_resolve_v4()
            .returning(|_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
        let mut datagram = pool
            .connect(
                DirectSocketKey {
                    source: "127.0.0.1:43101".parse().unwrap(),
                    iface_name: Some("physical-interface".into()),
                    so_mark: None,
                },
                None,
                SocksAddr::Domain("localhost".into(), dst.port()),
                Arc::new(dns),
            )
            .unwrap();
        assert!(datagram.entry.key.iface_name.is_some());

        datagram
            .send(UdpPacket::new(
                Bytes::from_static(b"loopback"),
                SocksAddr::any_ipv4(),
                SocksAddr::Domain("localhost".into(), dst.port()),
            ))
            .await
            .unwrap();
        assert_eq!(datagram.entry.key.iface_name, None);
        let mut buf = [0u8; 32];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..len], b"loopback");
    }

    #[tokio::test]
    async fn test_attach_keeps_old_destination_on_original_socket() {
        let pool = Arc::new(DirectDatagramPool::new());
        let key = DirectSocketKey {
            source: "127.0.0.1:0".parse().unwrap(),
            iface_name: None,
            so_mark: None,
        };

        // Create socket 1 with session 10 bound to old_dst (1.1.1.1:53)
        let entry1 =
            Arc::new(DirectDatagramPool::create_entry(&key, None, None).unwrap());
        let (tx10, _rx10) = channel(1);
        let tx10 = SessionSender::new(tx10);
        let old_dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        entry1.routing.write().try_register(10, tx10, Some(old_dst));

        // Add entry1 to pool
        pool.entries
            .write()
            .insert(key.clone(), vec![entry1.clone()]);

        // Session 20 is on another socket with an outstanding request to old_dst.
        let entry0 =
            Arc::new(DirectDatagramPool::create_entry(&key, None, None).unwrap());
        let (tx20, _rx20) = channel(1);
        let tx20 = SessionSender::new(tx20);
        let new_dst: SocketAddr = "2.2.2.2:53".parse().unwrap();
        entry0
            .routing
            .write()
            .try_register(20, tx20.clone(), Some(old_dst));
        pool.entries
            .write()
            .get_mut(&key)
            .unwrap()
            .push(entry0.clone());

        let attached = pool
            .attach(&key, &entry0, 20, tx20, new_dst, None)
            .expect("attach should succeed");

        assert!(!Arc::ptr_eq(&attached, &entry0));
        assert_eq!(
            attached.routing.read().dest_to_session.get(&new_dst),
            Some(&20)
        );
        assert_eq!(
            entry0.routing.read().dest_to_session.get(&old_dst),
            Some(&20)
        );
    }

    #[tokio::test]
    async fn test_poll_flush_does_not_re_resolve_when_resolved_dst_is_set() {
        use crate::app::dns::MockClashResolver;
        use std::sync::atomic::AtomicUsize;

        let pool = Arc::new(DirectDatagramPool::new());
        let key = DirectSocketKey {
            source: "127.0.0.1:0".parse().unwrap(),
            iface_name: None,
            so_mark: None,
        };

        let dns_counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = dns_counter.clone();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve_v4().returning(move |_, _| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            Ok(Some(std::net::Ipv4Addr::LOCALHOST))
        });
        let resolver: ThreadSafeDNSResolver = Arc::new(mock_resolver);

        let mut datagram = pool
            .connect(
                key,
                None,
                SocksAddr::Domain("example.com".into(), 12345),
                resolver,
            )
            .unwrap();

        let pkt = UdpPacket {
            data: Bytes::from_static(b"test"),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::Domain("example.com".into(), 12345),
            inbound_user: None,
        };

        Pin::new(&mut datagram).start_send(pkt).unwrap();
        // Simulate that DNS already resolved and resolved_dst was cached (as happens after Pending)
        let resolved: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        datagram.resolved_dst = Some(resolved);

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = Pin::new(&mut datagram).poll_flush(&mut cx);

        // DNS resolver should NOT have been called because resolved_dst was reused!
        assert_eq!(dns_counter.load(Ordering::SeqCst), 0);
    }
}
