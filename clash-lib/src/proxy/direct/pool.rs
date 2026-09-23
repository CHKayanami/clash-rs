use crate::{
    app::{dns::ThreadSafeDNSResolver, net::OutboundInterface},
    proxy::{
        datagram::UdpPacket,
        utils::new_dual_stack_udp_socket,
    },
    session::SocksAddr,
};
use bytes::Bytes;
use futures::{Sink, Stream, ready};
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
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
const MAX_LOGICAL_MAPPINGS: usize = 128;

#[derive(Default)]
pub(crate) struct SocketRoutingTable {
    is_closed: bool,
    /// Active sessions on this socket: SessionId -> Sender<UdpPacket>
    sessions: HashMap<SessionId, Sender<UdpPacket>>,
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
        tx: Sender<UdpPacket>,
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

    /// Try to register a session on this socket and atomically bind a collection of destinations.
    /// Returns false if the socket is closed or if any destination is already bound to another session.
    fn try_register_many<'a>(
        &mut self,
        session_id: SessionId,
        tx: Sender<UdpPacket>,
        _initial_dst: Option<SocketAddr>,
        all_dsts: impl IntoIterator<Item = &'a SocketAddr>,
    ) -> bool {
        if self.is_closed {
            return false;
        }
        let dst_vec: Vec<SocketAddr> = all_dsts.into_iter().copied().collect();
        for dst in &dst_vec {
            if let Some(&owner) = self.dest_to_session.get(dst) {
                if owner != session_id {
                    return false;
                }
            }
        }
        for dst in dst_vec {
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
    fn bind_destination(&mut self, session_id: SessionId, dst: SocketAddr) -> Result<(), ()> {
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
            return self.sessions.get(session_id).cloned();
        }

        // 2. Unregistered remote address (Full-Cone NAT behavior)
        // Under Full-Cone NAT, deliver unsolicited packets (such as P2P hole-punching packets)
        // to the active session on this socket.
        self.last_active_session
            .and_then(|id| self.sessions.get(&id).cloned())
            .or_else(|| self.sessions.values().next().cloned())
    }

    fn on_transmit(&mut self, session_id: SessionId, _dst: SocketAddr) {
        if self.is_closed {
            return;
        }
        self.last_active_session = Some(session_id);
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
            let mut buf = vec![0u8; 65535];
            let mut consecutive_recv_errors = 0;
            loop {
                match socket_recv.recv_from(&mut buf).await {
                    Ok((len, peer_addr)) => {
                        consecutive_recv_errors = 0;
                        let peer = canonicalize_src(peer_addr);
                        let packet_data = Bytes::copy_from_slice(&buf[..len]);

                        let target_tx = routing_recv.read().route(peer);

                        if let Some(tx) = target_tx {
                            let packet = UdpPacket {
                                data: packet_data,
                                src_addr: SocksAddr::Ip(peer),
                                dst_addr: SocksAddr::any_ipv4(),
                                inbound_user: None,
                            };
                            if let Err(TrySendError::Full(_)) = tx.try_send(packet) {
                                tracing::trace!(
                                    "Direct pooled UDP downstream buffer full, packet dropped"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        consecutive_recv_errors += 1;
                        if consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                            tracing::warn!(
                                "Direct pooled UDP socket reached error limit ({MAX_CONSECUTIVE_RECV_ERRORS}), closing: {e}"
                            );
                            routing_recv.write().close();
                            if let Some(pool) = pool_weak.and_then(|w| w.upgrade()) {
                                pool.cleanup_closed(&key_clone);
                            }
                            break;
                        }
                        tracing::trace!("Direct pooled UDP transient recv error: {e}");
                        tokio::task::yield_now().await;
                    }
                }
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
        key: DirectSocketKey,
        iface: Option<&OutboundInterface>,
        destination: SocksAddr,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<PooledDirectDatagram> {
        let canon_dst = match destination {
            SocksAddr::Ip(addr) => Some(canonicalize_src(addr)),
            SocksAddr::Domain(..) => None,
        };

        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = channel(64);

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
                let new_entry = Arc::new(Self::create_entry(&key, iface, Some(pool_weak))?);
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
                    new_entry
                        .routing
                        .write()
                        .try_register(session_id, tx.clone(), canon_dst);
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
            resolver,
            iface: iface.cloned(),
            tx,
            registered_dsts,
            rx,
            pkt: None,
            flushed: true,
            pending_dns: None,
            resolved_dst: None,
            ip_to_logical,
        })
    }

    /// Re-home a session to a different socket if its newly-resolved destination
    /// collides with an existing session on the current socket.
    fn rehome(
        self: &Arc<Self>,
        key: &DirectSocketKey,
        current_entry: &Arc<DirectSocketEntry>,
        session_id: SessionId,
        tx: Sender<UdpPacket>,
        dst: SocketAddr,
        registered_dsts: &HashSet<SocketAddr>,
        iface: Option<&OutboundInterface>,
    ) -> io::Result<Arc<DirectSocketEntry>> {
        // Phase 1: Try to acquire or allocate a new socket FIRST.
        // If allocation fails (e.g. EMFILE/bind error), return Err immediately
        // without touching current_entry so the session retains its existing receiver!
        let all_dsts: Vec<SocketAddr> = std::iter::once(dst)
            .chain(registered_dsts.iter().copied())
            .collect();

        let mut chosen_entry = None;
        {
            let entries_guard = self.entries.read();
            if let Some(list) = entries_guard.get(key) {
                for candidate in list {
                    if Arc::ptr_eq(candidate, current_entry) {
                        continue;
                    }
                    let mut routing = candidate.routing.write();
                    if routing.try_register_many(session_id, tx.clone(), Some(dst), all_dsts.iter()) {
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
                let fresh_entry = Arc::new(Self::create_entry(key, iface, Some(pool_weak))?);
                let mut entries_guard = self.entries.write();
                let list = entries_guard.entry(key.clone()).or_default();
                list.retain(|e| !e.routing.read().is_closed());
                let mut registered = false;
                for candidate in list.iter() {
                    if Arc::ptr_eq(candidate, current_entry) {
                        continue;
                    }
                    let mut routing = candidate.routing.write();
                    if routing.try_register_many(session_id, tx.clone(), Some(dst), all_dsts.iter()) {
                        fresh_entry.recv_task.abort();
                        registered = true;
                        chosen_entry = Some(candidate.clone());
                        break;
                    }
                }
                if !registered {
                    fresh_entry
                        .routing
                        .write()
                        .try_register_many(session_id, tx, Some(dst), all_dsts.iter());
                    list.push(fresh_entry.clone());
                    fresh_entry
                } else {
                    chosen_entry.unwrap()
                }
            }
        };

        // Phase 2: Now that new_entry is guaranteed to be ready and registered,
        // cleanly unregister from current_entry.
        current_entry
            .routing
            .write()
            .unregister_session(session_id, registered_dsts);
        self.release(key, current_entry);

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
                list.retain(|e| !Arc::ptr_eq(e, entry) && !e.routing.read().is_closed());
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
    resolver: ThreadSafeDNSResolver,
    iface: Option<OutboundInterface>,
    tx: Sender<UdpPacket>,
    registered_dsts: HashSet<SocketAddr>,
    rx: Receiver<UdpPacket>,
    pkt: Option<UdpPacket>,
    flushed: bool,
    pending_dns: Option<JoinHandle<io::Result<SocketAddr>>>,
    resolved_dst: Option<SocketAddr>,
    ip_to_logical: HashMap<SocketAddr, SocksAddr>,
}

impl Drop for PooledDirectDatagram {
    fn drop(&mut self) {
        if let Some(handle) = self.pending_dns.take() {
            handle.abort();
        }
        self.entry
            .routing
            .write()
            .unregister_session(self.session_id, &self.registered_dsts);

        self.pool.release(&self.entry.key, &self.entry);
    }
}

impl Stream for PooledDirectDatagram {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.rx.poll_recv(cx)) {
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

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
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
        if let Some(handle) = pin.pending_dns.take() {
            handle.abort();
        }
        pin.pkt = Some(item);
        pin.resolved_dst = None;
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            session_id,
            ref mut entry,
            ref pool,
            ref tx,
            ref iface,
            ref mut pkt,
            ref resolver,
            ref mut pending_dns,
            ref mut resolved_dst,
            ref mut ip_to_logical,
            ref mut registered_dsts,
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
                    let handle = pending_dns.get_or_insert_with(|| {
                        let resolver = resolver.clone();
                        let domain = domain.clone();
                        let port = *port;
                        tokio::spawn(async move {
                            let ip = if is_ipv6 {
                                resolver.resolve(&domain, false).await.map_err(
                                    |_| io::Error::other("resolve domain failed"),
                                )?
                            } else {
                                resolver
                                    .resolve_v4(&domain, false)
                                    .await
                                    .map_err(|_| {
                                        io::Error::other("resolve domain failed")
                                    })?
                                    .map(IpAddr::V4)
                            };
                            match ip {
                                Some(ip) => Ok(SocketAddr::from((ip, port))),
                                None => Err(io::Error::other(format!(
                                    "resolve domain failed: {domain}"
                                ))),
                            }
                        })
                    });
                    let join_result = ready!(Pin::new(handle).poll(cx));
                    *pending_dns = None;
                    let addr = match join_result {
                        Ok(result) => result?,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "DNS task panicked: {e}"
                            ))));
                        }
                    };
                    *resolved_dst = Some(addr);
                    (addr, Some(p.dst_addr.clone()))
                }
            },
        };

        let canon_dst = canonicalize_src(dst);
        // Bind destination on current socket. If another session on this socket
        // already bound this destination, dynamically re-home to another socket!
        let bind_result = entry.routing.write().bind_destination(session_id, canon_dst);
        if bind_result.is_err() {
            let new_entry = pool.rehome(
                &entry.key,
                entry,
                session_id,
                tx.clone(),
                canon_dst,
                registered_dsts,
                iface.as_ref(),
            )?;
            *entry = new_entry;
        } else {
            entry.routing.write().on_transmit(session_id, canon_dst);
        }
        registered_dsts.insert(canon_dst);

        let send_dst = match (entry.local_is_ipv6, dst) {
            (true, SocketAddr::V4(v4)) => {
                SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
            }
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
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_routing_try_register_many_atomic() {
        let mut routing = SocketRoutingTable::default();
        let (tx1, _rx1) = channel(1);
        let (tx2, _rx2) = channel(1);

        let dst1: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let dst2: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let dst3: SocketAddr = "9.9.9.9:53".parse().unwrap();

        // Register session 1 with dst1
        assert!(routing.try_register(1, tx1, Some(dst1)));

        // Session 2 attempts to register with dst2 and dst1 (dst1 collides with session 1)
        let all_dsts = vec![dst2, dst1];
        assert!(!routing.try_register_many(2, tx2.clone(), Some(dst2), all_dsts.iter()));

        // Verification: dst2 must NOT be bound to session 2 because registration failed atomically
        assert!(!routing.dest_to_session.contains_key(&dst2));
        assert!(!routing.sessions.contains_key(&2));

        // Now session 2 attempts to register with dst2 and dst3 (no collision)
        let all_dsts_ok = vec![dst2, dst3];
        assert!(routing.try_register_many(2, tx2, Some(dst2), all_dsts_ok.iter()));
        assert_eq!(routing.dest_to_session.get(&dst2), Some(&2));
        assert_eq!(routing.dest_to_session.get(&dst3), Some(&2));
    }

    #[tokio::test]
    async fn test_rehome_skips_candidate_with_conflicting_old_destination() {
        let pool = Arc::new(DirectDatagramPool::new());
        let key = DirectSocketKey {
            source: "127.0.0.1:0".parse().unwrap(),
            iface_name: None,
            so_mark: None,
        };

        // Create socket 1 with session 10 bound to old_dst (1.1.1.1:53)
        let entry1 = Arc::new(DirectDatagramPool::create_entry(&key, None, None).unwrap());
        let (tx10, _rx10) = channel(1);
        let old_dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
        entry1.routing.write().try_register(10, tx10, Some(old_dst));

        // Add entry1 to pool
        pool.entries.write().insert(key.clone(), vec![entry1.clone()]);

        // Now session 20 is on another socket (entry0), and has previously registered old_dst
        let entry0 = Arc::new(DirectDatagramPool::create_entry(&key, None, None).unwrap());
        let (tx20, _rx20) = channel(1);
        let new_dst: SocketAddr = "2.2.2.2:53".parse().unwrap();
        let mut registered_dsts = HashSet::new();
        registered_dsts.insert(old_dst);

        // When session 20 tries to rehome to new_dst, entry1 cannot be chosen
        // because old_dst collides with session 10 on entry1!
        let rehomed = pool
            .rehome(
                &key,
                &entry0,
                20,
                tx20,
                new_dst,
                &registered_dsts,
                None,
            )
            .expect("rehome should succeed by allocating a fresh socket");

        // The chosen entry MUST NOT be entry1
        assert!(!Arc::ptr_eq(&rehomed, &entry1));
        // On rehomed socket, both new_dst and old_dst must belong to session 20
        assert_eq!(rehomed.routing.read().dest_to_session.get(&new_dst), Some(&20));
        assert_eq!(rehomed.routing.read().dest_to_session.get(&old_dst), Some(&20));
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
        mock_resolver
            .expect_resolve_v4()
            .returning(move |_, _| {
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


