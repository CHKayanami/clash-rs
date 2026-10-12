//! Route caches own leases, never protocol I/O or forwarding tasks.
use super::*;
use crate::{app::dispatcher::udp::association::FlowClosed, app::sniffer::SniffUdpOutcome};
use std::{pin::Pin as PacketPin, task::Poll};
use futures::{Stream, future::poll_fn};
use hashbrown::{Equivalent, HashMap as RouteMap};
use std::{collections::hash_map::RandomState, hash::{Hash, Hasher}};
use tokio::sync::mpsc;
use tracing::{trace, warn};

struct SessionLookup<'a> {
    source: SocketAddr,
    destination: &'a SocksAddr,
    user: Option<&'a str>,
}

impl Hash for SessionLookup<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.source, self.destination, self.user).hash(state);
    }
}

impl Equivalent<SessionKey> for SessionLookup<'_> {
    fn equivalent(&self, key: &SessionKey) -> bool {
        self.source == key.0 && self.destination == &key.1 && self.user == key.2.as_deref()
    }
}

struct UdpRoutes {
    sess: Session,
    ctx: UdpDispatchContext,
    sniffer: Option<ArcSniffer>,
    allow_quic: Arc<AtomicBool>,
    force_dns_mapping: bool,
    has_explicit_timeout: bool,
    timeout_duration: Duration,
    sessions: RouteMap<SessionKey, OutboundSession, RandomState>,
    connecting_sessions: HashMap<SessionKey, ConnectingSession>,
    pending_sniff_sessions: HashMap<SessionKey, PendingSniffSession>,
    delay_queue: DelayQueue<UdpQueueEvent>,
    session_established_tx: mpsc::Sender<EstablishOutcome>,
}

const PACKET_BATCH_LIMIT: usize = 16;
const PACKET_BATCH_TIME: Duration = Duration::from_millis(1);

pub(super) async fn run<S: Stream<Item = UdpPacket> + Unpin>(
    sess: Session, ctx: UdpDispatchContext, sniffer: Option<ArcSniffer>,
    allow_quic: Arc<AtomicBool>, mut incoming: S,
    mut closed: mpsc::UnboundedReceiver<FlowClosed>,
) {
    let (session_established_tx, mut established) = mpsc::channel(64);
    let mut routes = UdpRoutes {
        force_dns_mapping: sniffer.as_ref().is_some_and(|s| s.config.force_dns_mapping),
        has_explicit_timeout: sess.udp_timeout.is_some(),
        timeout_duration: sess.udp_timeout.unwrap_or_else(|| Duration::from_secs(DEFAULT_UDP_SESSION_TIMEOUT_SECS)),
        sess, ctx, sniffer, allow_quic, session_established_tx,
        sessions: RouteMap::with_hasher(RandomState::new()), connecting_sessions: HashMap::new(),
        pending_sniff_sessions: HashMap::new(), delay_queue: DelayQueue::new(),
    };
    loop {
        tokio::select! {
            biased;
            _ = routes.ctx.reply_sender.closed() => break,
            Some(outcome) = established.recv() => routes.established(outcome),
            Some(closed) = closed.recv() => routes.closed(closed),
            Some(expired) = routes.delay_queue.next() => routes.expired(expired.into_inner()),
            packet = incoming.next() => match packet {
                Some(packet) => {
                    let started = Instant::now();
                    routes.packet(packet);
                    tokio::task::consume_budget().await;
                    for _ in 1..PACKET_BATCH_LIMIT {
                        if started.elapsed() >= PACKET_BATCH_TIME { break; }
                        let next = poll_fn(|cx| Poll::Ready(PacketPin::new(&mut incoming).poll_next(cx))).await;
                        match next {
                            Poll::Ready(Some(packet)) => {
                                routes.packet(packet);
                                tokio::task::consume_budget().await;
                            },
                            Poll::Ready(None) => return,
                            Poll::Pending => break,
                        }
                    }
                },
                None => break,
            },
        }
    }
}

impl UdpRoutes {
    fn closed(&mut self, closed: FlowClosed) {
        let key = (closed.source, closed.original, closed.user);
        if self.sessions.get(&key).is_some_and(|flow| flow.id == closed.id)
            && let Some(flow) = self.sessions.remove(&key)
        { self.delay_queue.remove(&flow.delay_key); }
    }

    fn established(&mut self, outcome: EstablishOutcome) {
        match outcome {
            EstablishOutcome::Success(established, capacity_permit) => {
                let session_key = established.session_key.clone();
                let Some(mut connecting) = self.connecting_sessions.remove(&session_key) else {
                    // The connect attempt timed out or was superseded while
                    // its result was in flight. Do not resurrect the flow.
                    drop(established);
                    return;
                };
                if connecting.id != established.sess_id {
                    self.connecting_sessions.insert(session_key, connecting);
                    drop(established);
                    return;
                }
                self.delay_queue.remove(&connecting.delay_key);
                let buffered_packets = std::mem::take(&mut connecting.packets);
                let EstablishedSession {
                    sess_id,
                    dest,
                    flow,
                    reply_activity,
                    ..
                } = established;

                if flow.is_closed() { return; }
                let initial_upload_count = (buffered_packets.len() as u32).max(1);
                for packet in buffered_packets {
                    let _ = forward_to_remote(&flow, packet, sess_id);
                }
                let is_short_flow = !self.has_explicit_timeout
                    && initial_upload_count <= 2
                    && is_short_flow_port(session_key.1.port());
                let initial_timeout = if is_short_flow {
                    SHORT_FLOW_INIT_TIMEOUT
                } else {
                    self.timeout_duration
                };

                let last_upload = Instant::now();
                let idle_deadline = last_upload + initial_timeout;
                // A first reply can shorten a short flow's timeout.
                // Check at the earliest possible deadline without
                // sending per-packet activity messages to the actor.
                let scheduled_deadline = if is_short_flow {
                    last_upload + FAST_RESPONSE_TIMEOUT
                } else {
                    idle_deadline
                };
                let delay_key = self.delay_queue.insert_at(
                    UdpQueueEvent::SessionIdle(session_key.clone()),
                    scheduled_deadline,
                );

                self.sessions.insert(
                    session_key,
                    OutboundSession {
                        id: sess_id,
                        dest,
                        flow,
                        delay_key,
                        idle_deadline,
                        scheduled_deadline,
                        last_upload,
                        reply_activity,
                        _capacity_permit: capacity_permit,
                        upload_count: initial_upload_count,
                        is_short_flow,
                    },
                );
            }
            EstablishOutcome::Failed(session_key, sess_id) => {
                if self.connecting_sessions
                    .get(&session_key)
                    .is_some_and(|connecting| connecting.id == sess_id)
                    && let Some(connecting) = self.connecting_sessions.remove(&session_key)
                {
                    self.delay_queue.remove(&connecting.delay_key);
                }
            }

        }
    }

    fn expired(&mut self, event: UdpQueueEvent) {
        match event {
            UdpQueueEvent::SessionIdle(key) => {
                if let Some(session) = self.sessions.get_mut(&key) {
                    let deadline = session.latest_idle_deadline(self.timeout_duration);
                    if deadline > Instant::now() {
                        session.delay_key = self.delay_queue.insert_at(
                            UdpQueueEvent::SessionIdle(key.clone()),
                            deadline,
                        );
                        session.scheduled_deadline = deadline;
                    } else {
                        trace!("UDP session expired for src: {}, dst: {}", key.0, key.1);
                        self.sessions.remove(&key);
                    }
                }
            }
            UdpQueueEvent::PendingSniff(key) => {
                if let Some(pending) = self.pending_sniff_sessions.remove(&key) {
                    trace!(
                        "UDP pending sniff timed out for src: {}, dst: {}, flushing buffered packets",
                        key.0, key.1
                    );
                    start_connecting_session(
                        pending.sess,
                        pending.packets,
                        false,
                        &self.ctx,
                        &self.session_established_tx,
                        self.sessions.len(),
                        &mut self.connecting_sessions,
                        &mut self.delay_queue,
                    );
                }
            }
            UdpQueueEvent::Connecting(key, sess_id) => {
                if self.connecting_sessions
                    .get(&key)
                    .is_some_and(|connecting| connecting.id == sess_id)
                {
                    trace!(
                        "UDP outbound connection timed out for src: {}, dst: {}",
                        key.0, key.1
                    );
                    self.connecting_sessions.remove(&key);
                }
            }
        }
    }

    fn packet(&mut self, mut packet: UdpPacket) {
        if let SocksAddr::Ip(addr) = &mut packet.src_addr {
            addr.set_ip(addr.ip().to_canonical());
        }
        if let SocksAddr::Ip(addr) = &mut packet.dst_addr {
            addr.set_ip(addr.ip().to_canonical());
        }

        if !self.allow_quic.load(Ordering::Relaxed) && packet.dst_addr.port() == 443 {
            trace!(
                "QUIC packet dropped (UDP 443) from {} to {}",
                packet.src_addr, packet.dst_addr
            );
            return;
        }

        let Some(src_addr) = (match packet.src_addr {
            SocksAddr::Ip(addr) => Some(addr),
            SocksAddr::Domain(..) => None,
        }) else {
            warn!(
                "dropping inbound udp packet with non-ip source {}",
                packet.src_addr
            );
            return;
        };

        let lookup = SessionLookup {
            source: src_addr, destination: &packet.dst_addr,
            user: packet.inbound_user.as_deref().or(self.sess.inbound_user.as_deref()),
        };

        // Fast-path: Check if an active session already exists for this exact flow
        if let Some(session) = self.sessions.get_mut(&lookup) {
            debug!("reusing session #{} sent to remote {}", session.id, session.dest);
            if session.is_short_flow {
                session.upload_count += 1;
                if session.upload_count > 2 {
                    session.is_short_flow = false;
                }
            }
            let next_timeout = if session.is_short_flow {
                SHORT_FLOW_INIT_TIMEOUT
            } else {
                self.timeout_duration
            };
            session.refresh_idle(&mut self.delay_queue, next_timeout);
            if let Some(returned_packet) = forward_to_remote(
                &session.flow,
                packet,
                session.id,
            ) {
                packet = returned_packet;
                let lookup = SessionLookup {
                    source: src_addr, destination: &packet.dst_addr,
                    user: packet.inbound_user.as_deref().or(self.sess.inbound_user.as_deref()),
                };
                let dead_session = self.sessions.remove(&lookup).unwrap();
                self.delay_queue.remove(&dead_session.delay_key);
            } else {
                return;
            }
        }

        let orig_inbound_dst = packet.dst_addr.clone();
        let user = packet.inbound_user.clone().or_else(|| self.sess.inbound_user.clone());
        let session_key = (src_addr, orig_inbound_dst.clone(), user);

        // If this flow is currently establishing an outbound session, buffer the packet
        if let Some(buf) = self.connecting_sessions.get_mut(&session_key) {
            if buf.packets.len() < MAX_CONNECTING_PACKETS {
                buf.packets.push(packet);
            }
            return;
        }

        // Check if this flow is currently in the pending sniff buffer
        if let Some(pending) = self.pending_sniff_sessions.get_mut(&session_key) {
            let dst_sock = packet.dst_addr.clone().try_into_socket_addr();
            let outcome = if let (Some(s), Some(dst_sock)) = (self.sniffer.as_ref(), dst_sock) {
                s.sniff_udp_datagram_full(src_addr, dst_sock, &packet.data)
            } else {
                SniffUdpOutcome::NotMatched
            };

            match outcome {
                SniffUdpOutcome::Incomplete => {
                    if pending.packets.len() < MAX_PENDING_SNIFF_PACKETS {
                        pending.packets.push(packet);
                        return;
                    }
                    // Buffer full, flush with cached session
                    let pending = self.pending_sniff_sessions.remove(&session_key).unwrap();
                    self.delay_queue.remove(&pending.delay_key);
                    let mut packets = pending.packets;
                    packets.push(packet);

                    start_connecting_session(
                        pending.sess,
                        packets,
                        false,
                        &self.ctx,
                        &self.session_established_tx,
                        self.sessions.len(),
                        &mut self.connecting_sessions,
                        &mut self.delay_queue,
                    );
                }
                SniffUdpOutcome::Domain(domain, should_override) => {
                    let mut pending = self.pending_sniff_sessions.remove(&session_key).unwrap();
                    self.delay_queue.remove(&pending.delay_key);
                    pending.sess.destination = SocksAddr::Domain(domain.clone().into(), orig_inbound_dst.port());
                    pending.sess.sniffed_domain = Some(domain);

                    let mut packets = pending.packets;
                    packets.push(packet);

                    start_connecting_session(
                        pending.sess,
                        packets,
                        should_override,
                        &self.ctx,
                        &self.session_established_tx,
                        self.sessions.len(),
                        &mut self.connecting_sessions,
                        &mut self.delay_queue,
                    );
                }
                _ => {
                    // CompleteNoDomain or NotMatched
                    let pending = self.pending_sniff_sessions.remove(&session_key).unwrap();
                    self.delay_queue.remove(&pending.delay_key);
                    let mut packets = pending.packets;
                    packets.push(packet);

                    start_connecting_session(
                        pending.sess,
                        packets,
                        false,
                        &self.ctx,
                        &self.session_established_tx,
                        self.sessions.len(),
                        &mut self.connecting_sessions,
                        &mut self.delay_queue,
                    );
                }
            }
            return;
        }

        // Fresh flow (first packet):
        // 1. DNS / Fake-IP reverse lookup to resolve destination (Fake-IP > original target)
        let Some(target_dest) = reverse_lookup(
            &self.ctx.resolver,
            &orig_inbound_dst,
            self.force_dns_mapping,
        ) else {
            warn!("failed to resolve UDP destination {}", orig_inbound_dst);
            return;
        };
        let mapped_domain = if !orig_inbound_dst.is_domain() {
            target_dest.domain().map(|d| d.to_string())
        } else {
            None
        };

        let mut flow_sess = make_udp_flow_session(
            &self.sess,
            src_addr,
            orig_inbound_dst.clone(),
            target_dest.clone(),
            mapped_domain,
            packet.inbound_user.clone(),
        );

        // 2. Determine if sniffing is needed
        let should_sniff = self.sniffer.as_ref().map_or(false, |s| {
            if target_dest.is_domain() {
                // Known domain: only sniff if explicitly configured in force-domain
                s.should_force_sniff(&target_dest) || s.should_force_sniff(&orig_inbound_dst)
            } else {
                // Pure IP: follow parse_pure_ip configuration
                s.parse_pure_ip()
            }
        });

        // 3. Fast-path: no sniffing needed (Fake-IP / domain inbound / pure IP with parse_pure_ip=false)
        if !should_sniff {
            start_connecting_session(
                flow_sess,
                vec![packet],
                false,
                &self.ctx,
                &self.session_established_tx,
                self.sessions.len(),
                &mut self.connecting_sessions,
                &mut self.delay_queue,
            );
            return;
        }

        // 4. Sniffing path: perform QUIC SNI sniffing
        let mut override_dest = false;
        let mut should_buffer = false;

        if let Some(ref sniffer) = self.sniffer {
            let outcome = if let Some(dst_sock) = packet.dst_addr.clone().try_into_socket_addr() {
                sniffer.sniff_udp_datagram_full(src_addr, dst_sock, &packet.data)
            } else {
                match sniffer.sniff_datagram(packet.dst_addr.port(), &packet.data) {
                    Some((d, o)) => SniffUdpOutcome::Domain(d, o),
                    None => SniffUdpOutcome::NotMatched,
                }
            };

            match outcome {
                SniffUdpOutcome::Incomplete => {
                    should_buffer = true;
                }
                SniffUdpOutcome::Domain(domain, should_override) => {
                    flow_sess.sniffed_domain = Some(domain.clone());
                    flow_sess.destination = SocksAddr::Domain(domain.into(), packet.dst_addr.port());
                    override_dest = should_override;
                }
                _ => {}
            }
        }

        if should_buffer {
            if self.pending_sniff_sessions.len() >= MAX_CONNECTING_SESSIONS { return; }
            trace!("buffering incomplete QUIC packet for {} -> {}", src_addr, orig_inbound_dst);
            let delay_key = self.delay_queue.insert(
                UdpQueueEvent::PendingSniff(session_key.clone()),
                PENDING_SNIFF_TIMEOUT,
            );
            self.pending_sniff_sessions.insert(
                session_key,
                PendingSniffSession {
                    delay_key,
                    packets: vec![packet],
                    sess: flow_sess,
                },
            );
            return;
        }

        start_connecting_session(
            flow_sess,
            vec![packet],
            override_dest,
            &self.ctx,
            &self.session_established_tx,
            self.sessions.len(),
            &mut self.connecting_sessions,
            &mut self.delay_queue,
        );
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_route_keys_match_owned_addresses_and_user_identity() {
        let source = SocketAddr::from(([127, 0, 0, 1], 23456));
        let mut routes = RouteMap::with_hasher(RandomState::new());
        for destination in [SocksAddr::Ip(SocketAddr::from(([192, 0, 2, 1], 80))),
            SocksAddr::Domain("example.test".into(), 80)] {
            routes.insert((source, destination.clone(), Some(Arc::from("user-a"))), 1);
            routes.insert((source, destination.clone(), Some(Arc::from("user-b"))), 2);
            routes.insert((source, destination.clone(), None), 3);
            for (user, expected) in [(Some("user-a"), 1), (Some("user-b"), 2), (None, 3)] {
                let lookup = SessionLookup { source, destination: &destination, user };
                assert_eq!(routes.get(&lookup), Some(&expected));
                *routes.get_mut(&lookup).unwrap() += 10;
                assert_eq!(routes.remove(&lookup), Some(expected + 10));
            }
            let lookup = SessionLookup { source, destination: &destination, user: Some("missing") };
            assert!(routes.get(&lookup).is_none());
        }
    }
}
