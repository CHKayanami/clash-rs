//! UDP ingress dispatch, route caches and physical associations.
//!
//! Each destination is routed as a logical flow. Multi-target transports share
//! an endpoint-independent mapping within the same source/outbound security
//! scope; fixed-target transports and ambiguous reply projections stay private.
//! Reply filtering is endpoint-independent at the relay layer: unknown peers
//! are forwarded without assigning them to a guessed flow. Peer aliases restore
//! logical addresses and attribute traffic, independently of protocol policy.
//! These local guarantees do not imply that an upstream server or outer NAT
//! provides an endpoint-independent public mapping or filtering policy.
use crate::proxy::datagram::batch::MAX_BATCH_PACKETS;
use inbound::InboundIo;
use futures::future::poll_fn as poll_batch;
pub(crate) mod association;
mod routes;
mod inbound;
#[cfg(test)]
mod tests;

use std::{collections::HashMap, future::Future, net::{IpAddr, SocketAddr}, sync::{Arc,
    atomic::{AtomicBool, AtomicU8, Ordering}}, time::Duration};
use futures::{StreamExt, stream::poll_fn};
use tokio::{sync::mpsc::error::TrySendError, task::JoinHandle, time::Instant};
use tokio_util::{task::AbortOnDropHandle, time::DelayQueue};
use tracing::{Instrument, debug, error, info, info_span};
use crate::{
    app::{dns::ThreadSafeDNSResolver, outbound::manager::ThreadSafeOutboundManager,
        router::ArcRouter, sniffer::ArcSniffer},
    config::{def::RunMode, internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL}},
    proxy::{AnyInboundDatagram, OutboundType, datagram::UdpPacket},
    session::{Session, SocksAddr},
};
use super::{Dispatcher, TrackerInfo};
use super::dispatcher_impl::{decode_mode, effective_outbound_type, is_reject_error, reverse_lookup};
use association::{AssociationConfig, ReplyActivity, UdpAssociationPool, UdpFlow, UdpConnectContext};
#[cfg(feature = "tun")]
use crate::{app::net::get_default_outbound_interface, session::Type};

const DEFAULT_UDP_SESSION_TIMEOUT_SECS: u64 = 60;
const UDP_CHANNEL_CAPACITY: usize = 64;
const UDP_ROUTE_SHARDS: usize = 4;
const MAX_PENDING_SNIFF_PACKETS: usize = 4;
const MAX_CONNECTING_PACKETS: usize = 64;
const MAX_CONNECTING_SESSIONS: usize = 256;
/// Bound all resident UDP outbound state, not just concurrent connection
/// attempts. A permit is retained by an established session until it is
/// expired or otherwise removed.
const MAX_UDP_SESSIONS_PER_ACTOR: usize = 4096;
pub(super) const MAX_GLOBAL_UDP_SESSIONS: usize = 4096;
const PENDING_SNIFF_TIMEOUT: Duration = Duration::from_millis(100);
const CONNECTING_SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const SHORT_FLOW_INIT_TIMEOUT: Duration = Duration::from_secs(5);
const FAST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

#[inline]
fn is_short_flow_port(port: u16) -> bool {
    matches!(port, 53 | 123 | 5353)
}

type SessionKey = (SocketAddr, SocksAddr, Option<Arc<str>>);
type OutboundPacketSender = tokio::sync::mpsc::Sender<UdpPacket>;

struct OutboundSession {
    id: u64,
    dest: SocksAddr,
    flow: UdpFlow,
    delay_key: tokio_util::time::delay_queue::Key,
    idle_deadline: Instant,
    scheduled_deadline: Instant,
    last_upload: Instant,
    reply_activity: Arc<ReplyActivity>,
    _capacity_permit: tokio::sync::OwnedSemaphorePermit,
    upload_count: u32,
    is_short_flow: bool,
}

impl OutboundSession {
    fn refresh_idle(
        &mut self,
        delay_queue: &mut DelayQueue<UdpQueueEvent>,
        timeout: Duration,
    ) {
        self.last_upload = Instant::now();
        self.idle_deadline = self.last_upload + timeout;
        // Keep an earlier timer in place. When it fires, the actor will check
        // the latest activity and reschedule only if the flow is still active.
        if self.idle_deadline < self.scheduled_deadline {
            delay_queue.reset_at(&self.delay_key, self.idle_deadline);
            self.scheduled_deadline = self.idle_deadline;
        }
    }

    fn latest_idle_deadline(&self, timeout: Duration) -> Instant {
        match self.reply_activity.latest() {
            Some(reply) if reply > self.last_upload => {
                let reply_timeout = if self.is_short_flow {
                    FAST_RESPONSE_TIMEOUT
                } else {
                    timeout
                };
                reply + reply_timeout
            }
            _ => self.idle_deadline,
        }
    }
}

struct EstablishedSession {
    session_key: SessionKey,
    sess_id: u64,
    dest: SocksAddr,
    flow: UdpFlow,
    reply_activity: Arc<ReplyActivity>,
}

enum EstablishOutcome {
    Success(EstablishedSession, tokio::sync::OwnedSemaphorePermit),
    Failed(SessionKey, u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UdpQueueEvent {
    SessionIdle(SessionKey),
    PendingSniff(SessionKey),
    Connecting(SessionKey, u64),
}

struct PendingSniffSession {
    delay_key: tokio_util::time::delay_queue::Key,
    packets: Vec<UdpPacket>,
    sess: Session,
}

struct ConnectingSession {
    id: u64,
    delay_key: tokio_util::time::delay_queue::Key,
    packets: Vec<UdpPacket>,
    establish_handle: JoinHandle<()>,
}

impl Drop for ConnectingSession {
    fn drop(&mut self) {
        self.establish_handle.abort();
    }
}

#[derive(Clone)]
struct UdpDispatchContext {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<AtomicU8>,
    reply_sender: OutboundPacketSender,
    session_semaphore: Arc<tokio::sync::Semaphore>,
    associations: Arc<UdpAssociationPool>,
}

fn make_udp_flow_session(
    sess_base: &Session,
    src_addr: SocketAddr,
    orig_inbound_dst: SocksAddr,
    dest: SocksAddr,
    mapped_domain: Option<String>,
    inbound_user: Option<Arc<str>>,
) -> Session {
    let mut sess = sess_base.clone();
    #[cfg(feature = "tun")]
    if sess.typ == Type::Tun {
        sess.iface = get_default_outbound_interface();
    }
    sess.id = crate::session::generate_session_id();
    sess.source = src_addr;
    sess.destination = dest;
    sess.orig_destination = Some(orig_inbound_dst);
    sess.inbound_user = inbound_user.or_else(|| sess_base.inbound_user.clone());
    sess.mapped_domain = mapped_domain;
    sess.proxy_chain = crate::session::ProxyChain::new();
    sess
}

impl Dispatcher {
    pub fn dispatch_datagram(
        &self, sess: Session, udp_inbound: AnyInboundDatagram,
    ) -> impl Future<Output = tokio::sync::oneshot::Sender<u8>> + Send + '_ {
        let span = info_span!("dispatch_datagram", trace_id = sess.id);
        self.dispatch_datagram_inner(sess, udp_inbound).instrument(span)
    }

    async fn dispatch_datagram_inner(
        &self, sess: Session, udp_inbound: AnyInboundDatagram,
    ) -> tokio::sync::oneshot::Sender<u8> {
        let (replies, reply_rx) = tokio::sync::mpsc::channel(UDP_CHANNEL_CAPACITY);
        let (closed_flows, mut closed_rx) = tokio::sync::mpsc::unbounded_channel();
        let (close_sender, mut close_receiver) = tokio::sync::oneshot::channel();
        let associations = UdpAssociationPool::new(AssociationConfig {
            replies: replies.clone(), closed_flows, manager: self.manager.clone(),
            allow_quic: self.allow_quic.clone(),
            timeout: sess.udp_timeout.unwrap_or_else(|| Duration::from_secs(DEFAULT_UDP_SESSION_TIMEOUT_SECS)),
            capacity: self.udp_association_semaphore.clone(),
        });
        let ctx = UdpDispatchContext {
            outbound_manager: self.outbound_manager.clone(), router: self.router.clone(),
            resolver: self.resolver.clone(), mode: self.mode.clone(),
            reply_sender: replies, session_semaphore: self.udp_session_semaphore.clone(), associations,
        };
        let sniffer = self.sniffer.clone();
        let allow_quic = self.allow_quic.clone();
        // A connected inbound already isolates one client; wide UDP listeners
        // partition their route caches so different clients progress in parallel.
        let shard_count = if sess.source.port() == 0 { UDP_ROUTE_SHARDS } else { 1 };
        tokio::spawn(async move {
            let mut local = InboundIo::new(udp_inbound, reply_rx);
            if shard_count == 1 {
                tokio::select! {
                    _ = &mut close_receiver => {},
                    _ = routes::run(sess, ctx, sniffer, allow_quic, local, closed_rx) => {},
                }
                return;
            }
            let mut shards = Vec::with_capacity(shard_count);
            for _ in 0..shard_count {
                let (packets, mut incoming) = tokio::sync::mpsc::channel(UDP_CHANNEL_CAPACITY);
                let (closed, closed_rx) = tokio::sync::mpsc::unbounded_channel();
                let task = AbortOnDropHandle::new(tokio::spawn(routes::run(
                    sess.clone(), ctx.clone(), sniffer.clone(), allow_quic.clone(), poll_fn(move |cx| incoming.poll_recv(cx)), closed_rx,
                ).instrument(tracing::Span::current())));
                shards.push((packets, closed, task));
            }
            let mut inbound_batch = Vec::with_capacity(MAX_BATCH_PACKETS);
            'ingress: loop {
                tokio::select! {
                    _ = &mut close_receiver => break,
                    Some(closed) = closed_rx.recv() => {
                        let index = route_shard(closed.source, shard_count);
                        let _ = shards[index].1.send(closed);
                    }
                    result = poll_batch(|cx| local.poll_recv_batch(cx, &mut inbound_batch)) => {
                        let Some(()) = result else { break; };
                        for mut packet in inbound_batch.drain(..) {
                            tokio::task::consume_budget().await;
                            let source = match &mut packet.src_addr {
                                SocksAddr::Ip(addr) => { addr.set_ip(addr.ip().to_canonical()); *addr }
                                SocksAddr::Domain(..) => continue,
                            };
                            let index = route_shard(source, shard_count);
                            match shards[index].0.try_send(packet) {
                                Ok(()) => {},
                                Err(TrySendError::Full(_)) => debug!("UDP route queue full, dropping packet"),
                                Err(TrySendError::Closed(_)) => break 'ingress,
                            }
                        }
                    }
                }
            }
        }.instrument(tracing::Span::current()));
        close_sender
    }

}

fn route_shard(source: SocketAddr, count: usize) -> usize {
    let ip = match source.ip() {
        IpAddr::V4(ip) => u32::from(ip),
        IpAddr::V6(ip) => ip.segments().iter().fold(0u32, |hash, value| hash.rotate_left(5) ^ u32::from(*value)),
    };
    (ip ^ u32::from(source.port())) as usize % count
}

fn start_connecting_session(
    sess: Session,
    packets: Vec<UdpPacket>,
    override_dest: bool,
    ctx: &UdpDispatchContext,
    established_tx: &tokio::sync::mpsc::Sender<EstablishOutcome>,
    active_session_count: usize,
    connecting_sessions: &mut HashMap<SessionKey, ConnectingSession>,
    delay_queue: &mut DelayQueue<UdpQueueEvent>,
) {
    if connecting_sessions.len() >= MAX_CONNECTING_SESSIONS {
        debug!(
            "too many UDP outbound connections in progress, dropping flow {} -> {}",
            sess.source, sess.destination
        );
        return;
    }
    if active_session_count + connecting_sessions.len() >= MAX_UDP_SESSIONS_PER_ACTOR
    {
        debug!(
            "UDP outbound session limit reached for actor, dropping flow {} -> {}",
            sess.source, sess.destination
        );
        return;
    }
    let Ok(capacity_permit) = ctx.session_semaphore.clone().try_acquire_owned()
    else {
        debug!(
            "global UDP outbound session limit reached, dropping flow {} -> {}",
            sess.source, sess.destination
        );
        return;
    };

    let session_key = (
        sess.source,
        sess.orig_destination
            .clone()
            .unwrap_or_else(|| sess.destination.clone()),
        sess.inbound_user.clone(),
    );
    let sess_id = sess.id;
    let delay_key = delay_queue.insert(
        UdpQueueEvent::Connecting(session_key.clone(), sess_id),
        CONNECTING_SESSION_TIMEOUT,
    );
    let establish_handle = spawn_establish_session(
        sess,
        override_dest,
        ctx,
        established_tx,
        capacity_permit,
    );

    connecting_sessions.insert(
        session_key,
        ConnectingSession {
            id: sess_id,
            delay_key,
            packets,
            establish_handle,
        },
    );
}

fn spawn_establish_session(
    sess: Session,
    override_dest: bool,
    ctx: &UdpDispatchContext,
    established_tx: &tokio::sync::mpsc::Sender<EstablishOutcome>,
    capacity_permit: tokio::sync::OwnedSemaphorePermit,
) -> JoinHandle<()> {
    let ctx = ctx.clone();
    let established_tx = established_tx.clone();
    let sess_id = sess.id;
    let session_key = (
        sess.source,
        sess.orig_destination
            .clone()
            .unwrap_or_else(|| sess.destination.clone()),
        sess.inbound_user.clone(),
    );

    tokio::spawn(async move {
        let outcome = match establish_outbound_session(
            sess,
            override_dest,
            &ctx,
        )
        .await
        {
            Some(established) => {
                EstablishOutcome::Success(established, capacity_permit)
            }
            None => EstablishOutcome::Failed(session_key, sess_id),
        };
        let _ = established_tx.send(outcome).await;
    }.instrument(info_span!("udp_outbound", trace_id = sess_id)))
}

async fn establish_outbound_session(
    mut sess: Session,
    override_dest: bool,
    ctx: &UdpDispatchContext,
) -> Option<EstablishedSession> {
    let orig_inbound_dst = sess
        .orig_destination
        .clone()
        .unwrap_or_else(|| sess.destination.clone());
    let orig_dst_ip = orig_inbound_dst.ip();
    let is_fake_ip = orig_dst_ip.map_or(false, |ip| ctx.resolver.is_fake_ip(ip));
    let is_real_ip = match orig_dst_ip {
        Some(_) => !is_fake_ip,
        None => false,
    };
    if is_real_ip {
        sess.resolved_ip = orig_dst_ip;
    }

    let mode = decode_mode(ctx.mode.load(Ordering::Relaxed));
    let (outbound_name, rule) = match mode {
        RunMode::Global => (PROXY_GLOBAL, None),
        RunMode::Rule => ctx.router.match_route(&mut sess).await,
        RunMode::Direct => (PROXY_DIRECT, None),
    };

    if !override_dest && is_real_ip {
        sess.destination = orig_inbound_dst.clone();
    }

    let handler = match ctx.outbound_manager.get_outbound(outbound_name) {
        Some(h) => h,
        None => {
            debug!("unknown rule: {}, fallback to direct", outbound_name);
            ctx.outbound_manager.get_outbound(PROXY_DIRECT).unwrap()
        }
    };

    let effective_proto = effective_outbound_type(&handler).await;
    if matches!(effective_proto, OutboundType::Reject) {
        info!(
            "[UDP Short-Circuit] Drop packet immediately for sess: {}",
            sess
        );
        return None;
    }

    debug!(
        "building {} outbound datagram connecting to {}",
        sess, sess.destination
    );
    let tracker_info = Arc::new(TrackerInfo::new(&sess, rule));
    let flow = match handler
        .connect_datagram_using(&sess, ctx.resolver.clone(), &UdpConnectContext { pool: &ctx.associations, tracker: &tracker_info })
        .await
    {
        Ok(v) => v,
        Err(err) => {
            if is_reject_error(&err) {
                info!(
                    "[UDP Short-Circuit] Drop packet immediately for sess: {}",
                    sess
                );
            } else {
                error!("failed to connect outbound: sess = {} ,err = {}", sess, err);
            }
            return None;
        }
    };

    let reply_activity = flow.reply_activity();
    Some(EstablishedSession {
        session_key: (sess.source, orig_inbound_dst, sess.inbound_user.clone()), sess_id: sess.id,
        dest: sess.destination, flow, reply_activity,
    })
}

/// Hand a packet directly to its association without awaiting.
///
/// A packet is returned only when the route or association is closed, allowing
/// the actor to remove the stale session and route that packet through a new
/// outbound association.
fn forward_to_remote(
    flow: &UdpFlow,
    packet: UdpPacket,
    sess_id: u64,
) -> Option<UdpPacket> {
    match flow.try_send(packet) {
        Ok(_) => None,
        Err(TrySendError::Full(_)) => {
            debug!(
                "[UDP] outbound queue full, dropping packet for session #{}",
                sess_id
            );
            None
        }
        Err(TrySendError::Closed(packet)) => {
            debug!("[UDP] outbound relay gone, rebuilding session #{}", sess_id);
            Some(packet)
        }
    }
}
