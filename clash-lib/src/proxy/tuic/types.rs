use crate::{
    app::{dns::ThreadSafeDNSResolver, net::get_default_outbound_interface},
    proxy::{
        datagram::UdpPacket,
        utils::{
            new_udp_socket,
            quic_stream::{
                QUIC_HALF_CLOSED_DRAIN_GRACE, QUIC_STREAM_DRAIN_TIMEOUT,
                QuicStreamLease, QuicUploadGrace, close_after_grace,
            },
        },
    },
    session::SocksAddr as ClashSocksAddr,
};
use anyhow::{Result, anyhow};
use arc_swap::ArcSwapOption;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::runtime::Handle;
use tracing::debug;
use uuid::Uuid;

use super::proto::Address;
use super::proto::fragment::FragmentReassembler;

pub struct TuicEndpoint {
    pub ep: quinn::Endpoint,
    pub server: ServerAddr,
    pub uuid: Uuid,
    pub password: Arc<[u8]>,
    pub udp_relay_mode: UdpRelayMode,
    pub zero_rtt_handshake: bool,
    pub heartbeat: Duration,
    pub gc_interval: Duration,
    pub gc_lifetime: Duration,
}

impl TuicEndpoint {
    pub async fn connect(
        &self,
        resolver: &ThreadSafeDNSResolver,
        rebind: bool,
        keep_idle: Arc<AtomicBool>,
        cache_slot: Weak<ArcSwapOption<TuicConnection>>,
    ) -> Result<Arc<TuicConnection>> {
        let remote_addr = self.server.resolve(resolver).await?;
        let connect_to = async {
            if rebind {
                debug!("rebinding endpoint UDP socket");

                let socket = {
                    let iface = get_default_outbound_interface();
                    new_udp_socket(
                        None,
                        iface.as_deref(),
                        #[cfg(target_os = "linux")]
                        None,
                        Some(remote_addr),
                    )
                    .await?
                };

                debug!("rebound endpoint UDP socket to {}", socket.local_addr()?);

                self.ep.rebind(socket.into_std()?).map_err(|err| {
                    anyhow!("failed to rebind endpoint UDP socket {}", err)
                })?;
            }

            tracing::trace!(
                "connecting to {} {} from {}",
                remote_addr,
                self.server.server_name(),
                self.ep.local_addr().unwrap()
            );

            let conn = self.ep.connect(remote_addr, self.server.server_name())?;
            let (conn, zero_rtt_accepted) = if self.zero_rtt_handshake {
                match conn.into_0rtt() {
                    Ok((conn, zero_rtt_accepted)) => (conn, Some(zero_rtt_accepted)),
                    Err(conn) => (conn.await?, None),
                }
            } else {
                (conn.await?, None)
            };

            anyhow::Ok((conn, zero_rtt_accepted))
        };

        let (conn, zero_rtt_accepted) = connect_to.await?;
        Ok(TuicConnection::new(
            conn,
            zero_rtt_accepted,
            self.udp_relay_mode,
            self.uuid,
            self.password.clone(),
            self.heartbeat,
            self.gc_interval,
            self.gc_lifetime,
            keep_idle,
            cache_slot,
        ))
    }
}

/// Highest bit of `active_streams`: once set, the connection is closing
/// and must not accept any new stream leases.
const TUIC_CLOSING_BIT: usize = 1usize << (usize::BITS - 1);
pub(super) const TUIC_STREAM_DRAIN_TIMEOUT: Duration = QUIC_STREAM_DRAIN_TIMEOUT;
pub(super) const TUIC_HALF_CLOSED_DRAIN_GRACE: Duration =
    QUIC_HALF_CLOSED_DRAIN_GRACE;

pub struct TuicStreamLease {
    conn: Arc<TuicConnection>,
}

impl Drop for TuicStreamLease {
    fn drop(&mut self) {
        self.conn.release_lease();
    }
}

impl QuicStreamLease for TuicStreamLease {
    fn record_upload_ack_grace(&self, grace: Duration) {
        self.conn.upload_grace.extend(grace);
    }
}

pub struct TuicConnection {
    pub conn: quinn::Connection,
    pub uuid: Uuid,
    pub password: Arc<[u8]>,
    pub udp_relay_mode: UdpRelayMode,
    pub udp_sessions: Arc<parking_lot::RwLock<HashMap<u16, UdpSession>>>,
    pub next_pkt_id: AtomicU16,
    pub fragments: parking_lot::Mutex<FragmentReassembler>,
    active_streams: AtomicUsize,
    keep_idle: Arc<AtomicBool>,
    /// Set once evicted or retired (e.g. handler dropped on provider refresh or
    /// config reload) so the connection closes as soon as active streams finish.
    evicted: AtomicBool,
    upload_grace: QuicUploadGrace,
    runtime: Handle,
    drain_timeout_ms: AtomicU64,
    cache_slot: Weak<ArcSwapOption<TuicConnection>>,
}

pub struct UdpSession {
    pub incoming: tokio::sync::mpsc::Sender<UdpPacket>,
    pub local_addr: ClashSocksAddr,
}

impl TuicConnection {
    pub fn check_open(&self) -> Result<()> {
        self.conn
            .close_reason()
            .map_or(Ok(()), |err| Err(err.into()))
    }

    pub(super) fn drain_timeout(&self) -> Duration {
        Duration::from_millis(self.drain_timeout_ms.load(Ordering::Relaxed))
    }

    pub fn try_acquire_lease(self: &Arc<Self>) -> Option<TuicStreamLease> {
        self.active_streams
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                if val & TUIC_CLOSING_BIT != 0 {
                    None
                } else {
                    Some(val + 1)
                }
            })
            .ok()
            .map(|_| TuicStreamLease { conn: self.clone() })
    }

    fn evict_from_cache(self: &Arc<Self>) {
        if let Some(cache_slot) = self.cache_slot.upgrade() {
            let _ = cache_slot.rcu(|current| match current {
                Some(cached) if Arc::ptr_eq(cached, self) => None,
                _ => current.clone(),
            });
        }
    }

    fn should_keep_idle(&self) -> bool {
        self.keep_idle.load(Ordering::SeqCst) && !self.evicted.load(Ordering::SeqCst)
    }

    pub(super) fn mark_evicted(self: &Arc<Self>) {
        self.evicted.store(true, Ordering::SeqCst);
        self.close_if_idle();
    }

    fn release_lease(self: &Arc<Self>) {
        let keep_idle = self.should_keep_idle();
        let mut closed_now = false;
        let mut became_zero = false;
        let _ = self.active_streams.try_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |val| {
                let closing = (val & TUIC_CLOSING_BIT) != 0;
                let count = (val & !TUIC_CLOSING_BIT).saturating_sub(1);
                let next_closing = closing || (!keep_idle && count == 0);
                closed_now = !closing && next_closing;
                became_zero = !next_closing && count == 0;
                Some(if next_closing {
                    TUIC_CLOSING_BIT | count
                } else {
                    count
                })
            },
        );
        if closed_now {
            self.evict_from_cache();
            self.close_with_grace();
        } else if became_zero && !self.should_keep_idle() {
            self.close_if_idle();
        }
    }

    pub fn close_if_idle(self: &Arc<Self>) {
        if self
            .active_streams
            .compare_exchange(
                0,
                TUIC_CLOSING_BIT,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            self.evict_from_cache();
            self.close_with_grace();
        }
    }

    fn close_with_grace(self: &Arc<Self>) {
        close_after_grace(
            &self.runtime,
            &self.upload_grace,
            &self.conn,
            b"idle",
            (),
        );
    }

    #[cfg(test)]
    pub(super) fn active_streams_for_test(&self) -> usize {
        self.active_streams.load(Ordering::Acquire) & !TUIC_CLOSING_BIT
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: quinn::Connection,
        zero_rtt_accepted: Option<quinn::ZeroRttAccepted>,
        udp_relay_mode: UdpRelayMode,
        uuid: Uuid,
        password: Arc<[u8]>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
        keep_idle: Arc<AtomicBool>,
        cache_slot: Weak<ArcSwapOption<TuicConnection>>,
    ) -> Arc<Self> {
        let conn = Self {
            conn,
            uuid,
            password,
            udp_relay_mode,
            udp_sessions: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            next_pkt_id: AtomicU16::new(0),
            fragments: parking_lot::Mutex::new(FragmentReassembler::default()),
            active_streams: AtomicUsize::new(0),
            keep_idle,
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            drain_timeout_ms: AtomicU64::new(
                TUIC_STREAM_DRAIN_TIMEOUT.as_millis() as u64,
            ),
            cache_slot,
        };
        let conn = Arc::new(conn);
        tokio::spawn(conn.clone().init(
            zero_rtt_accepted,
            heartbeat,
            gc_interval,
            gc_lifetime,
        ));

        conn
    }

    async fn init(
        self: Arc<Self>,
        zero_rtt_accepted: Option<quinn::ZeroRttAccepted>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) {
        tracing::info!("connection established");

        tokio::spawn(self.clone().tuic_auth(zero_rtt_accepted));
        tokio::spawn(self.clone().cyclical_tasks(
            heartbeat,
            gc_interval,
            gc_lifetime,
        ));

        let err = loop {
            tokio::select! {
                res = self.accept_uni_stream() => match res {
                    Ok(recv) => { tokio::spawn(self.clone().handle_uni_stream(recv)); },
                    Err(err) => break err,
                },
                res = self.accept_bi_stream() => match res {
                    Ok((send, recv)) => { tokio::spawn(self.clone().handle_bi_stream(send, recv)); },
                    Err(err) => break err,
                },
                res = self.accept_datagram() => match res {
                    Ok(dg) => self.handle_datagram(dg).await,
                    Err(err) => break err,
                },
            };
        };

        tracing::warn!("connection error: {err:?}");
    }

    #[inline]
    pub fn get_next_pkt_id(&self) -> u16 {
        self.next_pkt_id.fetch_add(1, Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        conn: quinn::Connection,
        udp_relay_mode: UdpRelayMode,
        next_pkt_id: u16,
    ) -> Arc<Self> {
        Arc::new(Self {
            conn,
            uuid: Uuid::nil(),
            password: Arc::from([]),
            udp_relay_mode,
            udp_sessions: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            next_pkt_id: AtomicU16::new(next_pkt_id),
            fragments: parking_lot::Mutex::new(FragmentReassembler::default()),
            active_streams: AtomicUsize::new(0),
            keep_idle: Arc::new(AtomicBool::new(true)),
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            drain_timeout_ms: AtomicU64::new(
                TUIC_STREAM_DRAIN_TIMEOUT.as_millis() as u64,
            ),
            cache_slot: Weak::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn set_keep_idle_for_test(self: &Arc<Self>, keep: bool) {
        self.keep_idle.store(keep, Ordering::SeqCst);
        if !keep {
            self.close_if_idle();
        }
    }

    #[cfg(test)]
    pub(crate) fn set_drain_timeout_for_test(&self, timeout: Duration) {
        self.drain_timeout_ms
            .store(timeout.as_millis().max(1) as u64, Ordering::Relaxed);
    }
}

pub struct ServerAddr {
    domain: String,
    port: u16,
    ip: Option<IpAddr>,
    sni: Option<String>,
}

impl ServerAddr {
    pub fn new(
        domain: String,
        port: u16,
        ip: Option<IpAddr>,
        sni: Option<String>,
    ) -> Self {
        Self {
            domain,
            port,
            ip,
            sni,
        }
    }

    #[inline]
    pub fn server_name(&self) -> &str {
        self.sni.as_ref().unwrap_or(&self.domain)
    }

    pub async fn resolve(
        &self,
        resolver: &ThreadSafeDNSResolver,
    ) -> Result<SocketAddr> {
        if let Some(ip) = self.ip {
            Ok(SocketAddr::from((ip, self.port)))
        } else if let Ok(ip) = self.domain.parse::<IpAddr>() {
            Ok(SocketAddr::from((ip, self.port)))
        } else {
            let ip = resolver
                .resolve(self.domain.as_str(), false)
                .await?
                .ok_or(anyhow!("Resolve failed: unknown hostname"))?;
            Ok(SocketAddr::from((ip, self.port)))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

impl From<&str> for UdpRelayMode {
    #[inline]
    fn from(s: &str) -> Self {
        if s.eq_ignore_ascii_case("native") {
            Self::Native
        } else {
            Self::Quic
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    #[default]
    Bbr,
    Bbr3,
}

impl From<&str> for CongestionControl {
    #[inline]
    fn from(s: &str) -> Self {
        if s.eq_ignore_ascii_case("cubic") {
            Self::Cubic
        } else if s.eq_ignore_ascii_case("new_reno")
            || s.eq_ignore_ascii_case("newreno")
        {
            Self::NewReno
        } else if s.eq_ignore_ascii_case("bbr") {
            Self::Bbr
        } else if s.eq_ignore_ascii_case("bbr3") {
            Self::Bbr3
        } else {
            tracing::warn!(
                "Unknown congestion controller {s}. Use default controller"
            );
            Self::default()
        }
    }
}

pub trait SocketAdderTrans {
    fn into_tuic(self) -> Address;
}

impl SocketAdderTrans for crate::session::SocksAddr {
    #[inline]
    fn into_tuic(self) -> Address {
        self.into()
    }
}
