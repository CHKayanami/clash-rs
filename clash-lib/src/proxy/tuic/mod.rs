mod compat;
mod handle_stream;
mod handle_task;
pub(crate) mod proto;
pub(crate) mod stream;
pub(crate) mod types;

use crate::{
    common::tls::{DefaultTlsVerifier, build_tls_client_config},
    proxy::{tuic::types::SocketAdderTrans, utils::new_udp_socket},
};
use anyhow::Result;
use arc_swap::ArcSwapOption;
use futures::{StreamExt, stream::FuturesUnordered};

use quinn::{
    ClientConfig as QuinnConfig, Endpoint as QuinnEndpoint, EndpointConfig,
    TokioRuntime, TransportConfig as QuinnTransportConfig, VarInt,
    crypto::rustls::QuicClientConfig,
};
use quinn_proto::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use tracing::debug;

use erased_serde::Serialize as ErasedSerialize;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use uuid::Uuid;

use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::{
        AnyOutboundDatagram, AnyStream, DialWithConnector,
        tuic::types::{ServerAddr, TuicEndpoint},
    },
    session::Session,
};

use crate::session::SocksAddr as ClashSocksAddr;
use tokio::{
    runtime::Handle,
    sync::{
        Mutex as AsyncMutex, OnceCell,
        mpsc::{self, Receiver as MpscReceiver, error::TryRecvError},
    },
    time::{Instant, Sleep, sleep, sleep_until, timeout_at},
};
use tokio_util::sync::{CancellationToken, PollSender};

use self::{
    proto::{ParsedPacket, fragment::FragmentReassembler},
    types::{
        CongestionControl, TUIC_HALF_CLOSED_DRAIN_GRACE, TuicConnection,
        TuicStreamLease, UdpRelayMode,
    },
};

use super::{
    HandlerCommonOptions, OutboundHandler, OutboundType,
    PlainProxyAPIResponse, datagram::UdpPacket,
};

#[derive(Debug, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub udp_relay_mode: UdpRelayMode,
    pub disable_sni: bool,
    pub alpn: Vec<Vec<u8>>,
    pub heartbeat_interval: Duration,
    pub reduce_rtt: bool,
    pub request_timeout: Duration,
    pub idle_timeout: Duration,
    pub congestion_controller: CongestionControl,
    pub max_open_stream: VarInt,
    pub gc_interval: Duration,
    pub gc_lifetime: Duration,
    pub send_window: u64,
    pub receive_window: VarInt,
    pub skip_cert_verify: bool,
    pub fingerprint: Option<String>,

    #[allow(dead_code)]
    pub common_opts: HandlerCommonOptions,

    /// not used
    #[allow(dead_code)]
    pub max_udp_relay_packet_size: u64,
    pub ip: Option<String>,
    pub sni: Option<String>,
    /// File path or inline PEM client certificate for mTLS.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    pub tls_key: Option<String>,
}

pub struct Handler {
    opts: HandlerOptions,
    client_config: OnceCell<QuinnConfig>,
    conn: Arc<ArcSwapOption<TuicConnection>>,
    keep_idle: Arc<AtomicBool>,
    reconnect: AsyncMutex<()>,
    next_assoc_id: AtomicU16,
}

struct DialEndpointGuard {
    ep: Option<Arc<TuicEndpoint>>,
}

impl DialEndpointGuard {
    fn new(ep: Arc<TuicEndpoint>) -> Self {
        Self { ep: Some(ep) }
    }

    fn as_arc(&self) -> &Arc<TuicEndpoint> {
        self.ep.as_ref().expect("tuic dial endpoint present")
    }

    fn disarm(&mut self) -> Arc<TuicEndpoint> {
        self.ep.take().expect("tuic dial endpoint already taken")
    }
}

impl Drop for DialEndpointGuard {
    fn drop(&mut self) {
        if let Some(ep) = self.ep.take() {
            ep.ep.close(0u32.into(), b"dial aborted");
        }
    }
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuic")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl DialWithConnector for Handler {}

impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tuic
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        self.do_connect_stream(sess, resolver).await.map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::other(e.to_string())
        })
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyOutboundDatagram> {
        self.do_connect_datagram(sess, resolver).await.map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::other(e.to_string())
        })
    }

    fn set_keep_idle(&self, keep: bool) {
        self.keep_idle.store(keep, Ordering::SeqCst);
        if !keep {
            self.close_idle_connections();
        }
    }

    fn close_idle_connections(&self) {
        if let Some(conn) = self.conn.load_full() {
            conn.close_if_idle();
        }
    }

}

impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert("uuid".to_owned(), Box::new(self.opts.uuid.to_string()) as _);
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        let udp_relay_mode = match &self.opts.udp_relay_mode {
            crate::proxy::tuic::types::UdpRelayMode::Native => "native",
            crate::proxy::tuic::types::UdpRelayMode::Quic => "quic",
        };
        m.insert(
            "udp-relay-mode".to_owned(),
            Box::new(udp_relay_mode.to_string()) as _,
        );
        if self.opts.skip_cert_verify {
            m.insert("skip-cert-verify".to_owned(), Box::new(true) as _);
        }
        if let Some(sni) = self.opts.sni.as_ref() {
            m.insert("sni".to_owned(), Box::new(sni.clone()) as _);
        }
        if self.opts.disable_sni {
            m.insert("disable-sni".to_owned(), Box::new(true) as _);
        }
        m
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.keep_idle.store(false, Ordering::SeqCst);
        if let Some(conn) = self.conn.swap(None) {
            conn.mark_evicted();
        }
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            client_config: OnceCell::new(),
            conn: Arc::new(ArcSwapOption::empty()),
            keep_idle: Arc::new(AtomicBool::new(true)),
            reconnect: AsyncMutex::new(()),
            next_assoc_id: AtomicU16::new(0),
        }
    }

    fn build_client_config(opts: &HandlerOptions) -> Result<QuinnConfig> {
        let verifier = Arc::new(DefaultTlsVerifier::new(
            opts.fingerprint.clone(),
            opts.skip_cert_verify,
        ));
        let mut crypto = build_tls_client_config(
            verifier,
            opts.tls_cert.as_deref(),
            opts.tls_key.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!("tuic TLS: {e}"))?;
        // TODO(error-handling) if alpn not match the following error will be
        // throw: aborted by peer: the cryptographic handshake failed: error
        // 120: peer doesn't support any known protocol
        crypto.alpn_protocols.clone_from(&opts.alpn);
        crypto.enable_early_data = true;
        crypto.enable_sni = !opts.disable_sni;

        let mut quinn_config =
            QuinnConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
        let mut transport_config = QuinnTransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(opts.max_open_stream)
            .max_concurrent_uni_streams(opts.max_open_stream)
            .send_window(opts.send_window)
            .stream_receive_window(opts.receive_window)
            .max_idle_timeout(Some(opts.idle_timeout.try_into().unwrap()));
        match opts.congestion_controller {
            CongestionControl::Cubic => transport_config
                .congestion_controller_factory(Arc::new(CubicConfig::default())),
            CongestionControl::NewReno => transport_config
                .congestion_controller_factory(Arc::new(NewRenoConfig::default())),
            CongestionControl::Bbr => transport_config
                .congestion_controller_factory(Arc::new(BbrConfig::default())),
            CongestionControl::Bbr3 => {
                tracing::warn!(
                    "TUIC BBR3 is unavailable with Quinn 0.11; using BBR"
                );
                transport_config
                    .congestion_controller_factory(Arc::new(BbrConfig::default()))
            }
        };

        quinn_config.transport_config(Arc::new(transport_config));
        Ok(quinn_config)
    }

    async fn init_endpoint(
        &self,
        quinn_config: QuinnConfig,
        resolver: &ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<Arc<TuicEndpoint>> {
        let socket = if resolver.ipv6() {
            new_udp_socket(
                Some((Ipv6Addr::UNSPECIFIED, 0).into()),
                sess.iface.as_deref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                None,
            )
            .await?
        } else {
            new_udp_socket(
                Some((Ipv4Addr::UNSPECIFIED, 0).into()),
                sess.iface.as_deref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                None,
            )
            .await?
        };

        debug!("binding socket to: {:?}", socket.local_addr()?);

        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(TokioRuntime),
        )?;

        endpoint.set_default_client_config(quinn_config);

        let ip_addr = self
            .opts
            .ip
            .as_ref()
            .and_then(|ip_str| ip_str.parse().ok())
            .or_else(|| self.opts.server.parse().ok());

        Ok(Arc::new(TuicEndpoint {
            ep: endpoint,
            server: ServerAddr::new(
                self.opts.server.clone(),
                self.opts.port,
                ip_addr,
                self.opts.sni.clone(),
            ),
            uuid: self.opts.uuid,
            password: Arc::from(self.opts.password.as_bytes()),
            udp_relay_mode: self.opts.udp_relay_mode,
            zero_rtt_handshake: self.opts.reduce_rtt,
            heartbeat: self.opts.heartbeat_interval,
            gc_interval: self.opts.gc_interval,
            gc_lifetime: self.opts.gc_lifetime,
        }))
    }

    async fn get_conn(
        &self,
        resolver: &ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<(Arc<TuicConnection>, TuicStreamLease)> {
        let fut = async {
            if let Some(conn) = self.conn.load().as_ref()
                && conn.is_alive()
                && let Some(lease) = conn.try_acquire_lease()
            {
                return Ok((conn.clone(), lease));
            }
            let _reconnect = self.reconnect.lock().await;
            let existing = self.conn.load_full();
            if let Some(conn) = &existing
                && conn.is_alive()
                && let Some(lease) = conn.try_acquire_lease()
            {
                return Ok((conn.clone(), lease));
            }
            if let Some(old) = existing.as_ref() {
                old.evict_from_cache();
            }

            let quinn_config = self
                .client_config
                .get_or_try_init(|| async { Self::build_client_config(&self.opts) })
                .await?
                .clone();

            let mut ep_guard = DialEndpointGuard::new(
                self.init_endpoint(quinn_config, resolver, sess).await?,
            );
            let conn = ep_guard
                .as_arc()
                .connect(
                    resolver,
                    self.keep_idle.clone(),
                    Arc::downgrade(&self.conn),
                )
                .await?;
            let _endpoint = ep_guard.disarm();
            let lease = conn
                .try_acquire_lease()
                .expect("fresh tuic connection must accept initial lease");

            self.publish_conn(&conn);
            Ok((conn, lease))
        };

        tokio::time::timeout(self.opts.request_timeout, fut).await?
    }

    pub(crate) fn publish_conn(&self, conn: &Arc<TuicConnection>) {
        if conn.is_alive() {
            if let Some(old) = self.conn.swap(Some(conn.clone())) {
                old.mark_evicted();
            }
            // Re-check liveness after publishing so an immediate close callback
            // that ran before caching cannot leave a dead connection cached, and
            // reclaim immediately if `keep_idle` is false and no leases remain.
            if !conn.is_alive() {
                conn.evict_from_cache();
                conn.mark_evicted();
            } else if !self.keep_idle.load(Ordering::SeqCst) {
                conn.close_if_idle();
            }
        } else {
            conn.mark_evicted();
        }
    }

    #[cfg(test)]
    pub(crate) fn cached_endpoint_for_test(&self) -> Option<Arc<TuicEndpoint>> {
        self.conn.load_full().and_then(|c| c.endpoint_for_test())
    }

    #[cfg(test)]
    pub(crate) fn cached_conn_for_test(&self) -> Option<Arc<TuicConnection>> {
        self.conn.load_full()
    }

    #[cfg(test)]
    pub(crate) fn has_client_config_for_test(&self) -> bool {
        self.client_config.get().is_some()
    }

    async fn do_connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<AnyStream> {
        let (conn, lease) = self.get_conn(&resolver, sess).await?;
        let dest = sess.destination.clone().into_tuic();
        let tuic_tcp = conn.connect_tcp(dest, lease).await?;
        sess.push_chain(self.name());
        Ok(AnyStream::new(tuic_tcp))
    }

    async fn do_connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<AnyOutboundDatagram> {
        let (conn, lease) = self.get_conn(&resolver, sess).await?;
        let assos_id = self.next_assoc_id.fetch_add(1, Ordering::SeqCst);
        let quic_udp = TuicDatagramOutbound::new_with_lease(
            assos_id,
            conn,
            sess.source.into(),
            Some(lease),
        );
        sess.push_chain(self.name());
        Ok(AnyOutboundDatagram::new(quic_udp))
    }
}

const UDP_SESSION_QUEUE_CAP: usize = 256;

pub struct TuicDatagramOutbound {
    send_tx: Option<PollSender<UdpPacket>>,
    cancel: Option<CancellationToken>,
    conn: Arc<TuicConnection>,
    runtime: Handle,
    assoc_id: u16,
    local_addr: ClashSocksAddr,
    closed: bool,
    fragments: FragmentReassembler,
    gc_interval: Duration,
    gc_timer: Option<Pin<Box<Sleep>>>,
    #[cfg(test)]
    gc_timer_allocs: usize,
    recv_rx: MpscReceiver<ParsedPacket>,
    _lease: Option<TuicStreamLease>,
}

impl TuicDatagramOutbound {
    #[cfg(test)]
    pub fn new(
        assoc_id: u16,
        conn: Arc<TuicConnection>,
        local_addr: ClashSocksAddr,
    ) -> Self {
        let lease = conn.try_acquire_lease();
        Self::new_with_lease(assoc_id, conn, local_addr, lease)
    }

    pub fn new_with_lease(
        assoc_id: u16,
        conn: Arc<TuicConnection>,
        local_addr: ClashSocksAddr,
        lease: Option<TuicStreamLease>,
    ) -> Self {
        let (recv_tx, recv_rx) =
            mpsc::channel::<ParsedPacket>(UDP_SESSION_QUEUE_CAP);
        let registered = conn.register_udp_session(assoc_id, recv_tx);
        let (send_tx, cancel, outbound_lease) = if !registered {
            (None, None, None)
        } else if conn.udp_relay_mode == UdpRelayMode::Quic {
            let (send_tx, send_rx) = mpsc::channel::<UdpPacket>(32);
            let cancel = CancellationToken::new();
            let task_cancel = cancel.clone();
            let conn = conn.clone();
            // Move the stream lease into the background sender task so the QUIC
            // connection stays alive until every queued UDP packet, all
            // in-flight uni-streams, and the trailing dissociate frame complete
            // (bounded by a single shared `drain_timeout()` started as soon as
            // the outbound closes or drops).
            tokio::spawn(async move {
                async fn wait_stopped(send: quinn::SendStream) {
                    let _ = send.stopped().await;
                }

                let _lease = lease;
                let mut send_rx = send_rx;
                let mut in_flight = FuturesUnordered::new();
                let mut drain_deadline: Option<Instant> = None;

                'send_loop: loop {
                    let next_send = if let Some(deadline) = drain_deadline {
                        if Instant::now() >= deadline {
                            break;
                        }
                        match send_rx.try_recv() {
                            Ok(pkt) => Some(pkt),
                            Err(
                                TryRecvError::Empty
                                | TryRecvError::Disconnected,
                            ) => None,
                        }
                    } else {
                        tokio::select! {
                            biased;
                            Some(()) = in_flight.next(), if !in_flight.is_empty() => continue,
                            pkt = send_rx.recv() => pkt,
                            _ = task_cancel.cancelled() => {
                                conn.remove_udp_session(assoc_id);
                                drain_deadline = Some(
                                    Instant::now() + conn.drain_timeout(),
                                );
                                continue;
                            }
                        }
                    };

                    let Some(next_send) = next_send else {
                        break;
                    };

                    let send_fut = conn.send_stream_packet(
                        next_send.data,
                        next_send.dst_addr.into_tuic(),
                        assoc_id,
                    );
                    tokio::pin!(send_fut);

                    let send = loop {
                        if let Some(deadline) = drain_deadline {
                            tokio::select! {
                                res = &mut send_fut => match res {
                                    Ok(send) => break send,
                                    Err(_) => break 'send_loop,
                                },
                                Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
                                _ = sleep_until(deadline) => break 'send_loop,
                            }
                        } else {
                            tokio::select! {
                                res = &mut send_fut => match res {
                                    Ok(send) => break send,
                                    Err(_) => break 'send_loop,
                                },
                                Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
                                _ = task_cancel.cancelled() => {
                                    conn.remove_udp_session(assoc_id);
                                    drain_deadline = Some(
                                        Instant::now() + conn.drain_timeout(),
                                    );
                                }
                            }
                        }
                    };

                    in_flight.push(wait_stopped(send));
                }

                // TuicDatagramOutbound dropped or outgoing_udp occurs error.
                // Remove the session immediately even if `open_uni()` blocks,
                // and always wait for in-flight ACKs + grace window so a
                // concurrent `set_keep_idle(false)` cannot truncate writes.
                tracing::info!(
                    "[udp] [dissociate] closing UDP session [{assoc_id:#06x}]"
                );
                conn.remove_udp_session(assoc_id);
                let deadline = drain_deadline.unwrap_or_else(|| {
                    Instant::now() + conn.drain_timeout()
                });
                let _ = timeout_at(deadline, async {
                    if conn.conn.close_reason().is_none()
                        && let Ok(send) = conn.send_dissociate(assoc_id).await
                    {
                        in_flight.push(wait_stopped(send));
                    }
                    while in_flight.next().await.is_some() {}
                    if conn.conn.close_reason().is_none() {
                        tokio::select! {
                            _ = sleep(TUIC_HALF_CLOSED_DRAIN_GRACE) => {}
                            _ = conn.conn.closed() => {}
                        }
                    }
                })
                .await;
                anyhow::Ok(())
            });

            (
                Some(PollSender::new(send_tx)),
                Some(cancel),
                None,
            )
        } else {
            (None, None, lease)
        };

        let gc_interval = conn.gc_interval;
        let fragments = FragmentReassembler::new(conn.gc_lifetime);
        Self {
            send_tx,
            cancel,
            conn,
            runtime: Handle::current(),
            assoc_id,
            local_addr,
            closed: !registered,
            fragments,
            gc_interval,
            gc_timer: None,
            #[cfg(test)]
            gc_timer_allocs: 0,
            recv_rx,
            _lease: outbound_lease,
        }
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod cache_tests;
