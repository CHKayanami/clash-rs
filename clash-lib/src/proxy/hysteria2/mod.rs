#[cfg(all(test, docker_test))]
use crate::proxy::OutboundNode;

pub(crate) use datagram::HysteriaDatagramOutbound;
mod codec;
mod congestion;
mod datagram;
mod h3;
mod salamander;
mod udp_hop;
#[cfg(test)]
mod quic_tests;

use quinn_proto::congestion::{BbrConfig, ControllerFactory};

use self::{
    codec::Hy2TcpCodec,
    congestion::BrutalConfig,
    datagram::UdpSession,
    h3::{
        H3_STREAM_QPACK_DECODER, H3_STREAM_QPACK_ENCODER, auth_request_frame, client_preface,
        read_h3_response_headers,
    },
};
use super::{
    DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse, converters::hysteria2::PortGenerator,
    datagram::UdpPacket,
    utils::{
        new_udp_socket,
        quic_stream::{
            QuicBidiStream, QuicStreamLease, QuicUploadGrace, close_after_grace,
        },
    },
};
use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::tls::{DefaultTlsVerifier, build_tls_client_config},
    proxy::{AnyOutboundDatagram, AnyStream},
    session::{Session, SocksAddr},
};
use anyhow::{Context as _, anyhow};
use bytes::{Bytes, BytesMut};
use codec::Fragments;
use erased_serde::Serialize as ErasedSerialize;
use futures::SinkExt;
use arc_swap::ArcSwapOption;
use parking_lot::Mutex as SyncMutex;
use quinn::{
    ClientConfig, Connection, TokioRuntime, crypto::rustls::QuicClientConfig,
};
use quinn_proto::TransportConfig;
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    io::{self, Error as IoError, ErrorKind},
    net::SocketAddr,
    num::ParseIntError,
    path::PathBuf,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::Handle,
    sync::{Mutex, mpsc::error::TrySendError},
};

#[derive(Clone)]
pub struct SalamanderObfs {
    pub key: Vec<u8>,
}

#[derive(Clone)]
pub enum Obfs {
    Salamander(SalamanderObfs),
}

#[derive(Clone)]
pub struct HystOption {
    pub name: String,
    pub addr: SocksAddr,
    pub ports: Option<PortGenerator>,
    pub sni: Option<String>,
    pub passwd: String,
    pub obfs: Option<Obfs>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    #[allow(dead_code)]
    /// Bandwidth hints: (up_bytes_per_sec, down_bytes_per_sec)
    pub up_down: Option<(u64, u64)>,
    pub fingerprint: Option<String>,
    pub ca: Option<PathBuf>,
    pub udp_mtu: Option<u32>,
    pub disable_mtu_discovery: bool,
    pub max_stream_receive_window: Option<u64>,
    pub max_connection_receive_window: Option<u64>,
    #[allow(dead_code)]
    pub ca_str: Option<String>,
    /// File path or inline PEM client certificate for mTLS.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum CcRx {
    Auto,
    Fixed(u64),
}

impl FromStr for CcRx {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            Ok(Self::Auto)
        } else {
            let n = s.parse::<u64>()?;
            Ok(Self::Fixed(n))
        }
    }
}

type H3Preface = (quinn::SendStream, quinn::SendStream, quinn::SendStream);

pub struct Handler {
    opts: HystOption,
    ep_config: quinn::EndpointConfig,
    client_config: quinn::ClientConfig,
    conn: Arc<ArcSwapOption<HysteriaConnection>>,
    keep_idle: Arc<AtomicBool>,
    reconnect_lock: Mutex<()>,
    next_session_id: AtomicU32,
    // support udp is decided by server
    support_udp: AtomicBool,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystClient").finish()
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
    const DEFAULT_MAX_IDLE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(120);
    const DEFAULT_KEEP_ALIVE_INTERVAL: std::time::Duration =
        std::time::Duration::from_secs(10);

    #[cfg(test)]
    pub fn opts(&self) -> &HystOption {
        &self.opts
    }

    pub fn evict_connection(&self, failed: &Arc<HysteriaConnection>) {
        // Retry against the current snapshot so a stale failure cannot evict
        // a replacement connection. Keep side effects outside the retry loop.
        let previous = self.conn.rcu(|current| match current {
            Some(cached) if Arc::ptr_eq(cached, failed) => None,
            _ => current.clone(),
        });
        if previous
            .as_ref()
            .is_some_and(|cached| Arc::ptr_eq(cached, failed))
        {
            tracing::warn!(
                "hysteria2 connection to {} failed, actively evicting from cache",
                self.opts.addr
            );
            failed.mark_evicted();
        }
    }

    pub fn new(opts: HystOption) -> io::Result<Self> {
        // Fail closed. Warning and carrying on validated the server against the
        // default root store instead of the CA the user pinned — the opposite
        // of what configuring `ca` asks for, and silently so.
        if opts.ca.is_some() {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "hysteria2: `ca` is not supported yet; remove it, or use \
                 `fingerprint` to pin the server certificate",
            ));
        }
        let verify = Arc::new(DefaultTlsVerifier::new(
            opts.fingerprint.clone(),
            opts.skip_cert_verify,
        ));
        let mut tls_config = build_tls_client_config(
            verify,
            opts.tls_cert.as_deref(),
            opts.tls_key.as_deref(),
        )
        .map_err(|e| IoError::new(e.kind(), format!("hysteria2 TLS: {e}")))?;

        // should set alpn_protocol `h3` default
        tls_config.alpn_protocols = if opts.alpn.is_empty() {
            vec![b"h3".to_vec()]
        } else {
            opts.alpn.iter().map(|x| x.as_bytes().to_vec()).collect()
        };

        let mut transport = TransportConfig::default();
        if opts.disable_mtu_discovery {
            tracing::debug!("disable mtu discovery");
            transport.mtu_discovery_config(None);
        }
        let receive_window = |value: Option<u64>, default: u64, name: &str| {
            quinn::VarInt::from_u64(value.unwrap_or(default)).map_err(|_| {
                IoError::new(
                    ErrorKind::InvalidInput,
                    format!("hysteria2: `{name}` exceeds the QUIC maximum"),
                )
            })
        };
        transport.stream_receive_window(receive_window(
            opts.max_stream_receive_window,
            8 * 1024 * 1024,
            "max-stream-receive-window",
        )?);
        transport.receive_window(receive_window(
            opts.max_connection_receive_window,
            20 * 1024 * 1024,
            "max-connection-receive-window",
        )?);

        let up_bytes = opts.up_down.map(|(up, _)| up).unwrap_or(0);
        let factory: Arc<dyn ControllerFactory + Send + Sync> = if up_bytes > 0 {
            Arc::new(BrutalConfig::new(up_bytes))
        } else {
            Arc::new(BbrConfig::default())
        };
        transport.congestion_controller_factory(factory);

        transport.max_idle_timeout(Some(
            Self::DEFAULT_MAX_IDLE_TIMEOUT.try_into().unwrap(),
        ));
        transport.keep_alive_interval(Some(Self::DEFAULT_KEEP_ALIVE_INTERVAL));

        let quic_config: QuicClientConfig = tls_config.try_into().map_err(|e| {
            IoError::new(
                ErrorKind::InvalidInput,
                format!("hysteria2: TLS config is not QUIC-compatible: {e}"),
            )
        })?;
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));
        let ep_config = quinn::EndpointConfig::default();

        Ok(Self {
            opts,
            ep_config,
            client_config,
            next_session_id: AtomicU32::new(0),
            conn: Arc::new(ArcSwapOption::empty()),
            keep_idle: Arc::new(AtomicBool::new(true)),
            reconnect_lock: Mutex::new(()),
            support_udp: AtomicBool::new(true),
        })
    }

    // connect and auth
    async fn new_authed_connection_inner(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<(Connection, H3Preface)> {
        tracing::trace!(
            "hysteria2 new_authed_connection_inner: starting connection to {:?}",
            self.opts.addr
        );
        // Everytime we enstablish a new session, we should lookup the server
        // address. maybe it changed since it use ddns
        let server_socket_addr = match self.opts.addr.clone() {
            SocksAddr::Ip(ip) => ip,
            SocksAddr::Domain(d, port) => {
                let ip = resolver
                    .resolve(d.as_ref(), true)
                    .await?
                    .ok_or_else(|| anyhow!("resolve domain {} failed", d))?;
                SocketAddr::new(ip, port)
            }
        };

        // Here maybe we should use a AsyncUdpSocket which implement salamander obfs
        // and port hopping
        let create_socket = || async {
            new_udp_socket(
                None,
                sess.iface.as_deref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                Some(server_socket_addr),
            )
            .await
        };

        let socket = create_socket().await?.into_std()?;

        let has_hop = self
            .opts
            .ports
            .as_ref()
            .map(|p| p.has_hopping())
            .unwrap_or(false);
        let has_obfs = self.opts.obfs.is_some();

        let mut ep = if has_hop || has_obfs {
            use quinn::Runtime;
            let mut current: Arc<dyn quinn::AsyncUdpSocket> =
                TokioRuntime.wrap_udp_socket(socket)?;

            if let Some(port_gen) = self.opts.ports.as_ref() {
                if port_gen.has_hopping() {
                    current = Arc::new(udp_hop::UdpHop::new_with_inner(
                        current,
                        server_socket_addr.port(),
                        port_gen.clone(),
                        None,
                    ));
                }
            }

            if let Some(obfs) = self.opts.obfs.as_ref() {
                match obfs {
                    Obfs::Salamander(salamander_obfs) => {
                        current = Arc::new(salamander::Salamander::new_with_inner(
                            current,
                            salamander_obfs.key.to_vec(),
                        ));
                    }
                }
            }

            quinn::Endpoint::new_with_abstract_socket(
                self.ep_config.clone(),
                None,
                current,
                Arc::new(TokioRuntime),
            )?
        } else {
            quinn::Endpoint::new(
                self.ep_config.clone(),
                None,
                socket,
                Arc::new(TokioRuntime),
            )?
        };

        ep.set_default_client_config(self.client_config.clone());

        tracing::trace!("hysteria2 connecting to server: {:?}", server_socket_addr);
        let default_sni = self.opts.addr.host();
        let sni = self
            .opts
            .sni
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&default_sni);
        let session = ep.connect(server_socket_addr, sni)?.await?;
        tracing::trace!("hysteria2 QUIC connection established");
        let down_bytes = self.opts.up_down.map(|(_, down)| down).unwrap_or(0);
        let (preface, cc_rx, udp) =
            Self::auth(&session, &self.opts.passwd, down_bytes).await?;
        tracing::trace!(
            "hysteria2 authentication successful, cc_rx={:?}, udp={}",
            cc_rx,
            udp
        );
        self.support_udp.store(udp, Ordering::Relaxed);

        let up_bytes = self.opts.up_down.map(|(up, _)| up).unwrap_or(0);
        let effective_up_bytes = match (up_bytes, cc_rx) {
            (0, CcRx::Fixed(rx)) if rx > 0 => rx,
            (0, _) => 0,
            (up, CcRx::Auto) => up,
            (up, CcRx::Fixed(rx)) if rx > 0 => up.min(rx),
            (up, CcRx::Fixed(_)) => up,
        };

        tracing::info!(
            "hysteria2 cc_rx negotiation: server cc_rx={:?}, local up_bytes={}, negotiated effective_up_bytes={}",
            cc_rx,
            up_bytes,
            effective_up_bytes
        );

        Ok((session, preface))
    }

    async fn auth(
        conn: &quinn::Connection,
        passwd: &str,
        down_bytes: u64,
    ) -> anyhow::Result<(H3Preface, CcRx, bool)> {
        // 1. 打开 3 个 H3 关键单向流：Control, QPACK Encoder, QPACK Decoder
        let mut control = conn
            .open_uni()
            .await
            .context("hysteria2: open control stream failed")?;
        control
            .write_all(&client_preface())
            .await
            .context("hysteria2: send SETTINGS failed")?;

        let mut qpack_enc = conn
            .open_uni()
            .await
            .context("hysteria2: open QPACK encoder stream failed")?;
        qpack_enc
            .write_all(&[H3_STREAM_QPACK_ENCODER as u8])
            .await
            .context("hysteria2: send QPACK encoder stream preface failed")?;

        let mut qpack_dec = conn
            .open_uni()
            .await
            .context("hysteria2: open QPACK decoder stream failed")?;
        qpack_dec
            .write_all(&[H3_STREAM_QPACK_DECODER as u8])
            .await
            .context("hysteria2: send QPACK decoder stream preface failed")?;

        // 2. 打开双向流发送 POST https://hysteria/auth 请求
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("hysteria2: open auth stream failed")?;
        send.write_all(&auth_request_frame(passwd, down_bytes))
            .await
            .context("hysteria2: send auth request failed")?;
        send.finish().context("hysteria2: finish auth request failed")?;

        let headers = read_h3_response_headers(&mut recv)
            .await
            .context("hysteria2: read auth response headers failed")?;

        let get_header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };

        let status: u16 = get_header(":status")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        const HYSTERIA_STATUS_OK: u16 = 233;
        if status != HYSTERIA_STATUS_OK {
            return Err(anyhow!("auth failed: response status code {status}"));
        }

        let cc_rx = get_header("hysteria-cc-rx")
            .ok_or_else(|| anyhow!("auth failed: missing Hysteria-CC-RX header"))?
            .parse()?;

        let support_udp = get_header("hysteria-udp")
            .ok_or_else(|| anyhow!("auth failed: missing Hysteria-UDP header"))?
            .parse()?;

        Ok(((control, qpack_enc, qpack_dec), cc_rx, support_udp))
    }

    pub async fn new_authed_connection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<(Arc<HysteriaConnection>, HystStreamLease)> {
        // Fast path: atomically acquire a stream lease on the cached connection
        // before returning so idle reclamation cannot race with stream setup.
        if let Some(cached) = self.conn.load().as_ref()
            && cached.conn.close_reason().is_none()
            && let Some(lease) = cached.try_acquire_lease()
        {
            tracing::trace!(
                "hysteria2 reusing active QUIC connection to {}",
                self.opts.addr
            );
            return Ok((cached.clone(), lease));
        }

        // Slow path: acquire async reconnect_lock for double-checked locking & reconnect
        let _reconnect_guard = self.reconnect_lock.lock().await;

        // Double check after acquiring lock
        if let Some(cached) = self.conn.load().as_ref() {
            match cached.conn.close_reason() {
                Some(reason) => {
                    tracing::debug!("old connection closed: {:?}", reason);
                }
                None => {
                    if let Some(lease) = cached.try_acquire_lease() {
                        return Ok((cached.clone(), lease));
                    }
                }
            }
        }

        let (session, preface) = self
            .new_authed_connection_inner(sess, resolver)
            .await
            .map_err(|e| {
                IoError::other(format!(
                    "connect to {} failed: {}",
                    self.opts.addr, e
                ))
            })?;
        let session = Arc::new(session);
        let hyst_conn = HysteriaConnection::new_managed(
            session,
            Some(Arc::new(preface)),
            self.opts.udp_mtu,
            self.keep_idle.clone(),
            Arc::downgrade(&self.conn),
        );
        let lease = hyst_conn
            .try_acquire_lease()
            .expect("fresh hysteria2 connection must accept initial lease");

        if let Some(old) = self.conn.swap(Some(hyst_conn.clone())) {
            old.mark_evicted();
        }

        Ok((hyst_conn, lease))
    }
}

impl DialWithConnector for Handler {}

impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        self.opts.addr.domain()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Hysteria2
    }

    fn support_udp(&self) -> bool {
        self.support_udp.load(Ordering::Relaxed)
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let mut retry = true;
        loop {
            let (authed_conn, lease) =
                self.new_authed_connection(sess, resolver.clone()).await?;
            match authed_conn.connect_tcp(sess, lease).await {
                Ok(hy_stream) => {
                    sess.push_chain(self.name());
                    return Ok(AnyStream::new(hy_stream));
                }
                Err(e) => {
                    // 如果错误是业务层的 ConnectionRefused（即服务端正常回应拒绝，如目标域名不存在、端口拒绝），
                    // 证明底层 QUIC 连接完全健康，绝不能驱逐连接，更不能盲目重试！
                    if e.kind() == ErrorKind::ConnectionRefused {
                        return Err(e);
                    }
                    self.evict_connection(&authed_conn);
                    if retry {
                        tracing::warn!(
                            "hysteria2 connect_tcp to {} on cached connection failed ({}), retrying with fresh connection...",
                            self.opts.addr,
                            e
                        );
                        retry = false;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        let (authed_conn, lease) =
            self.new_authed_connection(sess, resolver.clone()).await?;
        let next_session_id = self
            .next_session_id
            .fetch_add(1, Ordering::Relaxed);
        let hy_datagram = authed_conn.connect_udp(sess, next_session_id, lease);
        sess.push_chain(self.name());
        Ok(AnyOutboundDatagram::new(hy_datagram))
    }

    fn set_keep_idle(&self, keep: bool) {
        self.keep_idle.store(keep, Ordering::SeqCst);
        if !keep {
            self.close_idle_connections();
        }
    }

    fn close_idle_connections(&self) {
        if let Some(cached) = self.conn.load_full() {
            cached.close_if_idle();
        }
    }

}

impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        let (server, port) = match &self.opts.addr {
            crate::session::SocksAddr::Ip(addr) => {
                (addr.ip().to_string(), addr.port())
            }
            crate::session::SocksAddr::Domain(host, port) => (host.to_string(), *port),
        };
        m.insert("server".to_owned(), Box::new(server) as _);
        m.insert("port".to_owned(), Box::new(port) as _);
        if let Some(sni) = self.opts.sni.as_ref() {
            m.insert("sni".to_owned(), Box::new(sni.clone()) as _);
        }
        if self.opts.skip_cert_verify {
            m.insert("skip-cert-verify".to_owned(), Box::new(true) as _);
        }
        if let Some(obfs) = self.opts.obfs.as_ref() {
            m.insert(
                "obfs".to_owned(),
                Box::new(
                    match obfs {
                        Obfs::Salamander(_) => "salamander",
                    }
                    .to_owned(),
                ) as _,
            );
        }
        if !self.opts.alpn.is_empty() {
            m.insert("alpn".to_owned(), Box::new(self.opts.alpn.clone()) as _);
        }
        m
    }
}

/// Highest bit of `active_streams`: once set, the connection is closing
/// and must not accept any new stream leases.
const HY2_CLOSING_BIT: usize = 1usize << (usize::BITS - 1);

pub struct HystStreamLease {
    conn: Arc<HysteriaConnection>,
}

impl Drop for HystStreamLease {
    fn drop(&mut self) {
        self.conn.release_lease();
    }
}

impl QuicStreamLease for HystStreamLease {
    fn record_upload_ack_grace(&self, grace: Duration) {
        self.conn.upload_grace.extend(grace);
    }
}

pub struct HysteriaConnection {
    pub conn: Arc<Connection>,
    /// H3 client preface streams (control + QPACK encoder/decoder). Held
    /// open for the life of the connection (including stream drain): dropping
    /// the send half finishes the stream, and closing a critical H3 stream is
    /// a connection error.
    #[allow(dead_code)]
    _preface: Option<Arc<H3Preface>>,
    pub udp_sessions: Arc<SyncMutex<HashMap<u32, UdpSession>>>,
    active_streams: AtomicUsize,
    keep_idle: Arc<AtomicBool>,
    /// Set once evicted from the handler cache so the connection closes as
    /// soon as all active streams finish, even when `keep_idle` is enabled.
    evicted: AtomicBool,
    upload_grace: QuicUploadGrace,
    runtime: Handle,
    cache_slot: Weak<ArcSwapOption<HysteriaConnection>>,

    // config
    pub udp_mtu: Option<usize>,
}

impl HysteriaConnection {
    pub fn new_with_task_loop(
        conn: Arc<Connection>,
        udp_mtu: Option<u32>,
    ) -> Arc<Self> {
        Self::new_managed(
            conn,
            None,
            udp_mtu,
            Arc::new(AtomicBool::new(true)),
            Weak::new(),
        )
    }

    fn new_managed(
        conn: Arc<Connection>,
        preface: Option<Arc<H3Preface>>,
        udp_mtu: Option<u32>,
        keep_idle: Arc<AtomicBool>,
        cache_slot: Weak<ArcSwapOption<HysteriaConnection>>,
    ) -> Arc<Self> {
        let s = Arc::new(Self {
            conn,
            _preface: preface,
            udp_sessions: Arc::new(SyncMutex::new(HashMap::new())),
            active_streams: AtomicUsize::new(0),
            keep_idle,
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            cache_slot,
            udp_mtu: udp_mtu.map(|x| x as usize),
        });
        tokio::spawn(Self::spawn_tasks(s.clone()));

        s
    }

    pub(super) fn try_acquire_lease(self: &Arc<Self>) -> Option<HystStreamLease> {
        self.active_streams
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                if val & HY2_CLOSING_BIT != 0 {
                    None
                } else {
                    Some(val + 1)
                }
            })
            .ok()
            .map(|_| HystStreamLease { conn: self.clone() })
    }

    #[cfg(test)]
    pub(super) fn is_closing(&self) -> bool {
        (self.active_streams.load(Ordering::Acquire) & HY2_CLOSING_BIT) != 0
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
                let closing = (val & HY2_CLOSING_BIT) != 0;
                let count = (val & !HY2_CLOSING_BIT).saturating_sub(1);
                let next_closing = closing || (!keep_idle && count == 0);
                closed_now = !closing && next_closing;
                became_zero = !next_closing && count == 0;
                Some(if next_closing {
                    HY2_CLOSING_BIT | count
                } else {
                    count
                })
            },
        );
        if closed_now {
            self.evict_from_cache();
            self.close_with_grace();
        } else if became_zero && !self.should_keep_idle() {
            // Re-check `keep_idle` / `evicted` after publishing zero (SeqCst)
            // so a concurrent `set_keep_idle(false)` or eviction cannot miss.
            self.close_if_idle();
        }
    }

    pub(super) fn close_if_idle(self: &Arc<Self>) {
        if self
            .active_streams
            .compare_exchange(
                0,
                HY2_CLOSING_BIT,
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
            self._preface.clone(),
        );
    }

    async fn spawn_tasks(self: Arc<Self>) {
        tracing::trace!("hysteria2 spawn_tasks: starting datagram receive loop");
        let err = loop {
            match self.conn.read_datagram().await {
                Ok(pkt) => {
                    tracing::trace!(
                        "hysteria2 received datagram: {} bytes",
                        pkt.len()
                    );
                    self.clone().recv_packet(pkt).await
                }
                Err(e) => {
                    tracing::debug!("hysteria2 read datagram stopped: {}", e);
                    break e;
                }
            }
        };
        tracing::debug!("hysteria2 connection closed: {:?}", err);
    }

    pub async fn connect_tcp(
        self: &Arc<Self>,
        sess: &Session,
        lease: HystStreamLease,
    ) -> io::Result<HystStream> {
        tracing::debug!(
            "hysteria2 opening stream to destination: {}",
            sess.destination
        );
        let (mut tx, mut rx) = self.conn.open_bi().await.map_err(|e| {
            tracing::error!(
                "hysteria2 failed to open bi-stream for {}: {}",
                sess.destination,
                e
            );
            e
        })?;

        tokio_util::codec::FramedWrite::new(&mut tx, Hy2TcpCodec)
            .send(&sess.destination)
            .await
            .map_err(|e| {
                tracing::error!(
                    "hysteria2 failed to send destination request for {}: {}",
                    sess.destination,
                    e
                );
                e
            })?;

        let resp = codec::read_hy2_resp(&mut rx).await.map_err(|e| {
            tracing::error!(
                "hysteria2 response decode error for {}: {}",
                sess.destination,
                e
            );
            IoError::other(format!("hysteria2 response decode error: {}", e))
        })?;

        if resp.status != 0x00 {
            tracing::warn!(
                "hysteria2 server refused connection to {}, status: {:#x}, msg: {:?}",
                sess.destination,
                resp.status,
                resp.msg
            );
            return Err(IoError::new(
                ErrorKind::ConnectionRefused,
                format!("server response error, msg: {:?}", resp.msg),
            ));
        } else {
            tracing::debug!(
                "hysteria2 tcp connection established to {}: status={:#x}, msg={:?}",
                sess.destination,
                resp.status,
                resp.msg
            );
        }

        Ok(HystStream::new(tx, rx, lease))
    }

    pub fn connect_udp(
        self: Arc<Self>,
        sess: &Session,
        session_id: u32,
        lease: HystStreamLease,
    ) -> HysteriaDatagramOutbound {
        tracing::trace!(
            "hysteria connect udp, sess: {:?}, session_id: {}",
            sess,
            session_id
        );
        HysteriaDatagramOutbound::new_with_lease(
            session_id,
            self,
            sess.destination.clone(),
            Some(lease),
        )
    }

    pub fn max_fragment_size(&self) -> io::Result<usize> {
        self.conn.max_datagram_size()
            .map(|limit| self.udp_mtu.map_or(limit, |mtu| mtu.min(limit)))
            .ok_or_else(|| IoError::other("hysteria2 QUIC datagrams unavailable"))
    }

    pub fn send_packet(
        &self,
        pkt: &[u8],
        addr: &SocksAddr,
        session_id: u32,
        pkt_id: u16,
        max_frag_size: usize,
    ) -> io::Result<()> {
        let fragments = Fragments::new(session_id, pkt_id, addr, max_frag_size, pkt)
            .map_err(|e| IoError::new(ErrorKind::InvalidInput, e.to_string()))?;
        let mut frag_count = 0;
        for frag in fragments {
            frag_count += 1;
            tracing::trace!(
                "hysteria2 sending fragment #{} for session_id={}",
                frag_count,
                session_id
            );
            self.conn
                .send_datagram(frag)
                .map_err(IoError::other)?;
        }
        tracing::trace!(
            "hysteria2 sent {} fragments for session_id={}",
            frag_count,
            session_id
        );
        Ok(())
    }

    pub async fn recv_packet(self: Arc<Self>, pkt: Bytes) {
        tracing::trace!("hysteria2 recv_packet: {} bytes", pkt.len());
        let mut buf: BytesMut = pkt.into();
        let pkt = match codec::HysUdpPacket::decode(&mut buf) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("hysteria2 decode udp packet failed: {}", e);
                return;
            }
        };
        let session_id = pkt.session_id;

        let res = {
            let mut udp_sessions = self.udp_sessions.lock();
            if let Some(session) = udp_sessions.get_mut(&session_id) {
                tracing::trace!(
                    "hysteria2 found session {}, feeding packet",
                    session_id
                );
                session.feed(pkt).map(|complete_pkt| {
                    (
                        session.incoming.clone(),
                        session.local_addr.clone(),
                        complete_pkt,
                    )
                })
            } else {
                tracing::warn!("hysteria2 udp session not found: {}", session_id);
                None
            }
        };

        if let Some((incoming, local_addr, pkt)) = res {
            tracing::trace!(
                "hysteria2 complete packet received for session {}: {} bytes to {:?}",
                session_id,
                pkt.data.len(),
                local_addr
            );
            // Every UDP session on this connection is served by the single
            // `read_datagram` loop that calls us, so awaiting a full channel
            // here stalled *all* of them behind one slow consumer. Dropping is
            // the right answer for UDP.
            match incoming.try_send(UdpPacket {
                data: pkt.data,
                src_addr: pkt.addr,
                dst_addr: local_addr,
                inbound_user: None,
            }) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    tracing::debug!(
                        "hysteria2 udp session {} queue full, dropping packet",
                        session_id
                    );
                }
                Err(TrySendError::Closed(_)) => {
                    tracing::debug!(
                        "hysteria2 udp session {} receiver gone, dropping packet",
                        session_id
                    );
                }
            }
        }
    }
}

pub struct HystStream {
    inner: QuicBidiStream<HystStreamLease>,
}

impl HystStream {
    fn new(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        lease: HystStreamLease,
    ) -> Self {
        Self {
            inner: QuicBidiStream::new(send, recv, lease),
        }
    }
}

impl crate::proxy::ProxyStream for HystStream {}

impl Debug for HystStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystStream").finish()
    }
}

impl AsyncRead for HystStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().inner.poll_read_inner(cx, buf)
    }
}

fn is_normal_write_closure(e: &quinn::WriteError) -> bool {
    match e {
        quinn::WriteError::Stopped(code) => code.into_inner() == 0,
        quinn::WriteError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(app)) => {
            app.error_code.into_inner() == 0
        }
        quinn::WriteError::ConnectionLost(quinn::ConnectionError::LocallyClosed) => true,
        _ => false,
    }
}

impl AsyncWrite for HystStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(poll) = self.get_mut().inner.poll_write_raw(cx, buf) else {
            return Poll::Ready(Err(IoError::new(
                ErrorKind::BrokenPipe,
                "hysteria2 stream closed",
            )));
        };
        poll.map_err(|e| {
            if is_normal_write_closure(&e) {
                tracing::debug!("hysteria2 write closed: {}", e);
            } else {
                tracing::error!("hysteria2 write error: {}", e);
            }
            e.into()
        })
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().inner.poll_flush_io(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().inner.poll_shutdown_io(cx)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::config::internal::proxy::OutboundHysteria2;
    use quinn::{Endpoint, ServerConfig};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::RootCertStore;
    use std::time::Duration;

    #[tokio::test]
    async fn test_stale_failure_preserves_replacement_and_preface() {
        crate::setup_default_crypto_provider();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::with_single_cert(
            vec![cert.der().clone()], signing_key.into(),
        ).unwrap();
        let server = Endpoint::server(
            server_config, "127.0.0.1:0".parse().unwrap(),
        ).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let connecting = client.connect(server.local_addr().unwrap(), "localhost").unwrap();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connecting, async {
                server.accept().await.unwrap().await.unwrap()
            })
        }).await.unwrap();
        let connection = Arc::new(connection.unwrap());
        let preface = Arc::new((
            connection.open_uni().await.unwrap(),
            connection.open_uni().await.unwrap(),
            connection.open_uni().await.unwrap(),
        ));
        let weak_preface = Arc::downgrade(&preface);
        let make_connection = |preface| Arc::new(HysteriaConnection {
            conn: connection.clone(),
            _preface: preface,
            udp_sessions: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            active_streams: AtomicUsize::new(0),
            keep_idle: Arc::new(AtomicBool::new(true)),
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            cache_slot: Weak::new(),
            udp_mtu: None,
        });
        let failed = make_connection(None);
        let replacement = make_connection(Some(preface));
        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: cache-test\nserver: localhost\nport: 443\npassword: test-only",
        ).unwrap();
        let handler = Handler::try_from(options).unwrap();
        handler.conn.store(Some(replacement.clone()));
        let snapshot = handler.conn.load_full();

        handler.evict_connection(&failed);
        assert!(Arc::ptr_eq(
            handler.conn.load().as_ref().unwrap(), &replacement,
        ));
        handler.evict_connection(&replacement);
        assert!(handler.conn.load().is_none());
        assert!(weak_preface.upgrade().is_some());
        drop(replacement);
        assert!(weak_preface.upgrade().is_some());
        drop(snapshot);
        assert!(weak_preface.upgrade().is_none());

        connection.close(0u32.into(), b"test complete");
        peer.close(0u32.into(), b"test complete");
    }

    #[test]
    fn test_is_normal_write_closure() {
        let err = quinn::WriteError::Stopped(quinn::VarInt::from_u32(0));
        assert!(is_normal_write_closure(&err));

        let err_nonzero = quinn::WriteError::Stopped(quinn::VarInt::from_u32(1));
        assert!(!is_normal_write_closure(&err_nonzero));
    }

    #[tokio::test]
    async fn test_disable_keep_idle_drains_tail_and_preserves_preface() {
        use tokio::io::AsyncWriteExt;

        crate::setup_default_crypto_provider();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::with_single_cert(
            vec![cert.der().clone()],
            signing_key.into(),
        )
        .unwrap();
        let server =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let connecting =
            client.connect(server.local_addr().unwrap(), "localhost").unwrap();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connecting, async {
                server.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .unwrap();
        let connection = Arc::new(connection.unwrap());

        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: idle-test\nserver: localhost\nport: 443\npassword: test-only",
        )
        .unwrap();
        let handler = Handler::try_from(options).unwrap();

        let preface = Arc::new((
            connection.open_uni().await.unwrap(),
            connection.open_uni().await.unwrap(),
            connection.open_uni().await.unwrap(),
        ));
        let weak_preface = Arc::downgrade(&preface);
        let managed = Arc::new(HysteriaConnection {
            conn: connection.clone(),
            _preface: Some(preface),
            udp_sessions: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            active_streams: AtomicUsize::new(0),
            keep_idle: handler.keep_idle.clone(),
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            cache_slot: Arc::downgrade(&handler.conn),
            udp_mtu: None,
        });
        handler.conn.store(Some(managed.clone()));

        let lease = managed
            .try_acquire_lease()
            .expect("open connection accepts lease");
        let (tx, rx) = connection.open_bi().await.unwrap();
        let mut stream = HystStream::new(tx, rx, lease);
        let payload = b"tail-bytes-must-not-be-truncated";
        stream.write_all(payload).await.unwrap();

        // Disable keep_idle while stream is active: must stay open and cached.
        handler.set_keep_idle(false);
        assert!(handler.conn.load().is_some());
        assert!(connection.close_reason().is_none());
        assert!(weak_preface.upgrade().is_some());

        // Drop the stream and delay the peer application read so `send.stopped()`
        // completes well before the peer app accepts/reads the stream.
        drop(stream);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            connection.close_reason().is_none(),
            "connection must not close before peer finishes reading buffered tail data"
        );

        let (mut peer_tx, mut peer_rx) =
            tokio::time::timeout(Duration::from_secs(2), peer.accept_bi())
                .await
                .unwrap()
                .unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            peer_rx.read_to_end(1024),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, payload);

        // Once the peer app finishes its side of the stream, the drain task
        // releases the lease and closes the idle QUIC connection promptly.
        let _ = peer_tx.finish();
        drop(peer_tx);

        tokio::time::timeout(Duration::from_secs(2), connection.closed())
            .await
            .expect("connection should close after peer completes stream");
        assert!(managed.is_closing());
        assert!(managed.try_acquire_lease().is_none());
        assert!(handler.conn.load().is_none());
        assert!(connection.close_reason().is_some());

        drop(managed);
        assert!(weak_preface.upgrade().is_none());
        peer.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn test_evict_healthy_connection_closes_and_stops_datagram_task() {
        crate::setup_default_crypto_provider();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::with_single_cert(
            vec![cert.der().clone()],
            signing_key.into(),
        )
        .unwrap();
        let server =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let connecting =
            client.connect(server.local_addr().unwrap(), "localhost").unwrap();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connecting, async {
                server.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .unwrap();
        let connection = Arc::new(connection.unwrap());

        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: evict-test\nserver: localhost\nport: 443\npassword: test-only",
        )
        .unwrap();
        let handler = Handler::try_from(options).unwrap();
        let preface = Arc::new((
            connection.open_uni().await.unwrap(),
            connection.open_uni().await.unwrap(),
            connection.open_uni().await.unwrap(),
        ));
        let weak_preface = Arc::downgrade(&preface);
        let managed = HysteriaConnection::new_managed(
            connection.clone(),
            Some(preface),
            None,
            handler.keep_idle.clone(),
            Arc::downgrade(&handler.conn),
        );
        handler.conn.store(Some(managed.clone()));

        // Keep keep_idle enabled (default): evicting a healthy connection must
        // close it once idle so its datagram receive loop and preface exit.
        let lease = managed.try_acquire_lease().unwrap();
        handler.evict_connection(&managed);
        assert!(handler.conn.load().is_none());
        assert!(connection.close_reason().is_none());

        drop(lease);
        drop(managed);

        tokio::time::timeout(Duration::from_secs(2), connection.closed())
            .await
            .expect("evicted connection must close once last lease drops");
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_preface.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("datagram task must exit and release preface streams");
        peer.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn test_half_closed_peer_fin_still_grants_upload_grace() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::setup_default_crypto_provider();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::with_single_cert(
            vec![cert.der().clone()],
            signing_key.into(),
        )
        .unwrap();
        let server =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let connecting =
            client.connect(server.local_addr().unwrap(), "localhost").unwrap();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connecting, async {
                server.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .unwrap();
        let connection = Arc::new(connection.unwrap());

        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: half-close-test\nserver: localhost\nport: 443\npassword: test-only",
        )
        .unwrap();
        let handler = Handler::try_from(options).unwrap();
        let managed = Arc::new(HysteriaConnection {
            conn: connection.clone(),
            _preface: None,
            udp_sessions: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            active_streams: AtomicUsize::new(0),
            keep_idle: handler.keep_idle.clone(),
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            cache_slot: Arc::downgrade(&handler.conn),
            udp_mtu: None,
        });
        handler.conn.store(Some(managed.clone()));

        let lease = managed.try_acquire_lease().unwrap();
        handler.set_keep_idle(false);
        let (tx, rx) = connection.open_bi().await.unwrap();
        let mut stream = HystStream::new(tx, rx, lease);
        let payload = b"upload-after-peer-already-sent-banner-and-fin";
        stream.write_all(payload).await.unwrap();

        // Peer accepts stream and immediately sends unrelated downlink data +
        // FIN BEFORE reading our upload payload.
        let (mut peer_tx, mut peer_rx) =
            tokio::time::timeout(Duration::from_secs(2), peer.accept_bi())
                .await
                .unwrap()
                .unwrap();
        peer_tx
            .write_all(b"unrelated-peer-banner-and-more-downlink-data")
            .await
            .unwrap();
        let _ = peer_tx.finish();
        drop(peer_tx);

        // Local side reads part of the downlink data (and leaves the rest + FIN
        // for background drain). Neither local reads nor background drain reads
        // may cancel the upload grace window.
        let mut banner_prefix = [0u8; 9];
        stream.read_exact(&mut banner_prefix).await.unwrap();
        assert_eq!(&banner_prefix, b"unrelated");

        drop(stream);

        // Peer delays reading the upload; connection must stay open during the
        // half-close grace window so the upload payload is not truncated.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            connection.close_reason().is_none(),
            "unrelated downlink data + FIN must not skip upload grace window"
        );
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            peer_rx.read_to_end(1024),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, payload);

        // After the grace window expires, connection closes cleanly.
        tokio::time::timeout(Duration::from_secs(3), connection.closed())
            .await
            .expect("connection should close after grace window expires");
        peer.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn test_drop_outside_runtime_still_drains_tail() {
        use tokio::io::AsyncWriteExt;

        crate::setup_default_crypto_provider();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::with_single_cert(
            vec![cert.der().clone()],
            signing_key.into(),
        )
        .unwrap();
        let server =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let connecting =
            client.connect(server.local_addr().unwrap(), "localhost").unwrap();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connecting, async {
                server.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .unwrap();
        let connection = Arc::new(connection.unwrap());

        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: drop-thread-test\nserver: localhost\nport: 443\npassword: test-only",
        )
        .unwrap();
        let handler = Handler::try_from(options).unwrap();
        let managed = Arc::new(HysteriaConnection {
            conn: connection.clone(),
            _preface: None,
            udp_sessions: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            active_streams: AtomicUsize::new(0),
            keep_idle: handler.keep_idle.clone(),
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            cache_slot: Arc::downgrade(&handler.conn),
            udp_mtu: None,
        });
        handler.conn.store(Some(managed.clone()));

        let lease = managed.try_acquire_lease().unwrap();
        handler.set_keep_idle(false);
        let (tx, rx) = connection.open_bi().await.unwrap();
        let mut stream = HystStream::new(tx, rx, lease);
        let payload = b"tail-bytes-dropped-on-plain-os-thread";
        stream.write_all(payload).await.unwrap();

        // Drop the stream on a plain OS thread outside any Tokio runtime.
        std::thread::spawn(move || drop(stream)).join().unwrap();

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            connection.close_reason().is_none(),
            "dropping stream outside Tokio runtime must still spawn drain task"
        );

        let (mut peer_tx, mut peer_rx) =
            tokio::time::timeout(Duration::from_secs(2), peer.accept_bi())
                .await
                .unwrap()
                .unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            peer_rx.read_to_end(1024),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, payload);
        let _ = peer_tx.finish();
        drop(peer_tx);

        tokio::time::timeout(Duration::from_secs(3), connection.closed())
            .await
            .expect("connection should close once drain completes");
        peer.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn test_drop_bidi_stream_sends_stop_sending_and_skips_downlink_drain() {
        use tokio::io::AsyncWriteExt;

        crate::setup_default_crypto_provider();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::with_single_cert(
            vec![cert.der().clone()],
            signing_key.into(),
        )
        .unwrap();
        let server =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let connecting =
            client.connect(server.local_addr().unwrap(), "localhost").unwrap();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connecting, async {
                server.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .unwrap();
        let connection = Arc::new(connection.unwrap());

        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: stop-sending-test\nserver: localhost\nport: 443\npassword: test-only",
        )
        .unwrap();
        let handler = Handler::try_from(options).unwrap();
        let managed = Arc::new(HysteriaConnection {
            conn: connection.clone(),
            _preface: None,
            udp_sessions: Arc::new(SyncMutex::new(HashMap::new())),
            active_streams: AtomicUsize::new(0),
            keep_idle: handler.keep_idle.clone(),
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            cache_slot: Arc::downgrade(&handler.conn),
            udp_mtu: None,
        });
        handler.conn.store(Some(managed.clone()));

        // keep_idle stays enabled; client writes an HTTP-like request then drops
        // the stream while the peer is still open for downlink transmission.
        let lease = managed.try_acquire_lease().unwrap();
        let (tx, rx) = connection.open_bi().await.unwrap();
        let mut stream = HystStream::new(tx, rx, lease);
        let payload = b"GET /large-file HTTP/1.1\r\n\r\n";
        stream.write_all(payload).await.unwrap();

        let (mut peer_tx, mut peer_rx) =
            tokio::time::timeout(Duration::from_secs(2), peer.accept_bi())
                .await
                .unwrap()
                .unwrap();
        // Peer writes downlink data without finishing its send stream.
        peer_tx.write_all(&[0xAB; 4096]).await.unwrap();

        // Client aborts/drops the stream without reading the downlink.
        drop(stream);

        // Peer must immediately observe STOP_SENDING(0) instead of being kept
        // open for a 10-second background downlink drain.
        let stopped = tokio::time::timeout(
            Duration::from_millis(500),
            peer_tx.stopped(),
        )
        .await
        .expect("dropping stream must promptly send STOP_SENDING")
        .unwrap();
        assert_eq!(stopped, Some(quinn::VarInt::from_u32(0)));

        // Upload payload must still arrive intact on peer_rx.
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            peer_rx.read_to_end(1024),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, payload);

        // Because keep_idle == true, the lease must release promptly right
        // after send.stopped() without waiting the 1-second closing grace.
        tokio::time::timeout(Duration::from_millis(500), async {
            while managed.active_streams.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("kept-idle stream must release lease without waiting 1s closing grace");
        assert!(connection.close_reason().is_none());

        connection.close(0u32.into(), b"test complete");
        peer.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn test_keep_idle_switch_after_upload_ack_respects_grace_window() {
        use tokio::io::AsyncWriteExt;

        crate::setup_default_crypto_provider();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::with_single_cert(
            vec![cert.der().clone()],
            signing_key.into(),
        )
        .unwrap();
        let server =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let connecting =
            client.connect(server.local_addr().unwrap(), "localhost").unwrap();
        let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connecting, async {
                server.accept().await.unwrap().await.unwrap()
            })
        })
        .await
        .unwrap();
        let connection = Arc::new(connection.unwrap());

        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: grace-after-ack\nserver: localhost\nport: 443\npassword: test-only",
        )
        .unwrap();
        let handler = Handler::try_from(options).unwrap();
        let preface = Arc::new((
            connection.open_uni().await.unwrap(),
            connection.open_uni().await.unwrap(),
            connection.open_uni().await.unwrap(),
        ));
        let weak_preface = Arc::downgrade(&preface);
        let managed = Arc::new(HysteriaConnection {
            conn: connection.clone(),
            _preface: Some(preface),
            udp_sessions: Arc::new(SyncMutex::new(HashMap::new())),
            active_streams: AtomicUsize::new(0),
            keep_idle: handler.keep_idle.clone(),
            evicted: AtomicBool::new(false),
            upload_grace: QuicUploadGrace::default(),
            runtime: Handle::current(),
            cache_slot: Arc::downgrade(&handler.conn),
            udp_mtu: None,
        });
        handler.conn.store(Some(managed.clone()));

        // keep_idle is enabled while client uploads and drops the stream.
        let lease = managed.try_acquire_lease().unwrap();
        let (tx, rx) = connection.open_bi().await.unwrap();
        let mut stream = HystStream::new(tx, rx, lease);
        let payload = b"acked-upload-before-node-switch";
        stream.write_all(payload).await.unwrap();
        drop(stream);

        // Wait until QUIC ACKs the FIN and the stream lease is released.
        tokio::time::timeout(Duration::from_secs(2), async {
            while managed.active_streams.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("upload ACK must release kept-idle stream lease");

        // Immediately switch away from this node (disable keep_idle): the
        // connection must honor the remaining grace period from the ACK.
        handler.set_keep_idle(false);
        assert!(managed.is_closing());
        assert!(handler.conn.load().is_none());

        // Drop the test's own `managed` handle so only the delayed close task
        // can keep the H3 preface alive across the grace window.
        drop(managed);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            connection.close_reason().is_none(),
            "switching nodes right after upload ACK must not close connection \
             before grace expires"
        );
        assert!(
            weak_preface.upgrade().is_some(),
            "delayed close task must keep H3 preface alive during grace window"
        );

        let (_peer_tx, mut peer_rx) =
            tokio::time::timeout(Duration::from_secs(2), peer.accept_bi())
                .await
                .unwrap()
                .unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            peer_rx.read_to_end(1024),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, payload);

        // Once the grace period from ACK expires, the connection closes cleanly
        // and the delayed close task releases the H3 preface.
        tokio::time::timeout(Duration::from_secs(3), connection.closed())
            .await
            .expect("connection must close after upload ACK grace expires");
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_preface.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("delayed close task must release H3 preface after close");
        peer.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn test_dropping_handler_retires_kept_idle_and_active_connections() {
        crate::setup_default_crypto_provider();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = ServerConfig::with_single_cert(
            vec![cert.der().clone()],
            signing_key.into(),
        )
        .unwrap();
        let server =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );

        let connect_pair = || async {
            let connecting =
                client.connect(server.local_addr().unwrap(), "localhost").unwrap();
            let (connection, peer) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(connecting, async {
                    server.accept().await.unwrap().await.unwrap()
                })
            })
            .await
            .unwrap();
            (Arc::new(connection.unwrap()), peer)
        };

        // 1. Idle connection with keep_idle = true closes immediately when handler drops.
        let (idle_conn, idle_peer) = connect_pair().await;
        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: retire-idle\nserver: localhost\nport: 443\npassword: test-only",
        )
        .unwrap();
        let idle_handler = Handler::try_from(options).unwrap();
        let idle_preface = Arc::new((
            idle_conn.open_uni().await.unwrap(),
            idle_conn.open_uni().await.unwrap(),
            idle_conn.open_uni().await.unwrap(),
        ));
        let weak_idle_preface = Arc::downgrade(&idle_preface);
        let idle_managed = HysteriaConnection::new_managed(
            idle_conn.clone(),
            Some(idle_preface),
            None,
            idle_handler.keep_idle.clone(),
            Arc::downgrade(&idle_handler.conn),
        );
        idle_handler.conn.store(Some(idle_managed));
        drop(idle_handler);

        tokio::time::timeout(Duration::from_secs(2), idle_conn.closed())
            .await
            .expect("dropping handler must close idle connection even when keep_idle=true");
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_idle_preface.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("datagram task must exit and drop H3 preface streams");
        idle_peer.close(0u32.into(), b"done");

        // 2. Active connection stays open until its final lease drops, then closes.
        let (active_conn, active_peer) = connect_pair().await;
        let options: OutboundHysteria2 = yaml_serde::from_str(
            "name: retire-active\nserver: localhost\nport: 443\npassword: test-only",
        )
        .unwrap();
        let active_handler = Handler::try_from(options).unwrap();
        let active_preface = Arc::new((
            active_conn.open_uni().await.unwrap(),
            active_conn.open_uni().await.unwrap(),
            active_conn.open_uni().await.unwrap(),
        ));
        let weak_active_preface = Arc::downgrade(&active_preface);
        let active_managed = HysteriaConnection::new_managed(
            active_conn.clone(),
            Some(active_preface),
            None,
            active_handler.keep_idle.clone(),
            Arc::downgrade(&active_handler.conn),
        );
        active_handler.conn.store(Some(active_managed.clone()));
        let lease = active_managed.try_acquire_lease().unwrap();
        drop(active_managed);
        drop(active_handler);

        assert!(
            active_conn.close_reason().is_none(),
            "dropping handler must not interrupt active stream"
        );
        drop(lease);

        tokio::time::timeout(Duration::from_secs(2), active_conn.closed())
            .await
            .expect("retired active connection must close once last lease drops");
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_active_preface.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retired active connection's datagram task must exit");
        active_peer.close(0u32.into(), b"done");
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::{
        io::Write,
        net::{IpAddr, Ipv4Addr},
    };

    use super::super::utils::test_utils::{
        consts::*, docker_runner::DockerTestRunner,
    };
    use crate::{
        proxy::utils::{
            GLOBAL_DIRECT_CONNECTOR,
            test_utils::{
                Suite,
                config_helper::test_config_base_dir,
                docker_runner::{DockerTestRunnerBuilder, alloc_docker_port},
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    use super::*;

    const HYSTERIA_SERVER_CONFIG: &str = r#"{
    "listen": ":10002",
    "tls":{
        "cert": "/home/ubuntu/my.crt",
        "key": "/home/ubuntu/my.key"
    },
    "obfs": {
        "type": "salamander",
        "salamander": {
            "password": "beauty will save the world"
        }
    },
    "up_mbps": 100,
    "down_mbps": 100,
    "auth": {
        "type": "password",
        "password": "passwd"
    }
}"#;

    async fn get_hysteria_runner(
        host_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(HYSTERIA_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_HYSTERIA)
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/config.json"),
                (cert.to_str().unwrap(), "/home/ubuntu/my.crt"),
                (key.to_str().unwrap(), "/home/ubuntu/my.key"),
            ])
            .cmd(&["server"])
            .host_port(host_port, 10002)
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn test_hysteria() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();

        let container = get_hysteria_runner(host_port).await?;

        let container_ip =
            container.container_ip().unwrap_or("127.0.0.1".to_owned());

        let ip = IpAddr::from_str(&container_ip)
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let port = 10002;

        let obfs = Some(Obfs::Salamander(SalamanderObfs {
            key: "beauty will save the world".to_owned().into(),
        }));

        let ports_gen = Some(
            PortGenerator::new(port)
                .parse_ports_str("")
                .map_err(|_| crate::Error::InvalidConfig("".into()))?,
        );

        let opts = HystOption {
            name: "test-hysteria".to_owned(),
            sni: "example.org".to_owned().into(),
            addr: (ip, port).into(),
            alpn: vec![],
            ca: None,
            fingerprint: None,
            skip_cert_verify: true,
            passwd: "passwd".to_owned(),
            ports: ports_gen,
            obfs,
            up_down: Some((100, 100)),
            ca_str: None,
            udp_mtu: None,
            disable_mtu_discovery: false,
            max_stream_receive_window: None,
            max_connection_receive_window: None,
            tls_cert: None,
            tls_key: None,
        };

        let handler = Arc::new(
            Handler::new(opts).expect("failed to create hysteria2 handler"),
        );
        run_test_suites_and_cleanup(OutboundNode::protocol(handler), container, Suite::all()).await
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use std::io::Write as _;

    use crate::{
        proxy::utils::test_utils::{
            config_helper,
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    const CONTAINER_PORT: u16 = 10002;
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB

    // Plain hysteria2 server — no obfs, auth password "passwd"
    const HYSTERIA2_SERVER_CONFIG: &str = r#"{
    "listen": ":10002",
    "tls": {
        "cert": "/home/ubuntu/my.crt",
        "key": "/home/ubuntu/my.key"
    },
    "up_mbps": 100,
    "down_mbps": 100,
    "auth": {
        "type": "password",
        "password": "passwd"
    }
}"#;

    // Hysteria2 server with obfs-salamander, auth password "passwd"
    const HYSTERIA_SALAMANDER_SERVER_CONFIG: &str = r#"{
    "listen": ":10002",
    "tls": {
        "cert": "/home/ubuntu/my.crt",
        "key": "/home/ubuntu/my.key"
    },
    "obfs": {
        "type": "salamander",
        "salamander": {
            "password": "salamander-password"
        }
    },
    "up_mbps": 100,
    "down_mbps": 100,
    "auth": {
        "type": "password",
        "password": "passwd"
    }
}"#;

    async fn build_hysteria2_runner(
        server_config: &str,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(server_config.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_HYSTERIA)
            .cmd(&["server"])
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/config.json"),
                (cert.to_str().unwrap(), "/home/ubuntu/my.crt"),
                (key.to_str().unwrap(), "/home/ubuntu/my.key"),
            ])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_hysteria2_plain() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = build_hysteria2_runner(HYSTERIA2_SERVER_CONFIG).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: hysteria2
    server: {server}
    port: {port}
    password: passwd
    sni: example.org
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "hysteria2-plain",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_hysteria2_plain_netem() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = build_hysteria2_runner(HYSTERIA2_SERVER_CONFIG).await?;
        container.apply_netem(50, 1.0).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: hysteria2
    server: {server}
    port: {port}
    password: passwd
    sni: example.org
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "hysteria2-plain-netem",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_hysteria2_salamander() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container =
            build_hysteria2_runner(HYSTERIA_SALAMANDER_SERVER_CONFIG).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: hysteria2
    server: {server}
    port: {port}
    password: passwd
    obfs: salamander
    obfs-password: salamander-password
    sni: example.org
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "hysteria2-salamander",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .await
                .map(|_| ())
            })
            .await
    }
}
