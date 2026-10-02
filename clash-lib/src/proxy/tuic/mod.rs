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
use async_trait::async_trait;

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
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
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
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use self::types::{CongestionControl, TuicConnection, UdpRelayMode, UdpSession};

use super::{
    ConnectorType, HandlerCommonOptions, OutboundHandler, OutboundType,
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
    ep: OnceCell<TuicEndpoint>,
    conn: AsyncMutex<Option<Arc<TuicConnection>>>,
    next_assoc_id: AtomicU16,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuic")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
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

    async fn support_udp(&self) -> bool {
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

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
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

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            ep: OnceCell::new(),
            conn: AsyncMutex::new(None),
            next_assoc_id: AtomicU16::new(0),
        }
    }

    async fn init_endpoint(
        opts: HandlerOptions,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<TuicEndpoint> {
        let verifier =
            Arc::new(DefaultTlsVerifier::new(None, opts.skip_cert_verify));
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

        // TODO: we should try to resolve the server address once?
        let socket = {
            if resolver.ipv6() {
                new_udp_socket(
                    Some((Ipv6Addr::UNSPECIFIED, 0).into()),
                    sess.iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                    None,
                )
                .await?
            } else {
                new_udp_socket(
                    Some((Ipv4Addr::UNSPECIFIED, 0).into()),
                    None,
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                    None,
                )
                .await?
            }
        };

        debug!("binding socket to: {:?}", socket.local_addr()?);

        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(TokioRuntime),
        )?;

        endpoint.set_default_client_config(quinn_config);

        // Parse ip field if provided, or fallback to parsing server as IP literal
        let ip_addr = opts
            .ip
            .as_ref()
            .and_then(|ip_str| ip_str.parse().ok())
            .or_else(|| opts.server.parse().ok());

        let endpoint = TuicEndpoint {
            ep: endpoint,
            server: ServerAddr::new(opts.server, opts.port, ip_addr, opts.sni),
            uuid: opts.uuid,
            password: Arc::from(opts.password.into_bytes().into_boxed_slice()),
            udp_relay_mode: opts.udp_relay_mode,
            zero_rtt_handshake: opts.reduce_rtt,
            heartbeat: opts.heartbeat_interval,
            gc_interval: opts.gc_interval,
            gc_lifetime: opts.gc_lifetime,
        };

        Ok(endpoint)
    }

    async fn get_conn(
        &self,
        resolver: &ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<Arc<TuicConnection>> {
        let endpoint = self
            .ep
            .get_or_try_init(|| {
                Self::init_endpoint(self.opts.clone(), resolver.clone(), sess)
            })
            .await?;

        let fut = async {
            let mut guard = self.conn.lock().await;

            let conn = match guard.as_ref() {
                None => {
                    // init
                    let new_conn = endpoint.connect(resolver, false).await?;
                    *guard = Some(new_conn.clone());
                    new_conn
                }
                Some(existing) if existing.check_open().is_err() => {
                    // reconnect
                    let new_conn = endpoint.connect(resolver, true).await?;
                    *guard = Some(new_conn.clone());
                    new_conn
                }
                Some(existing) => existing.clone(),
            };

            Ok(conn)
        };

        tokio::time::timeout(self.opts.request_timeout, fut).await?
    }

    async fn do_connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<AnyStream> {
        let conn = self.get_conn(&resolver, sess).await?;
        let dest = sess.destination.clone().into_tuic();
        let tuic_tcp = conn.connect_tcp(dest).await?;
        sess.push_chain(self.name());
        Ok(AnyStream::new(tuic_tcp))
    }

    async fn do_connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<AnyOutboundDatagram> {
        let conn = self.get_conn(&resolver, sess).await?;
        let assos_id = self.next_assoc_id.fetch_add(1, Ordering::SeqCst);
        let quic_udp = TuicDatagramOutbound::new(assos_id, conn, sess.source.into());
        sess.push_chain(self.name());
        Ok(AnyOutboundDatagram::new(quic_udp))
    }
}

#[derive(Debug)]
pub struct TuicDatagramOutbound {
    send_tx: tokio_util::sync::PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
}

impl TuicDatagramOutbound {
    pub fn new(
        assoc_id: u16,
        conn: Arc<TuicConnection>,
        local_addr: ClashSocksAddr,
    ) -> Self {
        // TODO not sure about the size of buffer
        let (send_tx, send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let udp_sessions = conn.udp_sessions.clone();
        udp_sessions.write().insert(
            assoc_id,
            UdpSession {
                incoming: recv_tx,
                local_addr,
            },
        );
        tokio::spawn(async move {
            // capture vars
            let mut send_rx = send_rx;
            while let Some(next_send) = send_rx.recv().await {
                let res = conn
                    .outgoing_udp(
                        next_send.data,
                        next_send.dst_addr.into_tuic(),
                        assoc_id,
                    )
                    .await;
                if res.is_err() {
                    break;
                }
            }
            // TuicDatagramOutbound dropped or outgoing_udp occurs error
            tracing::info!(
                "[udp] [dissociate] closing UDP session [{assoc_id:#06x}]"
            );
            _ = conn.dissociate(assoc_id).await;
            udp_sessions.write().remove(&assoc_id);
            anyhow::Ok(())
        });

        Self {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
        }
    }
}
