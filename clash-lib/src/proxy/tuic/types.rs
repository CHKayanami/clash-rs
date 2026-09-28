use crate::{
    app::{dns::ThreadSafeDNSResolver, net::get_default_outbound_interface},
    proxy::{datagram::UdpPacket, utils::new_udp_socket},
    session::SocksAddr as ClashSocksAddr,
};
use anyhow::{Result, anyhow};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};
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
        ))
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
    ) -> Arc<Self> {
        let conn = Self {
            conn,
            uuid,
            password,
            udp_relay_mode,
            udp_sessions: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            next_pkt_id: AtomicU16::new(0),
            fragments: parking_lot::Mutex::new(FragmentReassembler::default()),
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
