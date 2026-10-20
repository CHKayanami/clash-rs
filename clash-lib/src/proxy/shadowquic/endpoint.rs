use std::{io, net::{Ipv4Addr, Ipv6Addr, SocketAddr}, sync::Arc, time::Duration};

use quinn_jls::{
    ClientConfig, Connection, Endpoint, EndpointConfig, MtuDiscoveryConfig,
    TokioRuntime, TransportConfig,
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
    rustls::{ClientConfig as TlsClientConfig, RootCertStore, jls::JlsClientConfig, version::TLS13},
};
#[cfg(feature = "aws-lc-rs")]
use quinn_jls::rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use quinn_jls::rustls::crypto::ring as crypto_provider;

use tokio::time::timeout;

use crate::{
    common::errors::new_io_error, proxy::utils::new_udp_socket, session::Session,
};

use super::{brutal::BrutalConfig, config::{CongestionControl, HandlerOptions}};

pub(super) struct ClientEndpoint {
    endpoint: Endpoint,
    ipv4: bool,
}

impl ClientEndpoint {
    pub async fn new(
        opts: &HandlerOptions, addr: SocketAddr, sess: &Session,
    ) -> io::Result<Self> {
        let config = client_config(opts)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = new_udp_socket(
            Some(bind_addr),
            sess.iface.as_deref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
            Some(addr),
        ).await?;
        let endpoint = Endpoint::new(
            EndpointConfig::default(), None, socket.into_std()?, Arc::new(TokioRuntime),
        )?;
        endpoint.set_default_client_config(config);
        Ok(Self { endpoint, ipv4: addr.is_ipv4() })
    }

    pub fn is_ipv4(&self) -> bool {
        self.ipv4
    }

    pub async fn connect(
        &self, opts: &HandlerOptions, addr: SocketAddr,
    ) -> io::Result<Connection> {
        self.connect_with_timeout(opts, addr, Duration::from_secs(10)).await
    }

    pub(super) async fn connect_with_timeout(
        &self, opts: &HandlerOptions, addr: SocketAddr, deadline: Duration,
    ) -> io::Result<Connection> {
        timeout(deadline, self.connect_inner(opts, addr, deadline)).await
            .map_err(|_| io::Error::new(
                io::ErrorKind::TimedOut, "shadowquic JLS handshake timed out",
            ))?
    }

    async fn connect_inner(
        &self, opts: &HandlerOptions, addr: SocketAddr, deadline: Duration,
    ) -> io::Result<Connection> {
        let connecting = self.endpoint.connect(addr, &opts.server_name)
            .map_err(new_io_error)?;
        let conn = if opts.zero_rtt {
            match connecting.into_0rtt() {
                Ok((conn, accepted)) => {
                    if conn.is_jls() == Some(false) {
                        check_jls(&conn)?;
                    }
                    let check = conn.clone();
                    tokio::spawn(async move {
                        let accepted = match timeout(deadline, accepted).await {
                            Ok(accepted) => accepted,
                            Err(_) => {
                                check.close(0u8.into(), b"JLS handshake timed out");
                                return;
                            }
                        };
                        tracing::debug!("shadowquic 0-RTT accepted: {accepted}");
                        if let Err(err) = check_jls(&check) {
                            tracing::warn!("shadowquic handshake failed: {err}");
                        }
                    });
                    return Ok(conn);
                }
                Err(connecting) => connecting.await.map_err(new_io_error)?,
            }
        } else {
            connecting.await.map_err(new_io_error)?
        };
        check_jls(&conn)?;
        Ok(conn)
    }
}

fn check_jls(conn: &Connection) -> io::Result<()> {
    if conn.is_jls() != Some(true) {
        conn.close(0u8.into(), b"JLS authentication failed");
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied, "shadowquic JLS authentication failed",
        ));
    }
    Ok(())
}

pub(super) fn client_config(opts: &HandlerOptions) -> io::Result<ClientConfig> {
    opts.validate()?;
    let mut crypto = TlsClientConfig::builder_with_provider(
        Arc::new(crypto_provider::default_provider()),
    )
        .with_protocol_versions(&[&TLS13])
        .map_err(new_io_error)?
        .with_root_certificates(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        })
        .with_no_client_auth();
    crypto.alpn_protocols = opts.alpn.iter().map(|x| x.as_bytes().to_vec()).collect();
    crypto.enable_early_data = opts.zero_rtt;
    crypto.jls_config = JlsClientConfig::new(&opts.password, &opts.username);
    let mut transport = TransportConfig::default();
    let discovery = opts.mtu_discovery.then(|| {
        let mut config = MtuDiscoveryConfig::default();
        config.black_hole_cooldown(Duration::from_secs(120));
        config.interval(Duration::from_secs(90));
        config.blackhole_reset_mtu(false);
        config
    });
    transport
        .max_concurrent_bidi_streams(500u32.into())
        .max_concurrent_uni_streams(500u32.into())
        .stream_receive_window(5_000_000u32.into())
        .datagram_receive_buffer_size(Some(10_000_000))
        .mtu_discovery_config(discovery)
        .min_mtu(opts.min_mtu)
        .initial_mtu(opts.initial_mtu)
        .enable_segmentation_offload(opts.gso)
        .keep_alive_interval(opts.keep_alive());
    match &opts.congestion_control {
        CongestionControl::Bbr | CongestionControl::Bbr3 => {
            if matches!(opts.congestion_control, CongestionControl::Bbr3) {
                tracing::warn!("shadowquic BBR3 is unavailable; using BBR");
            }
            transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
        CongestionControl::Cubic => {
            transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        CongestionControl::NewReno => {
            transport.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
        }
        CongestionControl::Brutal(params) => {
            transport.congestion_controller_factory(Arc::new(BrutalConfig::new(params)));
        }
    }
    let mut config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).map_err(new_io_error)?,
    ));
    config.transport_config(Arc::new(transport));
    Ok(config)
}
