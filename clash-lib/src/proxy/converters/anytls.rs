use std::sync::Arc;
use tracing::warn;

use crate::{
    config::internal::proxy::OutboundAnytls,
    proxy::{
        HandlerCommonOptions,
        anytls::{Handler, HandlerOptions},
        transport::{TlsClient, TransportLayer},
        utils::RemoteConnector,
    },
};

const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

impl TryFrom<OutboundAnytls> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundAnytls) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

pub fn build_handler(
    s: &OutboundAnytls,
    connector: Option<Arc<dyn RemoteConnector>>,
) -> Result<Handler, crate::Error> {
    let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
    if skip_cert_verify {
        warn!("skip_cert_verify is set to true for {}", s.common_opts.name);
    }
    let default_pool = crate::proxy::anytls::pool::SessionPoolConfig::default();

    Ok(Handler::new(
        HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            pool_config: crate::proxy::anytls::pool::SessionPoolConfig {
                min_connections: s.min_idle_session.map(|v| v as usize).unwrap_or(1),
                max_connections: s.max_connections.unwrap_or(16),
                // Fall back to the pool default rather than 1: pinning it to a
                // single stream per session meant every connection dialled its
                // own TLS handshake and AnyTLS never multiplexed.
                max_streams_per_connection: s
                    .max_streams
                    .unwrap_or(default_pool.max_streams_per_connection),
                idle_timeout: std::time::Duration::from_secs(
                    s.idle_session_timeout.unwrap_or(60),
                ),
                idle_session_check_interval: std::time::Duration::from_secs(
                    s.idle_session_check_interval.unwrap_or(30),
                ),
            },
            tls: {
                let client = TlsClient::new_advanced(
                    skip_cert_verify,
                    s.sni
                        .clone()
                        .unwrap_or_else(|| s.common_opts.server.clone()),
                    s.alpn
                        .clone()
                        .or(Some(DEFAULT_ALPN.map(str::to_owned).to_vec())),
                    None,
                    s.fingerprint.as_deref(),
                    s.client_fingerprint.as_deref(),
                    s.tls_cert.as_deref(),
                    s.tls_key.as_deref(),
                )?;
                Some(TransportLayer::Tls(client))
            },
            transport: None,
        },
        connector,
    ))
}

impl TryFrom<&OutboundAnytls> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundAnytls) -> Result<Self, Self::Error> {
        build_handler(s, None)
    }
}
