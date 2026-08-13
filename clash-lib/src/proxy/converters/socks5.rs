use std::sync::Arc;

use crate::{
    config::internal::proxy::OutboundSocks5,
    proxy::{
        HandlerCommonOptions,
        socks::outbound::{Handler, HandlerOptions},
        transport::TlsClient,
        utils::RemoteConnector,
    },
};

impl TryFrom<OutboundSocks5> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundSocks5) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

pub fn build_handler(
    s: &OutboundSocks5,
    connector: Option<Arc<dyn RemoteConnector>>,
) -> Result<Handler, crate::Error> {
    let tls_client = if s.tls {
        Some(crate::proxy::transport::TransportLayer::Tls(
            TlsClient::new(
                s.skip_cert_verify,
                s.sni.clone().unwrap_or(s.common_opts.server.to_owned()),
                None,
                None,
                None,
                None,
            )?,
        ))
    } else {
        None
    };
    let h = Handler::new(
        HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            user: s.username.clone(),
            password: s.password.clone(),
            udp: s.udp,
            tls_client,
        },
        connector,
    );
    Ok(h)
}

impl TryFrom<&OutboundSocks5> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundSocks5) -> Result<Self, Self::Error> {
        build_handler(s, None)
    }
}
