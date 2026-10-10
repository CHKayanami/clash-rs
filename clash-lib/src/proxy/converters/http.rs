use std::sync::Arc;

use crate::{
    Error,
    config::internal::proxy::OutboundHttp,
    proxy::{
        HandlerCommonOptions,
        http::outbound::{Handler, HandlerOptions},
        transport::{TlsClient, TransportLayer},
        utils::RemoteConnector,
    },
};

pub fn build_handler(
    s: &OutboundHttp,
    connector: Option<Arc<RemoteConnector>>,
) -> Result<Handler, Error> {
    let tls_client = if s.tls {
        Some(TransportLayer::Tls(TlsClient::new_advanced(
            s.skip_cert_verify,
            s.sni.clone().unwrap_or_else(|| s.common_opts.server.clone()),
            Some(vec!["http/1.1".to_owned()]),
            None,
            s.fingerprint.as_deref(),
            None,
            None,
            None,
        )?))
    } else {
        None
    };
    Handler::new(HandlerOptions {
        name: s.common_opts.name.clone(),
        common_opts: HandlerCommonOptions {
            connector: s.common_opts.connect_via.clone(),
            tfo: s.common_opts.tfo,
            ..Default::default()
        },
        server: s.common_opts.server.clone(),
        port: s.common_opts.port,
        user: s.username.clone(),
        password: s.password.clone(),
        headers: s.headers.clone().unwrap_or_default(),
        tls_client,
    }, connector).map_err(Into::into)
}

impl TryFrom<OutboundHttp> for Handler {
    type Error = Error;

    fn try_from(s: OutboundHttp) -> Result<Self, Self::Error> {
        build_handler(&s, None)
    }
}
