use std::sync::Arc;
use tracing::warn;

const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];
const DEFAULT_WS_ALPN: [&str; 1] = ["http/1.1"];

use crate::{
    Error,
    config::internal::proxy::OutboundTrojan,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcClient, TlsClient, TransportLayer, WsClient},
        trojan::{Handler, HandlerOptions},
        utils::RemoteConnector,
    },
};

impl TryFrom<OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTrojan) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

pub fn build_handler(
    s: &OutboundTrojan,
    connector: Option<Arc<dyn RemoteConnector>>,
) -> Result<Handler, crate::Error> {
    s.smux.as_ref().map(|m| m.validate()).transpose()?;

    let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
    if skip_cert_verify {
        warn!("skip_cert_verify is set to true for {}", s.common_opts.name);
    }

    let h = Handler::new(
        HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.to_owned(),
            udp: s.udp.unwrap_or_default(),
            tls: {
                let client = TlsClient::new(
                    skip_cert_verify,
                    s.sni
                        .as_ref()
                        .map(|x| x.to_owned())
                        .unwrap_or(s.common_opts.server.to_owned()),
                    s.alpn.clone().or(Some({
                        let network = s.network.as_deref();
                        let alpn: &[&str] = if let Some("ws") = network {
                            &DEFAULT_WS_ALPN
                        } else {
                            &DEFAULT_ALPN
                        };

                        alpn.iter()
                            .copied()
                            .map(|x| x.to_owned())
                            .collect::<Vec<String>>()
                    })),
                    None,
                    s.tls_cert.as_deref(),
                    s.tls_key.as_deref(),
                )?;
                Some(TransportLayer::Tls(client))
            },
            transport: s
                .network
                .as_ref()
                .map(|x| match x.as_str() {
                    "tcp" => Ok(None),
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            let client: WsClient = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid ws_opts");
                            Some(TransportLayer::Ws(client))
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            let client: GrpcClient =
                                (s.sni.clone(), x, &s.common_opts)
                                    .try_into()
                                    .expect("invalid grpc_opts");
                            Some(TransportLayer::Grpc(client))
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported trojan network: {x}"
                    ))),
                })
                .transpose()?
                .flatten(),
            smux: s.smux.clone(),
        },
        connector,
    );
    Ok(h)
}

impl TryFrom<&OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTrojan) -> Result<Self, Self::Error> {
        build_handler(s, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::CommonConfigOptions;

    #[test]
    fn test_trojan_network_tcp() {
        crate::tests::initialize();
        let config = OutboundTrojan {
            common_opts: CommonConfigOptions {
                name: "test-trojan-tcp".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            password: "test-password".to_string(),
            sni: Some("example.com".to_string()),
            network: Some("tcp".to_string()),
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "Trojan handler with network: tcp should parse successfully"
        );
    }
}
