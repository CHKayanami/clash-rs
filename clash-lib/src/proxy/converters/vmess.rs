use std::sync::Arc;
use tracing::warn;

use crate::{
    Error,
    config::internal::proxy::OutboundVmess,
    proxy::{
        HandlerCommonOptions,
        transport::{
            GrpcClient, H2Client, HttpClient, TlsClient, TransportLayer,
            WsClient,
        },
        utils::RemoteConnector,
        vmess::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundVmess> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVmess) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

pub fn build_handler(
    s: &OutboundVmess,
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
            uuid: s.uuid.clone(),
            alter_id: s.alter_id,
            security: s.cipher.clone().unwrap_or_default(),
            udp: s.udp.unwrap_or(true),
            transport: s
                .network
                .clone()
                .map(|x| match x.as_str() {
                    "tcp" => Ok(None),
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            let client: WsClient = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid ws options");
                            Some(TransportLayer::Ws(client))
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "http" => {
                        let default_http_opts =
                            crate::config::proxy::HttpOpt::default();
                        let opts =
                            s.http_opts.as_ref().unwrap_or(&default_http_opts);
                        let client: HttpClient = (opts, &s.common_opts)
                            .try_into()
                            .map_err(|e| {
                                Error::InvalidConfig(format!(
                                    "invalid http options: {e}"
                                ))
                            })?;
                        Ok(Some(TransportLayer::Http(client)))
                    }
                    "h2" => s
                        .h2_opts
                        .as_ref()
                        .map(|x| {
                            let client: H2Client = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid h2 options");
                            Some(TransportLayer::H2(client))
                        })
                        .ok_or(Error::InvalidConfig(
                            "h2_opts is required for h2".to_owned(),
                        )),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            let client: GrpcClient =
                                (s.server_name.clone(), x, &s.common_opts)
                                    .try_into()
                                    .expect("invalid grpc options");
                            Some(TransportLayer::Grpc(client))
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {x}"
                    ))),
                })
                .transpose()?
                .flatten(),
            tls: if s.tls.unwrap_or_default() {
                let client = TlsClient::new_advanced(
                    s.skip_cert_verify.unwrap_or_default(),
                    s.server_name.as_ref().map(|x| x.to_owned()).unwrap_or(
                        s.ws_opts
                            .as_ref()
                            .and_then(|x| {
                                x.headers.clone().and_then(|x| {
                                    let h = x.get("Host");
                                    h.cloned()
                                    })
                            })
                            .unwrap_or(s.common_opts.server.to_owned()),
                    ),
                    s.network
                        .as_ref()
                        .map(|x| match x.as_str() {
                            "tcp" => Ok(vec![]),
                            "ws" | "http" => Ok(vec!["http/1.1".to_owned()]),
                            "h2" | "grpc" => Ok(vec!["h2".to_owned()]),
                            _ => Err(Error::InvalidConfig(format!(
                                "unsupported network: {x}"
                            ))),
                        })
                        .transpose()?,
                    None,
                    s.fingerprint.as_deref(),
                    s.client_fingerprint.as_deref(),
                    s.tls_cert.as_deref(),
                    s.tls_key.as_deref(),
                )?;
                Some(TransportLayer::Tls(client))
            } else {
                None
            },
            smux: s.smux.clone(),
        },
        connector,
    );
    Ok(h)
}

impl TryFrom<&OutboundVmess> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVmess) -> Result<Self, Self::Error> {
        build_handler(s, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::{CommonConfigOptions, H2Opt, HttpOpt};
    use std::collections::HashMap;

    #[test]
    fn test_vmess_network_tcp() {
        crate::tests::initialize();
        let config = OutboundVmess {
            common_opts: CommonConfigOptions {
                name: "test-tcp".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            alter_id: 0,
            cipher: Some("auto".to_string()),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("tcp".to_string()),
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VMess handler with network: tcp should parse successfully"
        );
    }

    #[test]
    fn test_vmess_network_h2() {
        crate::tests::initialize();
        let config = OutboundVmess {
            common_opts: CommonConfigOptions {
                name: "test-h2".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            alter_id: 0,
            cipher: Some("auto".to_string()),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("h2".to_string()),
            h2_opts: Some(H2Opt {
                host: Some(vec!["example.com".to_string()]),
                path: Some("/test".to_string()),
            }),
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VMess handler with network: h2 should parse successfully"
        );
    }

    #[test]
    fn test_vmess_network_http() {
        crate::tests::initialize();
        let mut headers = HashMap::new();
        headers.insert(
            "Host".to_string(),
            vec!["example.com".to_string()],
        );

        let config = OutboundVmess {
            common_opts: CommonConfigOptions {
                name: "test-http".to_string(),
                server: "example.com".to_string(),
                port: 80,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            alter_id: 0,
            cipher: Some("auto".to_string()),
            udp: Some(true),
            network: Some("http".to_string()),
            http_opts: Some(HttpOpt {
                method: Some("GET".to_string()),
                path: Some(vec!["/video".to_string()]),
                headers: Some(headers),
            }),
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VMess handler with network: http should parse successfully"
        );
    }
}
