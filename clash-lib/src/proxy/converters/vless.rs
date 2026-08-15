use std::sync::Arc;

use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::{
        HandlerCommonOptions,
        transport::{
            GrpcClient, H2Client, HttpClient, RealityClient, TlsClient,
            TransportLayer, WsClient,
        },
        utils::RemoteConnector,
        vless::{Handler, HandlerOptions},
    },
};
use tracing::warn;

impl TryFrom<OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVless) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

pub fn build_handler(
    s: &OutboundVless,
    connector: Option<Arc<dyn RemoteConnector>>,
) -> Result<Handler, crate::Error> {
    s.smux.as_ref().map(|m| m.validate()).transpose()?;

    let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        if s.client_fingerprint.is_some() {
            warn!(
                "client-fingerprint (uTLS) is not yet implemented, ignored for {}",
                s.common_opts.name
            );
        }

        if let Some(flow) = s.flow.as_deref() {
            if flow == "xtls-rprx-vision"
                && !s.tls.unwrap_or_default()
                && s.reality_opts.is_none()
            {
                return Err(Error::InvalidConfig(format!(
                    "flow '{}' requires TLS or Reality to be enabled for {}",
                    flow, s.common_opts.name
                )));
            }
        }

        let tls: Option<TransportLayer> = if let Some(ref reality_opts) =
            s.reality_opts
        {
            // vless with reality

            // reality public-key bytes
            let pk_bytes =
                super::utils::decode_base64_public_key(&reality_opts.public_key)?;

            // reality short id bytes
            let short_id = super::utils::decode_short_id(
                reality_opts.short_id.as_deref().unwrap_or_default(),
            )?;

            // SNI
            let sni = s
                .server_name
                .clone()
                .unwrap_or_else(|| s.common_opts.server.clone());

            Some(TransportLayer::Reality(RealityClient::new(
                sni, pk_bytes, short_id,
            )))
        } else {
            // vless without reality
            match s.tls.unwrap_or_default() {
                true => {
                    let client = TlsClient::new(
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
                        s.tls_cert.as_deref(),
                        s.tls_key.as_deref(),
                    )?;
                    Some(TransportLayer::Tls(client))
                }
                false => None,
            }
        };

        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                tfo: s.common_opts.tfo,
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
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
                        let default_http_opts = crate::config::proxy::HttpOpt::default();
                        let opts = s.http_opts.as_ref().unwrap_or(&default_http_opts);
                        let client: HttpClient = (opts, &s.common_opts)
                            .try_into()
                            .map_err(|e| Error::InvalidConfig(format!("invalid http options: {e}")))?;
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
            tls,
            flow: s.flow.clone(),
            smux: s.smux.clone(),
        },
        connector,
    ))
}

impl TryFrom<&OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVless) -> Result<Self, Self::Error> {
        build_handler(s, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::CommonConfigOptions;

    #[test]
    fn test_vless_network_tcp() {
        crate::tests::initialize();
        // Test that network: tcp is accepted and results in successful parsing
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-tcp".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("tcp".to_string()),
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VLess handler with network: tcp should parse successfully"
        );
    }

    #[test]
    fn test_vless_network_none() {
        crate::tests::initialize();
        // Test that omitting network field also results in successful parsing
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-none".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: None,
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VLess handler without network field should parse successfully"
        );
    }

    #[test]
    fn test_vless_network_invalid() {
        crate::tests::initialize();
        // Test that invalid network types are rejected
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-invalid".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("invalid-network".to_string()),
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_err(),
            "VLess handler with invalid network should fail"
        );
    }

    #[test]
    fn test_vless_flow_without_tls_or_reality() {
        // Test that flow: xtls-rprx-vision is rejected without TLS or Reality
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-flow-no-tls".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            tls: Some(false),
            reality_opts: None,
            flow: Some("xtls-rprx-vision".to_string()),
            ..Default::default()
        };

        let result = Handler::try_from(&config);
        assert!(
            result.is_err(),
            "VLess handler with flow but without TLS/Reality should fail"
        );
        if let Err(e) = result {
            assert!(
                e.to_string()
                    .contains("requires TLS or Reality to be enabled"),
                "Error message should mention requirement of TLS or Reality"
            );
        }
    }

    #[test]
    fn test_vless_flow_with_reality() {
        crate::tests::initialize();
        use crate::config::internal::proxy::RealityOpt;

        // Test that flow: xtls-rprx-vision is accepted with Reality enabled (even if tls is false/None)
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-flow-reality".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            tls: Some(false),
            reality_opts: Some(RealityOpt {
                public_key: "abc".to_string(), // public key format isn't fully validated here since TryInto base64-decodes it
                short_id: Some("1234".to_string()),
            }),
            flow: Some("xtls-rprx-vision".to_string()),
            ..Default::default()
        };

        // Note: decode_base64_public_key might fail on "abc" so TryFrom might fail with base64 error,
        // but it should pass the flow validation phase first. Let's provide a valid base64 key just in case.
        let mut config = config;
        config.reality_opts.as_mut().unwrap().public_key =
            "qpUtN9F_H6pQ4lF5Fp9G1G5eFm5eFm5eFm5eFm5eFm4=".to_string(); // valid base64
        config.reality_opts.as_mut().unwrap().short_id =
            Some("0123456789abcdef".to_string()); // hex format

        let handler = Handler::try_from(&config);
        // We just want to check it passed the flow check. Depending on base64 decoding, it might succeed or fail on PK parsing.
        // Let's assert that it doesn't fail with the "flow requires TLS or Reality" error.
        match handler {
            Ok(_) => {}
            Err(e) => {
                assert!(
                    !e.to_string()
                        .contains("requires TLS or Reality to be enabled"),
                    "Should not fail flow validation"
                );
            }
        }
    }

    #[test]
    fn test_vless_reality_without_short_id() {
        crate::tests::initialize();
        use crate::config::internal::proxy::RealityOpt;

        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-reality-no-short-id".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            tls: Some(false),
            reality_opts: Some(RealityOpt {
                public_key: "qpUtN9F_H6pQ4lF5Fp9G1G5eFm5eFm5eFm5eFm5eFm4="
                    .to_string(),
                short_id: None,
            }),
            flow: Some("xtls-rprx-vision".to_string()),
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VLESS with Reality and omitted short_id should succeed"
        );
    }

    #[test]
    fn test_vless_network_h2() {
        crate::tests::initialize();
        use crate::config::internal::proxy::H2Opt;

        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-h2".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
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
            "VLess handler with network: h2 should parse successfully"
        );
    }

    #[test]
    fn test_vless_network_http() {
        crate::tests::initialize();
        use crate::config::internal::proxy::HttpOpt;
        use std::collections::HashMap;

        let mut headers = HashMap::new();
        headers.insert(
            "Host".to_string(),
            vec!["example.com".to_string()],
        );

        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-http".to_string(),
                server: "example.com".to_string(),
                port: 80,
                ..Default::default()
            },
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
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
            "VLess handler with network: http should parse successfully"
        );
    }
}

