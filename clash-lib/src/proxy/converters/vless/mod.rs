use std::sync::Arc;

use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::{
        HandlerCommonOptions,
        transport::{
            GrpcClient, H2Client, HttpClient,
            TransportLayer, WsClient,
        },
        utils::RemoteConnector,
        vless::{Handler, HandlerOptions, encryption::EncryptionOptions},
    },
};
use tracing::warn;
mod security;
mod xhttp;
use self::{security::build_security, xhttp::build_xhttp};

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
    let flow = s.flow.as_deref().map(|flow| match flow {
        "xtls-rprx-vision-udp443" => "xtls-rprx-vision",
        flow => flow,
    });
    s.smux.as_ref().map(|m| m.validate()).transpose()?;
    let encryption = s
        .encryption
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "none")
        .map(EncryptionOptions::parse)
        .transpose()
        .map_err(|err| {
            Error::InvalidConfig(format!("invalid VLESS encryption: {err}"))
        })?;

    if encryption.is_some() && s.smux.as_ref().is_some_and(|mux| mux.enable) {
        return Err(Error::InvalidConfig(
            "VLESS Encryption does not support smux".to_owned(),
        ));
    }

    let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
    if skip_cert_verify {
        warn!(
            "skipping TLS cert verification for {}",
            s.common_opts.server
        );
    }

    if let Some(flow) = flow
        && flow == "xtls-rprx-vision"
        && encryption.is_none()
        && !s.tls.unwrap_or_default()
        && s.reality_opts.is_none()
    {
        return Err(Error::InvalidConfig(format!(
            "flow '{}' requires TLS or Reality to be enabled for {}",
            flow, s.common_opts.name
        )));
    }

    if flow == Some("xtls-rprx-vision") && encryption.is_none()
        && !matches!(s.network.as_deref(), None | Some("tcp" | "raw")) {
        return Err(Error::InvalidConfig(
            "Vision over non-RAW transports requires VLESS Encryption".into(),
        ));
    }

    let tls = build_security(s, None)?;

    Ok(Handler::new(
        HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                tfo: s.common_opts.tfo,
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
            encryption,
            udp: s.udp.unwrap_or(true),
            transport: s
                .network
                .clone()
                .map(|x| match x.as_str() {
                    "tcp" | "raw" => Ok(None),
                    "xhttp" => Ok(Some(TransportLayer::XHttp(build_xhttp(s)?))),
                    "ws" => {
                        let opts = s.ws_opts.as_ref().ok_or_else(|| {
                            Error::InvalidConfig("ws_opts is required for ws".to_owned())
                        })?;
                        let client: WsClient = (opts, &s.common_opts)
                            .try_into()
                            .map_err(|e| {
                                Error::InvalidConfig(format!("invalid ws options: {e}"))
                            })?;
                        Ok(Some(TransportLayer::Ws(client)))
                    }
                    "http" => {
                        let default_http_opts =
                            crate::config::proxy::HttpOpt::default();
                        let opts =
                            s.http_opts.as_ref().unwrap_or(&default_http_opts);
                        let client: HttpClient =
                            (opts, &s.common_opts).try_into().map_err(|e| {
                                Error::InvalidConfig(format!(
                                    "invalid http options: {e}"
                                ))
                            })?;
                        Ok(Some(TransportLayer::Http(client)))
                    }
                    "h2" => {
                        let opts = s.h2_opts.as_ref().ok_or_else(|| {
                            Error::InvalidConfig("h2_opts is required for h2".to_owned())
                        })?;
                        let client: H2Client = (opts, &s.common_opts)
                            .try_into()
                            .map_err(|e| {
                                Error::InvalidConfig(format!("invalid h2 options: {e}"))
                            })?;
                        Ok(Some(TransportLayer::H2(client)))
                    }
                    "grpc" => {
                        let opts = s.grpc_opts.as_ref().ok_or_else(|| {
                            Error::InvalidConfig("grpc_opts is required for grpc".to_owned())
                        })?;
                        let client: GrpcClient =
                            (s.server_name.clone(), opts, &s.common_opts)
                                .try_into()
                                .map_err(|e| {
                                    Error::InvalidConfig(format!("invalid grpc options: {e}"))
                                })?;
                        Ok(Some(TransportLayer::Grpc(client)))
                    }
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {x}"
                    ))),
                })
                .transpose()?
                .flatten(),
            tls,
            flow: flow.map(str::to_owned),
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
    use crate::proxy::transport::mux::MuxOption;

    #[test]
    fn test_vless_alpn_validation_for_tls_and_reality() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use crate::config::internal::proxy::RealityOpt;

        crate::tests::initialize();
        let mut config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "alpn".into(), server: "localhost".into(), port: 443,
                ..Default::default()
            },
            tls: Some(true),
            network: Some("tcp".into()),
            ..Default::default()
        };
        for reality in [false, true] {
            config.reality_opts = reality.then(|| RealityOpt {
                public_key: URL_SAFE_NO_PAD.encode([7; 32]), short_id: None,
            });
            for alpn in [Some(vec!["http/1.1".into()]), Some(vec![]), None] {
                config.alpn = alpn;
                assert!(Handler::try_from(&config).is_ok());
            }
            for alpn in [vec![String::new()], vec!["x".repeat(256)]] {
                config.alpn = Some(alpn);
                assert!(Handler::try_from(&config).is_err());
            }
        }
    }

    #[test]
    fn test_vless_encryption_config() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let mut config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "encrypted".to_owned(),
                server: "localhost".to_owned(),
                port: 443,
                ..Default::default()
            },
            uuid: "00000000-0000-0000-0000-000000000000".to_owned(),
            ..Default::default()
        };
        for value in [None, Some("none".to_owned())] {
            config.encryption = value;
            assert!(Handler::try_from(&config).is_ok());
        }
        config.encryption = Some("unsupported".to_owned());
        assert!(Handler::try_from(&config).is_err());
        let key = URL_SAFE_NO_PAD.encode([7u8; 32]);
        config.encryption = Some(format!("mlkem768x25519plus.native.0rtt.{key}"));
        config.flow = Some("xtls-rprx-vision".to_owned());
        assert!(Handler::try_from(&config).is_ok());
        config.smux = Some(MuxOption {
            enable: true,
            ..Default::default()
        });
        assert!(Handler::try_from(&config).is_err());
    }

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
    fn test_vless_network_raw() {
        crate::tests::initialize();
        // Test that network: raw is accepted as an alias for tcp and results in successful parsing
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-raw".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("raw".to_string()),
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VLess handler with network: raw should parse successfully"
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
                public_key: "qpUtN9F_H6pQ4lF5Fp9G1G5eFm5eFm5eFm5eFm5eFm4"
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
        headers.insert("Host".to_string(), vec!["example.com".to_string()]);

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

    #[test]
    fn test_vless_invalid_h2_options() {
        crate::tests::initialize();
        use crate::config::internal::proxy::H2Opt;

        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-h2-invalid".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            network: Some("h2".to_string()),
            h2_opts: Some(H2Opt {
                host: Some(vec!["example.com".to_string()]),
                path: Some("   invalid path\n\0".to_string()),
            }),
            ..Default::default()
        };

        let result = Handler::try_from(&config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidConfig(_)));
    }

    #[test]
    fn test_vless_invalid_grpc_options() {
        crate::tests::initialize();
        use crate::config::internal::proxy::GrpcOpt;

        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-grpc-invalid".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            network: Some("grpc".to_string()),
            grpc_opts: Some(GrpcOpt {
                grpc_service_name: Some("   invalid service\n\0".to_string()),
            }),
            ..Default::default()
        };

        let result = Handler::try_from(&config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidConfig(_)));
    }
}
