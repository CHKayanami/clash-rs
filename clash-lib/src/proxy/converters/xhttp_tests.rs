use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use crate::{
    config::internal::proxy::{OutboundTrojan, OutboundVless, OutboundVmess},
    proxy::{trojan, vless, vmess},
};
use super::xhttp_alpn;
use crate::config::internal::proxy::XHttpOpt;

#[test]
fn xhttp_reality_and_stream_one_alpn_require_h2() {
    for reality in [false, true] {
        for mode in ["packet-up", "stream-up", "stream-one"] {
            let opts = XHttpOpt { mode: Some(mode.into()), ..Default::default() };
            for protocols in [vec![], vec!["http/1.1".into()]] {
                assert_eq!(xhttp_alpn(Some(&opts), Some(&protocols), reality).is_err(),
                    reality || mode == "stream-one", "mode={mode}, reality={reality}");
            }
            for protocols in [vec!["h2".into()], vec!["h2".into(), "http/1.1".into()]] {
                assert_eq!(xhttp_alpn(Some(&opts), Some(&protocols), reality).unwrap(), protocols);
            }
            assert!(xhttp_alpn(Some(&opts), None, reality).unwrap().iter().any(|protocol| protocol == "h2"));
        }
    }
}

#[test]
fn xhttp_configuration_accepts_vless_and_rejects_other_protocols() {
    crate::tests::initialize();
    for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
        let common = json!({
            "name": "xhttp", "server": "localhost", "port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000", "alterId": 0,
            "password": "test-password", "network": "xhttp", "tls": true,
            "xhttp-opts": { "path": "/test", "mode": mode,
                "x-padding-bytes": "100-1000", "sc-min-posts-interval-ms": "30",
                "sc-max-each-post-bytes": "500000-1000000", "no-grpc-header": true }
        });
        let vless = serde_json::from_value::<OutboundVless>(common.clone()).unwrap();
        assert!(vless::Handler::try_from(&vless).is_ok());
        let vmess = serde_json::from_value::<OutboundVmess>(common.clone()).unwrap();
        assert!(vmess::Handler::try_from(&vmess).is_err());
        let trojan = serde_json::from_value::<OutboundTrojan>(common).unwrap();
        assert!(trojan::Handler::try_from(&trojan).is_err());
    }
}

#[test]
fn xhttp_configuration_rejects_incompatible_flow_and_alpn() {
    crate::tests::initialize();
    let mut config: OutboundVless = serde_json::from_value(json!({
        "name": "xhttp", "server": "localhost", "port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000", "network": "xhttp", "tls": true,
    })).unwrap();
    config.flow = Some("xtls-rprx-vision".into());
    assert!(vless::Handler::try_from(&config).is_err());
    config.encryption = Some(format!("mlkem768x25519plus.native.0rtt.{}",
        URL_SAFE_NO_PAD.encode([7; 32])));
    assert!(vless::Handler::try_from(&config).is_ok());
    config.alpn = Some(vec!["h3".into()]);
    assert!(vless::Handler::try_from(&config).is_err());
    config.alpn = Some(vec!["h2".into()]);
    assert!(vless::Handler::try_from(&config).is_ok());
}

#[test]
fn xhttp_download_configuration_validates_security_and_flat_schema() {
    crate::tests::initialize();
    let base = json!({
        "name": "xhttp", "server": "localhost", "port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000", "network": "xhttp", "tls": true,
        "xhttp-opts": { "mode": "stream-up", "download-settings": {
            "server": "download.example", "port": 8443, "host": "cdn.example",
            "path": "/down", "tls": true, "servername": "download.example", "alpn": ["http/1.1"],
            "skip-cert-verify": true, "reuse-settings": { "max-connections": "1" }
        }}
    });
    let config: OutboundVless = serde_json::from_value(base.clone()).unwrap();
    assert!(vless::Handler::try_from(&config).is_ok());
    let mut stream_one = base.clone();
    stream_one["xhttp-opts"]["mode"] = json!("stream-one");
    let config: OutboundVless = serde_json::from_value(stream_one).unwrap();
    assert!(vless::Handler::try_from(&config).is_err());
    let mut h3 = base.clone();
    h3["xhttp-opts"]["download-settings"]["alpn"] = json!(["h3"]);
    let config: OutboundVless = serde_json::from_value(h3).unwrap();
    assert!(vless::Handler::try_from(&config).is_err());
    for invalid in [json!({"extra": {}}), json!({"http-version": "h2"}), json!({"download-settings": {"unknown": true}})] {
        let mut config = base.clone();
        config["xhttp-opts"] = invalid;
        assert!(serde_json::from_value::<OutboundVless>(config).is_err());
    }
}
