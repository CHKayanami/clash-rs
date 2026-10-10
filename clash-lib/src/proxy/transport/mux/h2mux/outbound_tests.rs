use std::sync::Arc;

use crate::{
    config::internal::proxy::OutboundProxyProtocol,
    proxy::{OutboundNode, converters},
};

fn handler(protocol: &str, enabled: bool, only_tcp: bool) -> OutboundNode {
    let yaml = format!("type: {protocol}
name: mux-udp-test
server: 127.0.0.1
port: 9
uuid: 00000000-0000-0000-0000-000000000000
password: test-only-password
cipher: aes-128-gcm
alterId: 0
udp: false
smux:
  enabled: {enabled}
  only-tcp: {only_tcp}
");
    match yaml_serde::from_str::<OutboundProxyProtocol>(&yaml).unwrap() {
        OutboundProxyProtocol::Vless(config) =>
            OutboundNode::protocol(Arc::new(converters::vless::build_handler(&config, None).unwrap())),
        OutboundProxyProtocol::Vmess(config) =>
            OutboundNode::protocol(Arc::new(converters::vmess::build_handler(&config, None).unwrap())),
        OutboundProxyProtocol::Trojan(config) =>
            OutboundNode::protocol(Arc::new(converters::trojan::build_handler(&config, None).unwrap())),
        #[cfg(feature = "shadowsocks")]
        OutboundProxyProtocol::Ss(config) =>
            OutboundNode::protocol(Arc::new(converters::shadowsocks::build_handler(&config, None).unwrap())),
        _ => panic!("unexpected outbound protocol"),
    }
}

#[tokio::test]
async fn udp_capability_respects_mux_enable_and_only_tcp() {
    crate::tests::initialize();
    for protocol in ["vless", "vmess", "trojan", #[cfg(feature = "shadowsocks")] "ss"] {
        // Mux can carry UDP even when the original transport has UDP disabled.
        assert!(handler(protocol, true, false).support_udp().await);
        assert!(!handler(protocol, true, true).support_udp().await);
        assert!(!handler(protocol, false, false).support_udp().await);
    }
}
