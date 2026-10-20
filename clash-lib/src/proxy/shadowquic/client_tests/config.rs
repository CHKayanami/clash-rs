use super::*;

#[test]
fn configuration_defaults_and_bandwidth_units() {
    use crate::proxy::shadowquic::config::CongestionControl;
    use crate::config::internal::proxy::OutboundShadowQuic;
    let config: OutboundShadowQuic = yaml_serde::from_str(
        "name: sq\nserver: localhost\nport: 443\nusername: user\npassword: pass\nserver-name: localhost",
    ).unwrap();
    let handler = Handler::try_from(config).unwrap();
    assert_eq!(handler.opts.initial_mtu, 1300);
    assert_eq!(handler.opts.min_mtu, 1290);
    assert_eq!(handler.opts.alpn, ["h3"]);
    assert!(handler.opts.zero_rtt && handler.opts.gso && handler.opts.mtu_discovery);
    assert!(!handler.opts.over_stream);
    for (value, expected) in [("10000000", 10_000_000), ("'1.5M'", 1_572_864)] {
        let cc: CongestionControl = yaml_serde::from_str(
            &format!("!brutal\nbandwidth: {value}"),
        ).unwrap();
        let CongestionControl::Brutal(params) = cc else { panic!("expected brutal") };
        assert_eq!(params.bandwidth, expected);
        assert_eq!(params.min_window, 16384);
    }
    let mut opts = HandlerOptions { min_mtu: 1199, ..Default::default() };
    assert!(opts.validate().is_err());
    opts.min_mtu = 1290;
    opts.initial_mtu = 1200;
    assert!(opts.validate().is_err());
    assert_eq!(protocol::encode_addr(&SocksAddr::Domain("a".repeat(256).into(), 80))
        .unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert!(!format!("{:?}", handler.opts).contains("pass"));
}
