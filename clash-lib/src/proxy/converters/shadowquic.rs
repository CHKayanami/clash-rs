use crate::{
    config::proxy::OutboundShadowQuic,
    proxy::shadowquic::{Handler, HandlerOptions},
    session::SocksAddr,
};

impl TryFrom<OutboundShadowQuic> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundShadowQuic) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundShadowQuic> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundShadowQuic) -> Result<Self, Self::Error> {
        let defaults = HandlerOptions::default();
        let opts = HandlerOptions {
            addr: SocksAddr::try_from((
                s.common_opts.server.clone(), s.common_opts.port,
            ))?.to_string(),
            password: s.password.clone(),
            username: s.username.clone(),
            server_name: s.server_name.clone(),
            alpn: s.alpn.clone().unwrap_or(defaults.alpn),
            initial_mtu: s.initial_mtu.unwrap_or(defaults.initial_mtu),
            congestion_control: s.congestion_control.clone()
                .unwrap_or(defaults.congestion_control),
            zero_rtt: s.zero_rtt.unwrap_or(defaults.zero_rtt),
            over_stream: s.over_stream.unwrap_or(defaults.over_stream),
            min_mtu: s.min_mtu.unwrap_or(defaults.min_mtu),
            keep_alive_interval: s.keep_alive_interval
                .unwrap_or(defaults.keep_alive_interval),
            gso: s.gso.unwrap_or(defaults.gso),
            mtu_discovery: s.mtu_discovery.unwrap_or(defaults.mtu_discovery),
        };
        opts.validate()?;
        Ok(Handler::new(s.common_opts.name.clone(), opts))
    }
}
