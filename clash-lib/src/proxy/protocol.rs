//! Static dispatch for protocol establishment and API metadata.
use super::{AnyOutboundDatagram, AnyStream, OutboundHandler, OutboundType, OutboundNode, DialWithConnector, PlainProxyAPIResponse};
use crate::{app::dns::ThreadSafeDNSResolver, session::Session};
use erased_serde::Serialize;
use std::{collections::HashMap, io};

use std::sync::{Arc, Weak};

use crate::proxy::direct::Handler as DirectHandler;
use crate::proxy::reject::Handler as RejectHandler;
use crate::proxy::socks::outbound::Handler as Socks5Handler;
use crate::proxy::http::outbound::Handler as HttpHandler;
use crate::proxy::anytls::Handler as AnyTlsHandler;
use crate::proxy::vmess::Handler as VmessHandler;
use crate::proxy::vless::Handler as VlessHandler;
use crate::proxy::trojan::Handler as TrojanHandler;
use crate::proxy::hysteria2::Handler as Hysteria2Handler;
#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks::outbound::Handler as ShadowsocksHandler;
#[cfg(feature = "ssh")]
use crate::proxy::ssh::Handler as SshHandler;
#[cfg(feature = "tuic")]
use crate::proxy::tuic::Handler as TuicHandler;
#[cfg(feature = "wireguard")]
use crate::proxy::wg::Handler as WireguardHandler;
#[cfg(feature = "shadowquic")]
use crate::proxy::shadowquic::Handler as ShadowQuicHandler;
#[cfg(feature = "tailscale")]
use crate::proxy::tailscale::Handler as TailscaleHandler;
#[cfg(feature = "onion")]
use crate::proxy::tor::Handler as TorHandler;
#[cfg(test)]
use crate::proxy::mocks::MockDummyOutboundHandler as MockHandler;
#[cfg(test)]
use crate::proxy::utils::test_utils::noop::NoopOutboundHandler as NoopHandler;
#[cfg(test)]
use crate::proxy::group::outbound_tests::Leaf as LeafHandler;
#[cfg(test)]
use crate::proxy::utils::dialer_proxy_tests::SpawnedDialer as SpawnedHandler;

use crate::proxy::common::handler_enum;

handler_enum!(ProtocolOutbound, WeakProtocolOutbound, $;
    Direct(DirectHandler),
    Reject(RejectHandler),
    Socks5(Socks5Handler),
    Http(HttpHandler),
    AnyTls(AnyTlsHandler),
    Vmess(VmessHandler),
    Vless(VlessHandler),
    Trojan(TrojanHandler),
    Hysteria2(Hysteria2Handler),
    #[cfg(feature = "shadowsocks")]
    Shadowsocks(ShadowsocksHandler),
    #[cfg(feature = "ssh")]
    Ssh(SshHandler),
    #[cfg(feature = "tuic")]
    Tuic(TuicHandler),
    #[cfg(feature = "wireguard")]
    Wireguard(WireguardHandler),
    #[cfg(feature = "shadowquic")]
    ShadowQuic(ShadowQuicHandler),
    #[cfg(feature = "tailscale")]
    Tailscale(TailscaleHandler),
    #[cfg(feature = "onion")]
    Tor(TorHandler),
    #[cfg(test)]
    Mock(MockHandler),
    #[cfg(test)]
    Noop(NoopHandler),
    #[cfg(test)]
    Leaf(LeafHandler),
    #[cfg(test)]
    Spawned(SpawnedHandler),
);

impl ProtocolOutbound {
    pub fn name(&self) -> &str { dispatch!(self, h, OutboundHandler::name(h.as_ref())) }
    pub fn proto(&self) -> OutboundType { dispatch!(self, h, OutboundHandler::proto(h.as_ref())) }
    pub fn server_name(&self) -> Option<&str> { dispatch!(self, h, OutboundHandler::server_name(h.as_ref())) }
    pub fn support_udp(&self) -> bool { dispatch!(self, h, OutboundHandler::support_udp(h.as_ref())) }
    pub fn support_dialer(&self) -> Option<&str> { dispatch!(self, h, DialWithConnector::support_dialer(h.as_ref())) }
    pub fn dialer_dependency(&self) -> Option<OutboundNode> { dispatch!(self, h, DialWithConnector::dialer_dependency(h.as_ref())) }

    pub async fn connect_stream(&self, sess: &Session, resolver: ThreadSafeDNSResolver) -> io::Result<AnyStream> {
        dispatch!(self, h, OutboundHandler::connect_stream(h.as_ref(), sess, resolver).await)
    }
    pub async fn connect_datagram(&self, sess: &Session, resolver: ThreadSafeDNSResolver) -> io::Result<AnyOutboundDatagram> {
        dispatch!(self, h, OutboundHandler::connect_datagram(h.as_ref(), sess, resolver).await)
    }

    pub async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        match self {
            Self::Direct(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            Self::Reject(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            Self::Socks5(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            Self::Http(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            Self::AnyTls(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            Self::Vmess(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            Self::Vless(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            Self::Trojan(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            Self::Hysteria2(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            #[cfg(feature = "ssh")]
            Self::Ssh(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            #[cfg(feature = "tuic")]
            Self::Tuic(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            #[cfg(feature = "wireguard")]
            Self::Wireguard(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            #[cfg(feature = "shadowquic")]
            Self::ShadowQuic(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            #[cfg(feature = "tailscale")]
            Self::Tailscale(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            #[cfg(feature = "onion")]
            Self::Tor(h) => PlainProxyAPIResponse::as_map(h.as_ref()).await,
            #[cfg(test)]
            _ => HashMap::new(),
        }
    }
}
