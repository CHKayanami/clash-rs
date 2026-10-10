use std::{
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock},
};

use super::{DialerProxyConnector, dial_tcp_with_happy_eyeballs, new_udp_socket};
#[cfg(test)]
use crate::proxy::{socks::outbound::dialer_tests::RecordingConnector, anytls::tests::retry::CountingConnector};
use crate::{
    app::{
        dns::ThreadSafeDNSResolver,
        net::OutboundInterface,
    },
    proxy::{
        AnyOutboundDatagram, OutboundNode, AnyStream,
        direct::datagram::OutboundDatagramImpl,
    },
    session::SocksAddr,
};

/// Static dispatch for direct transport and named dialer routes.
#[derive(Debug, Clone)]
pub enum RemoteConnector {
    Direct,
    DialerProxy(DialerProxyConnector),
    #[cfg(test)]
    Recording(Arc<RecordingConnector>),
    #[cfg(test)]
    Counting(Arc<CountingConnector>),
}

impl RemoteConnector {
    pub fn outbound_dependency(&self) -> Option<OutboundNode> {
        match self { Self::DialerProxy(connector) => connector.outbound_dependency(), _ => None }
    }

    pub fn clone_connector(&self) -> Arc<Self> {
        match self {
            Self::Direct => GLOBAL_DIRECT_CONNECTOR.clone(),
            Self::DialerProxy(connector) => connector.clone_connector(),
            #[cfg(test)]
            Self::Recording(_) | Self::Counting(_) => Arc::new(self.clone()),
        }
    }

    pub fn pool_key(&self) -> usize {
        match self {
            Self::Direct => 0,
            Self::DialerProxy(connector) => connector.pool_key(),
            #[cfg(test)]
            Self::Recording(connector) => Arc::as_ptr(connector) as usize,
            #[cfg(test)]
            Self::Counting(connector) => Arc::as_ptr(connector) as usize,
        }
    }

    pub fn pool_context(&self) -> String {
        match self { Self::DialerProxy(connector) => connector.pool_context(), _ => String::new() }
    }

    pub async fn connect_stream(
        &self, resolver: ThreadSafeDNSResolver, address: &str, port: u16,
        tfo: bool, iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> io::Result<AnyStream> {
        match self {
            Self::Direct => DirectConnector.connect_stream(resolver, address, port, tfo, iface,
                #[cfg(target_os = "linux")] packet_mark,
            ).await,
            Self::DialerProxy(connector) => connector.connect_stream(resolver, address, port, tfo, iface,
                #[cfg(target_os = "linux")] packet_mark,
            ).await,
            #[cfg(test)]
            Self::Recording(connector) => connector.connect_stream(resolver, address, port, tfo, iface,
                #[cfg(target_os = "linux")] packet_mark,
            ).await,
            #[cfg(test)]
            Self::Counting(connector) => connector.connect_stream(resolver, address, port, tfo, iface,
                #[cfg(target_os = "linux")] packet_mark,
            ).await,
        }
    }

    pub async fn connect_datagram(
        &self, resolver: ThreadSafeDNSResolver, src: Option<SocketAddr>,
        destination: SocksAddr, iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> io::Result<AnyOutboundDatagram> {
        match self {
            Self::Direct => DirectConnector.connect_datagram(resolver, src, destination, iface,
                #[cfg(target_os = "linux")] packet_mark,
            ).await,
            Self::DialerProxy(connector) => connector.connect_datagram(resolver, src, destination, iface,
                #[cfg(target_os = "linux")] packet_mark,
            ).await,
            #[cfg(test)]
            Self::Recording(connector) => connector.connect_datagram(resolver, src, destination, iface,
                #[cfg(target_os = "linux")] packet_mark,
            ).await,
            #[cfg(test)]
            Self::Counting(connector) => connector.connect_datagram(resolver, src, destination, iface,
                #[cfg(target_os = "linux")] packet_mark,
            ).await,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirectConnector;

pub static GLOBAL_DIRECT_CONNECTOR: LazyLock<Arc<RemoteConnector>> =
    LazyLock::new(global_direct_connector);

fn global_direct_connector() -> Arc<RemoteConnector> {
    Arc::new(RemoteConnector::Direct)
}

impl DirectConnector {
    pub async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        tfo: bool,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        dial_tcp_with_happy_eyeballs(
            address,
            port,
            &resolver,
            iface,
            tfo,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await
    }

    pub async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<&OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let dgram = new_udp_socket(
            src,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
            destination
                .ip()
                .map(|ip| SocketAddr::new(ip, destination.port())),
        )
        .await
        .map(|x| OutboundDatagramImpl::new(x, resolver))?;

        Ok(AnyOutboundDatagram::Udp(Box::new(dgram)))
    }
}
