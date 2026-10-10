//! Named dialers resolve the current handler instead of capturing a stale node.

use super::{OutboundNodeRegistry, ProviderRegistry, ProviderSnapshot, RemoteConnector, dialer_route::{self, WeakRoute}};
use crate::{
    app::{dns::ThreadSafeDNSResolver, net::OutboundInterface},
    proxy::{AnyOutboundDatagram, OutboundNode, AnyStream, WeakOutboundNode},
    session::{Network, Session, SocksAddr, Type},
};
use arc_swap::ArcSwap;
use futures::future::BoxFuture;
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, Weak},
};

// Weak handles preserve allocation identity without retaining handler resources
// or forming cycles through cached transport factories.
type DialerPath = Option<Arc<PathEntry>>;

#[derive(Debug)]
struct PathEntry {
    target: WeakOutboundNode,
    name: Arc<str>,
    parent: DialerPath,
    depth: usize,
}

tokio::task_local! {
    static DIALER_PATH: DialerPath;
}

#[derive(Debug, Clone)]
pub struct DialerProxyConnector {
    name: Arc<str>,
    registry: Weak<ArcSwap<HashMap<String, OutboundNode>>>,
    identity: Arc<()>,
    ancestry: DialerPath,
    local: Option<Weak<ArcSwap<ProviderSnapshot>>>,
    route: Option<WeakRoute>,
}

impl DialerProxyConnector {
    pub fn new(name: String, registry: &OutboundNodeRegistry) -> Self {
        Self {
            name: name.into(),
            registry: Arc::downgrade(registry),
            identity: Arc::new(()),
            ancestry: None,
            local: None,
            route: None,
        }
    }

    pub fn with_local(mut self, registry: &ProviderRegistry) -> Self {
        self.local = Some(Arc::downgrade(registry));
        self
    }

    fn handler(&self) -> io::Result<OutboundNode> {
        if let Some(local) = self.local.as_ref().and_then(Weak::upgrade) {
            if let Some(handler) = local.load().entries.get(self.name.as_ref()).cloned() {
                return Ok(handler);
            }
        }
        let registry = self.registry.upgrade().ok_or_else(|| {
            io::Error::other("outbound registry released")
        })?;
        let handler = registry.load().get(self.name.as_ref()).cloned();
        handler.ok_or_else(|| io::Error::other(format!(
            "dialer-proxy {} not available", self.name
        )))
    }

    async fn scoped<T>(
        &self,
        handler: &OutboundNode,
        future: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let parent = DIALER_PATH.try_with(Clone::clone)
            .unwrap_or_else(|_| self.ancestry.clone());
        let target = handler.downgrade();
        let depth = parent.as_ref().map_or(1, |entry| entry.depth + 1);
        let mut cursor = parent.as_deref();
        let mut cyclic = false;
        while let Some(entry) = cursor {
            cyclic |= entry.target.ptr_eq(&target);
            cursor = entry.parent.as_deref();
        }
        if depth > 64 || cyclic {
            let mut names = Vec::new();
            let mut cursor = parent.as_deref();
            while let Some(entry) = cursor {
                names.push(entry.name.as_ref());
                cursor = entry.parent.as_deref();
            }
            names.reverse();
            return Err(io::Error::other(format!(
                "cyclic or too deep dialer-proxy path: {names:?} -> {}", self.name
            )));
        }
        let path = Some(Arc::new(PathEntry { target, name: self.name.clone(), parent, depth }));
        DIALER_PATH.scope(path, future).await
    }
}

impl DialerProxyConnector {
    pub fn outbound_dependency(&self) -> Option<OutboundNode> {
        self.local.as_ref().and_then(Weak::upgrade)
            .and_then(|registry| registry.load().entries.get(self.name.as_ref()).cloned())
    }
    pub fn clone_connector(&self) -> Arc<RemoteConnector> {
        let mut connector = self.clone();
        // Tokio task locals are not inherited by spawned transport workers.
        connector.ancestry = DIALER_PATH.try_with(Clone::clone)
            .unwrap_or_else(|_| self.ancestry.clone());
        connector.route = dialer_route::capture().or_else(|| self.route.clone());
        Arc::new(RemoteConnector::DialerProxy(connector))
    }
    pub fn pool_key(&self) -> usize { Arc::as_ptr(&self.identity) as usize }

    pub fn pool_context(&self) -> String {
        let mut identities = Vec::new();
        let mut cursor = self.ancestry.as_deref();
        while let Some(entry) = cursor {
            identities.push(entry.target.identity());
            cursor = entry.parent.as_deref();
        }
        let route = self.route.as_ref().map(Weak::as_ptr);
        format!("{identities:?}:{route:?}")
    }

    pub fn connect_stream<'a>(
        &'a self, resolver: ThreadSafeDNSResolver, address: &'a str, port: u16,
        _tfo: bool, iface: Option<&'a OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> BoxFuture<'a, io::Result<AnyStream>> {
        Box::pin(dialer_route::scoped(self.route.as_ref(), async move {
            let handler = dialer_route::target(self.pool_key(), || self.handler())?;
            let sess = Session {
                network: Network::Tcp, typ: Type::Ignore,
                destination: SocksAddr::Domain(address.into(), port),
                iface: iface.cloned(),
                #[cfg(target_os = "linux")]
                so_mark: packet_mark,
                ..Default::default()
            };
            // Normal dialing honors the selected node's own dialer-proxy, allowing
            // arbitrary multi-hop chains without overriding its configured route.
            self.scoped(&handler, handler.connect_stream(&sess, resolver)).await

        }))
    }

    pub fn connect_datagram<'a>(
        &'a self, resolver: ThreadSafeDNSResolver, src: Option<SocketAddr>,
        destination: SocksAddr, iface: Option<&'a OutboundInterface>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> BoxFuture<'a, io::Result<AnyOutboundDatagram>> {
        Box::pin(dialer_route::scoped(self.route.as_ref(), async move {
            let handler = dialer_route::target(self.pool_key(), || self.handler())?;
            let sess = Session {
                network: Network::Udp, typ: Type::Ignore, destination,
                source: src.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
                iface: iface.cloned(),
                #[cfg(target_os = "linux")]
                so_mark: packet_mark,
                ..Default::default()
            };
            self.scoped(&handler, handler.connect_datagram(&sess, resolver)).await

        }))
    }
}

#[cfg(test)]
#[path = "dialer_context_tests.rs"]
mod context_tests;
