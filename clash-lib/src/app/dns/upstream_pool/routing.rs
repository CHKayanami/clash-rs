//! DNS operations run inside the common outbound group executor.
use futures::future::BoxFuture;
use std::{future::Future, io, net::SocketAddr, sync::Arc};
use crate::{
    app::dns::{endpoint::DnsProtocol, query::QueryContext, transport::UdpPool},
    proxy::{OutboundNode, ProtocolOperation, ProtocolOutbound},
    session::{Network, Session, SocksAddr, Type},
};
use super::{UpstreamPool, entries::UpstreamEntry, routes::ResolvedOutbound, selection::SelectionCache};

struct QueryOperation<'a> {
    pool: &'a UpstreamPool,
    entry: &'a UpstreamEntry,
    query: &'a QueryContext,
}
impl ProtocolOperation for QueryOperation<'_> {
    type Output = Vec<u8>;
    fn execute<'a>(&'a self, handler: &'a ProtocolOutbound, _sess: &'a Session)
        -> impl Future<Output = io::Result<Self::Output>> + Send + 'a
    {
        async move {
            let outbound = ResolvedOutbound::protocol(handler);
            self.pool.query_selected(self.entry, self.query, &outbound).await
                .map_err(io::Error::other)
        }
    }
}

struct UdpOperation<'a> {
    pool: &'a UpstreamPool,
    entry: &'a UpstreamEntry,
    address: SocketAddr,
}
impl ProtocolOperation for UdpOperation<'_> {
    type Output = Arc<UdpPool>;
    fn execute<'a>(&'a self, handler: &'a ProtocolOutbound, _sess: &'a Session)
        -> impl Future<Output = io::Result<Self::Output>> + Send + 'a
    {
        async move {
            self.pool.udp_pool_selected(self.entry, self.address,
                &ResolvedOutbound::protocol(handler),
            ).await.map_err(io::Error::other)
        }
    }
}

impl UpstreamPool {
    fn routing_session(&self, entry: &UpstreamEntry, network: Network) -> anyhow::Result<Session> {
        Ok(Session {
            network,
            typ: Type::Ignore,
            destination: SocksAddr::try_from((entry.endpoint.host.clone(), entry.endpoint.port))?,
            iface: entry.interface.clone().or_else(|| self.default_interface.clone()),
            so_mark: self.fw_mark,
            ..Default::default()
        })
    }

    async fn selected_outbound(&self, entry: &UpstreamEntry, outbound_name: Option<&str>,
        network: Network,
    ) -> anyhow::Result<ResolvedOutbound> {
        let route = self.resolve_outbound(entry, outbound_name).await?;
        let Some(node) = route.handler() else { return Ok(route); };
        if !node.as_group().is_some_and(|group| group.stable_selection()) {
            if network == Network::Udp
                && node.as_protocol().is_some_and(|handler| !handler.support_udp())
            {
                anyhow::bail!("DNS outbound '{}' does not support UDP", node.name());
            }
            return Ok(route);
        }
        let cached = self.selections.get(&route.key, || SelectionCache::new(node.clone()));
        let selection = cached.get().await?;
        if network == Network::Udp && !selection.udp_allowed {
            anyhow::bail!("DNS outbound '{}' does not support UDP", node.name());
        }
        cached.attach(&entry.state);
        Ok(ResolvedOutbound::selected(selection.node.as_ref().expect("valid DNS selection")))
    }

    pub(super) async fn query_entry_inner(
        &self, entry: &UpstreamEntry, query: &QueryContext, outbound_name: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let network = match entry.protocol {
            DnsProtocol::Udp | DnsProtocol::Quic | DnsProtocol::H3 => Network::Udp,
            _ => Network::Tcp,
        };
        let route = self.selected_outbound(entry, outbound_name, network).await?;
        if let Some(node) = route.handler().filter(|node| node.as_group().is_some()) {
            return self.query_group(entry, query, node, network).await;
        }
        self.query_selected(entry, query, &route).await
    }

    fn query_group<'a>(
        &'a self, entry: &'a UpstreamEntry, query: &'a QueryContext,
        node: &'a OutboundNode, network: Network,
    ) -> BoxFuture<'a, anyhow::Result<Vec<u8>>> {
        Box::pin(async move {
            let sess = self.routing_session(entry, network)?;
            Ok(node.execute_protocol(&sess, QueryOperation { pool: self, entry, query }).await?)
        })
    }

    fn udp_pool_group<'a>(
        &'a self, entry: &'a UpstreamEntry, address: SocketAddr, node: &'a OutboundNode,
    ) -> BoxFuture<'a, anyhow::Result<Arc<UdpPool>>> {
        Box::pin(async move {
            let mut sess = self.routing_session(entry, Network::Udp)?;
            sess.destination = address.into();
            Ok(node.execute_protocol(&sess, UdpOperation { pool: self, entry, address }).await?)
        })
    }

    pub async fn udp_pool(
        &self, entry: &UpstreamEntry, address: SocketAddr, outbound_name: Option<&str>,
    ) -> anyhow::Result<Arc<UdpPool>> {
        let _permit = self.admit_query().await?;
        let route = self.selected_outbound(entry, outbound_name, Network::Udp).await?;
        if let Some(node) = route.handler().filter(|node| node.as_group().is_some()) {
            return self.udp_pool_group(entry, address, node).await;
        }
        self.udp_pool_selected(entry, address, &route).await
    }
}
