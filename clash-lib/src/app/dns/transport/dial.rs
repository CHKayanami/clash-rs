use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::app::dispatcher::BoxedChainedStream;
use crate::app::dns::ClashResolver;
use crate::app::dns::endpoint::DnsEndpoint;
use crate::app::net::OutboundInterface;
use crate::config::proxy::PROXY_DIRECT;
use crate::proxy::{AnyOutboundHandler, OutboundHandler};
use crate::session::{Network, Session, Type};

/// Shared dial context for transports that may go direct or via a proxy handler.
#[derive(Clone)]
pub struct DialContext {
    pub endpoint: DnsEndpoint,
    pub query_timeout: Duration,
    pub dial_timeout: Duration,
    pub outbound: Option<AnyOutboundHandler>,
    pub iface: Option<OutboundInterface>,
    pub so_mark: Option<u32>,
    pub resolver: Option<Arc<dyn ClashResolver>>,
}

impl DialContext {
    pub async fn dial_tcp(&self) -> anyhow::Result<BoxedChainedStream> {
        let deadline = tokio::time::Instant::now() + self.dial_timeout;
        self.dial_tcp_until(deadline).await
    }

    pub async fn dial_tcp_until(&self, deadline: tokio::time::Instant) -> anyhow::Result<BoxedChainedStream> {
        let addresses = tokio::time::timeout_at(deadline, self.endpoint.resolve_addrs())
            .await
            .map_err(|_| anyhow::anyhow!("DNS dial address resolution timed out"))??;

        let resolver = self
            .resolver
            .clone()
            .unwrap_or_else(|| Arc::new(crate::app::dns::SystemResolver::new(false).unwrap()));

        dial_candidates(addresses, deadline, "TCP", |address, timeout| {
            let this = self.clone();
            let resolver = resolver.clone();
            async move {
                let src: SocketAddr = if address.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };
                let sess = Session {
                    source: src,
                    network: Network::Tcp,
                    typ: Type::Ignore,
                    destination: address.into(),
                    so_mark: this.so_mark,
                    iface: this.iface.clone(),
                    ..Default::default()
                };

                let stream = if let Some(ref outbound) = this.outbound {
                    tokio::time::timeout(timeout, outbound.connect_stream(&sess, resolver)).await??
                } else {
                    let direct = crate::proxy::direct::Handler::new(PROXY_DIRECT);
                    tokio::time::timeout(timeout, direct.connect_stream(&sess, resolver)).await??
                };
                Ok(stream)
            }
        })
        .await
    }
}

/// Try candidates in order, sharing the remaining aggregate time equally
/// among the attempts that have not started yet.
pub async fn dial_candidates<T, F, Fut>(
    addresses: Vec<SocketAddr>,
    deadline: tokio::time::Instant,
    label: &str,
    mut dial: F,
) -> anyhow::Result<T>
where
    F: FnMut(SocketAddr, Duration) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let candidate_count = addresses.len();
    let mut last_error = None;
    for (index, address) in addresses.into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let candidates_left = u32::try_from(candidate_count - index).unwrap_or(u32::MAX);
        let budget = remaining / candidates_left;
        let error = match tokio::time::timeout(budget, dial(address, budget)).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(error)) => error,
            Err(_) => anyhow::anyhow!("timed out after {budget:?}"),
        };
        tracing::debug!(
            %address,
            transport = label,
            error = %error,
            "DNS dial failed; trying next address"
        );
        last_error = Some(anyhow::anyhow!("{label} dial to {address}: {error}"));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{label} resolved to no addresses")))
}
