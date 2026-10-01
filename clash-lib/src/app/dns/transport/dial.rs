use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::app::dns::ClashResolver;
use crate::app::dns::endpoint::DnsEndpoint;
use crate::app::net::OutboundInterface;
use crate::config::proxy::PROXY_DIRECT;
use crate::proxy::{AnyOutboundHandler, AnyStream, OutboundHandler};
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
    pub(super) async fn dial_udp(
        &self,
        address: SocketAddr,
    ) -> anyhow::Result<crate::proxy::AnyOutboundDatagram> {
        let outbound = self
            .outbound
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing UDP DNS outbound"))?;
        if !outbound.support_udp().await {
            anyhow::bail!("DNS outbound '{}' does not support UDP", outbound.name());
        }
        let source = if address.is_ipv6() {
            SocketAddr::from(([0; 16], 0))
        } else {
            SocketAddr::from(([0; 4], 0))
        };
        let session = Session {
            source,
            network: Network::Udp,
            typ: Type::Ignore,
            destination: address.into(),
            so_mark: self.so_mark,
            iface: self.iface.clone(),
            ..Default::default()
        };
        let resolver = match &self.resolver {
            Some(resolver) => Arc::clone(resolver),
            None => Arc::new(crate::app::dns::SystemResolver::new(false)?),
        };
        Ok(outbound.connect_datagram(&session, resolver).await?)
    }

    pub async fn dial_tcp(&self) -> anyhow::Result<AnyStream> {
        let deadline = tokio::time::Instant::now() + self.dial_timeout;
        self.dial_tcp_until(deadline).await
    }

    pub async fn dial_tcp_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<AnyStream> {
        let addresses =
            tokio::time::timeout_at(deadline, self.endpoint.resolve_addrs())
                .await
                .map_err(|_| {
                    anyhow::anyhow!("DNS dial address resolution timed out")
                })??;

        let resolver = match &self.resolver {
            Some(resolver) => Arc::clone(resolver),
            None => Arc::new(crate::app::dns::SystemResolver::new(false)?),
        };

        let result =
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
                        tokio::time::timeout(
                            timeout,
                            outbound.connect_stream(&sess, resolver),
                        )
                        .await??
                    } else {
                        let direct =
                            crate::proxy::direct::Handler::new(PROXY_DIRECT);
                        tokio::time::timeout(
                            timeout,
                            direct.connect_stream(&sess, resolver),
                        )
                        .await??
                    };
                    Ok(stream)
                }
            })
            .await;
        if result.is_err() {
            self.endpoint.invalidate_addresses();
        }
        result
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
        let remaining =
            deadline.saturating_duration_since(tokio::time::Instant::now());
        let candidates_left =
            u32::try_from(candidate_count - index).unwrap_or(u32::MAX);
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
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("{label} resolved to no addresses")))
}

/// Create a bound, nonblocking UDP socket using the same interface binding as proxy dials.
pub(crate) fn direct_udp_socket(
    address: SocketAddr,
    iface: Option<&OutboundInterface>,
    so_mark: Option<u32>,
) -> anyhow::Result<std::net::UdpSocket> {
    let domain = socket2::Domain::for_address(address);
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    if let Some(mark) = so_mark {
        socket.set_mark(mark)?;
    }
    #[cfg(not(target_os = "linux"))]
    if so_mark.is_some() {
        anyhow::bail!("DNS fw_mark is only supported on Linux");
    }
    if let Some(iface) = iface {
        crate::proxy::utils::must_bind_socket_on_interface(&socket, iface, domain)?;
    }
    let bind_addr = if address.is_ipv6() {
        SocketAddr::from(([0; 16], 0))
    } else {
        SocketAddr::from(([0; 4], 0))
    };
    socket.bind(&bind_addr.into())?;
    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::{
        MockClashResolver,
        endpoint::{DnsProtocol, DnsStrategy},
    };

    #[tokio::test]
    async fn failed_tcp_candidates_invalidate_shared_bootstrap_cache() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut bootstrap = MockClashResolver::new();
        bootstrap
            .expect_resolve_v4()
            .times(2)
            .returning(|_, _| Ok(Some(std::net::Ipv4Addr::LOCALHOST)));
        bootstrap
            .expect_resolve_v6()
            .times(2)
            .returning(|_, _| Ok(None));
        let endpoint = DnsEndpoint::parse(
            &format!("dns.example:{port}"),
            DnsProtocol::Tcp,
            None,
            Some(Arc::new(bootstrap)),
            DnsStrategy::PreferIpv4,
        )
        .unwrap();
        let cloned = endpoint.clone();
        let dial = DialContext {
            endpoint,
            query_timeout: Duration::from_secs(1),
            dial_timeout: Duration::from_secs(1),
            outbound: None,
            iface: None,
            so_mark: None,
            resolver: None,
        };
        assert!(dial.dial_tcp().await.is_err());
        assert_eq!(
            cloned.resolve_addrs().await.unwrap(),
            vec![SocketAddr::from(([127, 0, 0, 1], port))]
        );
    }
}
