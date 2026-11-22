use std::net::IpAddr;
use bytes::Bytes;

use async_trait::async_trait;
use tracing::{error, info};
use clash_dns::{
    DNSListenAddr, DNSError, DnsIngress,
    DnsMessageExchanger as ServerMessageExchanger, get_dns_listener,
};
use super::query::IngressProfile;

use super::ThreadSafeDNSResolver;
use crate::runner::{AsyncService, ServiceContext};

mod handler;
pub use handler::exchange_with_resolver;

#[derive(Clone)]
struct DnsMessageExchanger {
    resolver: ThreadSafeDNSResolver,
}

impl ServerMessageExchanger for DnsMessageExchanger {
    fn ipv6(&self) -> bool {
        self.resolver.ipv6()
    }

    async fn exchange(
        &self,
        message: Bytes,
        source_ip: Option<IpAddr>,
        ingress: DnsIngress,
    ) -> Result<Vec<u8>, DNSError> {
        let profile = match ingress {
            DnsIngress::Udp => IngressProfile::Udp { advertised_size: 512 },
            DnsIngress::Tcp | DnsIngress::Dot | DnsIngress::Doh | DnsIngress::Doh3 => IngressProfile::Tcp,
        };
        exchange_with_resolver(&self.resolver, message, profile, source_ip).await
    }
}

pub struct DnsRunner {
    enable: bool,
    listen: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
}

impl DnsRunner {
    pub fn new(
        enable: bool,
        listen: DNSListenAddr,
        resolver: ThreadSafeDNSResolver,
    ) -> Self {
        Self {
            enable,
            listen,
            resolver,
        }
    }
}

#[async_trait]
impl AsyncService for DnsRunner {
    async fn start(&self, ctx: &ServiceContext) -> Result<(), crate::Error> {
        if !self.enable || self.listen.is_empty() {
            return Ok(());
        }

        let exchanger = DnsMessageExchanger {
            resolver: self.resolver.clone(),
        };
        let cancel = ctx.cancellation_token().clone();

        let mut listener_fut =
            match get_dns_listener(self.listen.clone(), exchanger).await {
                Ok(fut) => fut,
                Err(e) => {
                    error!("failed to start DNS server: {}", e);
                    return Err(crate::Error::DNSServerError(e));
                }
            };

        info!("DNS server started");
        ctx.spawn_critical("dns_server", async move {
            tokio::select! {
                _ = &mut listener_fut => {},
                _ = cancel.cancelled() => {
                    info!("DNS server is cancelled");
                }
            }
            listener_fut.shutdown().await;
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;
    use crate::app::dns::MockClashResolver;

    #[tokio::test]
    async fn enabled_resolver_without_listeners_does_not_spawn_server() {
        let ctx = ServiceContext::new(CancellationToken::new());
        let runner = DnsRunner::new(
            true,
            DNSListenAddr::default(),
            Arc::new(MockClashResolver::new()),
        );
        runner.start(&ctx).await.unwrap();
        assert_eq!(ctx.tracker().len(), 0);
        runner.stop().await.unwrap();
    }
}
