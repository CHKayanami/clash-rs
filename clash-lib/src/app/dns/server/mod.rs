use std::net::IpAddr;
use bytes::Bytes;

use async_trait::async_trait;
use tracing::{error, info};
use clash_dns::{DNSError, DnsIngress, DnsMessageExchanger as ServerMessageExchanger, PreparedDnsListener};
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
    listener: PreparedDnsListener,
    resolver: ThreadSafeDNSResolver,
    cancellation_token: tokio_util::sync::CancellationToken,
}

impl DnsRunner {
    pub fn new(
        enable: bool,
        listen: PreparedDnsListener,
        resolver: ThreadSafeDNSResolver,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            enable,
            listener: listen,
            resolver,
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }

    pub fn shutdown(&self) {
        self.cancellation_token.cancel();
    }
}

#[async_trait]
impl AsyncService for DnsRunner {
    async fn start(&self, ctx: &ServiceContext) -> Result<(), crate::Error> {
        if !self.enable || self.listener.is_empty() {
            return Ok(());
        }

        let exchanger = DnsMessageExchanger {
            resolver: self.resolver.clone(),
        };
        let cancellation_token = self.cancellation_token.clone();
        let child_cancel = cancellation_token.child_token();

        let mut listener_fut =
            match self.listener.bind(exchanger).await {
                Ok(fut) => fut,
                Err(e) => {
                    error!("failed to start DNS server: {}", e);
                    return Err(crate::Error::DNSServerError(e));
                }
            };

        info!("DNS server started");
        ctx.spawn_critical_with_token(
            "dns_server",
            cancellation_token,
            async move {
                tokio::select! {
                    _ = &mut listener_fut => {},
                    _ = child_cancel.cancelled() => {
                        info!("DNS server is cancelled");
                    }
                }
                listener_fut.shutdown().await;
            },
        );

        Ok(())
    }

    async fn stop(&self) -> Result<(), crate::Error> {
        self.shutdown();
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
            true, PreparedDnsListener::default(), Arc::new(MockClashResolver::new()), None,
        );
        runner.start(&ctx).await.unwrap();
        assert_eq!(ctx.tracker().len(), 0);
        runner.stop().await.unwrap();
    }
}
