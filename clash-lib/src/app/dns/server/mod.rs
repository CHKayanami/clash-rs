use async_trait::async_trait;
use tracing::{error, info, instrument};
use watfaq_dns::DNSListenAddr;

use super::ThreadSafeDNSResolver;
use crate::runner::{AsyncService, ServiceContext};

mod handler;
pub use handler::exchange_with_resolver;

#[derive(Clone)]
struct DnsMessageExchanger {
    resolver: ThreadSafeDNSResolver,
}

impl watfaq_dns::DnsMessageExchanger for DnsMessageExchanger {
    fn ipv6(&self) -> bool {
        self.resolver.ipv6()
    }

    #[instrument(skip(self))]
    async fn exchange(
        &self,
        message: &[u8],
    ) -> Result<Vec<u8>, watfaq_dns::DNSError> {
        exchange_with_resolver(&self.resolver, message, true).await
    }
}

pub struct DnsRunner {
    enable: bool,
    listener: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
    #[allow(dead_code)]
    cwd: std::path::PathBuf,
    cancellation_token: tokio_util::sync::CancellationToken,
}

impl DnsRunner {
    pub fn new(
        enable: bool,
        listen: DNSListenAddr,
        resolver: ThreadSafeDNSResolver,
        cwd: &std::path::Path,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            enable,
            listener: listen,
            resolver,
            cwd: cwd.to_path_buf(),
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
        if !self.enable {
            return Ok(());
        }

        let exchanger = DnsMessageExchanger {
            resolver: self.resolver.clone(),
        };
        let listener = self.listener.clone();
        let cancellation_token = self.cancellation_token.clone();
        let child_cancel = cancellation_token.child_token();

        let listener_fut =
            match watfaq_dns::get_dns_listener(listener, exchanger).await {
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
                    _ = listener_fut => {},
                    _ = child_cancel.cancelled() => {
                        info!("DNS server is cancelled");
                    }
                }
            },
        );

        Ok(())
    }

    async fn stop(&self) -> Result<(), crate::Error> {
        self.shutdown();
        Ok(())
    }
}
