use futures::future::BoxFuture;
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tracing::{error, info, instrument};
use watfaq_dns::DNSListenAddr;

use crate::runner::Runner;
use super::ThreadSafeDNSResolver;

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
    task_handle: Mutex<Option<JoinHandle<()>>>,
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
            task_handle: Mutex::new(None),
        }
    }
}

impl Runner for DnsRunner {
    fn run_async(&self) {
        if !self.enable {
            return;
        }

        let exchanger = DnsMessageExchanger {
            resolver: self.resolver.clone(),
        };
        let listener = self.listener.clone();
        let cancellation_token = self.cancellation_token.clone();

        let handle = tokio::spawn(async move {
            match watfaq_dns::get_dns_listener(listener, exchanger).await {
                Ok(listener_fut) => {
                    info!("DNS server started");
                    tokio::select! {
                        _ = listener_fut => {},
                        _ = cancellation_token.cancelled() => {
                            info!("DNS server is cancelled");
                        }
                    }
                }
                Err(e) => {
                    error!("failed to start DNS server: {}", e);
                }
            }
        });
        *self.task_handle.lock() = Some(handle);
    }

    fn shutdown(&self) {
        self.cancellation_token.cancel();
    }

    fn join(&self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move {
            let handle = self.task_handle.lock().take();
            if let Some(h) = handle {
                let _ = h.await;
            }
            Ok(())
        })
    }
}
