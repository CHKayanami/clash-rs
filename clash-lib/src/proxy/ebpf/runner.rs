use crate::app::dispatcher::Dispatcher;
use crate::app::dns::ThreadSafeDNSResolver;
use crate::config::def::EbpfConfig;
use crate::proxy::ebpf::EbpfInbound;
use crate::proxy::inbound::InboundHandlerTrait;
use crate::runner::Runner;
use futures::future::BoxFuture;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub struct EbpfRunner {
    cfg: EbpfConfig,
    dispatcher: Arc<Dispatcher>,
    dns_resolver: ThreadSafeDNSResolver,
    cancellation_token: CancellationToken,
}

impl EbpfRunner {
    pub fn new(
        cfg: EbpfConfig,
        dispatcher: Arc<Dispatcher>,
        dns_resolver: ThreadSafeDNSResolver,
        cancellation_token: Option<CancellationToken>,
    ) -> Self {
        Self {
            cfg,
            dispatcher,
            dns_resolver,
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }
}

impl Runner for EbpfRunner {
    fn run_async(&self) {
        if !self.cfg.enable {
            info!("ebpf is disabled, skipping");
            return;
        }

        let inbound = Arc::new(EbpfInbound::new(
            self.cfg.clone(),
            self.dispatcher.clone(),
            self.dns_resolver.clone(),
        ));
        let cancel = self.cancellation_token.clone();

        tokio::spawn(async move {
            info!("starting eBPF inbound runner");
            let inbound_tcp = inbound.clone();
            let mut tcp_task = tokio::spawn(async move {
                if let Err(err) = inbound_tcp.listen_tcp().await {
                    error!("eBPF TCP inbound error: {err}");
                }
            });

            let inbound_udp = inbound.clone();
            let mut udp_task = tokio::spawn(async move {
                if let Err(err) = inbound_udp.listen_udp().await {
                    error!("eBPF UDP inbound error: {err}");
                }
            });

            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("eBPF inbound cancelled, shutting down");
                    tcp_task.abort();
                    udp_task.abort();
                    inbound.stop().await;
                }
                _ = &mut tcp_task => {}
                _ = &mut udp_task => {}
            }

        });

    }

    fn shutdown(&self) {
        self.cancellation_token.cancel();
    }

    fn join(&self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move { Ok(()) })
    }
}
