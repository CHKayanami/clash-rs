use async_trait::async_trait;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::def::EbpfConfig,
    proxy::{ebpf::EbpfInbound, inbound::InboundHandlerTrait},
    runner::{AsyncService, ServiceContext},
};

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

    pub fn shutdown(&self) {
        self.cancellation_token.cancel();
    }
}

#[async_trait]
impl AsyncService for EbpfRunner {
    async fn start(&self, ctx: &ServiceContext) -> Result<(), crate::Error> {
        if !self.cfg.enable {
            info!("ebpf is disabled, skipping");
            return Ok(());
        }

        let inbound = Arc::new(EbpfInbound::new(
            self.cfg.clone(),
            self.dispatcher.clone(),
            self.dns_resolver.clone(),
        ));
        let cancel = self.cancellation_token.clone();
        let lifecycle_token = cancel.clone();

        info!("starting eBPF inbound runner");
        inbound.init().await.map_err(|e| {
            crate::Error::Operation(format!("failed to init ebpf inbound: {e}"))
        })?;

        ctx.spawn_critical_with_token("ebpf_inbound", lifecycle_token, async move {
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

        Ok(())
    }

    async fn stop(&self) -> Result<(), crate::Error> {
        self.shutdown();
        Ok(())
    }
}
