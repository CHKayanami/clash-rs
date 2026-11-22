use async_trait::async_trait;
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    Error,
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::def::EbpfConfig,
    proxy::ebpf::EbpfInbound,
    runner::{AsyncService, ServiceContext},
};

pub struct EbpfRunner {
    cfg: EbpfConfig,
    dispatcher: Arc<Dispatcher>,
    dns_resolver: ThreadSafeDNSResolver,
}

impl EbpfRunner {
    pub fn new(
        cfg: EbpfConfig,
        dispatcher: Arc<Dispatcher>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> Self {
        Self {
            cfg,
            dispatcher,
            dns_resolver,
        }
    }
}

#[async_trait]
impl AsyncService for EbpfRunner {
    async fn start(&self, ctx: &ServiceContext) -> Result<(), Error> {
        if !self.cfg.enable {
            info!("ebpf is disabled, skipping");
            return Ok(());
        }

        info!("starting eBPF inbound runner");
        let inbound = EbpfInbound::start(
            self.cfg.clone(),
            self.dispatcher.clone(),
            self.dns_resolver.clone(),
        )
        .await
        .map_err(|e| {
            Error::Operation(format!("failed to init ebpf inbound: {e}"))
        })?;

        let cancel = ctx.cancellation_token().clone();
        ctx.spawn_critical("ebpf_inbound", async move {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("eBPF inbound cancelled, shutting down");
                }
                _ = inbound.run_tcp() => {
                    error!("eBPF TCP inbound unexpectedly terminated");
                }
                _ = inbound.run_udp() => {
                    error!("eBPF UDP inbound unexpectedly terminated");
                }
            }
            inbound.stop().await;
        });

        Ok(())
    }
}
