use async_trait::async_trait;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    Error,
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::def::EbpfConfig,
    proxy::{ebpf::EbpfInbound, inbound::InboundHandlerTrait},
    runner::{AsyncService, ServiceContext, prepare_service},
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

        let mut inbound = EbpfInbound::new(
            self.cfg.clone(),
            self.dispatcher.clone(),
            self.dns_resolver.clone(),
        );
        let cancel = self.cancellation_token.clone();
        let lifecycle_token = cancel.clone();

        info!("starting eBPF inbound runner");
        inbound.init().await.map_err(|e| {
            crate::Error::Operation(format!("failed to init ebpf inbound: {e}"))
        })?;
        let inbound = Arc::new(inbound);

        let initialized = async {
            let tcp_inbound = inbound.clone();
            let tcp = prepare_service(move |ready| async move {
                tcp_inbound.listen_tcp(ready).await.map_err(Error::from)
            }).await?;
            let udp_inbound = inbound.clone();
            let udp = prepare_service(move |ready| async move {
                udp_inbound.listen_udp(ready).await.map_err(Error::from)
            }).await?;
            Ok::<_, Error>((tcp, udp))
        }.await;
        let (tcp, udp) = match initialized {
            Ok(listeners) => listeners,
            Err(e) => {
                inbound.stop().await;
                return Err(e);
            }
        };
        ctx.spawn_critical_with_token("ebpf_inbound", lifecycle_token, async move {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("eBPF inbound cancelled, shutting down");
                }
                result = futures::future::try_join(tcp, udp) => {
                    error!("eBPF inbound unexpectedly terminated: {result:?}");
                }
            }
            inbound.stop().await;
        });

        Ok(())
    }

    async fn stop(&self) -> Result<(), crate::Error> {
        self.shutdown();
        Ok(())
    }
}
