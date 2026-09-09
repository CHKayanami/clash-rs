mod enhanced;
pub mod router;

#[cfg(all(target_feature = "crt-static", target_env = "gnu"))]
#[path = "system_static_crt.rs"]
mod system;

#[cfg(not(all(target_feature = "crt-static", target_env = "gnu")))]
#[path = "system.rs"]
mod system;

use std::sync::Arc;

pub use enhanced::EnhancedResolver;
pub use router::RouterResolver;
pub use system::SystemResolver;

use super::{Config, ThreadSafeDNSResolver};
use crate::{
    app::profile::ThreadSafeCacheFile,
    dns::{RuleDispatch, filters::PendingMmdb},
    print_and_exit,
    proxy::utils::OutboundHandlerRegistry,
};

pub async fn new(
    mut cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<PendingMmdb>,
    outbounds: OutboundHandlerRegistry,
    rule_dispatch: Option<Arc<RuleDispatch>>,
    collector: Option<super::ThreadSafeDnsCollector>,
) -> ThreadSafeDNSResolver {
    if let Some(ref d2) = cfg.dns2 {
        if d2.enable {
            let dns2_cfg = cfg.dns2.take().unwrap();
            return Arc::new(
                RouterResolver::new(
                    dns2_cfg,
                    cfg.fw_mark,
                    store,
                    outbounds,
                    collector,
                )
                .await,
            );
        }
    }

    if cfg.enable {
        match store {
            Some(store) => Arc::new(
                EnhancedResolver::new(
                    cfg,
                    store,
                    mmdb,
                    outbounds,
                    rule_dispatch,
                    collector,
                )
                .await,
            ),
            _ => print_and_exit!("enhanced resolver requires cache store"),
        }
    } else {
        Arc::new(
            SystemResolver::new(cfg.ipv6).expect("failed to create system resolver"),
        )
    }
}
