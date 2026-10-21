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
    Error,
    proxy::utils::OutboundNodeRegistry,
};

pub async fn new(
    mut cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<PendingMmdb>,
    outbounds: OutboundNodeRegistry,
    rule_dispatch: Option<Arc<RuleDispatch>>,
) -> Result<ThreadSafeDNSResolver, Error> {
    if let Some(ref d2) = cfg.dns2 {
        if d2.enable {
            let dns2_cfg = cfg.dns2.take().unwrap();
            let store = store.filter(|_| cfg.store_fake_ip);
            return Ok(Arc::new(
                RouterResolver::new(
                    dns2_cfg,
                    cfg.fw_mark,
                    store,
                    outbounds,
                )
                .await?,
            ));
        }
    }

    if cfg.enable {
        let store = store.ok_or_else(|| Error::InvalidConfig(
            "enhanced resolver requires cache store".into(),
        ))?;
        Ok(Arc::new(EnhancedResolver::new(
            cfg, store, mmdb, outbounds, rule_dispatch,
        ).await))
    } else {
        let resolver = SystemResolver::new(cfg.ipv6)
            .map_err(|error| Error::DNSError(error.to_string()))?;
        Ok(Arc::new(resolver))
    }
}

#[cfg(test)]
mod tests;
