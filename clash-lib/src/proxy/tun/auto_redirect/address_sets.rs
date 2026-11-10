use std::{collections::HashMap, sync::Arc};

use tokio::sync::watch::{self, Receiver, Sender};
use tracing::warn;

use crate::{
    Error,
    app::remote_content_manager::providers::rule_provider::{
        ThreadSafeRuleProvider,
    },
    config::internal::config::TunConfig,
};
use super::AutoRedirect;

#[derive(Clone)]
pub(in crate::proxy::tun) struct RouteAddressSets {
    include: Vec<ThreadSafeRuleProvider>,
    exclude: Vec<ThreadSafeRuleProvider>,
    updates: Arc<Sender<u64>>,
}

impl RouteAddressSets {
    pub fn new(cfg: &TunConfig, registry: &HashMap<String, ThreadSafeRuleProvider>) -> Result<Self, Error> {
        fn resolve(names: &[String], field: &str, registry: &HashMap<String, ThreadSafeRuleProvider>)
            -> Result<Vec<ThreadSafeRuleProvider>, Error>
        {
            names.iter().map(|name| {
                let provider = registry.get(name).ok_or_else(|| Error::InvalidConfig(
                    format!("tun.{field}: rule-provider '{name}' does not exist"),
                ))?;
                Ok(provider.clone())
            }).collect()
        }
        let include = resolve(&cfg.route_address_set, "route-address-set", registry)?;
        let exclude = resolve(&cfg.route_exclude_address_set, "route-exclude-address-set", registry)?;
        let updates = Arc::new(watch::channel(0u64).0);
        for provider in include.iter().chain(&exclude) {
            // Providers retain callbacks. A weak sender prevents old TUN
            // generations and their provider snapshots from being retained.
            let weak = Arc::downgrade(&updates);
            provider.on_change(Arc::new(move || {
                if let Some(updates) = weak.upgrade() {
                    updates.send_modify(|generation| *generation = generation.wrapping_add(1));
                }
            }));
        }
        Ok(Self { include, exclude, updates })
    }

    pub fn subscribe(&self) -> Receiver<u64> { self.updates.subscribe() }

    pub fn snapshot(&self, cfg: &TunConfig) -> TunConfig {
        let mut cfg = cfg.clone();
        for provider in &self.include { cfg.routes.extend(provider.get_ip_cidrs()); }
        for provider in &self.exclude { cfg.route_exclude_address.extend(provider.get_ip_cidrs()); }
        cfg
    }

    pub async fn run(self, cfg: TunConfig, guard: Arc<AutoRedirect>, mut updates: Receiver<u64>)
        -> Result<(), Error>
    {
        loop {
            updates.changed().await.map_err(|error| Error::Operation(
                format!("TUN address set notifications stopped: {error}"),
            ))?;
            let sets = self.clone();
            let cfg = cfg.clone();
            let table = guard.table.clone();
            // CIDR aggregation and nft execution may be expensive for large
            // providers. Keep both off Tokio's worker threads. Capture only the
            // name so cancellation can release the table immediately. Refresh
            // only flushes/adds elements; it cannot recreate a deleted table.
            match tokio::task::spawn_blocking(move || {
                AutoRedirect::update_sets(&table, &sets.snapshot(&cfg))
            }).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!("TUN address set update failed; retrying on next provider update: {error}"),
                Err(error) => warn!("TUN address set update task failed; retrying on next provider update: {error}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::remote_content_manager::providers::rule_provider::{RuleProviderImpl, RuleSetBehavior, RuleSetFormat};

    #[tokio::test]
    async fn auto_redirect_address_sets_resolve_and_notify() {
        let provider: ThreadSafeRuleProvider = Arc::new(RuleProviderImpl::new(
            "networks".into(), RuleSetBehavior::Ipcidr, RuleSetFormat::Text,
            None, None, None, None, Some(vec!["10.0.0.0/8".into(), "fd00::/8".into()]),
        ));
        let registry = HashMap::from([("networks".into(), provider.clone())]);
        let cfg = TunConfig { route_address_set: vec!["networks".into()],
            route_exclude_address_set: vec!["networks".into()],
            routes: vec!["192.0.2.0/24".parse().unwrap()], ..Default::default() };
        let sets = RouteAddressSets::new(&cfg, &registry).unwrap();
        let mut updates = sets.subscribe();
        provider.initialize().await.unwrap();
        assert!(updates.has_changed().unwrap());
        updates.borrow_and_update();
        let snapshot = sets.snapshot(&cfg);
        assert_eq!(snapshot.routes.len(), 3);
        assert_eq!(snapshot.route_exclude_address.len(), 2);
        assert_eq!(cfg.routes.len(), 1);
        assert!(RouteAddressSets::new(&cfg, &HashMap::new()).is_err());

    }
}
