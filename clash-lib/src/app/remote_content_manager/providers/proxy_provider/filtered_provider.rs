use std::{collections::HashMap, io, sync::Arc};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use erased_serde::Serialize;
use regex::Regex;

use crate::{
    app::remote_content_manager::providers::{
        Provider, ProviderType, ProviderVehicleType,
    },
    proxy::AnyOutboundHandler,
};

use super::{ArcProxyProvider, ProxyProvider};

struct FilteredSnapshot {
    raw_snapshot: Arc<Vec<AnyOutboundHandler>>,
    filtered_snapshot: Arc<Vec<AnyOutboundHandler>>,
}

/// A wrapper around another `ProxyProvider` that filters its proxy nodes
/// by a regular expression matching against their names.
pub struct FilteredProxyProvider {
    inner: ArcProxyProvider,
    filter: Arc<Regex>,
    empty_fallback: Option<AnyOutboundHandler>,
    cache: Arc<ArcSwapOption<FilteredSnapshot>>,
}

impl FilteredProxyProvider {
    pub fn new(
        inner: ArcProxyProvider,
        filter: Arc<Regex>,
        empty_fallback: Option<AnyOutboundHandler>,
    ) -> Self {
        Self {
            inner,
            filter,
            empty_fallback,
            cache: Arc::new(ArcSwapOption::new(None)),
        }
    }
}

#[async_trait]
impl Provider for FilteredProxyProvider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        self.inner.vehicle_type()
    }

    fn typ(&self) -> ProviderType {
        self.inner.typ()
    }

    async fn initialize(&self) -> io::Result<()> {
        self.inner.initialize().await
    }

    async fn update(&self) -> io::Result<()> {
        self.inner.update().await
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        self.inner.as_map().await
    }
}

#[async_trait]
impl ProxyProvider for FilteredProxyProvider {
    fn proxies(&self) -> Arc<Vec<AnyOutboundHandler>> {
        let current = self.inner.proxies();
        let cached_guard = self.cache.load();

        if let Some(cached) = cached_guard.as_deref() {
            if Arc::ptr_eq(&cached.raw_snapshot, &current) {
                return cached.filtered_snapshot.clone();
            }
        }

        let mut filtered: Vec<AnyOutboundHandler> = current
            .iter()
            .filter(|p| self.filter.is_match(p.name()))
            .cloned()
            .collect();

        if filtered.is_empty() {
            if let Some(fb) = &self.empty_fallback {
                filtered.push(fb.clone());
            }
        }

        let filtered_arc = Arc::new(filtered);
        self.cache.store(Some(Arc::new(FilteredSnapshot {
            raw_snapshot: current,
            filtered_snapshot: filtered_arc.clone(),
        })));

        filtered_arc
    }

    fn touch(&self) {
        self.inner.touch();
    }

    async fn healthcheck(&self) {
        self.inner.healthcheck().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::remote_content_manager::providers::ProviderVehicleType;
    use crate::proxy::direct;
    use crate::proxy::reject;
    use erased_serde::Serialize as ESerialize;

    struct DummyProvider {
        name: String,
        proxies: Arc<Vec<AnyOutboundHandler>>,
    }

    #[async_trait]
    impl Provider for DummyProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn vehicle_type(&self) -> ProviderVehicleType {
            ProviderVehicleType::Compatible
        }

        fn typ(&self) -> ProviderType {
            ProviderType::Proxy
        }

        async fn initialize(&self) -> std::io::Result<()> {
            Ok(())
        }

        async fn update(&self) -> std::io::Result<()> {
            Ok(())
        }

        async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
            HashMap::new()
        }
    }

    #[async_trait]
    impl ProxyProvider for DummyProvider {
        fn proxies(&self) -> Arc<Vec<AnyOutboundHandler>> {
            self.proxies.clone()
        }

        fn touch(&self) {}

        async fn healthcheck(&self) {}
    }

    #[test]
    fn test_filtered_proxy_provider() {
        let p1: AnyOutboundHandler = Arc::new(direct::Handler::new("HK 01"));
        let p2: AnyOutboundHandler = Arc::new(direct::Handler::new("US 01"));
        let p3: AnyOutboundHandler = Arc::new(direct::Handler::new("TW 01"));
        let reject_handler: AnyOutboundHandler = Arc::new(reject::Handler::new("REJECT"));

        let dummy = Arc::new(DummyProvider {
            name: "test_provider".to_string(),
            proxies: Arc::new(vec![p1.clone(), p2.clone(), p3.clone()]),
        });

        // Test 1: Match HK
        let filter_hk = Arc::new(Regex::new(r"HK.*").unwrap());
        let filtered_provider = FilteredProxyProvider::new(dummy.clone(), filter_hk, None);
        let res = filtered_provider.proxies();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].name(), "HK 01");

        // Test 2: Caching check
        let res2 = filtered_provider.proxies();
        assert!(Arc::ptr_eq(&res, &res2));

        // Test 3: No match without fallback
        let filter_sg = Arc::new(Regex::new(r"SG.*").unwrap());
        let filtered_provider_empty = FilteredProxyProvider::new(dummy.clone(), filter_sg, None);
        let res_empty = filtered_provider_empty.proxies();
        assert_eq!(res_empty.len(), 0);

        // Test 4: No match with fallback
        let filter_sg2 = Arc::new(Regex::new(r"SG.*").unwrap());
        let filtered_provider_fallback =
            FilteredProxyProvider::new(dummy, filter_sg2, Some(reject_handler));
        let res_fb = filtered_provider_fallback.proxies();
        assert_eq!(res_fb.len(), 1);
        assert_eq!(res_fb[0].name(), "REJECT");
    }
}
