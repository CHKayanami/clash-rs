use std::{collections::HashSet, sync::Arc};

use arc_swap::ArcSwapOption;

use crate::{
    app::remote_content_manager::providers::proxy_provider::ArcProxyProvider,
    proxy::AnyOutboundHandler,
};

struct AggregatedSnapshot {
    sub_snapshots: Vec<Arc<Vec<AnyOutboundHandler>>>,
    merged: Arc<Vec<AnyOutboundHandler>>,
}

#[derive(Clone)]
pub struct Providers {
    providers: Vec<ArcProxyProvider>,
    cached_merged: Arc<ArcSwapOption<AggregatedSnapshot>>,
}

impl Providers {
    pub fn new(providers: Vec<ArcProxyProvider>) -> Self {
        Self {
            providers,
            cached_merged: Arc::new(ArcSwapOption::new(None)),
        }
    }

    pub fn get_proxies(&self, touch: bool) -> Arc<Vec<AnyOutboundHandler>> {
        if self.providers.is_empty() {
            return Arc::new(Vec::new());
        }

        if touch {
            for provider in &self.providers {
                provider.touch();
            }
        }

        if self.providers.len() == 1 {
            return self.providers[0].proxies();
        }

        let current_sub_snapshots: Vec<Arc<Vec<AnyOutboundHandler>>> =
            self.providers.iter().map(|p| p.proxies()).collect();

        let cached_guard = self.cached_merged.load();
        if let Some(cached) = cached_guard.as_deref() {
            if cached.sub_snapshots.len() == current_sub_snapshots.len()
                && cached
                    .sub_snapshots
                    .iter()
                    .zip(&current_sub_snapshots)
                    .all(|(a, b)| Arc::ptr_eq(a, b))
            {
                return cached.merged.clone();
            }
        }

        let mut proxy_names = HashSet::new();
        let mut proxies = Vec::new();
        for list in &current_sub_snapshots {
            for p in list.iter() {
                if proxy_names.insert(p.name().to_owned()) {
                    proxies.push(p.clone());
                }
            }
        }

        let merged = Arc::new(proxies);
        self.cached_merged.store(Some(Arc::new(AggregatedSnapshot {
            sub_snapshots: current_sub_snapshots,
            merged: merged.clone(),
        })));

        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::mocks::{MockDummyOutboundHandler, MockDummyProxyProvider};

    #[test]
    fn test_providers_merged_snapshot_cache() {
        let mut p1 = MockDummyProxyProvider::new();
        let mut p2 = MockDummyProxyProvider::new();

        let mut h1 = MockDummyOutboundHandler::new();
        h1.expect_name().return_const("p1-node1".to_owned());
        let h1: AnyOutboundHandler = Arc::new(h1);

        let mut h2 = MockDummyOutboundHandler::new();
        h2.expect_name().return_const("p2-node1".to_owned());
        let h2: AnyOutboundHandler = Arc::new(h2);

        let snap1 = Arc::new(vec![h1.clone()]);
        let snap2 = Arc::new(vec![h2.clone()]);

        let snap1_clone = snap1.clone();
        p1.expect_proxies().returning(move || snap1_clone.clone());

        let snap2_clone = snap2.clone();
        p2.expect_proxies().returning(move || snap2_clone.clone());

        let providers = Providers::new(vec![Arc::new(p1), Arc::new(p2)]);

        // 第一次获取：构建聚合快照
        let res1 = providers.get_proxies(false);
        assert_eq!(res1.len(), 2);

        // 第二次获取：子 Provider 快照指针未变，应当命中聚合缓存且指针地址完全相同！
        let res2 = providers.get_proxies(false);
        assert!(Arc::ptr_eq(&res1, &res2));
    }
}
