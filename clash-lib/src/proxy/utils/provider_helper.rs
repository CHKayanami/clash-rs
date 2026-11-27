use crate::proxy::RouteChange;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;

use crate::{
    app::remote_content_manager::providers::proxy_provider::ArcProxyProvider,
    proxy::OutboundNode,
};

#[derive(Clone)]
pub(crate) enum MemberUrls {
    Uniform(Option<Arc<str>>),
    PerMember(Arc<Vec<Option<Arc<str>>>>),
}

impl MemberUrls {
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Uniform(a), Self::Uniform(b)) => a.as_deref() == b.as_deref(),
            (Self::PerMember(a), Self::PerMember(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    pub(crate) fn url_at<'a>(
        &'a self,
        index: usize,
        fallback: Option<&'a str>,
    ) -> Option<&'a str> {
        let provider_url = match self {
            Self::Uniform(url) => url.as_deref(),
            Self::PerMember(urls) => urls.get(index).and_then(|u| u.as_deref()),
        };
        provider_url.or(fallback)
    }
}

struct AggregatedSnapshot {
    sub_snapshots: Vec<Arc<Vec<OutboundNode>>>,
    merged: Arc<Vec<OutboundNode>>,
    urls: MemberUrls,
}

#[derive(Clone)]
pub struct Providers {
    providers: Vec<ArcProxyProvider>,
    /// Pre-cached per-provider healthcheck URLs so `get_proxies()` and
    /// `get_members()` never allocate `Arc<str>` per call.
    provider_urls: Arc<Vec<Option<Arc<str>>>>,
    /// `Some(url)` when every provider shares the same healthcheck URL (or
    /// `None`), `None` when providers have distinct URLs.
    uniform_url: Option<Option<Arc<str>>>,
    cached_merged: Arc<ArcSwapOption<AggregatedSnapshot>>,
    publish_lock: Arc<Mutex<()>>,
}

impl Providers {
    pub fn new(providers: Vec<ArcProxyProvider>) -> Self {
        let provider_urls: Vec<Option<Arc<str>>> = providers
            .iter()
            .map(|p| p.healthcheck_url().map(Arc::<str>::from))
            .collect();
        let uniform_url = if provider_urls
            .first()
            .is_none_or(|first| provider_urls.iter().all(|u| u == first))
        {
            Some(provider_urls.first().cloned().flatten())
        } else {
            None
        };
        Self {
            providers,
            provider_urls: Arc::new(provider_urls),
            uniform_url,
            cached_merged: Arc::new(ArcSwapOption::new(None)),
            publish_lock: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn route_changes(&self, sources: &mut Vec<RouteChange>) {
        sources.extend(self.providers.iter().filter_map(|provider| provider.route_changes()));
    }

    pub(crate) fn touch(&self) {
        for provider in &self.providers { provider.touch(); }
    }

    pub(crate) fn snapshots_match(
        a: &[Arc<Vec<OutboundNode>>],
        b: &[Arc<Vec<OutboundNode>>],
    ) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| Arc::ptr_eq(x, y))
    }

    /// Drops cached derived snapshots when any underlying provider has moved
    /// to a new snapshot generation so superseded handlers are not kept alive
    /// by idle groups.
    pub(crate) fn invalidate_stale_cache(&self) {
        for provider in &self.providers {
            provider.invalidate_stale_cache();
        }
        let _guard = self.publish_lock.lock();
        if let Some(cached) = self.cached_merged.load().as_deref() {
            let still_current = cached.sub_snapshots.len() == self.providers.len()
                && cached
                    .sub_snapshots
                    .iter()
                    .zip(&self.providers)
                    .all(|(old, p)| p.is_snapshot_current(old));
            if !still_current {
                self.cached_merged.store(None);
            }
        }
    }

    fn merge_snapshots(
        &self,
        sub_snapshots: &[Arc<Vec<OutboundNode>>],
    ) -> (Arc<Vec<OutboundNode>>, MemberUrls) {
        let mut proxy_names = HashSet::new();
        let mut proxies = Vec::new();
        let mut per_member_urls = if self.uniform_url.is_some() {
            None
        } else {
            Some(Vec::new())
        };

        for (list, url) in sub_snapshots.iter().zip(self.provider_urls.iter()) {
            for p in list.iter() {
                if proxy_names.insert(p.name().to_owned()) {
                    proxies.push(p.clone());
                    if let Some(urls) = per_member_urls.as_mut() {
                        urls.push(url.clone());
                    }
                }
            }
        }

        let urls = match per_member_urls {
            Some(urls) => MemberUrls::PerMember(Arc::new(urls)),
            None => MemberUrls::Uniform(self.uniform_url.clone().flatten()),
        };
        (Arc::new(proxies), urls)
    }

    fn publish_or_reuse_merged(
        &self,
        sub_snapshots: Vec<Arc<Vec<OutboundNode>>>,
    ) -> (Arc<Vec<OutboundNode>>, MemberUrls) {
        if let Some(cached) = self.cached_merged.load().as_deref()
            && Self::snapshots_match(&cached.sub_snapshots, &sub_snapshots)
        {
            return (cached.merged.clone(), cached.urls.clone());
        }

        let (merged, urls) = self.merge_snapshots(&sub_snapshots);

        // Validate under `publish_lock` so a concurrent provider refresh +
        // invalidation cannot be overwritten by a stale merged snapshot, while
        // letting tracker rebuilds and traffic lookups share the same `Arc`.
        let _guard = self.publish_lock.lock();
        if let Some(cached) = self.cached_merged.load().as_deref()
            && Self::snapshots_match(&cached.sub_snapshots, &sub_snapshots)
        {
            return (cached.merged.clone(), cached.urls.clone());
        }
        let still_current = sub_snapshots
            .iter()
            .zip(&self.providers)
            .all(|(snap, p)| p.is_snapshot_current(snap));
        if still_current {
            self.cached_merged.store(Some(Arc::new(AggregatedSnapshot {
                sub_snapshots,
                merged: merged.clone(),
                urls: urls.clone(),
            })));
        }

        (merged, urls)
    }

    fn get_merged_members(&self) -> (Arc<Vec<OutboundNode>>, MemberUrls) {
        let current_sub_snapshots: Vec<Arc<Vec<OutboundNode>>> =
            self.providers.iter().map(|p| p.proxies()).collect();
        self.publish_or_reuse_merged(current_sub_snapshots)
    }

    pub(crate) fn get_members(
        &self,
        touch: bool,
    ) -> (Arc<Vec<OutboundNode>>, MemberUrls) {
        if self.providers.is_empty() {
            return (Arc::new(Vec::new()), MemberUrls::Uniform(None));
        }

        if touch { self.touch(); }

        if self.providers.len() == 1 {
            let url = self.provider_urls.first().cloned().flatten();
            return (self.providers[0].proxies(), MemberUrls::Uniform(url));
        }

        self.get_merged_members()
    }

    /// Captures the raw upstream snapshot for each provider in this group
    /// without invoking filters or merging, so callers can skip rebuilding
    /// unchanged groups when only another provider refreshed.
    pub(crate) fn input_snapshots_from(
        &self,
        snapshots: &HashMap<usize, Arc<Vec<OutboundNode>>>,
    ) -> Vec<Arc<Vec<OutboundNode>>> {
        self.providers
            .iter()
            .map(|p| p.raw_snapshot_from_snapshots(snapshots))
            .collect()
    }

    /// Resolves members from previously captured raw upstream snapshots,
    /// reusing or publishing the shared merged snapshot when still current so
    /// the tracker and traffic path observe the same `Arc<Vec<OutboundNode>>`.
    pub(crate) fn get_members_from_input_snapshots(
        &self,
        input_snapshots: &[Arc<Vec<OutboundNode>>],
    ) -> (Arc<Vec<OutboundNode>>, MemberUrls) {
        if self.providers.is_empty() {
            return (Arc::new(Vec::new()), MemberUrls::Uniform(None));
        }
        if self.providers.len() == 1 {
            let p = &self.providers[0];
            let url = self.provider_urls.first().cloned().flatten();
            return (
                p.resolve_from_raw_snapshot(input_snapshots[0].clone()),
                MemberUrls::Uniform(url),
            );
        }
        let sub_snapshots: Vec<Arc<Vec<OutboundNode>>> = self
            .providers
            .iter()
            .zip(input_snapshots)
            .map(|(p, raw)| p.resolve_from_raw_snapshot(raw.clone()))
            .collect();
        self.publish_or_reuse_merged(sub_snapshots)
    }

    /// Resolves members directly from a fixed provider snapshot table without
    /// re-reading live providers or mutating group caches.
    #[cfg(test)]
    pub(crate) fn get_members_from_snapshots(
        &self,
        snapshots: &HashMap<usize, Arc<Vec<OutboundNode>>>,
    ) -> (Arc<Vec<OutboundNode>>, MemberUrls) {
        if self.providers.is_empty() {
            return (Arc::new(Vec::new()), MemberUrls::Uniform(None));
        }
        let input_snapshots = self.input_snapshots_from(snapshots);
        self.get_members_from_input_snapshots(&input_snapshots)
    }

    pub fn get_proxies(&self, touch: bool) -> Arc<Vec<OutboundNode>> {
        if self.providers.is_empty() {
            return Arc::new(Vec::new());
        }
        if touch { self.touch(); }
        if self.providers.len() == 1 {
            return self.providers[0].proxies();
        }
        self.get_merged_members().0
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
        let h1: OutboundNode = OutboundNode::protocol(Arc::new(h1));

        let mut h2 = MockDummyOutboundHandler::new();
        h2.expect_name().return_const("p2-node1".to_owned());
        let h2: OutboundNode = OutboundNode::protocol(Arc::new(h2));

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

    #[test]
    fn concurrent_refresh_during_merge_does_not_cache_stale_snapshot() {
        use arc_swap::ArcSwap;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut h_old = MockDummyOutboundHandler::new();
        h_old.expect_name().return_const("p1-old".to_owned());
        let h_old = OutboundNode::protocol(Arc::new(h_old));
        let old_weak = h_old.downgrade();

        let mut h_new = MockDummyOutboundHandler::new();
        h_new.expect_name().return_const("p1-new".to_owned());
        let h_new = OutboundNode::protocol(Arc::new(h_new));
        let new_id = h_new.identity();

        let mut h2 = MockDummyOutboundHandler::new();
        h2.expect_name().return_const("p2-node".to_owned());
        let h2 = OutboundNode::protocol(Arc::new(h2));

        let slot1 = Arc::new(ArcSwap::from_pointee(vec![h_old]));
        let mut p1 = MockDummyProxyProvider::new();
        p1.expect_proxies().returning({
            let slot1 = slot1.clone();
            move || slot1.load_full()
        });

        let snap2 = Arc::new(vec![h2]);
        let swapped = Arc::new(AtomicBool::new(false));
        let mut p2 = MockDummyProxyProvider::new();
        p2.expect_proxies().returning({
            let slot1 = slot1.clone();
            let snap2 = snap2.clone();
            let swapped = swapped.clone();
            let h_new = h_new.clone();
            move || {
                // Deterministically trigger a refresh of p1 right between
                // `get_merged_members` reading p1 and publishing cached_merged.
                if !swapped.swap(true, Ordering::SeqCst) {
                    slot1.store(Arc::new(vec![h_new.clone()]));
                }
                snap2.clone()
            }
        });

        let providers = Providers::new(vec![Arc::new(p1), Arc::new(p2)]);
        let stale_merged = providers.get_proxies(false);
        assert_eq!(stale_merged[0].name(), "p1-old");
        drop(stale_merged);

        assert!(
            old_weak.upgrade().is_none(),
            "stale merged snapshot must not be written back into cached_merged after refresh"
        );

        let fresh_1 = providers.get_proxies(false);
        let fresh_2 = providers.get_proxies(false);
        assert_eq!(fresh_1[0].identity(), new_id);
        assert!(Arc::ptr_eq(&fresh_1, &fresh_2));
    }
}
