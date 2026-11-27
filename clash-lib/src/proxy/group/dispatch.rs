//! Static dispatch for group selection policies and API inspection.
use crate::proxy::{RouteChange, utils::provider_helper::MemberUrls};
use super::{GroupHandler, GroupProxyAPIResponse, UdpPolicy};
use crate::{proxy::{OutboundNode, OutboundType}, session::Session};
use erased_serde::Serialize;
use std::{collections::{HashMap, HashSet}, io, time::Duration};

use std::sync::{Arc, Weak};

use crate::proxy::group::selector::Handler as SelectorHandler;
use crate::proxy::group::fallback::Handler as FallbackHandler;
use crate::proxy::group::urltest::Handler as UrlTestHandler;
use crate::proxy::group::loadbalance::Handler as LoadBalanceHandler;
use crate::proxy::group::smart::Handler as SmartHandler;
#[cfg(test)]
use crate::proxy::group::outbound_tests::RetryGroup as RetryHandler;

use crate::proxy::common::handler_enum;

handler_enum!(ProxyGroup, WeakProxyGroup, $;
    Selector(SelectorHandler),
    Fallback(FallbackHandler),
    UrlTest(UrlTestHandler),
    LoadBalance(LoadBalanceHandler),
    Smart(SmartHandler),
    #[cfg(test)]
    Retry(RetryHandler),
);

impl ProxyGroup {
    pub(crate) fn route_changes(&self, sources: &mut Vec<RouteChange>) {
        dispatch!(self, h, GroupHandler::route_changes(h.as_ref(), sources))
    }
    pub(crate) fn route_changes_from(
        &self,
        proxies: &Arc<Vec<OutboundNode>>,
        urls: &MemberUrls,
        sources: &mut Vec<RouteChange>,
    ) {
        match self {
            Self::UrlTest(h) => h.route_changes_from(proxies, urls, sources),
            Self::Fallback(h) => h.route_changes_from(proxies, urls, sources),
            _ => self.route_changes(sources),
        }
    }
    pub(crate) fn provider_route_changes(&self, sources: &mut Vec<RouteChange>) {
        match self {
            Self::Selector(h) => h.providers().route_changes(sources),
            Self::Fallback(h) => h.providers().route_changes(sources),
            Self::UrlTest(h) => h.providers().route_changes(sources),
            Self::LoadBalance(h) => h.providers().route_changes(sources),
            Self::Smart(h) => h.providers().route_changes(sources),
            #[cfg(test)]
            Self::Retry(_) => {}
        }
    }
    pub(crate) fn input_snapshots_from(
        &self,
        snapshots: &HashMap<usize, Arc<Vec<OutboundNode>>>,
    ) -> Vec<Arc<Vec<OutboundNode>>> {
        match self {
            Self::Selector(h) => h.providers().input_snapshots_from(snapshots),
            Self::Fallback(h) => h.providers().input_snapshots_from(snapshots),
            Self::UrlTest(h) => h.providers().input_snapshots_from(snapshots),
            Self::LoadBalance(h) => h.providers().input_snapshots_from(snapshots),
            Self::Smart(h) => h.providers().input_snapshots_from(snapshots),
            #[cfg(test)]
            Self::Retry(_) => Vec::new(),
        }
    }
    pub(crate) fn members_from_input_snapshots(
        &self,
        input_snapshots: &[Arc<Vec<OutboundNode>>],
    ) -> (Arc<Vec<OutboundNode>>, MemberUrls) {
        match self {
            Self::Selector(h) => h
                .providers()
                .get_members_from_input_snapshots(input_snapshots),
            Self::Fallback(h) => h
                .providers()
                .get_members_from_input_snapshots(input_snapshots),
            Self::UrlTest(h) => h
                .providers()
                .get_members_from_input_snapshots(input_snapshots),
            Self::LoadBalance(h) => h
                .providers()
                .get_members_from_input_snapshots(input_snapshots),
            Self::Smart(h) => h
                .providers()
                .get_members_from_input_snapshots(input_snapshots),
            #[cfg(test)]
            Self::Retry(_) => (Arc::new(Vec::new()), MemberUrls::Uniform(None)),
        }
    }
    #[cfg(test)]
    pub(crate) fn members_from_snapshots(
        &self,
        snapshots: &HashMap<usize, Arc<Vec<OutboundNode>>>,
    ) -> (Arc<Vec<OutboundNode>>, MemberUrls) {
        match self {
            Self::Selector(h) => h.providers().get_members_from_snapshots(snapshots),
            Self::Fallback(h) => h.providers().get_members_from_snapshots(snapshots),
            Self::UrlTest(h) => h.providers().get_members_from_snapshots(snapshots),
            Self::LoadBalance(h) => h.providers().get_members_from_snapshots(snapshots),
            Self::Smart(h) => h.providers().get_members_from_snapshots(snapshots),
            #[cfg(test)]
            Self::Retry(_) => (Arc::new(Vec::new()), MemberUrls::Uniform(None)),
        }
    }
    pub(crate) fn invalidate_stale_provider_caches(&self) {
        match self {
            Self::Selector(h) => h.providers().invalidate_stale_cache(),
            Self::Fallback(h) => h.providers().invalidate_stale_cache(),
            Self::UrlTest(h) => h.invalidate_stale_cache(),
            Self::LoadBalance(h) => h.invalidate_stale_cache(),
            Self::Smart(h) => h.providers().invalidate_stale_cache(),
            #[cfg(test)]
            Self::Retry(_) => {}
        }
    }
    pub(crate) fn select_cached(&self) -> Option<OutboundNode> {
        match self {
            Self::Selector(h) => h.select_cached(),
            Self::Fallback(h) => h.select_cached(),
            Self::UrlTest(h) => h.select_cached(),
            _ => None,
        }
    }
    pub(crate) fn peek_selected_from(
        &self,
        proxies: &Arc<Vec<OutboundNode>>,
        urls: &MemberUrls,
    ) -> Option<OutboundNode> {
        match self {
            Self::Selector(h) => h.peek_selected_from(proxies),
            Self::Fallback(h) => h.peek_selected_from(proxies, urls),
            Self::UrlTest(h) => h.peek_selected_from(proxies, urls),
            _ => None,
        }
    }
    pub(crate) fn stable_selection(&self) -> bool {
        matches!(self, Self::Selector(_) | Self::UrlTest(_) | Self::Fallback(_))
    }

    /// Groups members by the exact probe URL that automatic selection reads for
    /// each member, so manual group speedtests update the same per-`(node, url)`
    /// state consulted by the immediately following group selection.
    pub(crate) fn member_probe_batches(
        &self,
        fallback_url: &str,
    ) -> Vec<(String, Vec<OutboundNode>)> {
        let group_url = self.get_latency_test_url();
        let default_url = group_url.as_deref().unwrap_or(fallback_url);
        let (members, urls) = match self {
            Self::Selector(h) => h.providers().get_members(false),
            Self::Fallback(h) => h.providers().get_members(false),
            Self::UrlTest(h) => h.providers().get_members(false),
            Self::LoadBalance(h) => h.providers().get_members(false),
            Self::Smart(h) => h.providers().get_members(false),
            #[cfg(test)]
            Self::Retry(_) => return Vec::new(),
        };

        let mut buckets: Vec<(String, Vec<OutboundNode>)> = Vec::new();
        let mut url_to_bucket: HashMap<&str, usize> = HashMap::new();
        for (index, member) in members.iter().enumerate() {
            let target_url = urls
                .url_at(index, group_url.as_deref())
                .unwrap_or(default_url);
            if let Some(&bucket_idx) = url_to_bucket.get(target_url) {
                buckets[bucket_idx].1.push(member.clone());
            } else {
                let bucket_idx = buckets.len();
                url_to_bucket.insert(target_url, bucket_idx);
                buckets.push((target_url.to_owned(), vec![member.clone()]));
            }
        }
        buckets
    }

    pub fn name(&self) -> &str { dispatch!(self, h, GroupHandler::name(h.as_ref())) }
    pub fn proto(&self) -> OutboundType { dispatch!(self, h, GroupHandler::proto(h.as_ref())) }
    pub fn udp_policy(&self) -> UdpPolicy { dispatch!(self, h, GroupHandler::udp_policy(h.as_ref())) }
    pub fn retry_delay(&self, attempt: u32) -> Duration { dispatch!(self, h, GroupHandler::retry_delay(h.as_ref(), attempt)) }

    pub async fn select(&self, sess: &Session, excluded: &HashSet<String>) -> io::Result<Option<OutboundNode>> {
        match self {
            Self::Selector(h) => h.select(sess, excluded).await,
            Self::Fallback(h) => h.select(sess, excluded).await,
            Self::UrlTest(h) => h.select(sess, excluded).await,
            Self::LoadBalance(h) => h.select(sess, excluded).await,
            // Keep the large Smart state out of every group's selection future.
            Self::Smart(h) => Box::pin(h.select(sess, excluded)).await,
            #[cfg(test)]
            Self::Retry(h) => h.select(sess, excluded).await,
        }
    }
    pub async fn attempts(&self, sess: &Session) -> u32 {
        dispatch!(self, h, GroupHandler::attempts(h.as_ref(), sess).await)
    }
    pub async fn record_result(&self, sess: &Session, proxy: &str, elapsed: Duration, success: bool) {
        dispatch!(self, h, GroupHandler::record_result(h.as_ref(), sess, proxy, elapsed, success).await)
    }
    pub async fn get_proxies(&self) -> Vec<OutboundNode> {
        dispatch!(self, h, GroupProxyAPIResponse::get_proxies(h.as_ref()).await)
    }
    pub async fn get_active_proxy(&self) -> Option<OutboundNode> {
        dispatch!(self, h, GroupProxyAPIResponse::get_active_proxy(h.as_ref()).await)
    }
    pub fn get_latency_test_url(&self) -> Option<String> {
        dispatch!(self, h, GroupProxyAPIResponse::get_latency_test_url(h.as_ref()))
    }
    pub async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        dispatch!(self, h, GroupProxyAPIResponse::as_map(h.as_ref()).await)
    }
}
