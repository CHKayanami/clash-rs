use crate::proxy::RouteChange;
use super::UdpPolicy;
use std::collections::HashSet;
use super::GroupHandler;

use std::{fmt::Debug, io, sync::Arc};
use tracing::debug;

use crate::{
    app::remote_content_manager::{
        ProxyManager, providers::proxy_provider::ArcProxyProvider,
    },
    proxy::{
        HandlerCommonOptions, OutboundNode, OutboundType,
        group::GroupProxyAPIResponse,
        utils::provider_helper::{MemberUrls, Providers},
    },
    session::Session,
};

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Providers,
    proxy_manager: ProxyManager,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fallback")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub(crate) fn select_cached(&self) -> Option<OutboundNode> { self.find_alive_proxy(false) }

    pub(crate) fn peek_selected_from(
        &self,
        proxies: &[OutboundNode],
        urls: &MemberUrls,
    ) -> Option<OutboundNode> {
        self.find_alive_proxy_in(proxies, urls)
    }

    pub(crate) fn providers(&self) -> &Providers {
        &self.providers
    }

    pub(crate) fn route_changes_from(
        &self,
        proxies: &[OutboundNode],
        urls: &MemberUrls,
        sources: &mut Vec<RouteChange>,
    ) {
        self.providers.route_changes(sources);
        let fallback_url = self.opts.common_opts.url.as_deref();
        sources.extend(proxies.iter().enumerate().map(|(index, node)| {
            self.proxy_manager.route_changes_for(
                node,
                urls.url_at(index, fallback_url),
                false,
            )
        }));
    }

    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        if let Some(url) = opts.common_opts.url.as_deref() {
            proxy_manager.register_probe_url(url);
        }
        Self {
            opts,
            providers: Providers::new(providers),
            proxy_manager,
        }
    }

    fn get_proxies(&self, touch: bool) -> Arc<Vec<OutboundNode>> {
        self.providers.get_proxies(touch)
    }

    fn find_alive_proxy(&self, touch: bool) -> Option<OutboundNode> {
        let (proxies, urls) = self.providers.get_members(touch);
        self.find_alive_proxy_in(&proxies, &urls)
    }

    fn find_alive_proxy_in(
        &self,
        proxies: &[OutboundNode],
        urls: &MemberUrls,
    ) -> Option<OutboundNode> {
        let fallback_url = self.opts.common_opts.url.as_deref();
        for (index, proxy) in proxies.iter().enumerate() {
            let probe_url = urls.url_at(index, fallback_url);
            if self.proxy_manager.alive_for(proxy, probe_url) {
                debug!("`{}` fallback to `{}`", self.name(), proxy.name());
                return Some(proxy.clone());
            }
        }
        proxies.first().cloned()
    }
}

impl GroupHandler for Handler {
    fn route_changes(&self, sources: &mut Vec<RouteChange>) {
        let (proxies, urls) = self.providers.get_members(false);
        self.route_changes_from(&proxies, &urls, sources);
    }

    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Fallback
    }

    fn udp_policy(&self) -> UdpPolicy {
        if self.opts.udp { UdpPolicy::Enabled } else { UdpPolicy::Selected }
    }

    async fn select(
        &self,
        sess: &Session,
        excluded: &HashSet<String>,
    ) -> io::Result<Option<OutboundNode>> {
        let _ = (sess, excluded);
        Ok(self.find_alive_proxy(true))
    }
}

impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<OutboundNode> {
        Handler::get_proxies(self, false).to_vec()
    }

    async fn get_active_proxy(&self) -> Option<OutboundNode> {
        Handler::find_alive_proxy(self, false)
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
