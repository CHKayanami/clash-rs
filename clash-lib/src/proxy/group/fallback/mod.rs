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
        OutboundNode, HandlerCommonOptions, OutboundType,
        group::GroupProxyAPIResponse,
        utils::provider_helper::Providers,
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
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            providers: Providers::new(providers),
            proxy_manager,
        }
    }

    fn get_proxies(&self, touch: bool) -> Arc<Vec<OutboundNode>> {
        self.providers.get_proxies(touch)
    }

    async fn find_alive_proxy(&self, touch: bool) -> Option<OutboundNode> {
        let proxies = self.get_proxies(touch);
        for proxy in proxies.iter() {
            if self.proxy_manager.alive(proxy.name()).await {
                debug!("`{}` fallback to `{}`", self.name(), proxy.name());
                return Some(proxy.clone());
            }
        }
        proxies.first().cloned()
    }
}

impl GroupHandler for Handler {
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
        Ok(self.find_alive_proxy(true).await)
    }
}

impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<OutboundNode> {
        Handler::get_proxies(self, false).to_vec()
    }

    async fn get_active_proxy(&self) -> Option<OutboundNode> {
        Handler::find_alive_proxy(self, false).await
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
