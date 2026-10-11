use super::UdpPolicy;
use std::collections::HashSet;
use super::GroupHandler;
mod helpers;

use helpers::strategy_sticky_session;
use std::{io, sync::Arc};

use self::helpers::{Strategy, strategy_consistent_hashring, strategy_rr};
use crate::{
    app::remote_content_manager::{
        ProxyManager, providers::proxy_provider::ArcProxyProvider,
    },
    config::internal::proxy::LoadBalanceStrategy,
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
    pub strategy: LoadBalanceStrategy,
}

pub struct Handler {
    opts: HandlerOptions,

    providers: Providers,

    strategy_fn: Strategy,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalance")
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
        let strategy_fn = match opts.strategy {
            LoadBalanceStrategy::ConsistentHashing => strategy_consistent_hashring(),
            LoadBalanceStrategy::RoundRobin => strategy_rr(),
            LoadBalanceStrategy::StickySession => {
                strategy_sticky_session(proxy_manager)
            }
        };

        Self {
            opts,
            providers: Providers::new(providers),
            strategy_fn,
        }
    }

    fn get_proxies(&self, touch: bool) -> Arc<Vec<OutboundNode>> {
        self.providers.get_proxies(touch)
    }

    /// Run the configured strategy over the group's current members.
    fn pick(&self, sess: &Session) -> io::Result<OutboundNode> {
        let proxies = self.get_proxies(false);
        if proxies.is_empty() {
            return Err(io::Error::other(format!(
                "no proxy available for {}",
                self.name()
            )));
        }
        self.strategy_fn.pick(proxies, sess)
    }
}

impl GroupHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::LoadBalance
    }

    fn udp_policy(&self) -> UdpPolicy {
        if self.opts.udp { UdpPolicy::Enabled } else { UdpPolicy::Disabled }
    }

    async fn select(
        &self,
        sess: &Session,
        excluded: &HashSet<String>,
    ) -> io::Result<Option<OutboundNode>> {
        let _ = (sess, excluded);
        self.pick(sess).map(Some)
    }
}

impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<OutboundNode> {
        Handler::get_proxies(self, false).to_vec()
    }

    /// A load balancer has no single active member — the strategy picks per
    /// connection — so there is nothing honest to report here.
    ///
    /// Note this also opts the group out of the dispatcher's group-aware UDP
    /// NAT re-keying and REJECT short-circuit (`dispatcher_impl.rs`), which key
    /// off the active proxy. Rejected traffic still fails at `connect_*`; it
    /// just is not short-circuited before the channel is set up.
    async fn get_active_proxy(&self) -> Option<OutboundNode> {
        None
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
