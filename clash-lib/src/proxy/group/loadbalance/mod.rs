mod helpers;

use async_trait::async_trait;
use helpers::strategy_sticky_session;
use std::{io, sync::Arc};
use tokio::sync::Mutex;
use tracing::debug;

use self::helpers::{StrategyFn, strategy_consistent_hashring, strategy_rr};
use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ArcProxyProvider,
        },
    },
    config::internal::proxy::LoadBalanceStrategy,
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{RemoteConnector, provider_helper::Providers},
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

struct HandlerInner {
    strategy_fn: StrategyFn,
}

pub struct Handler {
    opts: HandlerOptions,

    providers: Providers,

    inner: Arc<Mutex<HandlerInner>>,
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
            inner: Arc::new(Mutex::new(HandlerInner { strategy_fn })),
        }
    }

    fn get_proxies(&self, touch: bool) -> Arc<Vec<AnyOutboundHandler>> {
        self.providers.get_proxies(touch)
    }

    /// Run the configured strategy over the group's current members.
    ///
    /// The strategy future is built under the lock and awaited *outside* it.
    /// Awaiting while holding the guard serialized every concurrent connection
    /// through this group, and the sticky-session strategy awaits liveness
    /// checks and an LRU lock of its own.
    async fn pick(&self, sess: &Session) -> io::Result<AnyOutboundHandler> {
        let proxies = self.get_proxies(false);
        if proxies.is_empty() {
            return Err(io::Error::other(format!(
                "no proxy available for {}",
                self.name()
            )));
        }
        let fut = {
            let mut inner = self.inner.lock().await;
            (inner.strategy_fn)(proxies, sess)
        };
        fut.await
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.opts.name
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType {
        OutboundType::LoadBalance
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let proxy = self.pick(sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());

        let s = proxy.connect_stream(sess, resolver).await?;

        s.append_to_chain(self.name()).await;

        Ok(s)
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxy = self.pick(sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());

        let s = proxy.connect_datagram(sess, resolver).await?;

        s.append_to_chain(self.name()).await;

        Ok(s)
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let proxy = self.pick(sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        let s = proxy
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;

        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        Handler::get_proxies(self, false).to_vec()
    }

    /// A load balancer has no single active member — the strategy picks per
    /// connection — so there is nothing honest to report here.
    ///
    /// Note this also opts the group out of the dispatcher's group-aware UDP
    /// NAT re-keying and REJECT short-circuit (`dispatcher_impl.rs`), which key
    /// off the active proxy. Rejected traffic still fails at `connect_*`; it
    /// just is not short-circuited before the channel is set up.
    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        None
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
