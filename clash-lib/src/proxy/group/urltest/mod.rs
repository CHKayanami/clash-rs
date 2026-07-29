use std::{io, time::Duration};

use async_trait::async_trait;
use tracing::trace;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ArcProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    tolerance: u16,

    providers: Vec<ArcProxyProvider>,
    proxy_manager: ProxyManager,
    /// Name of the proxy the tolerance hysteresis is currently sticky to.
    /// Tracking a list position instead silently retargeted the selection
    /// whenever a provider refresh reordered the members.
    current_fastest: parking_lot::RwLock<Option<String>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTest")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        tolerance: u16,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            tolerance,
            providers,
            proxy_manager,
            current_fastest: parking_lot::RwLock::new(None),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    /// Pick the proxy to use.
    ///
    /// `commit` records the outcome as the new sticky choice. Read-only callers
    /// (the API, capability probes) pass `false` — previously every one of them
    /// rewrote the sticky state, so merely polling `/proxies` could change
    /// which proxy the group routed through.
    async fn fastest(
        &self,
        touch: bool,
        commit: bool,
    ) -> Option<AnyOutboundHandler> {
        let proxy_manager = self.proxy_manager.clone();

        let proxies = self.get_proxies(touch).await;
        if proxies.is_empty() {
            return None;
        }

        let current_name = self.current_fastest.read().clone();

        let mut fastest: Option<(usize, Duration)> = None;
        let mut current_alive = false;
        let mut current_delay = Duration::MAX;
        for (index, proxy) in proxies.iter().enumerate() {
            let is_current = current_name.as_deref() == Some(proxy.name());
            let (alive, delay) =
                proxy_manager.alive_and_last_delay(proxy.name()).await;
            if is_current {
                current_alive = alive;
            }
            if !alive {
                continue;
            }

            let delay = delay.unwrap_or(Duration::MAX);
            if is_current {
                current_delay = delay;
            }
            if match fastest {
                None => true,
                Some((_, fastest_delay)) => delay < fastest_delay,
            } {
                fastest = Some((index, delay));
            }
        }

        // Keep the historical first-proxy fallback when every candidate is
        // unavailable, while never preferring an unavailable proxy when a live
        // candidate exists (even if it has no delay sample yet).
        let (fastest_index, fastest_delay) = fastest.unwrap_or((0, Duration::MAX));
        let tolerance = Duration::from_millis(self.tolerance as u64);
        let switch_threshold = fastest_delay
            .checked_add(tolerance)
            .unwrap_or(Duration::MAX);

        let current_index = current_name
            .as_deref()
            .and_then(|name| proxies.iter().position(|p| p.name() == name));

        let selected_index = match current_index {
            // Stick with the current pick while it is alive and within
            // tolerance of the best.
            Some(index) if current_alive && current_delay <= switch_threshold => {
                index
            }
            _ => fastest_index,
        };

        let selected = &proxies[selected_index];

        if commit {
            *self.current_fastest.write() = Some(selected.name().to_owned());
        }

        let selected_delay = if selected_index == fastest_index {
            fastest_delay
        } else {
            current_delay
        };

        trace!(
            fastest = %selected.name(),
            delay = ?selected_delay,
            "`{}` fastest",
            self.name(),
        );

        Some(selected.clone())
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
    fn proto(&self) -> OutboundType {
        OutboundType::UrlTest
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        if self.opts.udp {
            return true;
        }
        match self.fastest(false, false).await {
            Some(fastest) => fastest.support_udp().await,
            None => false,
        }
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let fastest = self.fastest(true, true).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let s = fastest.connect_stream(sess, resolver).await?;

        s.append_to_chain(self.name()).await;

        Ok(s)
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let fastest = self.fastest(true, true).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let d = fastest.connect_datagram(sess, resolver).await?;

        d.append_to_chain(self.name()).await;

        Ok(d)
    }

    async fn support_connector(&self) -> ConnectorType {
        match self.fastest(false, false).await {
            Some(fastest) => fastest.support_connector().await,
            None => ConnectorType::Tcp,
        }
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let s = self
            .fastest(true, true)
            .await
            .ok_or_else(|| {
                io::Error::other(format!("no proxy found for {}", self.name()))
            })?
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;

        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let d = self
            .fastest(true, true)
            .await
            .ok_or_else(|| {
                io::Error::other(format!("no proxy found for {}", self.name()))
            })?
            .connect_datagram_with_connector(sess, resolver, connector)
            .await?;

        d.append_to_chain(self.name()).await;
        Ok(d)
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        Handler::get_proxies(self, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        self.fastest(false, false).await
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::{
        app::remote_content_manager::ProxyManager,
        proxy::{
            AnyOutboundHandler,
            group::GroupProxyAPIResponse,
            mocks::MockDummyProxyProvider,
            utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        },
    };

    #[tokio::test]
    async fn test_empty_provider_returns_none_active_proxy() {
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider1".to_owned());
        provider.expect_proxies().returning(Vec::new);

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                udp: true,
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            proxy_manager,
        );

        assert!(handler.get_active_proxy().await.is_none());
    }

    #[tokio::test]
    async fn test_tolerance_and_liveness_select_proxy() {
        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler { name: "a".into() }),
            Arc::new(NoopOutboundHandler { name: "b".into() }),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || proxies.clone()
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        proxy_manager
            .report_delay("a", true, Duration::from_millis(100))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(50))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            20,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("a", true, Duration::from_millis(40))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("a", true, Duration::from_millis(20))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        proxy_manager
            .report_delay("a", false, Duration::from_millis(20))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("b", false, Duration::from_millis(50))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");
    }
}
