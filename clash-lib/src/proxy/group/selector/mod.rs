use std::{io, sync::Arc};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use tracing::warn;

use crate::{
    Error,
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ArcProxyProvider,
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{RemoteConnector, provider_helper::Providers},
    },
    session::Session,
};

pub trait SelectorControl {
    fn select(&self, name: &str) -> Result<(), Error>;
    #[cfg(test)]
    fn current(&self) -> String;
}

pub type ThreadSafeSelectorControl = Arc<dyn SelectorControl + Send + Sync>;

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

struct ActiveSelection {
    name: String,
    snapshot: Arc<Vec<AnyOutboundHandler>>,
    handler: AnyOutboundHandler,
}

#[derive(Clone)]
pub struct Handler {
    opts: HandlerOptions,
    providers: Providers,
    cached_active: Arc<ArcSwapOption<ActiveSelection>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selector")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub async fn new(
        opts: HandlerOptions,
        providers: Vec<ArcProxyProvider>,
        selected: Option<String>,
    ) -> Self {
        // Resolve against every provider, the same set `selected_proxy` reads.
        // Consulting only `providers.first()` restored the wrong proxy for a
        // group backed by more than one provider.
        let providers = Providers::new(providers);
        let proxies = providers.get_proxies(false);
        let current_selected = selected
            .filter(|s| proxies.iter().any(|p| p.name() == s))
            .or_else(|| proxies.first().map(|p| p.name().to_owned()));

        let cached_active = current_selected.as_ref().and_then(|name| {
            proxies
                .iter()
                .find(|p| p.name() == name)
                .map(|p| Arc::new(ActiveSelection {
                    name: name.clone(),
                    snapshot: proxies.clone(),
                    handler: p.clone(),
                }))
        });

        Self {
            opts,
            providers,
            cached_active: Arc::new(ArcSwapOption::new(cached_active)),
        }
    }

    fn selected_proxy(&self, touch: bool) -> Option<AnyOutboundHandler> {
        let proxies = self.providers.get_proxies(touch);
        let cached_guard = self.cached_active.load();

        // Fast path: if the cached selection is valid and the provider snapshot
        // pointer has not changed, return the cached handler directly in O(1).
        if let Some(active) = cached_guard.as_deref() {
            if Arc::ptr_eq(&active.snapshot, &proxies) {
                return Some(active.handler.clone());
            }
        }

        // Slow path: resolve selection from current proxies list (e.g. subscription refreshed)
        let found_proxy = if let Some(active) = cached_guard.as_deref() {
            if let Some(proxy) = proxies.iter().find(|p| p.name() == active.name) {
                Some(proxy.clone())
            } else {
                // The provider no longer offers it — say which one went missing
                // rather than the `<unknown>` the old lookup could only ever print.
                warn!(
                    "`{}` selected proxy `{}` not found, falling back to the first \
                     member",
                    self.name(),
                    active.name
                );
                proxies.first().cloned()
            }
        } else {
            proxies.first().cloned()
        };

        if let Some(ref proxy) = found_proxy {
            self.cached_active.store(Some(Arc::new(ActiveSelection {
                name: proxy.name().to_string(),
                snapshot: proxies.clone(),
                handler: proxy.clone(),
            })));
        }

        found_proxy
    }
}

impl SelectorControl for Handler {
    fn select(&self, name: &str) -> Result<(), Error> {
        let proxies = self.providers.get_proxies(false);
        if let Some(proxy) = proxies.iter().find(|x| x.name() == name) {
            self.cached_active.store(Some(Arc::new(ActiveSelection {
                name: name.to_owned(),
                snapshot: proxies.clone(),
                handler: proxy.clone(),
            })));
            Ok(())
        } else {
            Err(Error::Operation(format!("proxy {name} not found")))
        }
    }

    #[cfg(test)]
    fn current(&self) -> String {
        self.selected_proxy(false)
            .map(|p| p.name().to_owned())
            .unwrap_or_else(|| "<none>".to_owned())
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Selector
    }

    async fn support_udp(&self) -> bool {
        if !self.opts.udp {
            return false;
        }
        match self.selected_proxy(false) {
            Some(selected) => selected.support_udp().await,
            None => false,
        }
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let selected = self.selected_proxy(true).ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let s = selected.connect_stream(sess, resolver).await?;

        s.append_to_chain(self.name()).await;

        Ok(s)
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let selected = self.selected_proxy(true).ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let s = selected.connect_datagram(sess, resolver).await?;

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
        let s = self
            .selected_proxy(true)
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
            .selected_proxy(true)
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
        self.providers.get_proxies(false).to_vec()
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        Handler::selected_proxy(self, false)
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
    use std::sync::Arc;

    use crate::proxy::{
        group::selector::ThreadSafeSelectorControl,
        mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
    };

    #[tokio::test]
    async fn test_selector_control() {
        let mut mock_provider = MockDummyProxyProvider::new();
        mock_provider
            .expect_name()
            .return_const("provider1".to_owned());

        mock_provider.expect_proxies().returning(|| {
            let mut proxy1 = MockDummyOutboundHandler::new();
            proxy1.expect_name().return_const("provider1".to_owned());
            let mut proxy2 = MockDummyOutboundHandler::new();
            proxy2.expect_name().return_const("provider2".to_owned());
            Arc::new(vec![Arc::new(proxy1), Arc::new(proxy2)])
        });

        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                udp: false,
                ..Default::default()
            },
            vec![Arc::new(mock_provider)],
            None,
        )
        .await;

        let selector_control =
            Arc::new(handler.clone()) as ThreadSafeSelectorControl;
        let outbound_handler = Arc::new(handler);

        assert_eq!(selector_control.current(), "provider1".to_owned());
        assert_eq!(
            outbound_handler.selected_proxy(false).unwrap().name(),
            "provider1".to_owned()
        );

        selector_control.select("provider2").unwrap();

        assert_eq!(selector_control.current(), "provider2".to_owned());
        assert_eq!(
            outbound_handler.selected_proxy(false).unwrap().name(),
            "provider2".to_owned()
        );

        let fail = selector_control.select("provider3");
        assert!(fail.is_err());
    }

    #[tokio::test]
    async fn test_selector_empty_provider() {
        let mut mock_provider = MockDummyProxyProvider::new();
        mock_provider
            .expect_name()
            .return_const("provider1".to_owned());
        mock_provider.expect_proxies().returning(|| Arc::new(Vec::new()));

        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test-empty".to_owned(),
                udp: true,
                ..Default::default()
            },
            vec![Arc::new(mock_provider)],
            None,
        )
        .await;

        let selector_control =
            Arc::new(handler.clone()) as ThreadSafeSelectorControl;

        assert_eq!(selector_control.current(), "<none>".to_owned());
        assert!(handler.selected_proxy(false).is_none());
        assert!(selector_control.select("provider1").is_err());
    }
}
