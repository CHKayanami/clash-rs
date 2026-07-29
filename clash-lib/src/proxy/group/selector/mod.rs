use std::{io, sync::Arc};

use async_trait::async_trait;
use parking_lot::RwLock;
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
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[async_trait]
pub trait SelectorControl {
    async fn select(&self, name: &str) -> Result<(), Error>;
    #[cfg(test)]
    async fn current(&self) -> String;
}

pub type ThreadSafeSelectorControl = Arc<dyn SelectorControl + Send + Sync>;

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

#[derive(Clone)]
pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ArcProxyProvider>,
    /// The chosen proxy's *name*. Storing a position instead meant a provider
    /// refresh that reordered or resized the member list silently moved the
    /// user's selection to whatever proxy now sat at that index.
    current_selected: Arc<RwLock<Option<String>>>,
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
        let proxies = get_proxies_from_providers(&providers, false).await;
        let current_selected = selected
            .filter(|s| proxies.iter().any(|p| p.name() == s))
            .or_else(|| proxies.first().map(|p| p.name().to_owned()));

        Self {
            opts,
            providers,
            current_selected: Arc::new(RwLock::new(current_selected)),
        }
    }

    async fn selected_proxy(&self, touch: bool) -> Option<AnyOutboundHandler> {
        let proxies = get_proxies_from_providers(&self.providers, touch).await;
        let selected = self.current_selected.read().clone();

        if let Some(name) = selected.as_deref() {
            if let Some(proxy) = proxies.iter().find(|p| p.name() == name) {
                return Some(proxy.clone());
            }
            // The provider no longer offers it — say which one went missing
            // rather than the `<unknown>` the old lookup could only ever print.
            warn!(
                "`{}` selected proxy `{}` not found, falling back to the first \
                 member",
                self.name(),
                name
            );
        }

        proxies.first().cloned()
    }
}

#[async_trait]
impl SelectorControl for Handler {
    async fn select(&self, name: &str) -> Result<(), Error> {
        let proxies = get_proxies_from_providers(&self.providers, false).await;
        if proxies.iter().any(|x| x.name() == name) {
            *self.current_selected.write() = Some(name.to_owned());
            Ok(())
        } else {
            Err(Error::Operation(format!("proxy {name} not found")))
        }
    }

    #[cfg(test)]
    async fn current(&self) -> String {
        self.selected_proxy(false)
            .await
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
        match self.selected_proxy(false).await {
            Some(selected) => selected.support_udp().await,
            None => false,
        }
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let selected = self.selected_proxy(true).await.ok_or_else(|| {
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
        let selected = self.selected_proxy(true).await.ok_or_else(|| {
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
            .selected_proxy(true)
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
        get_proxies_from_providers(&self.providers, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        Handler::selected_proxy(self, false).await
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
            vec![Arc::new(proxy1), Arc::new(proxy2)]
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

        assert_eq!(selector_control.current().await, "provider1".to_owned());
        assert_eq!(
            outbound_handler.selected_proxy(false).await.unwrap().name(),
            "provider1".to_owned()
        );

        selector_control.select("provider2").await.unwrap();

        assert_eq!(selector_control.current().await, "provider2".to_owned());
        assert_eq!(
            outbound_handler.selected_proxy(false).await.unwrap().name(),
            "provider2".to_owned()
        );

        let fail = selector_control.select("provider3").await;
        assert!(fail.is_err());
    }

    #[tokio::test]
    async fn test_selector_empty_provider() {
        let mut mock_provider = MockDummyProxyProvider::new();
        mock_provider
            .expect_name()
            .return_const("provider1".to_owned());
        mock_provider.expect_proxies().returning(Vec::new);

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

        assert_eq!(selector_control.current().await, "<none>".to_owned());
        assert!(handler.selected_proxy(false).await.is_none());
        assert!(selector_control.select("provider1").await.is_err());
    }
}
