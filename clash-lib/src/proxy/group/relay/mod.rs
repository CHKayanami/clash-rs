use std::{io, sync::Arc};

use async_trait::async_trait;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ArcProxyProvider,
    },
    common::errors::new_io_error,
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{
            DirectConnector, ProxyConnector, RemoteConnector,
            provider_helper::get_proxies_from_providers,
        },
    },
    session::Session,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ArcProxyProvider>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ArcProxyProvider>,
    ) -> AnyOutboundHandler {
        Arc::new(Self { opts, providers })
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.opts.name.as_str()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Relay
    }

    async fn support_udp(&self) -> bool {
        // Mirror `connect_datagram`: every hop but the last carries the
        // datagram as a connector, and the last one dials it. Returning true on
        // the *first* hop advertising `ConnectorType::All` skipped every hop
        // after it.
        let proxies = self.get_proxies(false).await;
        let Some((last, rest)) = proxies.split_last() else {
            return false;
        };
        for proxy in rest {
            if !matches!(proxy.support_connector().await, ConnectorType::All) {
                return false;
            }
        }
        last.support_udp().await
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let proxies = self.get_proxies(true).await;

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                debug!("tcp relay `{}` via proxy `{}`", self.name(), proxy.name());
                let s = proxy.connect_stream(sess, resolver).await?;
                s.append_to_chain(self.name()).await;
                Ok(s)
            }
            _ => {
                let mut connector: Box<dyn RemoteConnector> =
                    Box::new(DirectConnector::new());
                let (proxies, last) = proxies.split_at(proxies.len() - 1);
                for proxy in proxies {
                    debug!(
                        "tcp relay `{}` via proxy `{}`",
                        self.name(),
                        proxy.name()
                    );
                    connector =
                        Box::new(ProxyConnector::new(proxy.clone(), connector));
                }

                debug!("relay `{}` via proxy `{}`", self.name(), last[0].name());
                let s = last[0]
                    .connect_stream_with_connector(
                        sess,
                        resolver,
                        connector.as_ref(),
                    )
                    .await?;

                let chained = ChainedStreamWrapper::new(s);
                chained.append_to_chain(self.name()).await;
                Ok(Box::new(chained))
            }
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxies = self.get_proxies(true).await;

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                debug!("udp relay `{}` via proxy `{}`", self.name(), proxy.name());
                let d = proxy.connect_datagram(sess, resolver).await?;
                d.append_to_chain(self.name()).await;
                Ok(d)
            }
            _ => {
                let mut connector: Box<dyn RemoteConnector> =
                    Box::new(DirectConnector::new());
                let (proxies, last) = proxies.split_at(proxies.len() - 1);
                for proxy in proxies {
                    debug!(
                        "udp relay `{}` via proxy `{}`",
                        self.name(),
                        proxy.name()
                    );
                    connector =
                        Box::new(ProxyConnector::new(proxy.clone(), connector));
                }

                debug!("relay `{}` via proxy `{}`", self.name(), last[0].name());
                let d = last[0]
                    .connect_datagram_with_connector(
                        sess,
                        resolver,
                        connector.as_ref(),
                    )
                    .await?;

                let chained = ChainedDatagramWrapper::new(d);
                chained.append_to_chain(self.name()).await;
                Ok(Box::new(chained))
            }
        }
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
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

    /// A relay is the whole chain; naming any one hop as "active" would
    /// misreport it. See the note on the load balancer's implementation for the
    /// dispatcher behaviour this opts out of.
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

#[cfg(feature = "shadowsocks")]
#[cfg(all(test, docker_test))]
mod tests {

    use super::*;
    use crate::{
        proxy::{
            mocks::MockDummyProxyProvider,
            utils::test_utils::{
                Suite,
                consts::*,
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    const PASSWORD: &str = "FzcLbKs2dY9mhL";
    const CIPHER: &str = "aes-256-gcm";

    async fn get_ss_runner(port: u16) -> anyhow::Result<DockerTestRunner> {
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .port(port)
            .entrypoint(&["ssserver"])
            .cmd(&["-s", &host, "-m", CIPHER, "-k", PASSWORD, "-U"])
            .build()
            .await
    }

    #[tokio::test]
    async fn test_relay_1() -> anyhow::Result<()> {
        initialize();
        let port = alloc_docker_port();
        let container = get_ss_runner(port).await?;

        let container_ip = container.container_ip();

        debug!("container ip: {:?}", container_ip);
        let ss_opts = crate::proxy::shadowsocks::outbound::HandlerOptions {
            name: "test-ss".to_owned(),
            common_opts: Default::default(),
            server: container_ip.unwrap_or(LOCAL_ADDR.to_owned()),
            port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Default::default(),
            udp: false,
        };

        let ss_handler: AnyOutboundHandler =
            Arc::new(crate::proxy::shadowsocks::outbound::Handler::new(ss_opts))
                as _;

        let mut provider = MockDummyProxyProvider::new();

        provider.expect_touch().returning(|| ());
        provider.expect_healthcheck().returning(|| ());

        provider
            .expect_proxies()
            .returning(move || vec![ss_handler.clone()]);

        let handler = Handler::new(Default::default(), vec![Arc::new(provider)]);
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
    }

    #[tokio::test]
    async fn test_relay_2() -> anyhow::Result<()> {
        initialize();
        let port = alloc_docker_port();
        let container = get_ss_runner(port).await?;

        let container_ip = container.container_ip();

        let ss_opts = crate::proxy::shadowsocks::outbound::HandlerOptions {
            name: "test-ss".to_owned(),
            common_opts: Default::default(),
            server: container_ip.unwrap_or(LOCAL_ADDR.to_owned()),
            port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Default::default(),
            udp: false,
        };

        let ss_handler: AnyOutboundHandler =
            Arc::new(crate::proxy::shadowsocks::outbound::Handler::new(ss_opts))
                as _;

        let mut provider = MockDummyProxyProvider::new();

        provider.expect_touch().returning(|| ());
        provider.expect_healthcheck().returning(|| ());

        provider
            .expect_proxies()
            .returning(move || vec![ss_handler.clone(), ss_handler.clone()]);

        let handler = Handler::new(Default::default(), vec![Arc::new(provider)]);
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
    }
}
