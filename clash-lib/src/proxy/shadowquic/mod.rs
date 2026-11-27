#[cfg(all(test, docker_test))]
use crate::proxy::OutboundNode;

#[cfg(test)]
use parking_lot::Mutex;
use arc_swap::ArcSwapOption;
use erased_serde::Serialize as ErasedSerialize;
use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
use tokio_util::sync::{CancellationToken, PollSender};

pub mod config;
mod brutal;
mod compat;
mod endpoint;
mod ids;
mod protocol;
mod registry;
pub(crate) mod stream;
mod udp;
#[cfg(test)]
mod client_tests;

pub use config::HandlerOptions;
pub(crate) use compat::UdpSessionWrapper;
use endpoint::{ClientEndpoint, client_config};
use stream::ShadowQuicStream;
use udp::{ClientConnection, ConnectionState, ShadowQuicLease};

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::errors::new_io_error,
    proxy::{AnyOutboundDatagram, AnyStream},
    session::{Session, SocksAddr},
};

use super::{
    DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};
pub struct Handler {
    name: String,
    opts: HandlerOptions,
    client_config: OnceCell<quinn_jls::ClientConfig>,
    conn: Arc<ArcSwapOption<ConnectionState>>,
    keep_idle: Arc<AtomicBool>,
    reconnect: AsyncMutex<()>,
    #[cfg(test)]
    last_dial_local_addr: Mutex<Option<SocketAddr>>,
}

struct DialEndpointGuard {
    ep: Option<Arc<ClientEndpoint>>,
}

impl DialEndpointGuard {
    fn new(ep: Arc<ClientEndpoint>) -> Self {
        Self { ep: Some(ep) }
    }

    fn as_arc(&self) -> &Arc<ClientEndpoint> {
        self.ep.as_ref().expect("shadowquic dial endpoint present")
    }

    fn disarm(&mut self) -> Arc<ClientEndpoint> {
        self.ep.take().expect("shadowquic dial endpoint already taken")
    }
}

impl Drop for DialEndpointGuard {
    fn drop(&mut self) {
        if let Some(ep) = self.ep.take() {
            ep.close(b"dial aborted");
        }
    }
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").field("opts", &self.opts).finish()
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.keep_idle.store(false, Ordering::SeqCst);
        if let Some(conn) = self.conn.swap(None) {
            conn.mark_evicted();
        }
    }
}

impl Handler {
    pub fn new(name: String, opts: HandlerOptions) -> Self {
        Self {
            name,
            opts,
            client_config: OnceCell::new(),
            conn: Arc::new(ArcSwapOption::empty()),
            keep_idle: Arc::new(AtomicBool::new(true)),
            reconnect: AsyncMutex::new(()),
            #[cfg(test)]
            last_dial_local_addr: Mutex::new(None),
        }
    }

    async fn resolve_server(
        &self, resolver: ThreadSafeDNSResolver,
    ) -> io::Result<SocketAddr> {
        let addr = SocksAddr::from_str(&self.opts.addr).map_err(new_io_error)?;
        match addr {
            SocksAddr::Domain(host, port) => {
                let ip = resolver.resolve(&host, false).await
                    .map_err(new_io_error)?
                    .ok_or_else(|| io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "shadowquic server DNS returned no address",
                    ))?;
                Ok(SocketAddr::new(ip, port))
            }
            SocksAddr::Ip(addr) => Ok(addr),
        }
    }

    async fn prepare_conn(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<(ClientConnection, ShadowQuicLease)> {
        if let Some(conn) = self.conn.load().as_ref()
            && conn.is_alive()
            && let Some(lease) = conn.try_acquire_lease()
        {
            return Ok((ClientConnection::from_state(conn.clone()), lease));
        }
        let _reconnect = self.reconnect.lock().await;
        let existing = self.conn.load_full();
        if let Some(conn) = &existing
            && conn.is_alive()
            && let Some(lease) = conn.try_acquire_lease()
        {
            return Ok((ClientConnection::from_state(conn.clone()), lease));
        }
        if let Some(old) = existing.as_ref() {
            old.evict_from_cache();
        }
        // Resolve again after disconnects, retaining TLS/JLS tickets in
        // `client_config` across endpoint rebuilds.
        let addr = self.resolve_server(resolver).await?;
        let config = self
            .client_config
            .get_or_try_init(|| async { client_config(&self.opts) })
            .await?
            .clone();

        let mut ep_guard = DialEndpointGuard::new(Arc::new(
            ClientEndpoint::new_with_config(config, addr, sess).await?,
        ));
        #[cfg(test)]
        {
            *self.last_dial_local_addr.lock() = ep_guard.as_arc().local_addr().ok();
        }
        let quic_conn = ep_guard.as_arc().connect(&self.opts, addr).await?;
        let endpoint = ep_guard.disarm();
        let conn = ClientConnection::new_managed(
            quic_conn,
            Some(endpoint),
            self.keep_idle.clone(),
            Arc::downgrade(&self.conn),
        );
        let lease = conn
            .try_acquire_lease()
            .expect("fresh shadowquic connection must accept initial lease");

        self.publish_conn(&conn);
        Ok((conn, lease))
    }

    fn publish_conn(&self, conn: &ClientConnection) {
        if conn.is_alive() {
            if let Some(old) = self.conn.swap(Some(conn.state().clone())) {
                old.mark_evicted();
            }
            // Re-check liveness after publishing so an immediate close callback
            // that ran before caching cannot leave a dead connection cached, and
            // reclaim immediately if `keep_idle` is false and no leases remain.
            if !conn.is_alive() {
                conn.evict_from_cache();
                conn.mark_evicted();
            } else if !self.keep_idle.load(Ordering::SeqCst) {
                conn.close_if_idle();
            }
        } else {
            conn.mark_evicted();
        }
    }

    #[cfg(test)]
    fn last_dial_local_addr_for_test(&self) -> Option<SocketAddr> {
        *self.last_dial_local_addr.lock()
    }

    #[cfg(test)]
    fn cached_endpoint_for_test(&self) -> Option<Arc<ClientEndpoint>> {
        self.conn.load_full().and_then(|c| c.endpoint_for_test())
    }

    #[cfg(test)]
    fn cached_conn_for_test(&self) -> Option<ClientConnection> {
        self.conn.load_full().map(ClientConnection::from_state)
    }

    #[cfg(test)]
    fn has_client_config_for_test(&self) -> bool {
        self.client_config.get().is_some()
    }
}

impl DialWithConnector for Handler {}

impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.addr)
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType {
        OutboundType::ShadowQuic
    }

    /// whether the outbound handler support UDP
    fn support_udp(&self) -> bool {
        true
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let (conn, lease) = self.prepare_conn(sess, resolver).await?;
        let (mut send, recv) = conn.connection().open_bi().await
            .map_err(new_io_error)?;
        protocol::write_request(&mut send, protocol::CONNECT, &sess.destination).await?;
        let stream = ShadowQuicStream::new(send, recv, lease);
        sess.push_chain(self.name());
        Ok(AnyStream::new(stream))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        let (conn, lease) = self.prepare_conn(sess, resolver).await?;
        // clash-rs didn't expose udp associate address, so set to unspecified
        // address
        let addr = if sess.source.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let close_upload = CancellationToken::new();
        let socket = conn.associate_with_lease(
            addr.parse::<SocketAddr>().unwrap().into(),
            self.opts.over_stream,
            Some(lease),
            close_upload.clone(),
        ).await?;
        let chain = UdpSessionWrapper {
            s: PollSender::new(socket.0),
            r: socket.1,
            src_addr: sess.source.into(),
            close_upload,
        };
        sess.push_chain(self.name());
        Ok(AnyOutboundDatagram::new(chain))
    }

    fn set_keep_idle(&self, keep: bool) {
        self.keep_idle.store(keep, Ordering::SeqCst);
        if !keep {
            self.close_idle_connections();
        }
    }

    fn close_idle_connections(&self) {
        if let Some(conn) = self.conn.load_full() {
            conn.close_if_idle();
        }
    }
}

impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.addr.clone()) as _);
        m.insert(
            "server-name".to_owned(),
            Box::new(self.opts.server_name.clone()) as _,
        );
        m.insert(
            "username".to_owned(),
            Box::new(self.opts.username.clone()) as _,
        );
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        if !self.opts.alpn.is_empty() {
            m.insert("alpn".to_owned(), Box::new(self.opts.alpn.clone()) as _);
        }
        m
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::{io::Write, sync::Arc};

    use super::super::utils::test_utils::{
        consts::*, docker_runner::DockerTestRunner,
    };
    use crate::{
        proxy::utils::{
            GLOBAL_DIRECT_CONNECTOR,
            test_utils::{
                Suite,
                docker_runner::{DockerTestRunnerBuilder, alloc_docker_port},
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    use super::*;

    const SHADOWQUIC_SERVER_CONFIG: &str = r#"inbound:
    type: shadowquic
    bind-addr: 0.0.0.0:10002
    users:
      - password: "12345678"
        username: "87654321"
    jls-upstream:
        addr: "echo.free.beeceptor.com:443"
    alpn: ["h3"]
    congestion-control: bbr
    zero-rtt: true
outbound:
    type: direct
log-level: "trace"
"#;

    async fn get_shadowquic_runner(
        host_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(SHADOWQUIC_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOWQUIC)
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/shadowquic/config.yaml")])
            .host_port(host_port, 10002)
            .build()
            .await;
        drop(tmp);
        result
    }

    fn gen_options(
        opt_ip: Option<String>,
        host_port: u16,
        over_stream: bool,
    ) -> anyhow::Result<HandlerOptions> {
        let port = if opt_ip.is_some() { 10002 } else { host_port };
        Ok(HandlerOptions {
            addr: SocketAddr::new(
                opt_ip.unwrap_or(LOCAL_ADDR.to_owned()).parse().unwrap(),
                port,
            )
            .to_string(),
            password: "12345678".into(),
            username: "87654321".into(),
            server_name: "echo.free.beeceptor.com".into(),
            alpn: vec!["h3".into()],
            initial_mtu: 1400,
            zero_rtt: true,
            over_stream,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn test_shadowquic_over_datagram() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();

        let container = get_shadowquic_runner(host_port).await?;

        let container_ip = container.container_ip();

        let opts = gen_options(container_ip, host_port, false)?;

        let handler = Arc::new(Handler::new("test-shadowquic".into(), opts));
        run_test_suites_and_cleanup(OutboundNode::protocol(handler), container, Suite::all()).await
    }
    #[tokio::test]
    async fn test_shadowquic_over_stream() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let container = get_shadowquic_runner(host_port).await?;

        let container_ip = container.container_ip();

        let mut opts = gen_options(container_ip, host_port, true)?;
        opts.over_stream = true;

        let handler = Arc::new(Handler::new("test-shadowquic".into(), opts));
        run_test_suites_and_cleanup(OutboundNode::protocol(handler), container, Suite::all()).await
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use std::io::Write as _;

    use crate::{
        proxy::utils::test_utils::{
            config_helper,
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    const CONTAINER_PORT: u16 = 10002;
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB

    // Inlined from shadowquic.yaml
    const SHADOWQUIC_SERVER_CONFIG: &str = r#"inbound:
    type: shadowquic
    bind-addr: 0.0.0.0:10002
    users:
      - password: "12345678"
        username: "87654321"
    jls-upstream:
        addr: "echo.free.beeceptor.com:443"
    alpn: ["h3"]
    congestion-control: bbr
    zero-rtt: true
outbound:
    type: direct
log-level: "info"
"#;

    // Note: over-stream is a client-side setting; the server auto-detects the
    // mode, so we use the same server config as for plain shadowquic.
    const SHADOWQUIC_OVER_STREAM_SERVER_CONFIG: &str = r#"inbound:
    type: shadowquic
    bind-addr: 0.0.0.0:10002
    users:
      - password: "12345678"
        username: "87654321"
    jls-upstream:
        addr: "echo.free.beeceptor.com:443"
    alpn: ["h3"]
    congestion-control: bbr
    zero-rtt: true
outbound:
    type: direct
log-level: "info"
"#;

    async fn get_shadowquic_runner() -> anyhow::Result<DockerTestRunner> {
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(SHADOWQUIC_SERVER_CONFIG.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOWQUIC)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/shadowquic/config.yaml")])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_shadowquic_plain() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_shadowquic_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: shadowquic
    server: {server}
    port: {port}
    password: "12345678"
    username: "87654321"
    server-name: echo.free.beeceptor.com
    alpn:
      - h3
    zero-rtt: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "shadowquic-plain",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_shadowquic_plain_netem() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_shadowquic_runner().await?;
        container.apply_netem(50, 1.0).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: shadowquic
    server: {server}
    port: {port}
    password: "12345678"
    username: "87654321"
    server-name: echo.free.beeceptor.com
    alpn:
      - h3
    zero-rtt: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "shadowquic-plain-netem",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    async fn get_shadowquic_over_stream_runner() -> anyhow::Result<DockerTestRunner>
    {
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(SHADOWQUIC_OVER_STREAM_SERVER_CONFIG.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOWQUIC)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/shadowquic/config.yaml")])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_shadowquic_over_stream() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_shadowquic_over_stream_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: shadowquic
    server: {server}
    port: {port}
    password: "12345678"
    username: "87654321"
    server-name: echo.free.beeceptor.com
    alpn:
      - h3
    zero-rtt: true
    over-stream: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "shadowquic-over-stream",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }
}
