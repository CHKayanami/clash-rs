use std::io;
use super::{DialerProxyConnector, OutboundNodeRegistry, RemoteConnector};
use crate::{
    app::{dns::ThreadSafeDNSResolver, outbound::manager::OutboundManager},
    config::internal::proxy::OutboundProxyProtocol,
    proxy::{AnyOutboundDatagram, OutboundNode, AnyStream, DialWithConnector, OutboundHandler, OutboundType, mocks::{MockDummyOutboundHandler, MockDummyProxyProvider}, selector},
    session::{Session, SocksAddr},
};
use arc_swap::ArcSwap;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use crate::proxy::utils::test_utils::noop::NoopResolver;

async fn socks_server() -> (SocketAddr, tokio::task::JoinHandle<SocketAddr>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut hello = [0; 3];
        client.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 1, 0]);
        client.write_all(&[5, 0]).await.unwrap();
        let mut command = [0; 3];
        client.read_exact(&mut command).await.unwrap();
        assert_eq!(command, [5, 1, 0]);
        let target = SocksAddr::read_from(&mut client).await.unwrap();
        let target: SocketAddr = format!("{}:{}", target.host_cow(), target.port()).parse().unwrap();
        let mut upstream = TcpStream::connect(target).await.unwrap();
        client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        target
    });
    (address, task)
}

fn config(name: &str, server: SocketAddr, dialer: Option<&str>) -> OutboundProxyProtocol {
    let mut yaml = format!("type: socks5\nname: {name}\nserver: 127.0.0.1\nport: {}\n", server.port());
    if let Some(dialer) = dialer { yaml.push_str(&format!("dialer-proxy: {dialer}\n")); }
    yaml_serde::from_str(&yaml).unwrap()
}

fn registry() -> OutboundNodeRegistry {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

#[tokio::test]
async fn three_hop_dialer_proxy_preserves_every_hop() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = [0; 4];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let (a, a_task) = socks_server().await;
        let (b, b_task) = socks_server().await;
        let (c, c_task) = socks_server().await;
        let registry = registry();
        let handlers = OutboundManager::load_plain_outbounds(vec![
            config("c", c, Some("b")), config("b", b, Some("a")), config("a", a, None),
        ], &registry).unwrap();
        registry.store(Arc::new(handlers.into_iter().map(|h| (h.name().to_owned(), h)).collect()));
        let handler = registry.load().get("c").unwrap().clone();
        let resolver: ThreadSafeDNSResolver = Arc::new(NoopResolver);
        let mut stream = handler.connect_stream(&Session { destination: target.into(), ..Default::default() }, resolver).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        drop(stream);
        echo.await.unwrap();
        assert_eq!(a_task.await.unwrap(), b);
        assert_eq!(b_task.await.unwrap(), c);
        assert_eq!(c_task.await.unwrap(), target);
    }).await.unwrap();
}

#[tokio::test]
async fn named_dialer_observes_selector_and_provider_snapshot_changes() {
    use crate::proxy::selector::SelectorControl;
    let registry = registry();
    let leaf = |name: &str| -> OutboundNode {
        let mut handler = MockDummyOutboundHandler::new();
        handler.expect_name().return_const(name.to_owned());
        handler.expect_connect_stream().times(1).returning(|_, _| {
            let (stream, _) = tokio::io::duplex(64);
            Ok(stream.into())
        });
        OutboundNode::protocol(Arc::new(handler))
    };
    let first = leaf("first");
    let second = leaf("second");
    let snapshot = Arc::new(ArcSwap::from_pointee(vec![first, second]));
    let source = snapshot.clone();
    let mut provider = MockDummyProxyProvider::new();
    provider.expect_proxies().returning(move || source.load_full());
    provider.expect_touch().return_const(());
    let group = Arc::new(selector::Handler::new(selector::HandlerOptions {
        name: "entry".to_owned(), udp: true, ..Default::default()
    }, vec![Arc::new(provider)], None).await);
    registry.store(Arc::new(HashMap::from([("entry".to_owned(), OutboundNode::group(group.clone()))])));
    let connector = DialerProxyConnector::new("entry".to_owned(), &registry);
    // Each mock must receive exactly one dial, proving the actual route changes.
    for name in ["first", "second"] {
        group.select(name).unwrap();
        connector.connect_stream(Arc::new(NoopResolver), "127.0.0.1", 80, false, None,
            #[cfg(target_os = "linux")] None,
        ).await.unwrap();
    }
    snapshot.store(Arc::new(vec![leaf("replacement")]));
    connector.connect_stream(Arc::new(NoopResolver), "127.0.0.1", 80, false, None,
        #[cfg(target_os = "linux")] None,
    ).await.unwrap();
    assert_eq!(group.current(), "replacement");
}

#[tokio::test]
async fn runtime_cycle_is_an_error_and_registry_is_not_retained() {
    let registry = registry();
    let handlers = OutboundManager::load_plain_outbounds(vec![
        config("a", "127.0.0.1:1080".parse().unwrap(), Some("alias-b")),
        config("b", "127.0.0.1:1080".parse().unwrap(), Some("alias-a")),
    ], &registry).unwrap();
    let mut entries: HashMap<_, _> = handlers.into_iter().map(|h| (h.name().to_owned(), h)).collect();
    entries.insert("alias-a".to_owned(), entries["a"].clone());
    entries.insert("alias-b".to_owned(), entries["b"].clone());
    registry.store(Arc::new(entries));
    let connector = DialerProxyConnector::new("a".to_owned(), &registry);
    let error = tokio::time::timeout(Duration::from_secs(1), connector.connect_stream(
        Arc::new(NoopResolver), "127.0.0.1", 80, false, None,
        #[cfg(target_os = "linux")] None,
    )).await.unwrap().err().unwrap();
    assert!(error.to_string().contains("cyclic"));
    let weak = Arc::downgrade(&registry);
    drop(registry);
    assert!(weak.upgrade().is_none());
}

#[derive(Debug)]
pub struct SpawnedDialer(Arc<RemoteConnector>);

impl DialWithConnector for SpawnedDialer {}

impl OutboundHandler for SpawnedDialer {
    fn name(&self) -> &str { "spawned" }
    fn proto(&self) -> OutboundType { OutboundType::Direct }
    fn support_udp(&self) -> bool { false }
    async fn connect_stream(&self, _sess: &Session, resolver: ThreadSafeDNSResolver) -> io::Result<AnyStream> {
        let connector = self.0.clone_connector();
        tokio::spawn(async move {
            connector.connect_stream(resolver, "127.0.0.1", 80, false, None,
                #[cfg(target_os = "linux")] None,
            ).await
        }).await.unwrap()
    }
    async fn connect_datagram(&self, _sess: &Session, _resolver: ThreadSafeDNSResolver) -> io::Result<AnyOutboundDatagram> {
        Err(io::Error::other("not used"))
    }
}

#[tokio::test]
async fn dialer_proxy_cycle_guard_survives_spawned_transport_workers() {
    let registry = registry();
    let connector = Arc::new(RemoteConnector::DialerProxy(DialerProxyConnector::new("spawned".to_owned(), &registry)));
    let handler: OutboundNode = OutboundNode::protocol(Arc::new(SpawnedDialer(connector.clone())));
    registry.store(Arc::new(HashMap::from([("spawned".to_owned(), handler)])));
    let error = tokio::time::timeout(Duration::from_secs(1), connector.connect_stream(
        Arc::new(NoopResolver), "127.0.0.1", 80, false, None,
        #[cfg(target_os = "linux")] None,
    )).await.unwrap().err().unwrap();
    assert!(error.to_string().contains("cyclic"));
}

#[tokio::test]
async fn runtime_dialer_cycle_through_group_is_rejected() {
    let registry = registry();
    let exit = OutboundManager::load_plain_outbounds(vec![
        config("exit", "127.0.0.1:1080".parse().unwrap(), Some("entry")),
    ], &registry).unwrap().remove(0);
    let snapshot = Arc::new(vec![exit.clone()]);
    let mut provider = MockDummyProxyProvider::new();
    provider.expect_proxies().returning(move || snapshot.clone());
    provider.expect_touch().return_const(());
    let entry = OutboundNode::group(Arc::new(selector::Handler::new(
        selector::HandlerOptions { name: "entry".to_owned(), ..Default::default() },
        vec![Arc::new(provider)], None,
    ).await));
    let weak = entry.downgrade();
    assert!(entry.ptr_eq(&entry.clone()));
    assert!(weak.ptr_eq(&entry.downgrade()));
    registry.store(Arc::new(HashMap::from([
        ("entry".to_owned(), entry.clone()), ("exit".to_owned(), exit),
    ])));
    let connector = DialerProxyConnector::new("entry".to_owned(), &registry);
    let error = tokio::time::timeout(Duration::from_secs(1), connector.connect_stream(
        Arc::new(NoopResolver), "127.0.0.1", 80, false, None,
        #[cfg(target_os = "linux")] None,
    )).await.unwrap().err().unwrap();
    assert!(error.to_string().contains("cyclic"));
    registry.store(Arc::new(HashMap::new()));
    drop(entry);
    assert!(weak.upgrade().is_none());
}
