use std::{collections::HashMap, io, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use tokio::{io::{AsyncBufReadExt, BufReader}, net::TcpListener, time::timeout};

use crate::{
    app::outbound::manager::OutboundManager,
    config::internal::proxy::{OutboundProxyProtocol, OutboundSsh},
    proxy::{
        OutboundHandler, OutboundNode, mocks::MockDummyOutboundHandler,
        utils::{OutboundNodeRegistry, test_utils::noop::NoopResolver},
    },
    session::Session,
};

use super::Handler;

fn handler(registry: &OutboundNodeRegistry, port: u16) -> OutboundNode {
    let config: OutboundProxyProtocol = yaml_serde::from_str(&format!(
        "type: ssh\nname: exit\nserver: 127.0.0.1\nport: {port}\nusername: test-only\ndialer-proxy: entry\n"
    )).unwrap();
    OutboundManager::load_plain_outbounds(vec![config], registry).unwrap().remove(0)
}

#[tokio::test]
async fn missing_dialer_connector_does_not_open_a_direct_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config: OutboundSsh = yaml_serde::from_str(&format!(
        "name: exit\nserver: 127.0.0.1\nport: {port}\nusername: test-only\ndialer-proxy: entry\n"
    )).unwrap();
    let exit = Handler::try_from(config).unwrap();
    let error = timeout(Duration::from_secs(1), exit.connect_stream(
        &Session::default(), Arc::new(NoopResolver),
    )).await.unwrap().err().expect("missing connector must fail");
    assert!(error.to_string().contains("connector is unavailable"));
    assert!(timeout(Duration::from_millis(50), listener.accept()).await.is_err());
}

#[tokio::test]
async fn dialer_failure_does_not_open_a_direct_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut entry = MockDummyOutboundHandler::new();
    entry.expect_connect_stream().times(1).returning(move |sess, _| {
        assert_eq!(sess.destination.host(), "127.0.0.1");
        assert_eq!(sess.destination.port(), port);
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "test dialer denied"))
    });
    let registry = Arc::new(ArcSwap::from_pointee(HashMap::from([
        ("entry".to_owned(), OutboundNode::protocol(Arc::new(entry))),
    ])));
    let exit = handler(&registry, port);
    let error = timeout(Duration::from_secs(1), exit.connect_stream(
        &Session::default(), Arc::new(NoopResolver),
    )).await.unwrap().err().expect("dialer failure must propagate");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "test dialer denied");
    assert!(timeout(Duration::from_millis(50), listener.accept()).await.is_err());
}

#[tokio::test]
async fn ssh_handshake_uses_the_dialer_stream() {
    let (stream, peer) = tokio::io::duplex(1024);
    let peer = tokio::spawn(async move {
        let mut reader = BufReader::new(peer);
        let mut identification = String::new();
        reader.read_line(&mut identification).await.unwrap();
        assert!(identification.starts_with("SSH-2.0-"));
        // Closing before key exchange makes the test independent of an SSH server.
    });
    let mut stream = Some(stream);
    let mut entry = MockDummyOutboundHandler::new();
    entry.expect_connect_stream().times(1).returning(move |_, _| {
        Ok(stream.take().unwrap().into())
    });
    let registry = Arc::new(ArcSwap::from_pointee(HashMap::from([
        ("entry".to_owned(), OutboundNode::protocol(Arc::new(entry))),
    ])));
    let exit = handler(&registry, 9);
    assert!(timeout(Duration::from_secs(1), exit.connect_stream(
        &Session::default(), Arc::new(NoopResolver),
    )).await.unwrap().is_err());
    timeout(Duration::from_secs(1), peer).await.unwrap().unwrap();
}
