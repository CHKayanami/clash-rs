use super::*;
use crate::{
    proxy::{HandlerCommonOptions, direct, mocks::MockDummyOutboundHandler, transport::TransportDialer},
    proxy::utils::test_utils::noop::NoopResolver,
};

#[tokio::test]
async fn xhttp_factory_keys_and_redials_follow_captured_ancestry() {
    let mut leaf = MockDummyOutboundHandler::new();
    leaf.expect_name().return_const("a".to_owned());
    leaf.expect_connect_stream().times(1).return_once(|_, _| {
        let (stream, _) = tokio::io::duplex(64);
        Ok(stream.into())
    });
    let a = OutboundNode::protocol(Arc::new(leaf));
    let b = OutboundNode::protocol(Arc::new(direct::Handler::new("b")));
    let registry = Arc::new(ArcSwap::from_pointee(HashMap::from([("entry".to_owned(), a.clone())])));
    let connector = RemoteConnector::DialerProxy(DialerProxyConnector::new("entry".to_owned(), &registry));
    let scope = DialerProxyConnector::new("scope".to_owned(), &registry);
    let common = HandlerCommonOptions::default();
    let session = Session::default();
    let dialer = TransportDialer {
        server: "127.0.0.1", port: 80, common: &common, session: &session, tls: None,
        resolver: Arc::new(NoopResolver), connector: &connector,
    };
    let old = scope.scoped(&a, async { dialer.factory() }).await.unwrap();
    let same = scope.scoped(&a, async { dialer.factory() }).await.unwrap();
    let new = scope.scoped(&b, async { dialer.factory() }).await.unwrap();
    assert_eq!(old.key, same.key);
    assert_ne!(old.key, new.key);
    let error = tokio::spawn(async move { (old.dial)().await }).await.unwrap().err().unwrap();
    assert!(error.to_string().contains("cyclic"));
    tokio::spawn(async move { (new.dial)().await }).await.unwrap().unwrap();
}

#[tokio::test]
async fn association_pins_registry_targets_and_does_not_retain_nodes_in_factories() {
    let first = OutboundNode::protocol(Arc::new(direct::Handler::new("first")));
    let second = OutboundNode::protocol(Arc::new(direct::Handler::new("second")));
    let registry = Arc::new(ArcSwap::from_pointee(HashMap::from([("entry".to_owned(), first.clone())])));
    let connector = DialerProxyConnector::new("entry".to_owned(), &registry);
    let (worker, retained) = dialer_route::association(true, async {
        let selected = dialer_route::target(connector.pool_key(), || connector.handler()).unwrap();
        assert!(selected.ptr_eq(&first));
        registry.store(Arc::new(HashMap::from([("entry".to_owned(), second.clone())])));
        let selected = dialer_route::target(connector.pool_key(), || connector.handler()).unwrap();
        assert!(selected.ptr_eq(&first));
        (connector.clone_connector(), dialer_route::retain().unwrap())
    }).await;
    assert!(connector.handler().unwrap().ptr_eq(&second));
    let RemoteConnector::DialerProxy(captured) = worker.as_ref() else { unreachable!() };
    let selected = dialer_route::scoped(captured.route.as_ref(), async {
        dialer_route::target(captured.pool_key(), || captured.handler())
    }).await.unwrap();
    assert!(selected.ptr_eq(&first));
    drop(selected);
    drop(retained);
    let error = worker.connect_stream(Arc::new(NoopResolver), "127.0.0.1", 80, false, None,
        #[cfg(target_os = "linux")] None,
    ).await.err().unwrap();
    assert!(error.to_string().contains("association released"));
    let weak = first.downgrade();
    drop(first);
    assert!(weak.upgrade().is_none());
}
