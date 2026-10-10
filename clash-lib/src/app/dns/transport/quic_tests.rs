use super::*;
use crate::app::dns::endpoint::{DnsProtocol, DnsStrategy};
use crate::proxy::direct;
use std::sync::atomic::Ordering;

fn dial() -> super::super::dial::DialContext {
    super::super::dial::DialContext {
        endpoint: DnsEndpoint::parse(
            "127.0.0.1:853",
            DnsProtocol::Quic,
            None,
            None,
            DnsStrategy::PreferIpv4,
        )
        .unwrap(),
        dial_timeout: Duration::from_secs(1),
        query_timeout: Duration::from_secs(1),
        outbound: Some(Arc::new(direct::Handler::new("test-outbound"))),
        iface: None,
        so_mark: None,
        resolver: None,
    }
}

#[tokio::test]
async fn obsolete_idle_proxy_associations_are_reclaimed() {
    let active = Arc::new(AtomicUsize::new(0));
    let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
    let old = "127.0.0.1:853".parse().unwrap();
    let current = "127.0.0.2:853".parse().unwrap();
    shared.get(old).await.unwrap();
    shared.get(current).await.unwrap();
    let old_socket = shared.endpoints.lock()[&(false, Some(old))]
        .cached.load_full().unwrap()
        .proxy_socket
        .clone()
        .unwrap();
    let current_socket = shared.endpoints.lock()[&(false, Some(current))]
        .cached.load_full().unwrap()
        .proxy_socket
        .clone()
        .unwrap();
    shared.prune(&[current]).await;
    assert!(old_socket.is_closed());
    assert!(!current_socket.is_closed());
    assert_eq!(shared.endpoints.lock().len(), 1);
    assert_eq!(active.load(Ordering::SeqCst), 2);
    shared.close(Duration::ZERO).await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn obsolete_proxy_association_survives_until_its_connection_finishes() {
    let (server, config) = super::super::quic_test_support::server(b"doq");
    let target = server.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
    let endpoint = shared.get(target).await.unwrap();
    let (client, remote) = tokio::join!(
        endpoint.connect_with(config, target, "localhost").unwrap(),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let connection = client.unwrap();
    let socket = shared.endpoints.lock()[&(false, Some(target))]
        .cached.load_full().unwrap()
        .proxy_socket
        .clone()
        .unwrap();
    shared.prune(&[]).await;
    assert!(!socket.is_closed());
    assert!(shared.endpoints.lock().is_empty());
    assert_eq!(shared.retired.lock().len(), 1);
    assert!(connection.close_reason().is_none());
    connection.close(0_u32.into(), b"done");
    remote.closed().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        endpoint.wait_idle().await;
        while active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    shared.prune(&[]).await;
    assert!(shared.retired.lock().is_empty());
    assert!(socket.is_closed());
    assert!(shared.endpoints.lock().is_empty());
    assert_eq!(active.load(Ordering::SeqCst), 0);
    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn shutdown_closes_retiring_associations_and_cleanup_tasks() {
    let (server, config) = super::super::quic_test_support::server(b"doq");
    let target = server.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
    let endpoint = shared.get(target).await.unwrap();
    let (client, remote) = tokio::join!(
        endpoint.connect_with(config, target, "localhost").unwrap(),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let connection = client.unwrap();
    shared.prune(&[]).await;
    assert_eq!(shared.retired.lock().len(), 1);
    shared.close(Duration::ZERO).await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(shared.retired.lock().is_empty());
    assert!(connection.close_reason().is_some());
    remote.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}

#[tokio::test]
async fn failed_proxy_association_is_recreated() {
    let active = Arc::new(AtomicUsize::new(0));
    let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
    let target = "127.0.0.1:853".parse().unwrap();
    let key = (false, Some(target));
    let first_endpoint = shared.get(target).await.unwrap();
    let first = shared.endpoints.lock()[&key]
        .cached.load_full().unwrap()
        .proxy_socket
        .clone()
        .unwrap();
    first.close().await;
    let second_endpoint = shared.get(target).await.unwrap();
    let second = shared.endpoints.lock()[&key]
        .cached.load_full().unwrap()
        .proxy_socket
        .clone()
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(!second.is_closed());
    assert_eq!(shared.endpoints.lock().len(), 1);
    shared.close(Duration::ZERO).await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
    drop((first_endpoint, second_endpoint));
}

#[tokio::test]
async fn outbound_without_udp_fails_without_direct_fallback() {
    let active = Arc::new(AtomicUsize::new(0));
    let mut context = dial();
    context.outbound =
        Some(Arc::new(crate::proxy::reject::Handler::new("no-udp")));
    let shared = SharedQuicEndpoint::with_dial(context, active.clone());
    let result = shared.get("127.0.0.1:853".parse().unwrap()).await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("does not support UDP")
    );
    assert!(shared.endpoints.lock().values().all(|slot| slot.cached.load().is_none()));
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn concurrent_gets_share_one_proxy_association() {
    let active = Arc::new(AtomicUsize::new(0));
    let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
    let target = "127.0.0.1:853".parse().unwrap();
    let requests = (0..32).map(|_| shared.get(target));
    for result in futures::future::join_all(requests).await {
        result.unwrap();
    }
    assert_eq!(shared.endpoints.lock().len(), 1);
    assert_eq!(active.load(Ordering::SeqCst), 2);
    shared.close(Duration::ZERO).await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(shared.get(target).await.is_err());
}

#[tokio::test]
async fn initializing_one_address_does_not_block_another() {
    let active = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(SharedQuicEndpoint::with_dial(dial(), active.clone()));
    let slow = "127.0.0.1:853".parse().unwrap();
    let other = "127.0.0.2:853".parse().unwrap();
    let slot = Arc::new(EndpointSlot::new());
    let initialize = slot.initialize.lock().await;
    shared.endpoints.lock().insert((false, Some(slow)), slot.clone());
    let waiting = tokio::spawn({
        let shared = shared.clone();
        async move { shared.get(slow).await }
    });
    tokio::task::yield_now().await;
    tokio::time::timeout(Duration::from_secs(1), shared.get(other))
        .await.unwrap().unwrap();
    assert!(!waiting.is_finished());
    waiting.abort();
    let _ = waiting.await;
    drop(initialize);
    shared.get(slow).await.unwrap();
    shared.close(Duration::ZERO).await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_prune_keeps_initializing_slot_registered() {
    let shared = SharedQuicEndpoint::with_dial(dial(), Arc::new(AtomicUsize::new(0)));
    let target = "127.0.0.1:853".parse().unwrap();
    let slot = Arc::new(EndpointSlot::new());
    let initialize = slot.initialize.lock().await;
    shared.endpoints.lock().insert((false, Some(target)), slot.clone());
    let mut prune = Box::pin(shared.prune(&[]));
    tokio::select! {
        _ = &mut prune => panic!("prune skipped initialization"),
        _ = tokio::task::yield_now() => {}
    }
    drop(prune);
    assert!(Arc::ptr_eq(&shared.endpoints.lock()[&(false, Some(target))], &slot));
    drop(initialize);
    shared.get(target).await.unwrap();
    shared.close(Duration::ZERO).await;
}

#[tokio::test]
async fn cancelled_close_can_be_completed_by_next_caller() {
    let active = Arc::new(AtomicUsize::new(0));
    let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
    let target = "127.0.0.1:853".parse().unwrap();
    shared.get(target).await.unwrap();
    let permit = shared.admission.admit().unwrap();
    let mut close = Box::pin(shared.close(Duration::ZERO));
    tokio::select! {
        _ = &mut close => panic!("close skipped an admitted operation"),
        _ = tokio::task::yield_now() => {}
    }
    drop(close);
    assert!(shared.get(target).await.is_err());
    drop(permit);
    shared.close(Duration::ZERO).await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
}


#[tokio::test]
async fn close_waits_for_admitted_creation_and_reclaims_its_workers() {
    let active = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(SharedQuicEndpoint::with_dial(dial(), active.clone()));
    let target = "127.0.0.1:853".parse().unwrap();
    let slot = Arc::new(EndpointSlot::new());
    let initialize = slot.initialize.lock().await;
    shared.endpoints.lock().insert((false, Some(target)), slot.clone());
    let creation = tokio::spawn({
        let shared = shared.clone();
        async move { shared.get(target).await }
    });
    tokio::task::yield_now().await;
    let closing = tokio::spawn({
        let shared = shared.clone();
        async move { shared.close(Duration::ZERO).await }
    });
    tokio::task::yield_now().await;
    assert!(!closing.is_finished());
    drop(initialize);
    creation.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(1), closing).await.unwrap().unwrap();
    assert!(shared.endpoints.lock().is_empty());
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelling_close_after_detaching_endpoint_aborts_workers() {
    let (server, config) = super::super::quic_test_support::server(b"doq");
    let target = server.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let shared = SharedQuicEndpoint::with_dial(dial(), active.clone());
    let endpoint = shared.get(target).await.unwrap();
    let (client, remote) = tokio::join!(
        endpoint.connect_with(config, target, "localhost").unwrap(),
        async { server.accept().await.unwrap().await.unwrap() },
    );
    let connection = client.unwrap();
    let socket = shared.endpoints.lock()[&(false, Some(target))]
        .cached.load_full().unwrap().proxy_socket.clone().unwrap();
    let mut close = Box::pin(shared.close(Duration::from_secs(60)));
    tokio::select! {
        biased;
        _ = &mut close => panic!("connection skipped draining"),
        _ = tokio::task::yield_now() => {}
    }
    assert!(shared.endpoints.lock().is_empty());
    drop(close);
    assert!(socket.is_closed());
    tokio::time::timeout(Duration::from_secs(1), async {
        while active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    shared.close(Duration::ZERO).await;
    drop(connection);
    remote.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}
