use super::*;

#[tokio::test]
async fn dropping_flow_closes_it_with_all_registration_capacity_reserved() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, _, _servers) = outbound();
    let flow = fixture.connect(&outbound, &session(30001)).await;
    let association = flow.association.clone();
    let state = Arc::downgrade(&flow.state);
    let permits: Vec<_> = (0..QUEUE_CAPACITY)
        .map(|_| association.control.try_reserve().unwrap()).collect();
    drop(flow);
    timeout(Duration::from_secs(2), async {
        while state.upgrade().is_some() { tokio::task::yield_now().await; }
    }).await.expect("closing must not require space in the registration queue");
    assert!(fixture.manager.active_connections_snapshot().is_empty());
    assert!(!association.outgoing.is_closed());
    drop(permits);
}

#[tokio::test]
async fn admission_failure_preserves_original_domain_address_and_packet() {
    let mut flow = inert_flow();
    let original = SocksAddr::Domain("example.test".into(), 53);
    let state = Arc::get_mut(&mut flow.state).unwrap();
    state.target = "192.0.2.1:53".parse::<SocketAddr>().unwrap().into();
    state.original = original.clone();
    let (outgoing, mut packets) = mpsc::channel(1);
    let (control, _commands) = mpsc::channel(1);
    flow.association = Arc::new(Association { id: 0, outgoing, control,
        chain: vec![], task: tokio::spawn(std::future::pending()) });
    let packet = UdpPacket::new(Bytes::from_static(b"first"), flow.state.source.into(), original.clone());
    flow.try_send(packet).unwrap();
    let mut packet = UdpPacket::new(Bytes::from_static(b"retry"), flow.state.source.into(), original.clone());
    packet.inbound_user = Some("test-user".into());
    let Err(mpsc::error::TrySendError::Full(packet)) = flow.try_send(packet)
        else { panic!("expected full queue"); };
    assert_eq!(packet.dst_addr, original);
    assert_eq!(packet.src_addr, flow.state.source.into());
    assert_eq!(packet.data.as_ref(), b"retry");
    assert_eq!(packet.inbound_user.as_deref(), Some("test-user"));
    packets.close();
    let Err(mpsc::error::TrySendError::Closed(packet)) = flow.try_send(packet)
        else { panic!("expected closed queue"); };
    assert_eq!(packet.dst_addr, original);
}

#[tokio::test]
async fn old_worker_cannot_remove_slot_while_replacement_dial_is_pending() {
    use tokio::net::TcpListener;
    use crate::proxy::socks::outbound::{Handler, HandlerOptions};
    let fixture = Fixture::new(Duration::from_secs(60));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outbound: ProtocolOutbound = Arc::new(Handler::new(HandlerOptions {
        name: "test-socks".to_owned(), server: "127.0.0.1".to_owned(),
        port: listener.local_addr().unwrap().port(), ..Default::default()
    }, None)).into();
    let sess = session(30001);
    let slot = fixture.pool.slot(AssociationKey { outbound: outbound.identity(),
        source: sess.source, inbound: sess.typ, user: None, interface: None,
        mark: sess.so_mark, isolated: None }, &outbound);
    slot.generation.store(77, Ordering::Relaxed);
    let (outgoing, packets) = mpsc::channel(1);
    drop(packets);
    let (control, _commands) = mpsc::channel(1);
    *slot.association.lock().await = Some(Arc::new(Association { id: 77,
        outgoing, control, chain: vec![], task: tokio::spawn(std::future::pending()) }));
    let old_worker = WorkerGuard(Arc::downgrade(&slot), 77);
    let pool = fixture.pool.clone();
    let task = tokio::spawn(async move {
        pool.connect(&outbound, &sess, resolver(), Arc::new(TrackerInfo::new(&sess, None))).await
    });
    let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept()).await.unwrap().unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), 5);
    drop(old_worker);
    assert!(fixture.pool.shard(&slot.key).lock().get(&slot.key)
        .is_some_and(|current| Arc::ptr_eq(current, &slot)));
    task.abort();
    assert!(matches!(task.await, Err(err) if err.is_cancelled()));
    assert_eq!(slot_count(&fixture.pool), 0);
    assert_eq!(fixture.pool.config.capacity.available_permits(), 64);
}

#[tokio::test]
async fn waiter_retries_a_slot_removed_before_it_acquires_the_dial_lock() {
    let fixture = Fixture::new(Duration::from_secs(60));
    let (outbound, count, _servers) = outbound();
    let sess = session(30001);
    let slot = fixture.pool.slot(AssociationKey { outbound: outbound.identity(),
        source: sess.source, inbound: sess.typ, user: None, interface: None,
        mark: sess.so_mark, isolated: None }, &outbound);
    let locked = slot.association.lock().await;
    let pool = fixture.pool.clone();
    let leaf = outbound.clone();
    let task = tokio::spawn(async move {
        pool.connect(&leaf, &sess, resolver(), Arc::new(TrackerInfo::new(&sess, None))).await
    });
    tokio::task::yield_now().await;
    drop(WorkerGuard(Arc::downgrade(&slot), 0));
    assert_eq!(slot_count(&fixture.pool), 0);
    drop(locked);
    let first = timeout(Duration::from_secs(2), task).await.unwrap().unwrap().unwrap();
    let second = fixture.connect(&outbound, &session(30002)).await;
    assert!(Arc::ptr_eq(&first.association, &second.association));
    assert_eq!(slot_count(&fixture.pool), 1);
    assert_eq!(count.load(Ordering::Relaxed), 1);
}
