use super::*;
use super::super::{ReplyActivity, tests::inert_flow};
use std::sync::atomic::{AtomicBool, Ordering};

fn state(address: SocksAddr, original: SocksAddr) -> Arc<FlowState> {
    let mut flow = inert_flow();
    let state = Arc::get_mut(&mut flow.state).unwrap();
    state.target = address.clone();
    state.original = original;
    state.aliases = vec![address];
    state.closed = AtomicBool::new(false);
    state.activity = Arc::new(ReplyActivity::new());
    let state = flow.state.clone();
    drop(flow);
    state.closed.store(false, Ordering::Relaxed);
    state
}

#[tokio::test]
async fn real_ip_history_drops_peer_owners_and_still_prevents_fake_ip_rebinding() {
    let address: SocksAddr = "192.0.2.1:53".parse::<SocketAddr>().unwrap().into();
    let mut table = PeerTable::default();
    let first = state(address.clone(), address.clone());
    table.register(&first).unwrap();
    table.remove(&first, &HashMap::new());
    assert!(table.peers.is_empty());
    assert_eq!(table.real_history.len(), 1);
    assert_eq!(table.reply(&address), (None, None));
    let fake = state(address.clone(), "198.18.0.1:53".parse::<SocketAddr>().unwrap().into());
    assert_eq!(table.register(&fake).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    let again = state(address.clone(), address.clone());
    table.register(&again).unwrap();
    assert!(table.real_history.is_empty());
    assert_eq!(table.reply(&address).0, Some(again.id));
}

#[tokio::test]
async fn address_restoration_history_survives_owner_removal() {
    let real: SocksAddr = "192.0.2.1:53".parse::<SocketAddr>().unwrap().into();
    let fake: SocksAddr = "198.18.0.1:53".parse::<SocketAddr>().unwrap().into();
    let domain = SocksAddr::Domain("example.test".into(), 53);
    for original in [fake, domain] {
        let mut table = PeerTable::default();
        let flow = state(real.clone(), original.clone());
        table.register(&flow).unwrap();
        table.remove(&flow, &HashMap::new());
        assert_eq!(table.reply(&real), (None, Some(&original)));
        assert!(table.real_history.is_empty());
    }
}

#[tokio::test]
async fn compacting_history_reclaims_heavy_buckets_after_many_real_flows() {
    let mut table = PeerTable::default();
    let mut flows = HashMap::new();
    for port in 1..=256 {
        let address: SocksAddr = SocketAddr::from(([192, 0, 2, 1], port)).into();
        let flow = state(address.clone(), address);
        table.register(&flow).unwrap();
        flows.insert(flow.id, flow);
    }
    let capacity = table.peers.capacity();
    while let Some(id) = flows.keys().next().copied() {
        let flow = flows.remove(&id).unwrap();
        table.remove(&flow, &flows);
    }
    assert!(table.peers.is_empty());
    assert_eq!(table.real_history.len(), 256);
    assert!(table.peers.capacity() < capacity);
}
