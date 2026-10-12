use super::*;
use aya::EbpfLoader;
use clash_ebpf_common::{RedirectEntry, tracking::DIRECT};

const BYTECODE: &[u8] = include_bytes!(env!("CLASH_EBPF_OBJECT"));

fn tuple(index: u16, proto: u8) -> RedirectTuple {
    RedirectTuple { src_port: index, proto, ip_version: 4, ..RedirectTuple::default() }
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn bounded_batches_reclaim_expired_records_and_preserve_active_tcp() {
    let bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let mut collector = Collector::new(&bpf).unwrap();
    let now = 1_000_000_000_000;
    for index in 0..(CHUNK * 2 + 17) as u16 {
        let entry = FlowTrackEntry { last_seen_seconds: 1, state: index as u32 + 1, ..FlowTrackEntry::default() };
        collector.flows.map.insert(tuple(index, 17), entry, 0).unwrap();
    }
    let tcp = tuple(u16::MAX, 6);
    collector.flows.map.insert(tcp, FlowTrackEntry { last_seen_seconds: 1, state: 1 | DIRECT,
        ..FlowTrackEntry::default() }, 0).unwrap();
    let live_udp = tuple(u16::MAX, 17);
    collector.flows.map.insert(live_udp, FlowTrackEntry { last_seen_seconds: 1000, state: 2,
        ..FlowTrackEntry::default() }, 0).unwrap();
    let expired_reply = UdpReplyKey { client_port: 1, ..UdpReplyKey::default() };
    let live_reply = UdpReplyKey { client_port: 2, ..UdpReplyKey::default() };
    collector.replies.map.insert(expired_reply, UdpReplyEntry { last_seen_ns: 1,
        ..UdpReplyEntry::default() }, 0).unwrap();
    collector.replies.map.insert(live_reply, UdpReplyEntry { last_seen_ns: now,
        ..UdpReplyEntry::default() }, 0).unwrap();
    for _ in 0..8 {
        collector.step(now).unwrap();
        if collector.flows.cursor.is_none() { break; }
    }
    assert!(collector.flows.cursor.is_none(), "batch cursor completes despite deletions");
    assert_eq!(collector.flows.map.keys().count(), 2);
    assert!(collector.flows.map.get(&tcp, 0).is_ok());
    assert!(collector.flows.map.get(&live_udp, 0).is_ok());
    assert!(collector.replies.map.get(&expired_reply, 0).is_err());
    assert!(collector.replies.map.get(&live_reply, 0).is_ok());
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn recheck_preserves_records_refreshed_after_the_batch_snapshot() {
    let bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let mut scanner = Scanner::<RedirectTuple, FlowTrackEntry>::new(&bpf, "FLOW_TRACK").unwrap();
    let mut writer = Scanner::<RedirectTuple, FlowTrackEntry>::new(&bpf, "FLOW_TRACK").unwrap();
    let key = tuple(1, 17);
    let old = FlowTrackEntry { last_seen_seconds: 1, state: 1, ..FlowTrackEntry::default() };
    let fresh = FlowTrackEntry { last_seen_seconds: 1000, state: 1,
        route: RedirectEntry { ifindex: 9, ..RedirectEntry::default() }, ..FlowTrackEntry::default() };
    writer.map.insert(key, old, 0).unwrap();
    scanner.step(|key, observed| {
        if observed.activity() == old.activity() {
            writer.map.insert(*key, fresh, 0).unwrap();
            true
        } else { false }
    }).unwrap();
    assert_eq!(scanner.map.get(&key, 0).unwrap(), fresh);
}
