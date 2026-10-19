use super::*;
use aya::{EbpfLoader, maps::Array};
use clash_ebpf_common::{RedirectEntry, tracking::{CLOSING, DIRECT, gate::{bucket, reply_bucket}}};

const BYTECODE: &[u8] = include_bytes!(env!("CLASH_EBPF_OBJECT"));

fn tuple(index: u16, proto: u8) -> RedirectTuple {
    RedirectTuple { src_port: index, proto, ip_version: 4, ..RedirectTuple::default() }
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn bounded_batches_reclaim_expired_records_and_preserve_active_tcp() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let mut collector = Collector::new(&mut bpf).unwrap();
    assert_eq!(collector.pause(), BATCH_PAUSE);
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
    let expired_reply = UdpReplyKey { peer_ip: [1; 16], ..UdpReplyKey::default() };
    let live_reply = UdpReplyKey { peer_ip: [2; 16], ..UdpReplyKey::default() };
    collector.replies.map.insert(expired_reply, UdpReplyEntry { last_seen_ns: 1,
        ..UdpReplyEntry::default() }, 0).unwrap();
    collector.replies.map.insert(live_reply, UdpReplyEntry { last_seen_ns: now,
        ..UdpReplyEntry::default() }, 0).unwrap();
    for _ in 0..8 {
        collector.step(now).unwrap();
        if collector.flows.cursor.is_none() { break; }
        assert_eq!(collector.pause(), BATCH_PAUSE);
    }
    assert!(collector.flows.cursor.is_none(), "batch cursor completes despite deletions");
    assert_eq!(collector.pause(), Duration::from_secs(5));
    assert_eq!(collector.flows.map.keys().count(), 2);
    assert!(collector.flows.map.get(&tcp, 0).is_ok());
    assert!(collector.flows.map.get(&live_udp, 0).is_ok());
    assert!(collector.replies.map.get(&expired_reply, 0).is_err());
    assert!(collector.replies.map.get(&live_reply, 0).is_ok());
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn recheck_preserves_records_refreshed_after_the_batch_snapshot() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let mut scanner = Scanner::<RedirectTuple, FlowTrackEntry>::new(&bpf, "FLOW_TRACK").unwrap();
    let mut writer = Scanner::<RedirectTuple, FlowTrackEntry>::new(&bpf, "FLOW_TRACK").unwrap();
    let key = tuple(1, 17);
    let old = FlowTrackEntry { last_seen_seconds: 1, state: 1, ..FlowTrackEntry::default() };
    let fresh = FlowTrackEntry { last_seen_seconds: 1000, state: 1,
        route: RedirectEntry { ifindex: 9, ..RedirectEntry::default() }, ..FlowTrackEntry::default() };
    writer.map.insert(key, old, 0).unwrap();
    let mut gc = GcProgram::new(&mut bpf).unwrap();
    scanner.step(&mut gc, 1_000_000_000_000, |key, observed| {
        if observed.activity() == old.activity() {
            writer.map.insert(*key, fresh, 0).unwrap();
            true
        } else { false }
    }).unwrap();
    assert_eq!(scanner.map.get(&key, 0).unwrap(), fresh);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn recheck_preserves_a_new_incarnation_even_with_the_same_expired_timestamp() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let mut scanner = Scanner::<RedirectTuple, FlowTrackEntry>::new(&bpf, "FLOW_TRACK").unwrap();
    let mut writer = Scanner::<RedirectTuple, FlowTrackEntry>::new(&bpf, "FLOW_TRACK").unwrap();
    let key = tuple(1, 6);
    let old = FlowTrackEntry { last_seen_seconds: 1,
        state: 1 | CLOSING, generation: 1, ..FlowTrackEntry::default() };
    let replacement = FlowTrackEntry { generation: 2, ..old };
    writer.map.insert(key, old, 0).unwrap();
    let mut gc = GcProgram::new(&mut bpf).unwrap();
    scanner.step(&mut gc, 1_000_000_000_000, |key, observed| {
        if *observed == old {
            // Model a SYN/re-close replacing the scanned incarnation before
            // the collector rechecks it. Age alone cannot distinguish these.
            writer.map.insert(*key, replacement, 0).unwrap();
        }
        true
    }).unwrap();
    assert_eq!(scanner.map.get(&key, 0).unwrap(), replacement);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn collector_defers_to_a_writer_and_cannot_delete_its_replacement() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let mut gc = GcProgram::new(&mut bpf).unwrap();
    let mut states = Scanner::<RedirectTuple, FlowTrackEntry>::new(&bpf, "FLOW_TRACK").unwrap();
    let key = tuple(7, 17);
    let old = FlowTrackEntry { state: 1, generation: 2, last_seen_seconds: 1,
        ..FlowTrackEntry::default() };
    states.map.insert(key, old, 0).unwrap();
    let request = old.request(&key, 1_000_000_000_000);
    let mut gates = Array::<_, u64>::try_from(bpf.map_mut("TRACKING_GATES").unwrap()).unwrap();
    // Pause a simulated writer inside its critical section. The real BPF
    // collector must defer rather than using its previously scanned record.
    gates.set(bucket(&key), 3, 0).unwrap();
    assert_eq!(gc.run(&[request]).unwrap(), 0);
    assert_eq!(states.map.get(&key, 0).unwrap(), old);
    let replacement = FlowTrackEntry { generation: 4, ..old };
    states.map.insert(key, replacement, 0).unwrap();
    gates.set(bucket(&key), 4, 0).unwrap();
    assert_eq!(gc.run(&[request]).unwrap(), 0, "old candidate cannot delete a reused tuple");
    assert_eq!(states.map.get(&key, 0).unwrap(), replacement);
    assert_eq!(gc.run(&[replacement.request(&key, request.now_ns)]).unwrap(), 1);
    assert!(states.map.get(&key, 0).is_err());
}

fn finish_sweep(collector: &mut Collector, now: u64) {
    collector.step(now).unwrap();
    while !collector.flows.complete || !collector.replies.complete {
        assert_eq!(collector.pause(), BATCH_PAUSE);
        collector.step(now).unwrap();
    }
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn sweep_cadence_uses_both_capacities_and_only_backs_off_when_both_are_empty() {
    let mut loader = EbpfLoader::new();
    loader.map_max_entries("FLOW_TRACK", 4096);
    loader.map_max_entries("UDP_REPLY_TRACK", 8);
    let mut bpf = loader.load(BYTECODE).unwrap();
    let mut collector = Collector::new(&mut bpf).unwrap();
    let now = 1_000_000_000_000;
    for index in 0..1025 {
        collector.flows.map.insert(tuple(index, 6), FlowTrackEntry {
            state: 1, ..FlowTrackEntry::default()
        }, 0).unwrap();
    }
    for peer in 0..6 {
        collector.replies.map.insert(UdpReplyKey { peer_ip: [peer; 16], ..UdpReplyKey::default() },
            UdpReplyEntry { last_seen_ns: now, ..UdpReplyEntry::default() }, 0).unwrap();
    }
    collector.step(now).unwrap();
    assert!(collector.replies.complete);
    assert!(!collector.flows.complete);
    assert_eq!(collector.pause(), BATCH_PAUSE);
    while !collector.flows.complete {
        collector.step(now).unwrap();
        assert_eq!(collector.replies.entries, 6,
            "completed small map is not counted again during a large map sweep");
    }
    assert_eq!(collector.pause(), Duration::from_secs(1), "reply map alone is 75% full");
    for peer in 0..6 {
        collector.replies.map.remove(&UdpReplyKey { peer_ip: [peer; 16], ..UdpReplyKey::default() }).unwrap();
    }
    for _ in 0..2 {
        finish_sweep(&mut collector, now);
        assert_eq!(collector.pause(), Duration::from_secs(1));
    }
    finish_sweep(&mut collector, now);
    assert_eq!(collector.pause(), Duration::from_secs(5), "live flow table prevents idle backoff");
    for index in 0..1025 { collector.flows.map.remove(&tuple(index, 6)).unwrap(); }
    for seconds in [5, 10, 20, 30, 30] {
        finish_sweep(&mut collector, now);
        assert_eq!(collector.pause(), Duration::from_secs(seconds));
    }
    collector.flows.map.insert(tuple(1, 6), FlowTrackEntry {
        state: 1, ..FlowTrackEntry::default()
    }, 0).unwrap();
    finish_sweep(&mut collector, now);
    assert_eq!(collector.pause(), Duration::from_secs(5));
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn batch_results_distinguish_deleted_refreshed_replaced_and_busy_candidates() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let mut gc = GcProgram::new(&mut bpf).unwrap();
    let mut flows = Scanner::<RedirectTuple, FlowTrackEntry>::new(&bpf, "FLOW_TRACK").unwrap();
    let mut replies = Scanner::<UdpReplyKey, UdpReplyEntry>::new(&bpf, "UDP_REPLY_TRACK").unwrap();
    let now = 1_000_000_000_000;
    let old = FlowTrackEntry { state: 1, generation: 2, last_seen_seconds: 1,
        ..FlowTrackEntry::default() };
    for index in 1..=4 { flows.map.insert(tuple(index, 17), old, 0).unwrap(); }
    let fresh = FlowTrackEntry { last_seen_seconds: 1000, ..old };
    flows.map.insert(tuple(2, 17), fresh, 0).unwrap();
    let replacement = FlowTrackEntry { generation: 4, ..old };
    flows.map.insert(tuple(3, 17), replacement, 0).unwrap();
    let expired_key = UdpReplyKey { peer_ip: [5; 16], ip_version: 4, ..UdpReplyKey::default() };
    let fresh_key = UdpReplyKey { peer_ip: [6; 16], ..expired_key };
    let reply = UdpReplyEntry { last_seen_ns: 1, generation: 2, ..UdpReplyEntry::default() };
    replies.map.insert(expired_key, reply, 0).unwrap();
    replies.map.insert(fresh_key, UdpReplyEntry { last_seen_ns: now, ..reply }, 0).unwrap();
    let mut requests = [TrackingGcRequest::default(); GC_BATCH_SIZE];
    for index in 0..4 { requests[index] = old.request(&tuple(index as u16 + 1, 17), now); }
    requests[4] = reply.request(&expired_key, now);
    requests[5] = reply.request(&fresh_key, now);
    let busy = bucket(&tuple(4, 17));
    assert_ne!(busy, bucket(&tuple(1, 17)));
    assert_ne!(busy, reply_bucket(&expired_key));
    let mut gates = Array::<_, u64>::try_from(bpf.map_mut("TRACKING_GATES").unwrap()).unwrap();
    gates.set(busy, 3, 0).unwrap();
    assert_eq!(gc.run(&requests).unwrap(), (1 << 0) | (1 << 4));
    assert!(flows.map.get(&tuple(1, 17), 0).is_err());
    assert_eq!(flows.map.get(&tuple(2, 17), 0).unwrap(), fresh);
    assert_eq!(flows.map.get(&tuple(3, 17), 0).unwrap(), replacement);
    assert_eq!(flows.map.get(&tuple(4, 17), 0).unwrap(), old);
    assert!(replies.map.get(&expired_key, 0).is_err());
    assert!(replies.map.get(&fresh_key, 0).is_ok());
    assert_eq!(gc.run(&requests[..6]).unwrap(), 0, "partial batch cannot reuse stale result bits");
    gates.set(busy, 4, 0).unwrap();
    assert_eq!(gc.run(&requests[3..4]).unwrap(), 1, "result bits are relative to this batch");
    assert!(gc.run(&[TrackingGcRequest::default(); GC_BATCH_SIZE + 1]).is_err());
    assert_eq!(gc.run(&[]).unwrap(), 0);
}
