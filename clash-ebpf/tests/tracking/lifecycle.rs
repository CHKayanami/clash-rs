use super::*;
use clash_ebpf_common::tracking::{CLOSING, DIRECT, incarnation};
use std::sync::Barrier;

fn load(capacity: u32) -> Ebpf {
    let mut loader = EbpfLoader::new();
    loader.map_max_entries("FLOW_TRACK", capacity);
    loader.map_max_entries("UDP_REPLY_TRACK", 1);
    let mut bpf = loader.load(BYTECODE).unwrap();
    for name in ["lan_ingress_l2", "dae0peer_ingress"] {
        let program: &mut SchedClassifier = bpf.program_mut(name).unwrap().try_into().unwrap();
        program.load().unwrap();
    }
    Array::try_from(bpf.map_mut("DAE_PARAM").unwrap()).unwrap()
        .set(0, DaeParam { dae0_ifindex: 1, tproxy_port: 12345,
            ..DaeParam::default() }, 0).unwrap();
    bpf
}

fn proxy_burst(bpf: &mut Ebpf) {
    let gate = Barrier::new(8);
    let program: &mut SchedClassifier = bpf.program_mut("lan_ingress_l2").unwrap().try_into().unwrap();
    let program: &SchedClassifier = program;
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8).map(|_| {
            let gate = &gate;
            scope.spawn(move || {
                let data = packet(10);
                gate.wait();
                let verdict = program.test_run(TestRunOptions {
                    data_in: Some(&data), ..TestRunOptions::new()
                }).unwrap().return_value;
                assert!(verdict == 7 || verdict == 2,
                    "contended lifecycle changes may drop, never bypass the proxy");
            })
        }).collect();
        for worker in workers { worker.join().unwrap(); }
    });
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn concurrent_first_udp_packets_share_the_winning_decision() {
    let mut bpf = load(1);
    proxy_burst(&mut bpf);
    let (_, winner) = state(&bpf);
    for _ in 0..32 {
        assert_eq!(run(&mut bpf, &packet(10)), 7);
        assert_eq!(state(&bpf).1 >> 32, winner >> 32, "reuse the NOEXIST winner");
    }
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn expired_udp_direct_decision_is_reclassified_by_a_concurrent_burst() {
    let mut bpf = load(1);
    let ip = u32::from_ne_bytes([198, 51, 100, 9]);
    HashMap::<_, u32, u8>::try_from(bpf.map_mut("DYNAMIC_BYPASS_DST_IPS").unwrap())
        .unwrap().insert(ip, 1, 0).unwrap();
    assert_eq!(run(&mut bpf, &packet(10)), 0);
    let (key, old) = state(&bpf);
    HashMap::<_, u32, u8>::try_from(bpf.map_mut("DYNAMIC_BYPASS_DST_IPS").unwrap())
        .unwrap().remove(&ip).unwrap();
    let mut clock = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) }, 0);
    let mut states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
    let mut entry = states.get(&key, 0).unwrap();
    entry.last_seen_seconds = (clock.tv_sec as u32).wrapping_sub(123);
    states.insert(key, entry, 0).unwrap();
    proxy_burst(&mut bpf);
    let (_, current) = state(&bpf);
    assert_eq!((current >> 32) as u32 & DIRECT, 0);
    assert_ne!(incarnation(current), incarnation(old));
    assert_eq!(run(&mut bpf, &packet(10)), 7);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn direct_tcp_fin_keeps_its_decision_until_a_new_syn() {
    let mut bpf = load(1);
    let ip = u32::from_ne_bytes([198, 51, 100, 9]);
    HashMap::<_, u32, u8>::try_from(bpf.map_mut("DYNAMIC_BYPASS_DST_IPS").unwrap())
        .unwrap().insert(ip, 1, 0).unwrap();
    assert_eq!(run(&mut bpf, &tcp_packet(2)), 0);
    let (_, first) = state(&bpf);
    assert_ne!((first >> 32) as u32 & DIRECT, 0);
    HashMap::<_, u32, u8>::try_from(bpf.map_mut("DYNAMIC_BYPASS_DST_IPS").unwrap())
        .unwrap().remove(&ip).unwrap();
    assert_eq!(run(&mut bpf, &tcp_packet(17)), 0);
    let (_, closing) = state(&bpf);
    assert_eq!(incarnation(closing), incarnation(first));
    assert_ne!((closing >> 32) as u32 & CLOSING, 0);
    assert_eq!(run(&mut bpf, &tcp_packet(16)), 0, "final ACK must remain direct");
    assert_eq!(run(&mut bpf, &tcp_packet(17)), 0, "retransmitted FIN must remain direct");
    assert_eq!(run(&mut bpf, &tcp_packet(2)), 7, "new connection uses current policy");
    let (_, next) = state(&bpf);
    assert_eq!((next >> 32) as u32 & (DIRECT | CLOSING), 0);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn full_flow_table_drops_new_proxy_packets_without_overwriting_existing_flow() {
    let mut bpf = load(1);
    let mut states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
    let key = RedirectTuple { src_port: 1, proto: 6, ip_version: 4,
        ..RedirectTuple::default() };
    let active = FlowTrackEntry { state: 1 | DIRECT, ..FlowTrackEntry::default() };
    states.insert(key, active, 0).unwrap();
    for data in [packet(10), tcp_packet(2)] {
        assert_eq!(run(&mut bpf, &data), 2, "allocation failure cannot bypass the proxy");
    }
    let states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map("FLOW_TRACK").unwrap()).unwrap();
    assert_eq!(states.get(&key, 0).unwrap(), active);
    assert_eq!(states.keys().count(), 1);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn full_client_reply_table_drops_packets_without_a_return_route() {
    let mut bpf = load(1);
    let key = UdpReplyKey { peer_ip: [1; 16], ..UdpReplyKey::default() };
    HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map_mut("UDP_REPLY_TRACK").unwrap())
        .unwrap().insert(key, UdpReplyEntry::default(), 0).unwrap();
    assert_eq!(run(&mut bpf, &packet(10)), 2, "missing return state cannot be ignored");
    let routes = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map("UDP_REPLY_TRACK").unwrap()).unwrap();
    assert_eq!(routes.keys().count(), 1);
    assert_eq!(routes.get(&key, 0).unwrap(), UdpReplyEntry::default());
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn private_peer_rejects_packets_without_a_proxy_handoff() {
    let mut bpf = load(1);
    let program: &mut SchedClassifier = bpf.program_mut("dae0peer_ingress").unwrap().try_into().unwrap();
    let data = packet(10);
    assert_eq!(program.test_run(TestRunOptions {
        data_in: Some(&data), ..TestRunOptions::new()
    }).unwrap().return_value, 2);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn live_udp_reads_defer_refreshes_without_contending_with_a_bucket_writer() {
    use clash_ebpf_common::tracking::gate::{bucket, reply_bucket};

    let mut bpf = load(1);
    let program: &mut SchedClassifier = bpf.program_mut("dae0_ingress_l2").unwrap().try_into().unwrap();
    program.load().unwrap();
    assert_eq!(run(&mut bpf, &packet(10)), 7);
    let (tuple, _) = state(&bpf);
    let key = UdpReplyKey::from_request(&tuple);
    let mut clock = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) }, 0);
    // Fixtures change only while BPF execution is stopped. Activity is due
    // for refresh but still live; odd gates model unrelated bucket writers.
    let mut flows = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
    let mut flow = flows.get(&tuple, 0).unwrap();
    flow.last_seen_seconds = (clock.tv_sec as u32).wrapping_sub(2);
    flows.insert(tuple, flow, 0).unwrap();
    let mut clients = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map_mut("UDP_REPLY_TRACK").unwrap()).unwrap();
    let mut client = clients.get(&key, 0).unwrap();
    client.last_seen_ns = (clock.tv_sec as u64 - 2) * 1_000_000_000;
    clients.insert(key, client, 0).unwrap();
    for index in [bucket(&tuple), reply_bucket(&key)] {
        HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap()
            .insert(tuple, flow, 0).unwrap();
        HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map_mut("UDP_REPLY_TRACK").unwrap()).unwrap()
            .insert(key, client, 0).unwrap();
        let mut gates = Array::<_, u64>::try_from(bpf.map_mut("TRACKING_GATES").unwrap()).unwrap();
        let version = gates.get(&index, 0).unwrap();
        gates.set(index, version + 1, 0).unwrap();
        assert_eq!(run(&mut bpf, &packet(10)), 7,
            "stable flow lookup and same-route publication ignore writer gates");
        let mut gates = Array::<_, u64>::try_from(bpf.map_mut("TRACKING_GATES").unwrap()).unwrap();
        assert_eq!(gates.get(&index, 0).unwrap(), version + 1);
        gates.set(index, version, 0).unwrap();
        if index == bucket(&tuple) {
            let flows = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map("FLOW_TRACK").unwrap()).unwrap();
            assert_eq!(flows.get(&tuple, 0).unwrap().activity(), flow.activity(),
                "deferred flow refresh must not write through a busy gate");
        }
        if index == reply_bucket(&key) {
            let clients = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map("UDP_REPLY_TRACK").unwrap()).unwrap();
            assert_eq!(clients.get(&key, 0).unwrap().last_seen_ns, client.last_seen_ns,
                "deferred client refresh must not write through a busy gate");
        }
    }
    HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap()
        .remove(&tuple).unwrap();
    let index = reply_bucket(&key);
    let mut gates = Array::<_, u64>::try_from(bpf.map_mut("TRACKING_GATES").unwrap()).unwrap();
    let version = gates.get(&index, 0).unwrap();
    gates.set(index, version + 1, 0).unwrap();
    let reply = reply_packet([198, 51, 100, 9], 9999);
    let program: &mut SchedClassifier = bpf.program_mut("dae0_ingress_l2").unwrap().try_into().unwrap();
    assert_eq!(program.test_run(TestRunOptions { data_in: Some(&reply), ..TestRunOptions::new() })
        .unwrap().return_value, 7, "stable IP-pair lookup ignores writer gates");
    let mut gates = Array::<_, u64>::try_from(bpf.map_mut("TRACKING_GATES").unwrap()).unwrap();
    assert_eq!(gates.get(&index, 0).unwrap(), version + 1);
    gates.set(index, version, 0).unwrap();
}
