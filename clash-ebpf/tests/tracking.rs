//! Real kernel execution of the unified tracking path; no hooks are attached.
#![cfg(target_os = "linux")]
use aya::{Ebpf, EbpfLoader, maps::{Array, HashMap},
    programs::{SchedClassifier, TestRun, TestRunOptions}};
use clash_ebpf_common::{DaeParam, FlowTrackEntry, RedirectTuple, UdpReplyEntry, UdpReplyKey};

const BYTECODE: &[u8] = include_bytes!(env!("CLASH_EBPF_OBJECT"));

fn packet(source_mac: u8) -> [u8; 60] {
    let mut data = [0u8; 60];
    data[..6].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    data[6..12].copy_from_slice(&[2, 6, 7, 8, 9, source_mac]);
    data[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    data[14] = 0x45;
    data[16..18].copy_from_slice(&28u16.to_be_bytes());
    data[22] = 64;
    data[23] = 17;
    data[26..30].copy_from_slice(&[192, 0, 2, 2]);
    data[30..34].copy_from_slice(&[198, 51, 100, 9]);
    let sum: u32 = data[14..34].chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as u32).sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    data[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    data[34..36].copy_from_slice(&40000u16.to_be_bytes());
    data[36..38].copy_from_slice(&3478u16.to_be_bytes());
    data[38..40].copy_from_slice(&8u16.to_be_bytes());
    data
}

fn reply_packet(peer: [u8; 4], port: u16) -> [u8; 60] {
    let mut reply = packet(10);
    reply[26..30].copy_from_slice(&peer);
    reply[30..34].copy_from_slice(&[192, 0, 2, 2]);
    reply[34..36].copy_from_slice(&port.to_be_bytes());
    reply[36..38].copy_from_slice(&40000u16.to_be_bytes());
    reply[24..26].fill(0);
    let sum: u32 = reply[14..34].chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as u32).sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    reply[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    reply
}

fn run(bpf: &mut Ebpf, data: &[u8]) -> u32 {
    let program: &mut SchedClassifier = bpf.program_mut("lan_ingress_l2").unwrap().try_into().unwrap();
    program.test_run(TestRunOptions { data_in: Some(data), ..TestRunOptions::new() })
        .unwrap().return_value
}

fn state(bpf: &Ebpf) -> (RedirectTuple, u64) {
    let states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map("FLOW_TRACK").unwrap()).unwrap();
    let entries: Vec<_> = states.iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(entries.len(), 1, "one exclusive decision per tuple");
    (entries[0].0, entries[0].1.activity())
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root"]
fn direct_decision_expiration_and_redirect_metadata_are_consistent() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let program: &mut SchedClassifier = bpf.program_mut("lan_ingress_l2").unwrap().try_into().unwrap();
    program.load().unwrap();
    let mut params = Array::try_from(bpf.map_mut("DAE_PARAM").unwrap()).unwrap();
    params.set(0, DaeParam { dae0_ifindex: 1, tproxy_port: 12345,
        direct_offload_enabled: 1, ..DaeParam::default() }, 0).unwrap();
    let ip = u32::from_ne_bytes([198, 51, 100, 9]);
    HashMap::<_, u32, u8>::try_from(bpf.map_mut("DYNAMIC_BYPASS_DST_IPS").unwrap())
        .unwrap().insert(ip, 1, 0).unwrap();
    assert_eq!(run(&mut bpf, &packet(10)), 0);
    let (key, direct) = state(&bpf);
    assert_ne!(direct >> 63, 0);
    HashMap::<_, u32, u8>::try_from(bpf.map_mut("DYNAMIC_BYPASS_DST_IPS").unwrap())
        .unwrap().remove(&ip).unwrap();
    assert_eq!(run(&mut bpf, &packet(10)), 0, "active direct decision survives policy removal");
    assert_eq!(state(&bpf).1 >> 32, direct >> 32);

    let mut clock = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) }, 0);
    let expired = (direct & !0xffffffff) | (clock.tv_sec as u32).wrapping_sub(123) as u64;
    // No BPF execution runs concurrently with this deterministic fixture edit.
    let mut states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
    let mut entry = states.get(&key, 0).unwrap();
    entry.set_activity(expired);
    states.insert(key, entry, 0).unwrap();
    assert_ne!(run(&mut bpf, &packet(10)), 2, "reclassification must not drop the datagram");
    let (_, redirected) = state(&bpf);
    assert_eq!(redirected >> 63, 0);
    assert_ne!(redirected >> 32, direct >> 32);
    assert_ne!(run(&mut bpf, &packet(11)), 2);
    let (_, changed) = state(&bpf);
    assert_ne!(changed >> 32, redirected >> 32, "changed MAC replaces the complete record");
    let states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map("FLOW_TRACK").unwrap()).unwrap();
    assert_eq!(states.get(&key, 0).unwrap().route.smac[5], 11, "replacement contains the new source MAC");
}

fn tcp_packet(flags: u8) -> [u8; 60] {
    let mut data = packet(10);
    data[16..18].copy_from_slice(&40u16.to_be_bytes());
    data[23] = 6;
    data[24..26].fill(0);
    let sum: u32 = data[14..34].chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as u32).sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    data[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    data[34..54].fill(0);
    data[34..36].copy_from_slice(&40001u16.to_be_bytes());
    data[36..38].copy_from_slice(&8443u16.to_be_bytes());
    data[46] = 0x50;
    data[47] = flags;
    data
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root"]
fn tcp_syn_resets_identity_and_fin_retains_reply_route_until_close_timeout() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    let program: &mut SchedClassifier = bpf.program_mut("lan_ingress_l2").unwrap().try_into().unwrap();
    program.load().unwrap();
    Array::try_from(bpf.map_mut("DAE_PARAM").unwrap()).unwrap()
        .set(0, DaeParam { dae0_ifindex: 1, tproxy_port: 12345, ..DaeParam::default() }, 0).unwrap();
    assert_ne!(run(&mut bpf, &tcp_packet(2)), 2);
    let (key, initial) = state(&bpf);
    let mut states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
    let mut entry = states.get(&key, 0).unwrap();
    entry.set_activity((initial & !0xffffffff) | 1);
    let first = entry.activity();
    states.insert(key, entry, 0).unwrap();
    assert_ne!(run(&mut bpf, &tcp_packet(16)), 2);
    assert_eq!(state(&bpf).1, first, "active TCP does not refresh its timestamp");
    assert_ne!(run(&mut bpf, &tcp_packet(17)), 2);
    let (_, closing) = state(&bpf);
    assert_ne!(closing & (1u64 << 61), 0);
    let (key, _) = state(&bpf);
    let states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map("FLOW_TRACK").unwrap()).unwrap();
    assert_eq!(states.get(&key, 0).unwrap().route.smac[5], 10, "FIN keeps the final reply route");
    assert_ne!(run(&mut bpf, &tcp_packet(2)), 2);
    let (_, replacement) = state(&bpf);
    assert_eq!(replacement & (1u64 << 61), 0);
    assert_ne!(replacement >> 32, first >> 32);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root"]
fn concurrent_metadata_publication_keeps_one_complete_route() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    Array::try_from(bpf.map_mut("DAE_PARAM").unwrap()).unwrap()
        .set(0, DaeParam { dae0_ifindex: 1, tproxy_port: 12345, ..DaeParam::default() }, 0).unwrap();
    let program: &mut SchedClassifier = bpf.program_mut("lan_ingress_l2").unwrap().try_into().unwrap();
    program.load().unwrap();
    let program: &SchedClassifier = program;
    std::thread::scope(|scope| {
        let workers: Vec<_> = (10..14).map(|mac| {
            scope.spawn(move || {
                let data = packet(mac);
                for _ in 0..1000 {
                    program.test_run(TestRunOptions { data_in: Some(&data), ..TestRunOptions::new() }).unwrap();
                }
            })
        }).collect();
        for worker in workers { worker.join().unwrap(); }
    });
    let (key, current) = state(&bpf);
    assert_eq!(current >> 63, 0);
    let states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map("FLOW_TRACK").unwrap()).unwrap();
    let route = states.get(&key, 0).unwrap().route;
    assert_eq!(&route.smac[..5], &[2, 6, 7, 8, 9]);
    assert!((10..14).contains(&route.smac[5]));
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root"]
fn client_reply_route_refreshes_without_a_flow_and_rejects_ambiguity() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    for name in ["lan_ingress_l2", "dae0_ingress_l2"] {
        let program: &mut SchedClassifier = bpf.program_mut(name).unwrap().try_into().unwrap();
        program.load().unwrap();
    }
    Array::try_from(bpf.map_mut("DAE_PARAM").unwrap()).unwrap()
        .set(0, DaeParam { dae0_ifindex: 1, tproxy_port: 12345, ..DaeParam::default() }, 0).unwrap();
    assert_ne!(run(&mut bpf, &packet(10)), 2);
    let (tuple, _) = state(&bpf);
    let key = UdpReplyKey::from_request(&tuple);
    let mut clock = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) }, 0);
    let now = clock.tv_sec as u64 * 1_000_000_000 + clock.tv_nsec as u64;
    let mut routes = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map_mut("UDP_REPLY_TRACK").unwrap()).unwrap();
    let mut entry = routes.get(&key, 0).unwrap();
    entry.last_seen_ns = now - 2_000_000_000;
    let old_stamp = entry.last_seen_ns;
    routes.insert(key, entry, 0).unwrap();
    HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap()
        .remove(&tuple).unwrap();

    let reply = reply_packet([203, 0, 113, 7], 9999);
    let program: &mut SchedClassifier = bpf.program_mut("dae0_ingress_l2").unwrap().try_into().unwrap();
    assert_eq!(program.test_run(TestRunOptions { data_in: Some(&reply), ..TestRunOptions::new() })
        .unwrap().return_value, 7, "client-only fallback redirects the reply");
    let mut routes = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map_mut("UDP_REPLY_TRACK").unwrap()).unwrap();
    entry = routes.get(&key, 0).unwrap();
    assert!(entry.last_seen_ns > old_stamp, "reply keeps the client record alive");
    entry.ambiguous = 1;
    entry.last_seen_ns = old_stamp;
    routes.insert(key, entry, 0).unwrap();
    let program: &mut SchedClassifier = bpf.program_mut("dae0_ingress_l2").unwrap().try_into().unwrap();
    assert_eq!(program.test_run(TestRunOptions { data_in: Some(&reply), ..TestRunOptions::new() })
        .unwrap().return_value, 0, "ambiguous client route cannot restore the reply");
    let routes = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map("UDP_REPLY_TRACK").unwrap()).unwrap();
    assert_eq!(routes.get(&key, 0).unwrap().last_seen_ns, old_stamp);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root"]
fn exact_udp_replies_coalesce_client_touches_and_preserve_route_metadata() {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    for name in ["lan_ingress_l2", "dae0_ingress_l2"] {
        let program: &mut SchedClassifier = bpf.program_mut(name).unwrap().try_into().unwrap();
        program.load().unwrap();
    }
    Array::try_from(bpf.map_mut("DAE_PARAM").unwrap()).unwrap()
        .set(0, DaeParam { dae0_ifindex: 1, tproxy_port: 12345, ..DaeParam::default() }, 0).unwrap();
    assert_ne!(run(&mut bpf, &packet(10)), 2);
    let (tuple, _) = state(&bpf);
    let key = UdpReplyKey::from_request(&tuple);
    let mut clock = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) }, 0);
    let now = clock.tv_sec as u64 * 1_000_000_000 + clock.tv_nsec as u64;
    let mut states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
    let mut flow = states.get(&tuple, 0).unwrap();
    flow.last_seen_seconds = clock.tv_sec as u32 + 2;
    states.insert(tuple, flow, 0).unwrap();
    let mut routes = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map_mut("UDP_REPLY_TRACK").unwrap()).unwrap();
    let mut client = routes.get(&key, 0).unwrap();
    client.last_seen_ns = now - 2_000_000_000;
    let old_stamp = client.last_seen_ns;
    routes.insert(key, client, 0).unwrap();
    let reply = reply_packet([198, 51, 100, 9], 3478);
    let program: &mut SchedClassifier = bpf.program_mut("dae0_ingress_l2").unwrap().try_into().unwrap();
    assert_eq!(program.test_run(TestRunOptions { data_in: Some(&reply), ..TestRunOptions::new() })
        .unwrap().return_value, 7);
    let routes = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map("UDP_REPLY_TRACK").unwrap()).unwrap();
    assert_eq!(routes.get(&key, 0).unwrap().last_seen_ns, old_stamp, "fresh exact flow skips client touch");
    let mut states = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
    flow.last_seen_seconds = (clock.tv_sec as u32).wrapping_sub(2);
    states.insert(tuple, flow, 0).unwrap();
    let program: &mut SchedClassifier = bpf.program_mut("dae0_ingress_l2").unwrap().try_into().unwrap();
    assert_eq!(program.test_run(TestRunOptions { data_in: Some(&reply), ..TestRunOptions::new() })
        .unwrap().return_value, 7);
    let routes = HashMap::<_, UdpReplyKey, UdpReplyEntry>::try_from(bpf.map("UDP_REPLY_TRACK").unwrap()).unwrap();
    let refreshed = routes.get(&key, 0).unwrap();
    assert!(refreshed.last_seen_ns > old_stamp);
    assert_eq!(refreshed.route, client.route, "timestamp refresh preserves all route fields");
    assert_eq!(refreshed.ambiguous, client.ambiguous);
}
