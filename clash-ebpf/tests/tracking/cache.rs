//! Cache precedence and full-parser fallback must agree on the same flow key.
use super::*;
use aya::maps::{LpmTrie, lpm_trie::Key};
use clash_ebpf_common::tracking::DIRECT;

fn load() -> Ebpf {
    let mut bpf = EbpfLoader::new().load(BYTECODE).unwrap();
    for name in ["lan_ingress_l2", "lan_ingress_l3", "dae0_ingress_l2"] {
        let program: &mut SchedClassifier = bpf.program_mut(name).unwrap().try_into().unwrap();
        program.load().unwrap();
    }
    params(&mut bpf, DaeParam::default());
    bpf
}

fn params(bpf: &mut Ebpf, mut param: DaeParam) {
    param.dae0_ifindex = 1; param.tproxy_port = 12345;
    Array::try_from(bpf.map_mut("DAE_PARAM").unwrap()).unwrap().set(0, param, 0).unwrap();
}

// Validate packet output as well as the action: client MAC restoration must
// preserve the unsolicited peer's complete IP/UDP packet, including its port.
fn assert_full_cone_reply(bpf: &mut Ebpf, reply: &[u8]) {
    let mut output = vec![0u8; reply.len()];
    let program: &mut SchedClassifier = bpf.program_mut("dae0_ingress_l2").unwrap().try_into().unwrap();
    assert_eq!(program.test_run(TestRunOptions { data_in: Some(reply),
        data_out: Some(&mut output), ..TestRunOptions::new() }).unwrap().return_value, 7);
    let request = packet(10);
    assert_eq!(&output[..6], &request[6..12]);
    assert_eq!(&output[6..12], &request[..6]);
    assert_eq!(&output[12..], &reply[12..], "reply source, client endpoint and payload remain unchanged");
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn every_packet_routing_rule_publishes_a_sticky_direct_decision() {
    for rule in ["src_ip", "dst_ip", "src_port", "dst_port", "dscp", "src_mac_allow", "src_ip_allow", "dst_ip_allow", "src_port_allow", "dst_port_allow"] {
        let mut bpf = load();
        let data = packet(10);
        let mut param = DaeParam::default();
        match rule {
            "src_ip" | "dst_ip" => {
                let (name, ip) = if rule == "src_ip" { ("BYPASS_SRC_IPS", [192, 0, 2, 2]) }
                    else { ("BYPASS_DST_IPS", [198, 51, 100, 9]) };
                LpmTrie::<_, u32, u8>::try_from(bpf.map_mut(name).unwrap()).unwrap()
                    .insert(&Key::new(32, u32::from_ne_bytes(ip)), 1, 0).unwrap();
            }
            "src_port" | "dst_port" => {
                let (name, port) = if rule == "src_port" { ("BYPASS_SRC_PORTS", 40000) }
                    else { ("BYPASS_DST_PORTS", 3478) };
                HashMap::<_, u16, u8>::try_from(bpf.map_mut(name).unwrap()).unwrap().insert(port, 1, 0).unwrap();
            }
            "dscp" => {
                param.has_bypass_dscps = 1;
                HashMap::<_, u8, u8>::try_from(bpf.map_mut("BYPASS_DSCPS").unwrap()).unwrap().insert(0, 1, 0).unwrap();
            }
            "src_mac_allow" => param.has_proxy_src_macs = 1,
            "src_ip_allow" => param.has_proxy_src_ips = 1,
            "dst_ip_allow" => param.has_proxy_dst_ips = 1,
            "src_port_allow" => param.has_proxy_src_ports = 1,
            "dst_port_allow" => param.has_proxy_dst_ports = 1,
            _ => unreachable!(),
        }
        params(&mut bpf, param);
        assert_eq!(run(&mut bpf, &data), 0, "first packet: {rule}");
        let (tuple, first) = state(&bpf);
        assert_ne!((first >> 32) as u32 & DIRECT, 0, "rule cached: {rule}");
        match rule {
            "src_ip" | "dst_ip" => {
                let (name, ip) = if rule == "src_ip" { ("BYPASS_SRC_IPS", [192, 0, 2, 2]) }
                    else { ("BYPASS_DST_IPS", [198, 51, 100, 9]) };
                LpmTrie::<_, u32, u8>::try_from(bpf.map_mut(name).unwrap()).unwrap()
                    .remove(&Key::new(32, u32::from_ne_bytes(ip))).unwrap();
            }
            "src_port" | "dst_port" => {
                let (name, port) = if rule == "src_port" { ("BYPASS_SRC_PORTS", 40000) }
                    else { ("BYPASS_DST_PORTS", 3478) };
                HashMap::<_, u16, u8>::try_from(bpf.map_mut(name).unwrap()).unwrap().remove(&port).unwrap();
            }
            _ => {}
        }
        params(&mut bpf, DaeParam::default());
        assert_eq!(run(&mut bpf, &data), 0, "established decision wins: {rule}");
        assert_eq!(state(&bpf).1 >> 32, first >> 32);
        HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap()
            .remove(&tuple).unwrap();
        assert_eq!(run(&mut bpf, &data), 7, "new flow uses current rules: {rule}");
    }
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn cached_proxy_decisions_precede_new_bypass_rules_but_dns_and_safety_keep_precedence() {
    let mut bpf = load();
    assert_eq!(run(&mut bpf, &packet(10)), 7);
    HashMap::<_, u16, u8>::try_from(bpf.map_mut("BYPASS_DST_PORTS").unwrap()).unwrap().insert(3478, 1, 0).unwrap();
    params(&mut bpf, DaeParam { has_proxy_src_macs: 1, has_bypass_dscps: 1, ..DaeParam::default() });
    HashMap::<_, u8, u8>::try_from(bpf.map_mut("BYPASS_DSCPS").unwrap()).unwrap().insert(0, 1, 0).unwrap();
    assert_eq!(run(&mut bpf, &packet(10)), 7, "cached proxy ignores subsequently changed packet rules");
    let mut bpf = load();
    let mut dns = packet(10);
    dns[36..38].copy_from_slice(&53u16.to_be_bytes());
    HashMap::<_, u16, u8>::try_from(bpf.map_mut("BYPASS_DST_PORTS").unwrap()).unwrap().insert(53, 1, 0).unwrap();
    assert_eq!(run(&mut bpf, &dns), 7, "destination bypass cannot override DNS interception");
    let mut data = packet(10);
    data[..6].fill(0xff);
    assert_eq!(run(&mut bpf, &data), 0, "L2 broadcast bypasses even an existing proxy decision");
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn ipv4_options_reuse_the_same_cached_tuple_and_reply_binding() {
    let mut bpf = load();
    assert_eq!(run(&mut bpf, &packet(10)), 7);
    let (tuple, first) = state(&bpf);
    let mut options = packet(10).to_vec();
    options.splice(34..34, [1, 1, 1, 1]);
    options[14] = 0x46;
    options[16..18].copy_from_slice(&32u16.to_be_bytes());
    assert_eq!(run(&mut bpf, &options), 7, "IPv4 options use the full parser");
    assert_eq!(state(&bpf).1 >> 32, first >> 32);
    assert_eq!(state(&bpf).0, tuple);
    let mut reply = reply_packet([203, 0, 113, 77], 7777).to_vec();
    reply.splice(34..34, [1, 1, 1, 1]); reply[14] = 0x46;
    reply[16..18].copy_from_slice(&32u16.to_be_bytes());
    HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap()
        .remove(&tuple).unwrap();
    assert_full_cone_reply(&mut bpf, &reply);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn arp_icmp_and_special_destinations_do_not_allocate_tracking_state() {
    let mut bpf = load();
    for kind in ["arp", "icmp", "icmp6", "link_local", "multicast"] {
        let mut data = packet(10).to_vec();
        match kind {
            "arp" => data[12..14].copy_from_slice(&0x0806u16.to_be_bytes()),
            "icmp" => data[23] = 1,
            "icmp6" => {
                data.resize(70, 0); data[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
                data[14] = 0x60; data[20] = 58;
            }
            "link_local" => data[30..34].copy_from_slice(&[169, 254, 1, 2]),
            "multicast" => data[..6].fill(0xff),
            _ => unreachable!(),
        }
        assert_eq!(run(&mut bpf, &data), 0, "pass {kind}");
    }
    assert_eq!(HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map("FLOW_TRACK").unwrap()).unwrap().keys().count(), 0);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn ipv6_extension_fallback_preserves_cached_rules_and_udp_reply_routes() {
    let mut bpf = load();
    let mut data = vec![0u8; 62];
    data[..12].copy_from_slice(&packet(10)[..12]);
    data[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    data[14] = 0x60; data[18..20].copy_from_slice(&8u16.to_be_bytes());
    data[20] = 17; data[21] = 64;
    data[22..26].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]); data[37] = 2;
    data[38..42].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]); data[53] = 9;
    data[54..62].copy_from_slice(&packet(10)[34..42]);
    HashMap::<_, u16, u8>::try_from(bpf.map_mut("BYPASS_DST_PORTS").unwrap()).unwrap().insert(3478, 1, 0).unwrap();
    assert_eq!(run(&mut bpf, &data), 0);
    let (tuple, first) = state(&bpf);
    HashMap::<_, u16, u8>::try_from(bpf.map_mut("BYPASS_DST_PORTS").unwrap()).unwrap().remove(&3478).unwrap();
    data.splice(54..54, [17, 0, 0, 0, 0, 0, 0, 0]);
    data[20] = 0; data[18..20].copy_from_slice(&16u16.to_be_bytes());
    assert_eq!(run(&mut bpf, &data), 0, "extension fallback honors the existing direct decision");
    assert_eq!(state(&bpf).1 >> 32, first >> 32);
    HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap().remove(&tuple).unwrap();
    assert_eq!(run(&mut bpf, &data), 7, "new connection evaluates current rules through the fallback");
    let mut reply = data.clone();
    reply[22..38].copy_from_slice(&data[38..54]); reply[38..54].copy_from_slice(&data[22..38]);
    reply[62..64].copy_from_slice(&7777u16.to_be_bytes()); reply[64..66].copy_from_slice(&40000u16.to_be_bytes());
    reply[37] = 77;
    let keys: Vec<_> = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map("FLOW_TRACK").unwrap()).unwrap()
        .keys().collect::<Result<_, _>>().unwrap();
    let mut flows = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
    for key in keys { flows.remove(&key).unwrap(); }
    assert_full_cone_reply(&mut bpf, &reply);
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn stable_forward_and_tcp_reply_reads_leave_decision_scratch_untouched() {
    use aya::{maps::{PerCpuArray, PerCpuValues}, util::nr_cpus};
    let mut bpf = load();
    for direct in [true, false] {
        if direct {
            HashMap::<_, u16, u8>::try_from(bpf.map_mut("BYPASS_DST_PORTS").unwrap()).unwrap().insert(3478, 1, 0).unwrap();
        } else {
            HashMap::<_, u16, u8>::try_from(bpf.map_mut("BYPASS_DST_PORTS").unwrap()).unwrap().remove(&3478).unwrap();
        }
        let mut flows = HashMap::<_, RedirectTuple, FlowTrackEntry>::try_from(bpf.map_mut("FLOW_TRACK").unwrap()).unwrap();
        let keys = flows.keys().collect::<Result<Vec<_>, _>>().unwrap();
        for key in keys { flows.remove(&key).unwrap(); }
        assert_eq!(run(&mut bpf, &packet(10)), if direct { 0 } else { 7 });
        let marker = [0xabcddcba12344321u64; 10];
        let values = PerCpuValues::try_from(vec![marker; nr_cpus().unwrap()]).unwrap();
        PerCpuArray::<_, [u64; 10]>::try_from(bpf.map_mut("FLOW_SCRATCH").unwrap()).unwrap().set(0, values, 0).unwrap();
        assert_eq!(run(&mut bpf, &packet(10)), if direct { 0 } else { 7 });
        let scratch = PerCpuArray::<_, [u64; 10]>::try_from(bpf.map("FLOW_SCRATCH").unwrap()).unwrap().get(&0, 0).unwrap();
        assert!(scratch.iter().all(|value| *value == marker), "stable reads never materialize a Decision");
    }
    assert_eq!(run(&mut bpf, &tcp_packet(2)), 7);
    let marker = [0x13579bdf2468ace0u64; 10];
    let values = PerCpuValues::try_from(vec![marker; nr_cpus().unwrap()]).unwrap();
    PerCpuArray::<_, [u64; 10]>::try_from(bpf.map_mut("FLOW_SCRATCH").unwrap()).unwrap().set(0, values, 0).unwrap();
    let mut reply = tcp_packet(16);
    reply[26..30].copy_from_slice(&[198, 51, 100, 9]); reply[30..34].copy_from_slice(&[192, 0, 2, 2]);
    reply[34..36].copy_from_slice(&8443u16.to_be_bytes()); reply[36..38].copy_from_slice(&40001u16.to_be_bytes());
    let program: &mut SchedClassifier = bpf.program_mut("dae0_ingress_l2").unwrap().try_into().unwrap();
    assert_eq!(program.test_run(TestRunOptions { data_in: Some(&reply), ..TestRunOptions::new() }).unwrap().return_value, 7);
    let scratch = PerCpuArray::<_, [u64; 10]>::try_from(bpf.map("FLOW_SCRATCH").unwrap()).unwrap().get(&0, 0).unwrap();
    assert!(scratch.iter().all(|value| *value == marker));
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn linear_cache_misses_preserve_nonzero_dscp_for_both_ip_families() {
    for ipv6 in [false, true] {
        let mut bpf = load();
        let mut data = packet(10).to_vec();
        if ipv6 {
            data.resize(62, 0);
            data[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
            // DSCP 46 with ECN 3: traffic class 0xbb crosses both bytes.
            data[14] = 0x6b; data[15] = 0xb0;
            data[18..20].copy_from_slice(&8u16.to_be_bytes());
            data[20] = 17; data[21] = 64;
            data[22..54].fill(0);
            data[22..26].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]); data[37] = 2;
            data[38..42].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]); data[53] = 9;
            data[54..62].copy_from_slice(&packet(10)[34..42]);
        } else { data[15] = 0xbb; }
        params(&mut bpf, DaeParam { has_bypass_dscps: 1, ..DaeParam::default() });
        HashMap::<_, u8, u8>::try_from(bpf.map_mut("BYPASS_DSCPS").unwrap()).unwrap().insert(46, 1, 0).unwrap();
        assert_eq!(run(&mut bpf, &data), 0, "IPv6={ipv6}: first packet retains DSCP");
        assert_ne!((state(&bpf).1 >> 32) as u32 & DIRECT, 0);
    }
}

#[test]
#[ignore = "requires freshly built BPF bytecode and root; attaches no hooks"]
fn normal_events_are_opt_in_but_overflow_events_are_unconditional() {
    use aya::maps::RingBuf;
    use clash_ebpf_common::DaeEventType;

    for enabled in [false, true] {
        let mut loader = EbpfLoader::new();
        loader.map_max_entries("FLOW_TRACK", 1);
        let mut bpf = loader.load(BYTECODE).unwrap();
        let program: &mut SchedClassifier = bpf.program_mut("lan_ingress_l2").unwrap().try_into().unwrap();
        program.load().unwrap();
        params(&mut bpf, DaeParam { log_events: enabled as u8, ..DaeParam::default() });
        let mut events = RingBuf::try_from(bpf.take_map("EVENT_RINGBUF").unwrap()).unwrap();
        assert_eq!(run(&mut bpf, &packet(10)), 7);
        {
            let event = events.next();
            assert_eq!(event.is_some(), enabled);
            if let Some(event) = event {
                assert_eq!(u32::from_ne_bytes(event[8..12].try_into().unwrap()), DaeEventType::Redirected as u32);
            }
        }
        let mut overflow = packet(10);
        overflow[34..36].copy_from_slice(&40001u16.to_be_bytes());
        assert_eq!(run(&mut bpf, &overflow), 2);
        let event = events.next().expect("overflow must remain observable without normal event logging");
        assert_eq!(u32::from_ne_bytes(event[8..12].try_into().unwrap()), DaeEventType::UdpConnOverflow as u32);
    }
}
