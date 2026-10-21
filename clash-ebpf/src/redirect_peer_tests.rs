//! Real packets traverse isolated interfaces; no host routes or hooks are changed.
use std::{io, net::{SocketAddr, UdpSocket}, mem::{size_of_val, zeroed}, os::fd::{AsRawFd, FromRawFd, OwnedFd}, thread, time::Duration};
use aya::{EbpfLoader, maps::Array, programs::{SchedClassifier, TcAttachType, tc::qdisc_add_clsact}};
use socket2::{Domain, Protocol, Socket, Type};
use clash_ebpf_common::{DaeParam, DAE_TPROXY_MARK};
use crate::{bpf::EMBEDDED_BPF_OBJECT, netns::DaeNs,
    netlink::{NlSock, LinkPairKind, set_sysctl, FAM_V4, FAM_V6, ROUTE_LOCAL, SCOPE_HOST, PROTO_STATIC}};
use super::detect;

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn packet(v6: bool, src: [u8; 6], dst: [u8; 6]) -> Vec<u8> {
    let payload = b"peer-test";
    let len = 8 + payload.len();
    let mut udp = vec![0; len];
    udp[..2].copy_from_slice(&40000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&3478u16.to_be_bytes());
    udp[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let mut ip = vec![0; if v6 { 40 } else { 20 }];
    let mut pseudo = Vec::new();
    if v6 {
        ip[0] = 0x60; ip[6] = 17; ip[7] = 64;
        ip[4..6].copy_from_slice(&(len as u16).to_be_bytes());
        ip[8..12].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]); ip[23] = 2;
        ip[24..28].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]); ip[39] = 9;
        pseudo.extend_from_slice(&ip[8..40]);
        pseudo.extend_from_slice(&(len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
    } else {
        ip[0] = 0x45; ip[8] = 64; ip[9] = 17;
        ip[2..4].copy_from_slice(&((20 + len) as u16).to_be_bytes());
        ip[12..16].copy_from_slice(&[192, 0, 2, 2]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 9]);
        let sum = checksum(&ip); ip[10..12].copy_from_slice(&sum.to_be_bytes());
        pseudo.extend_from_slice(&ip[12..20]); pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&(len as u16).to_be_bytes());
    }
    pseudo.extend_from_slice(&udp);
    let sum = checksum(&pseudo); udp[6..8].copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst); frame.extend_from_slice(&src);
    frame.extend_from_slice(&if v6 { 0x86ddu16 } else { 0x0800u16 }.to_be_bytes());
    frame.extend_from_slice(&ip); frame.extend_from_slice(&udp);
    frame.resize(frame.len().max(60), 0);
    frame
}

fn deliver(kind: LinkPairKind, peer_redirect: bool) {
    // unshare only this dedicated test thread; everything disappears on exit.
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0, "{}", io::Error::last_os_error());
    let mut nl = NlSock::new().unwrap();
    nl.add_veth_pair("lan", "src").unwrap();
    match kind {
        LinkPairKind::Netkit => nl.add_netkit_pair("dae0", "dae0peer", true).unwrap(),
        LinkPairKind::Veth => nl.add_veth_pair("dae0", "dae0peer").unwrap(),
    }
    let enabled = detect(&mut nl, kind, "dae0");
    if peer_redirect { assert!(enabled, "test host must support safe redirect_peer for {kind:?}"); }
    let (lan, lan_mac) = nl.get_link("lan").unwrap();
    let (src, src_mac) = nl.get_link("src").unwrap();
    let (dae0, _) = nl.get_link("dae0").unwrap();
    let (peer, _) = nl.get_link("dae0peer").unwrap();
    for index in [lan, src, dae0] { nl.set_link_up(index, true).unwrap(); }
    let ns = DaeNs::new().unwrap();
    let fd: OwnedFd = ns.dae_file().unwrap().into();
    nl.set_link_netns_fd(peer, &fd).unwrap();
    let mut bpf = EbpfLoader::new().load(EMBEDDED_BPF_OBJECT).unwrap();
    let (peer_mac, sockets) = ns.with_daens(|| {
        let mut nl = NlSock::new().unwrap();
        let (peer, mac) = nl.get_link("dae0peer").unwrap();
        let (lo, _) = nl.get_link("lo").unwrap();
        nl.set_link_up(lo, true).unwrap(); nl.set_link_up(peer, true).unwrap();
        set_sysctl("net.ipv4.conf.all.rp_filter", "0").unwrap();
        set_sysctl("net.ipv4.conf.dae0peer.rp_filter", "0").unwrap();
        let mut sockets = Vec::new();
        for family in [FAM_V4, FAM_V6] {
            nl.add_rule_fwmark(family, DAE_TPROXY_MARK, 100).unwrap();
            nl.add_route(family, 100, ROUTE_LOCAL, SCOPE_HOST, PROTO_STATIC, None, None, Some(lo)).unwrap();
            let v6 = family == FAM_V6;
            let socket = Socket::new(if v6 { Domain::IPV6 } else { Domain::IPV4 }, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            if v6 { socket.set_only_v6(true).unwrap(); socket.set_ip_transparent_v6(true).unwrap(); }
            else { socket.set_ip_transparent_v4(true).unwrap(); }
            let address = if v6 { "[::]:3478" } else { "0.0.0.0:3478" }.parse::<SocketAddr>().unwrap();
            socket.bind(&address.into()).unwrap();
            let socket: UdpSocket = socket.into();
            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            sockets.push(socket);
        }
        qdisc_add_clsact("dae0peer").unwrap();
        let program: &mut SchedClassifier = bpf.program_mut("dae0peer_ingress").unwrap().try_into().unwrap();
        program.load().unwrap(); program.attach("dae0peer", TcAttachType::Ingress).unwrap();
        (mac, sockets)
    }).unwrap();
    Array::try_from(bpf.map_mut("DAE_PARAM").unwrap()).unwrap().set(0,
        DaeParam { dae0_ifindex: dae0, dae0peer_mac: peer_mac, tproxy_port: 12345,
            use_redirect_peer: peer_redirect as u8, ..DaeParam::default() }, 0).unwrap();
    qdisc_add_clsact("lan").unwrap();
    let program: &mut SchedClassifier = bpf.program_mut("lan_ingress_l2").unwrap().try_into().unwrap();
    program.load().unwrap(); program.attach("lan", TcAttachType::Ingress).unwrap();
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0x0003u16.to_be() as i32) };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    // Own the successful raw descriptor; sockaddr storage is fully initialized.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family = libc::AF_PACKET as u16; address.sll_ifindex = src as i32;
    address.sll_halen = 6; address.sll_addr[..6].copy_from_slice(&lan_mac);
    for (v6, socket) in [false, true].into_iter().zip(sockets) {
        let data = packet(v6, src_mac, lan_mac);
        let sent = unsafe { libc::sendto(fd.as_raw_fd(), data.as_ptr().cast(), data.len(), 0,
            (&address as *const libc::sockaddr_ll).cast(), size_of_val(&address) as libc::socklen_t) };
        assert_eq!(sent, data.len() as isize, "{}", io::Error::last_os_error());
        let mut data = [0u8; 64];
        let (len, from) = socket.recv_from(&mut data).expect("mark/cb handoff must reach the transparent UDP socket");
        assert_eq!(&data[..len], b"peer-test"); assert_eq!(from.port(), 40000);
    }
}

#[test]
#[ignore = "requires root, safe kernel, veth/netkit and IPv6; attaches only in isolated namespaces"]
fn real_ipv4_ipv6_handoff_preserves_marks_for_both_link_types() {
    for kind in [LinkPairKind::Veth, LinkPairKind::Netkit] {
        for enabled in [false, true] {
            thread::spawn(move || deliver(kind, enabled)).join().unwrap();
        }
    }
}
