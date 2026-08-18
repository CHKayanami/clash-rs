//! Minimal synchronous rtnetlink client (NETLINK_ROUTE).
//!
//! Provides direct kernel netlink configuration for daens topology:
//! veth pair creation, netns moving, IP addressing, policy routing,
//! local routing tables, and static neighbours.

#![allow(dead_code)]


#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};

#[cfg(target_os = "linux")]
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, recvfrom,
    send, setsockopt, socket, sockopt,
};
#[cfg(target_os = "linux")]
use nix::sys::time::TimeVal;

// ---- kernel ABI constants ----

#[cfg(target_os = "linux")]
const AF_INET: i32 = libc::AF_INET;
#[cfg(target_os = "linux")]
const AF_INET6: i32 = libc::AF_INET6;

#[cfg(target_os = "linux")]
const NLM_F_REQUEST: u16 = 0x01;
#[cfg(target_os = "linux")]
const NLM_F_ACK: u16 = 0x04;
#[cfg(target_os = "linux")]
const NLM_F_EXCL: u16 = 0x200;
#[cfg(target_os = "linux")]
const NLM_F_CREATE: u16 = 0x400;
#[cfg(target_os = "linux")]
const NLM_F_REPLACE: u16 = 0x100;

#[cfg(target_os = "linux")]
const NLMSG_ERROR: u16 = 2;

#[cfg(target_os = "linux")]
const RTM_NEWLINK: u16 = 16;
#[cfg(target_os = "linux")]
const RTM_DELLINK: u16 = 17;
#[cfg(target_os = "linux")]
const RTM_NEWADDR: u16 = 20;
#[cfg(target_os = "linux")]
const RTM_DELADDR: u16 = 21;
#[cfg(target_os = "linux")]
const RTM_NEWROUTE: u16 = 24;
#[cfg(target_os = "linux")]
const RTM_NEWRULE: u16 = 32;
#[cfg(target_os = "linux")]
const RTM_DELRULE: u16 = 33;
#[cfg(target_os = "linux")]
const RTM_NEWNEIGH: u16 = 28;

#[cfg(target_os = "linux")]
const ARPHRD_ETHER: u16 = 1;
#[cfg(target_os = "linux")]
const IFF_UP: u32 = 0x1;

#[cfg(target_os = "linux")]
const IFLA_ADDRESS: u16 = 1;
#[cfg(target_os = "linux")]
const IFLA_IFNAME: u16 = 3;
#[cfg(target_os = "linux")]
const IFLA_LINKINFO: u16 = 18;
#[cfg(target_os = "linux")]
const IFLA_NET_NS_FD: u16 = 28;
#[cfg(target_os = "linux")]
const IFLA_INFO_KIND: u16 = 1;
#[cfg(target_os = "linux")]
const IFLA_INFO_DATA: u16 = 2;
#[cfg(target_os = "linux")]
const VETH_INFO_PEER: u16 = 1;
#[cfg(target_os = "linux")]
const IFLA_NETKIT_PEER_INFO: u16 = 1;
#[cfg(target_os = "linux")]
const IFLA_NETKIT_PRIMARY_POLICY: u16 = 2;
#[cfg(target_os = "linux")]
const IFLA_NETKIT_PEER_POLICY: u16 = 3;
#[cfg(target_os = "linux")]
const IFLA_NETKIT_PRIMARY_SCRUB: u16 = 4;
#[cfg(target_os = "linux")]
const IFLA_NETKIT_PEER_SCRUB: u16 = 5;
#[cfg(target_os = "linux")]
const IFLA_NETKIT_MODE: u16 = 6;
#[cfg(target_os = "linux")]
const NETKIT_PASS: u32 = 0;
#[cfg(target_os = "linux")]
const NETKIT_L2: u32 = 0;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkPairKind {
    Netkit,
    Veth,
}

#[cfg(target_os = "linux")]
fn netkit_unavailable(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EOPNOTSUPP)
}

#[cfg(target_os = "linux")]
const IFA_ADDRESS: u16 = 1;
#[cfg(target_os = "linux")]
const IFA_LOCAL: u16 = 2;

#[cfg(target_os = "linux")]
const RTA_DST: u16 = 1;
#[cfg(target_os = "linux")]
const RTA_GATEWAY: u16 = 5;
#[cfg(target_os = "linux")]
const RTA_OIF: u16 = 4;
#[cfg(target_os = "linux")]
const RTA_TABLE: u16 = 15;

#[cfg(target_os = "linux")]
const NDA_DST: u16 = 1;
#[cfg(target_os = "linux")]
const NDA_LLADDR: u16 = 2;

#[cfg(target_os = "linux")]
const FRA_FWMARK: u16 = 10;
#[cfg(target_os = "linux")]
const FRA_TABLE: u16 = 15;
#[cfg(target_os = "linux")]
const FRA_FWMASK: u16 = 16;

#[cfg(target_os = "linux")]
const NUD_PERMANENT: u16 = 0x80;
#[cfg(target_os = "linux")]
const RTN_UNICAST: u8 = 1;
#[cfg(target_os = "linux")]
const RTN_LOCAL: u8 = 2;
#[cfg(target_os = "linux")]
const RTPROT_STATIC: u8 = 4;
#[cfg(target_os = "linux")]
const RT_SCOPE_LINK: u8 = 253;
#[cfg(target_os = "linux")]
const RT_SCOPE_UNIVERSE: u8 = 0;
#[cfg(target_os = "linux")]
const RT_SCOPE_HOST: u8 = 254;
#[cfg(target_os = "linux")]
const FR_ACT_TO_TBL: u8 = 1;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct NdMsg {
    ndm_family: u8,
    ndm_pad1: u8,
    ndm_pad2: u16,
    ndm_ifindex: i32,
    ndm_state: u16,
    ndm_flags: u8,
    ndm_type: u8,
}

#[cfg(target_os = "linux")]
const NLMSG_ALIGNTO: usize = 4;

#[cfg(target_os = "linux")]
fn align(len: usize) -> usize {
    len.div_ceil(NLMSG_ALIGNTO) * NLMSG_ALIGNTO
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
enum Attr {
    U32(u32),
    Bytes(Vec<u8>),
    Str(String),
    Nested(Vec<(u16, Attr)>),
}

#[cfg(target_os = "linux")]
fn attr_payload(attr: &Attr, out: &mut Vec<u8>) {
    match attr {
        Attr::U32(v) => out.extend_from_slice(&v.to_ne_bytes()),
        Attr::Bytes(b) => out.extend_from_slice(b),
        Attr::Str(s) => {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }
        Attr::Nested(children) => {
            for (ty, child) in children {
                put_attr(out, *ty, child);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn put_attr(buf: &mut Vec<u8>, rta_type: u16, attr: &Attr) {
    let mut payload = Vec::new();
    attr_payload(attr, &mut payload);
    let len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&rta_type.to_ne_bytes());
    buf.extend_from_slice(&payload);
    while buf.len() % NLMSG_ALIGNTO != 0 {
        buf.push(0);
    }
}

#[cfg(target_os = "linux")]
fn pod_bytes<T>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
}

#[cfg(target_os = "linux")]
fn ifinfo(ifindex: i32, flags: u32, change: u32) -> IfInfoMsg {
    IfInfoMsg {
        ifi_family: 0,
        ifi_pad: 0,
        ifi_type: ARPHRD_ETHER,
        ifi_index: ifindex,
        ifi_flags: flags,
        ifi_change: change,
    }
}

#[cfg(target_os = "linux")]
pub struct NlSock {
    fd: OwnedFd,
    seq: u32,
}

#[cfg(target_os = "linux")]
impl NlSock {
    pub fn new() -> io::Result<Self> {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )
        .map_err(io::Error::from)?;
        setsockopt(&fd, sockopt::ReceiveTimeout, &TimeVal::new(2, 0)).map_err(io::Error::from)?;
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0)).map_err(io::Error::from)?;
        Ok(Self { fd, seq: 0 })
    }

    fn recv_one(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        const MAX_BUF: usize = 1 << 20;
        loop {
            let needed = match recv(
                self.fd.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC,
            ) {
                Ok(needed) => needed,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(io::Error::from(error)),
            };
            if needed > MAX_BUF {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netlink message exceeds 1 MiB",
                ));
            }
            if needed > buf.len() {
                buf.resize(needed, 0);
            }
            let (received, source) = match recvfrom::<NetlinkAddr>(self.fd.as_raw_fd(), buf) {
                Ok(received) => received,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(io::Error::from(error)),
            };
            if source.is_some_and(|source| source.pid() != 0) {
                continue;
            }
            return Ok(received);
        }
    }

    fn send_datagram(&self, buf: &[u8]) -> io::Result<()> {
        let sent = send(self.fd.as_raw_fd(), buf, MsgFlags::empty()).map_err(io::Error::from)?;
        if sent == buf.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink datagram send",
            ))
        }
    }

    fn request(
        &mut self,
        msg_type: u16,
        flags: u16,
        header: &[u8],
        attrs: &[(u16, Attr)],
    ) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&[0u8; 4]); // length, patched below
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.extend_from_slice(header);
        for (ty, attr) in attrs {
            put_attr(&mut buf, *ty, attr);
        }
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        self.send_datagram(&buf)?;

        let mut resp = vec![0u8; 4096];
        loop {
            let n = self.recv_one(&mut resp)?;
            let mut off = 0usize;
            while off + 16 <= n {
                let hlen = u32::from_ne_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
                let htype = u16::from_ne_bytes(resp[off + 4..off + 6].try_into().unwrap());
                let hseq = u32::from_ne_bytes(resp[off + 8..off + 12].try_into().unwrap());
                if hlen < 16 || off + hlen > n {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed netlink message header",
                    ));
                }
                if hseq == seq && htype == NLMSG_ERROR {
                    if hlen < 20 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short NLMSG_ERROR",
                        ));
                    }
                    let err = i32::from_ne_bytes(resp[off + 16..off + 20].try_into().unwrap());
                    if err == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-err));
                }
                off += align(hlen);
            }
        }
    }

    /// Create an L2 netkit pair when supported, otherwise fallback to a veth pair.
    pub fn add_link_pair(&mut self, name: &str, peer: &str) -> io::Result<LinkPairKind> {
        match self.add_netkit_pair(name, peer) {
            Ok(()) => Ok(LinkPairKind::Netkit),
            Err(e) => {
                tracing::info!("Netkit pair not supported or failed ({e}), falling back to Veth");
                self.add_veth_pair(name, peer)?;
                Ok(LinkPairKind::Veth)
            }
        }
    }

    /// Create an L2 netkit pair (`name` <-> `peer_name`) with PASS policies.
    pub fn add_netkit_pair(&mut self, name: &str, peer: &str) -> io::Result<()> {
        let header = ifinfo(0, 0, 0);
        let mut peer_payload = pod_bytes(&ifinfo(0, 0, 0)).to_vec();
        put_attr(&mut peer_payload, IFLA_IFNAME, &Attr::Str(peer.to_string()));

        let attrs = [
            (IFLA_IFNAME, Attr::Str(name.to_string())),
            (
                IFLA_LINKINFO,
                Attr::Nested(vec![
                    (IFLA_INFO_KIND, Attr::Str("netkit".to_string())),
                    (
                        IFLA_INFO_DATA,
                        Attr::Nested(vec![
                            (IFLA_NETKIT_MODE, Attr::U32(NETKIT_L2)),
                            (IFLA_NETKIT_PRIMARY_POLICY, Attr::U32(NETKIT_PASS)),
                            (IFLA_NETKIT_PEER_POLICY, Attr::U32(NETKIT_PASS)),
                            (IFLA_NETKIT_PEER_INFO, Attr::Bytes(peer_payload)),
                        ]),
                    ),
                ]),
            ),
        ];
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            pod_bytes(&header),
            &attrs,
        )
    }

    /// Create a veth pair (`name` <-> `peer_name`).
    pub fn add_veth_pair(&mut self, name: &str, peer: &str) -> io::Result<()> {
        let header = ifinfo(0, 0, 0);
        let mut peer_payload = pod_bytes(&ifinfo(0, 0, 0)).to_vec();
        put_attr(&mut peer_payload, IFLA_IFNAME, &Attr::Str(peer.to_string()));

        let attrs = [
            (IFLA_IFNAME, Attr::Str(name.to_string())),
            (
                IFLA_LINKINFO,
                Attr::Nested(vec![
                    (IFLA_INFO_KIND, Attr::Str("veth".to_string())),
                    (
                        IFLA_INFO_DATA,
                        Attr::Nested(vec![(VETH_INFO_PEER, Attr::Bytes(peer_payload))]),
                    ),
                ]),
            ),
        ];
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            pod_bytes(&header),
            &attrs,
        )
    }

    /// Bring a link up or down.
    pub fn set_link_up(&mut self, ifindex: u32, up: bool) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, if up { IFF_UP } else { 0 }, IFF_UP);
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &[],
        )
    }

    /// Move a link into the namespace identified by `ns_fd`.
    pub fn set_link_netns_fd(&mut self, ifindex: u32, ns_fd: &OwnedFd) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, 0, 0);
        let fd_no = ns_fd.as_raw_fd() as u32;
        let attrs = [(IFLA_NET_NS_FD, Attr::U32(fd_no))];
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &attrs,
        )
    }

    /// Delete a link by index.
    pub fn del_link(&mut self, ifindex: u32) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, 0, 0);
        self.request(
            RTM_DELLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &[],
        )
    }

    /// Add (or remove) an IP address on an interface.
    pub fn addr_op(
        &mut self,
        add: bool,
        ifindex: u32,
        family: u8,
        addr: &[u8],
        prefix: u8,
    ) -> io::Result<()> {
        let header = IfAddrMsg {
            ifa_family: family,
            ifa_prefixlen: prefix,
            ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE,
            ifa_index: ifindex,
        };
        let attrs = [
            (IFA_LOCAL, Attr::Bytes(addr.to_vec())),
            (IFA_ADDRESS, Attr::Bytes(addr.to_vec())),
        ];
        let (ty, flags) = if add {
            (
                RTM_NEWADDR,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            )
        } else {
            (RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK)
        };
        self.request(ty, flags, pod_bytes(&header), &attrs)
    }

    /// Add a route. `dst` is (network, prefix) or None for default route.
    #[allow(clippy::too_many_arguments)]
    pub fn add_route(
        &mut self,
        family: u8,
        table: u32,
        route_type: u8,
        scope: u8,
        proto: u8,
        dst: Option<(&[u8], u8)>,
        gateway: Option<&[u8]>,
        oif: Option<u32>,
    ) -> io::Result<()> {
        let header = RtMsg {
            rtm_family: family,
            rtm_dst_len: dst.map(|(_, p)| p).unwrap_or(0),
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: if table <= 255 { table as u8 } else { 0 },
            rtm_protocol: proto,
            rtm_scope: scope,
            rtm_type: route_type,
            rtm_flags: 0,
        };
        let mut attrs: Vec<(u16, Attr)> = Vec::new();
        if table > 255 {
            attrs.push((RTA_TABLE, Attr::U32(table)));
        }
        if let Some((net, _)) = dst {
            attrs.push((RTA_DST, Attr::Bytes(net.to_vec())));
        }
        if let Some(gw) = gateway {
            attrs.push((RTA_GATEWAY, Attr::Bytes(gw.to_vec())));
        }
        if let Some(idx) = oif {
            attrs.push((RTA_OIF, Attr::U32(idx)));
        }
        self.request(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            pod_bytes(&header),
            &attrs,
        )
    }

    /// Add or delete a fwmark -> table rule.
    fn rule_fwmark(&mut self, add: bool, family: u8, fwmark: u32, table: u32) -> io::Result<()> {
        let header: [u8; 12] = [
            family,
            0,
            0,
            0,
            if table <= 255 { table as u8 } else { 0 },
            0,
            0,
            FR_ACT_TO_TBL,
            0,
            0,
            0,
            0,
        ];
        let mut attrs: Vec<(u16, Attr)> = vec![
            (FRA_FWMARK, Attr::U32(fwmark)),
            (FRA_FWMASK, Attr::U32(u32::MAX)),
        ];
        if table > 255 {
            attrs.push((FRA_TABLE, Attr::U32(table)));
        }
        let (ty, flags) = if add {
            (RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
        } else {
            (RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK)
        };
        self.request(ty, flags, &header, &attrs)
    }

    pub fn add_rule_fwmark(&mut self, family: u8, fwmark: u32, table: u32) -> io::Result<()> {
        self.rule_fwmark(true, family, fwmark, table)
    }

    pub fn del_rule_fwmark(&mut self, family: u8, fwmark: u32, table: u32) -> io::Result<()> {
        self.rule_fwmark(false, family, fwmark, table)
    }

    /// Replace a static neighbour entry (IP -> MAC).
    pub fn neigh_replace(
        &mut self,
        ifindex: u32,
        family: u8,
        ip: &[u8],
        mac: &[u8; 6],
    ) -> io::Result<()> {
        let header = NdMsg {
            ndm_family: family,
            ndm_pad1: 0,
            ndm_pad2: 0,
            ndm_ifindex: ifindex as i32,
            ndm_state: NUD_PERMANENT,
            ndm_flags: 0,
            ndm_type: 0,
        };
        let attrs = [
            (NDA_DST, Attr::Bytes(ip.to_vec())),
            (NDA_LLADDR, Attr::Bytes(mac.to_vec())),
        ];
        self.request(
            RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            pod_bytes(&header),
            &attrs,
        )
    }

    /// Look up an interface by name via netlink (works inside isolated namespaces).
    pub fn get_link(&mut self, name: &str) -> io::Result<(u32, [u8; 6])> {
        const RTM_GETLINK: u16 = 18;
        const NLM_F_DUMP: u16 = 0x300;
        const NLMSG_DONE: u16 = 3;
        self.seq += 1;
        let seq = self.seq;
        let header = ifinfo(0, 0, 0);
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&RTM_GETLINK.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(pod_bytes(&header));
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.send_datagram(&buf)?;

        let mut resp = vec![0u8; 8192];
        let mut found: Option<(u32, [u8; 6])> = None;
        loop {
            let n = self.recv_one(&mut resp)?;
            let mut done = false;
            let mut off = 0usize;
            while off + 16 <= n {
                let hlen = u32::from_ne_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
                if hlen < 16 || off + hlen > n {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed netlink message header",
                    ));
                }
                let htype = u16::from_ne_bytes(resp[off + 4..off + 6].try_into().unwrap());
                let hseq = u32::from_ne_bytes(resp[off + 8..off + 12].try_into().unwrap());
                if hseq != seq {
                    break;
                }
                if htype == NLMSG_DONE {
                    done = true;
                    break;
                }
                if htype == NLMSG_ERROR {
                    if hlen < 20 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short NLMSG_ERROR",
                        ));
                    }
                    let err = i32::from_ne_bytes(resp[off + 16..off + 20].try_into().unwrap());
                    return Err(io::Error::from_raw_os_error(-err));
                }
                if htype == RTM_NEWLINK && hlen >= 16 + 16 {
                    let ifi = &resp[off + 16..off + hlen];
                    let ifindex = i32::from_ne_bytes(ifi[4..8].try_into().unwrap());
                    let mut ifname: Option<String> = None;
                    let mut mac: Option<[u8; 6]> = None;
                    let mut aoff = 16;
                    while aoff + 4 <= ifi.len() {
                        let alen =
                            u16::from_ne_bytes(ifi[aoff..aoff + 2].try_into().unwrap()) as usize;
                        let atype = u16::from_ne_bytes(ifi[aoff + 2..aoff + 4].try_into().unwrap());
                        if alen < 4 || aoff + alen > ifi.len() {
                            break;
                        }
                        let payload = &ifi[aoff + 4..aoff + alen];
                        match atype {
                            IFLA_IFNAME => {
                                let end = payload
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(payload.len());
                                ifname =
                                    Some(String::from_utf8_lossy(&payload[..end]).into_owned());
                            }
                            IFLA_ADDRESS if payload.len() == 6 => {
                                mac = Some(payload.try_into().unwrap());
                            }
                            _ => {}
                        }
                        aoff += align(alen);
                    }
                    if ifname.as_deref() == Some(name) {
                        let mac_addr = mac.unwrap_or([0u8; 6]);
                        found = Some((ifindex as u32, mac_addr));
                    }
                }
                let next = align(hlen);
                if next == 0 {
                    break;
                }
                off += next;
            }
            if done {
                break;
            }
        }
        found.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {name} not found via netlink"),
            )
        })
    }
}


// Exported constants
#[cfg(target_os = "linux")]
pub const FAM_V4: u8 = AF_INET as u8;
#[cfg(target_os = "linux")]
pub const FAM_V6: u8 = AF_INET6 as u8;
#[cfg(target_os = "linux")]
pub const ROUTE_UNICAST: u8 = RTN_UNICAST;
#[cfg(target_os = "linux")]
pub const ROUTE_LOCAL: u8 = RTN_LOCAL;
#[cfg(target_os = "linux")]
pub const PROTO_STATIC: u8 = RTPROT_STATIC;
#[cfg(target_os = "linux")]
pub const SCOPE_LINK: u8 = RT_SCOPE_LINK;
#[cfg(target_os = "linux")]
pub const SCOPE_UNIVERSE: u8 = RT_SCOPE_UNIVERSE;
#[cfg(target_os = "linux")]
pub const SCOPE_HOST: u8 = RT_SCOPE_HOST;

#[cfg(target_os = "linux")]
pub fn ifindex_of(name: &str) -> io::Result<u32> {
    let path = format!("/sys/class/net/{name}/ifindex");
    let content = std::fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("read ifindex for {name}: {e}")))?;
    content
        .trim()
        .parse::<u32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parse ifindex: {e}")))
}

#[cfg(target_os = "linux")]
pub fn mac_of(name: &str) -> io::Result<[u8; 6]> {
    let path = format!("/sys/class/net/{name}/address");
    let content = std::fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("read MAC for {name}: {e}")))?;
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = content.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed MAC: {content}"),
        ));
    }
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("parse MAC byte: {e}"))
        })?;
    }
    Ok(mac)
}

#[cfg(target_os = "linux")]
pub fn set_sysctl(path: &str, value: &str) -> io::Result<()> {
    let full_path = format!("/proc/sys/{}", path.replace('.', "/"));
    std::fs::write(&full_path, value)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn netkit_fallback_is_only_for_missing_driver() {
        assert!(netkit_unavailable(&io::Error::from_raw_os_error(
            libc::EOPNOTSUPP
        )));
        assert!(!netkit_unavailable(&io::Error::from_raw_os_error(
            libc::EINVAL
        )));
        assert!(!netkit_unavailable(&io::Error::from_raw_os_error(
            libc::EPERM
        )));
    }
}

