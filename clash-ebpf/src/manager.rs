use crate::config::EbpfConfig;
use crate::listener::{EbpfListener, ListenerError};
use crate::netns::{DaeNs, NetNsError};
use network_interface::NetworkInterfaceConfig;
use std::sync::Arc;
use thiserror::Error;
use tracing::info;

#[cfg(target_os = "linux")]
const DAENS_HOST_IP: &str = "169.254.0.1";
#[cfg(target_os = "linux")]
const DAENS_PEER_IP: &str = "169.254.0.2";
#[cfg(target_os = "linux")]
const DAENS_HOST_IPV6: &str = "fd00::1";
#[cfg(target_os = "linux")]
const DAENS_PEER_IPV6: &str = "fd00::2";
#[cfg(target_os = "linux")]
const TPROXY_MARK: u32 = 0x1dae;

#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("Platform not supported: eBPF inbound requires Linux")]
    UnsupportedPlatform,
    #[error("NetNS failure: {0}")]
    NetNs(#[from] NetNsError),
    #[error("Listener failure: {0}")]
    Listener(#[from] ListenerError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct EbpfManager {
    #[allow(dead_code)]
    config: EbpfConfig,
    #[allow(dead_code)]
    netns: Option<Arc<DaeNs>>,
    #[allow(dead_code)]
    listener: Option<Arc<EbpfListener>>,
    bpf_manager: crate::bpf::BpfProgramManager,
}

impl EbpfManager {
    pub fn new(config: EbpfConfig) -> Self {
        Self {
            config,
            netns: None,
            listener: None,
            bpf_manager: crate::bpf::BpfProgramManager::new(),
        }
    }


    /// Initializes the eBPF datapath, veth topology, and transparent listener.
    pub async fn start(&mut self) -> Result<Arc<EbpfListener>, EbpfError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(EbpfError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            use crate::netlink::{
                self, FAM_V4, FAM_V6, NlSock, PROTO_STATIC, ROUTE_LOCAL, ROUTE_UNICAST,
                SCOPE_HOST, SCOPE_LINK, SCOPE_UNIVERSE,
            };
            use std::net::{Ipv4Addr, Ipv6Addr};

            info!("Starting clash-ebpf datapath and isolation netns...");
            let ns = Arc::new(DaeNs::new()?);

            // Clean up any stale dae0 interface in host namespace
            if let Ok(idx) = netlink::ifindex_of("dae0") {
                let mut nl = NlSock::new()?;
                let _ = nl.del_link(idx);
            }

            // Create host <-> daens link pair (L2 netkit if supported, fallback to veth)
            let mut host_nl = NlSock::new()?;
            let link_kind = host_nl.add_link_pair("dae0", "dae0peer")?;
            info!("Created dae0/dae0peer link pair (kind: {:?})", link_kind);

            let dae0_mac = match netlink::mac_of("dae0") {
                Ok(m) => m,
                Err(_) => {
                    let (_, mac) = host_nl.get_link("dae0")?;
                    mac
                }
            };
            let (dae0_idx, _) = host_nl.get_link("dae0")?;
            let (peer_idx, _dae0peer_mac) = host_nl.get_link("dae0peer")?;

            // Host side configuration
            let host_v4: Ipv4Addr = DAENS_HOST_IP.parse().unwrap();
            let peer_v4: Ipv4Addr = DAENS_PEER_IP.parse().unwrap();
            let host_v6: Ipv6Addr = DAENS_HOST_IPV6.parse().unwrap();
            let peer_v6: Ipv6Addr = DAENS_PEER_IPV6.parse().unwrap();

            host_nl.addr_op(true, dae0_idx, FAM_V4, &host_v4.octets(), 32)?;
            let _ = host_nl.addr_op(true, dae0_idx, FAM_V6, &host_v6.octets(), 64);
            host_nl.set_link_up(dae0_idx, true)?;

            // Move peer to daens
            let dae_fd = ns.dae_fd();
            // SAFETY: borrowing raw fd from owned fd inside daens
            let borrowed_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(dae_fd) };
            let owned_fd = borrowed_fd.try_clone_to_owned().map_err(EbpfError::Io)?;
            host_nl.set_link_netns_fd(peer_idx, &owned_fd)?;

            // Configure within daens
            let dae0peer_mac = ns.with_daens(|| -> std::io::Result<[u8; 6]> {
                let mut n = NlSock::new()?;
                let (lo_idx, _) = n.get_link("lo")?;
                let (dae0peer_idx, mac) = n.get_link("dae0peer")?;

                n.set_link_up(lo_idx, true)?;
                n.set_link_up(dae0peer_idx, true)?;

                let final_mac = if mac != [0; 6] {
                    mac
                } else {
                    n.get_link("dae0peer")?.1
                };

                // Fwmark -> table 100 with local route
                n.add_rule_fwmark(FAM_V4, TPROXY_MARK, 100)?;
                n.add_route(
                    FAM_V4,
                    100,
                    ROUTE_LOCAL,
                    SCOPE_HOST,
                    PROTO_STATIC,
                    None,
                    None,
                    Some(lo_idx),
                )?;

                let _ = n.add_rule_fwmark(FAM_V6, TPROXY_MARK, 100);
                let _ = n.add_route(
                    FAM_V6,
                    100,
                    ROUTE_LOCAL,
                    SCOPE_HOST,
                    PROTO_STATIC,
                    None,
                    None,
                    Some(lo_idx),
                );

                // Add peer IP & default route to host via dae0peer
                n.addr_op(true, dae0peer_idx, FAM_V4, &peer_v4.octets(), 32)?;
                n.add_route(
                    FAM_V4,
                    254,
                    ROUTE_UNICAST,
                    SCOPE_LINK,
                    PROTO_STATIC,
                    Some((&host_v4.octets(), 32)),
                    None,
                    Some(dae0peer_idx),
                )?;
                n.add_route(
                    FAM_V4,
                    254,
                    ROUTE_UNICAST,
                    SCOPE_UNIVERSE,
                    PROTO_STATIC,
                    None,
                    Some(&host_v4.octets()),
                    Some(dae0peer_idx),
                )?;

                let _ = n.addr_op(true, dae0peer_idx, FAM_V6, &peer_v6.octets(), 64);
                let _ = n.add_route(
                    FAM_V6,
                    254,
                    ROUTE_UNICAST,
                    SCOPE_UNIVERSE,
                    PROTO_STATIC,
                    None,
                    Some(&host_v6.octets()),
                    Some(dae0peer_idx),
                );

                // Static neighbour entry for dae0
                n.neigh_replace(dae0peer_idx, FAM_V4, &host_v4.octets(), &dae0_mac)?;
                let _ = n.neigh_replace(dae0peer_idx, FAM_V6, &host_v6.octets(), &dae0_mac);

                // Netns sysctls
                for (key, val) in [
                    ("net.ipv4.ip_nonlocal_bind", "1"),
                    ("net.ipv6.ip_nonlocal_bind", "1"),
                    ("net.ipv4.conf.all.rp_filter", "0"),
                    ("net.ipv4.conf.all.accept_local", "1"),
                    ("net.ipv4.conf.all.route_localnet", "1"),
                    ("net.ipv4.conf.dae0peer.rp_filter", "0"),
                    ("net.ipv4.conf.dae0peer.accept_local", "1"),
                    ("net.ipv4.conf.dae0peer.route_localnet", "1"),
                    ("net.ipv4.conf.lo.accept_local", "1"),
                    ("net.ipv4.conf.lo.route_localnet", "1"),
                    ("net.ipv6.conf.all.forwarding", "1"),
                    ("net.ipv6.conf.dae0peer.forwarding", "1"),
                    ("net.ipv6.conf.dae0peer.accept_ra", "0"),
                ] {
                    let _ = netlink::set_sysctl(key, val);
                }

                Ok(final_mac)
            })??;

            // Bind transparent listener inside daens
            let listener = Arc::new(EbpfListener::bind(&ns, self.config.clone())?);

            // Resolve effective WAN interface (handling "auto", OpenWrt PPPoE/VLAN, multi-metric routes)
            let effective_wan = match self.config.wan_interface.as_deref() {
                Some("auto") | None | Some("") => detect_default_wan_interface(&self.config.lan_interface),
                Some(w) => Some(w.to_string()),
            };

            // Resolve effective LAN interfaces (handling "auto", OpenWrt br-lan, multi-NIC and single-NIC setups)
            let effective_lan = detect_lan_interfaces(&self.config.lan_interface, effective_wan.as_deref());

            info!(
                "Resolved network topology -> LAN interfaces: {:?}, WAN interface: {:?}",
                effective_lan, effective_wan
            );

            let mut all_dst_ips = self.config.target.bypass_dst_ips.clone();
            let detected_ips = detect_interface_ips(&effective_lan, effective_wan.as_deref());
            let mut local_ip_u32 = 0u32;
            for ip in &detected_ips {
                if !all_dst_ips.contains(ip) {
                    info!("Auto-detected host interface IP: {}, injected into bypass whitelist", ip);
                    all_dst_ips.push(ip.clone());
                }
                if local_ip_u32 == 0 {
                    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
                        local_ip_u32 = u32::from_ne_bytes(v4.octets());
                    }
                }
            }
            all_dst_ips = crate::config::aggregate_ip_cidrs(&all_dst_ips);

            let has_proxy_src_ips = if !self.config.lan.proxy_src_ips.is_empty() { 1 } else { 0 };
            let has_proxy_dst_ips = if !self.config.target.proxy_dst_ips.is_empty() { 1 } else { 0 };
            let has_proxy_src_ports = if !self.config.lan.proxy_src_ports.is_empty() { 1 } else { 0 };
            let has_proxy_dst_ports = if !self.config.target.proxy_dst_ports.is_empty() { 1 } else { 0 };
            let direct_offload_enabled = if self.config.auto_direct_offload { 1 } else { 0 };
            let proxy_local = if self.config.host.proxy_local { 1 } else { 0 };
            let has_proxy_processes = if !self.config.host.proxy_processes.is_empty() { 1 } else { 0 };
            let has_bypass_processes = if !self.config.host.bypass_processes.is_empty() { 1 } else { 0 };

            // Initialize eBPF programs and attach TC/cgroup hooks via Aya
            let bpf_param = clash_ebpf_common::DaeParam {
                tproxy_port: self.config.tproxy_port as u32,
                dae0_ifindex: dae0_idx,
                wan_ifindex: 0,
                dae0peer_mac,
                use_redirect_peer: 0,
                proxy_local,
                dae_socket_mark: self.config.routing_mark.unwrap_or(clash_ebpf_common::DAE_BYPASS_MARK),
                control_plane_pid: std::process::id(),
                local_ip: local_ip_u32,
                has_proxy_src_ips,
                has_proxy_dst_ips,
                has_proxy_src_ports,
                has_proxy_dst_ports,
                direct_offload_enabled,
                has_proxy_processes,
                has_bypass_processes,
                _pad1: 0,
            };

            if let Err(e) = self.bpf_manager.load_and_attach(
                crate::bpf::EMBEDDED_BPF_OBJECT,
                &bpf_param,
                &effective_lan,
                effective_wan.as_deref(),
                &self.config.lan.bypass_src_ports,
                &self.config.target.bypass_dst_ports,
                &self.config.lan.bypass_src_ips,
                &all_dst_ips,
                &self.config.lan.proxy_src_ports,
                &self.config.target.proxy_dst_ports,
                &self.config.lan.proxy_src_ips,
                &self.config.target.proxy_dst_ips,
                &self.config.host.proxy_processes,
                &self.config.host.bypass_processes,
                Some(&ns),
            ) {
                tracing::warn!("eBPF hooks attachment: {e}");
            }

            // Publish listener socket fds into LISTEN_SOCKET_MAP for bpf_sk_assign.
            // This must happen after both listener binding and BPF loading.
            if let Err(e) = self.bpf_manager.publish_listener_sockets(
                listener.tcp_v4_raw_fd(),
                listener.tcp_v6_raw_fd(),
                listener.udp_v4_raw_fd(),
                listener.udp_v6_raw_fd(),
            ) {
                tracing::warn!("Failed to publish listener sockets to SOCKMAP: {e}");
            }

            self.netns = Some(ns);
            self.listener = Some(listener.clone());

            info!(
                "clash-ebpf started: TCP port {}, UDP port {}, LAN interfaces: {:?}, WAN interface: {:?}",
                self.config.tproxy_port, self.config.tproxy_udp_port, self.config.lan_interface, effective_wan
            );

            Ok(listener)

        }
    }


    /// Stops the eBPF datapath and cleans up all hooks, interfaces and namespaces.
    pub async fn stop(&self) {
        info!("Stopping clash-ebpf datapath...");
        self.bpf_manager.unload();

        #[cfg(target_os = "linux")]
        {
            use crate::netlink::{self, NlSock};
            if let Ok(idx) = netlink::ifindex_of("dae0") {
                if let Ok(mut nl) = NlSock::new() {
                    let _ = nl.del_link(idx);
                }
            }
        }

        info!("clash-ebpf datapath stopped successfully");
    }



    /// Dynamically update direct bypass IP destinations in batch.
    pub async fn update_dynamic_bypass_batch(
        &self,
        add_v4: &[std::net::Ipv4Addr],
        add_v6: &[std::net::Ipv6Addr],
        remove_v4: &[std::net::Ipv4Addr],
        remove_v6: &[std::net::Ipv6Addr],
    ) -> Result<(), String> {
        self.bpf_manager
            .update_dynamic_bypass_batch(add_v4, add_v6, remove_v4, remove_v6)
    }
}

/// Detect the default WAN egress interface for Linux and OpenWrt router environments.
pub fn detect_default_wan_interface(lan_interfaces: &[String]) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        // 1. Try reading /proc/net/route (IPv4 default routes sorted by Metric)
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            let mut candidates: Vec<(String, u32)> = Vec::new();
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 11 {
                    let iface = fields[0];
                    let dest = fields[1];
                    let mask = fields[7];
                    let flags_hex = fields[3];
                    let metric = fields[6].parse::<u32>().unwrap_or(u32::MAX);

                    let flags = u32::from_str_radix(flags_hex, 16).unwrap_or(0);
                    if (dest == "00000000" && mask == "00000000") || (flags & 0x1 != 0 && dest == "00000000") {
                        if iface != "lo"
                            && iface != "dae0"
                            && iface != "dae0peer"
                            && !iface.starts_with("docker")
                            && !iface.starts_with("veth")
                            && !iface.starts_with("tun")
                            && !lan_interfaces.iter().any(|lan| lan == iface)
                        {
                            candidates.push((iface.to_string(), metric));
                        }
                    }
                }
            }
            if !candidates.is_empty() {
                candidates.sort_by_key(|(_, m)| *m);
                return Some(candidates[0].0.clone());
            }
        }

        // 2. Try reading /proc/net/ipv6_route (IPv6 default routes sorted by Metric)
        if let Ok(content) = std::fs::read_to_string("/proc/net/ipv6_route") {
            let mut candidates: Vec<(String, u32)> = Vec::new();
            for line in content.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 10 {
                    let dest = fields[0];
                    let prefix_len = fields[1];
                    let metric = u32::from_str_radix(fields[5], 16).unwrap_or(u32::MAX);
                    let iface = fields[9];
                    if dest == "00000000000000000000000000000000" && prefix_len == "00" {
                        if iface != "lo"
                            && iface != "dae0"
                            && iface != "dae0peer"
                            && !iface.starts_with("docker")
                            && !iface.starts_with("veth")
                            && !iface.starts_with("tun")
                            && !lan_interfaces.iter().any(|lan| lan == iface)
                        {
                            candidates.push((iface.to_string(), metric));
                        }
                    }
                }
            }
            if !candidates.is_empty() {
                candidates.sort_by_key(|(_, m)| *m);
                return Some(candidates[0].0.clone());
            }
        }
    }

    // 3. Heuristic matching via NetworkInterface::show() for OpenWrt & Linux
    if let Ok(interface_list) = network_interface::NetworkInterface::show() {
        let priority_prefixes = [
            "pppoe-wan",
            "pppoe",
            "wan",
            "ppp",
            "eth",
            "enp",
            "en",
            "wlp",
            "wlan",
        ];

        let mut valid_ifaces: Vec<(String, usize, bool)> = Vec::new();
        for iface in interface_list {
            let name = iface.name;
            if name == "lo"
                || name == "dae0"
                || name == "dae0peer"
                || name.starts_with("docker")
                || name.starts_with("veth")
                || name.starts_with("tun")
                || name.starts_with("br-")
                || lan_interfaces.iter().any(|lan| lan == &name)
            {
                continue;
            }

            let has_non_local_ip = iface.addr.iter().any(|a| {
                let ip = a.ip();
                !ip.is_loopback() && !ip.is_unspecified()
            });

            let prio = priority_prefixes
                .iter()
                .position(|&p| name.starts_with(p) || name.contains(p))
                .unwrap_or(usize::MAX);

            valid_ifaces.push((name, prio, has_non_local_ip));
        }

        valid_ifaces.sort_by(|a, b| {
            b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1))
        });

        if let Some((name, _, _)) = valid_ifaces.first() {
            return Some(name.clone());
        }
    }

    // 4. Fallback to primary LAN interface in single-NIC / single-homed setups
    lan_interfaces.first().cloned()
}

/// Detect effective LAN ingress interfaces for Linux and OpenWrt router environments.
pub fn detect_lan_interfaces(configured_lan: &[String], effective_wan: Option<&str>) -> Vec<String> {
    let non_auto_lan: Vec<String> = configured_lan
        .iter()
        .filter(|s| !s.is_empty() && s.as_str() != "auto")
        .cloned()
        .collect();

    if !non_auto_lan.is_empty() {
        return non_auto_lan;
    }

    // 1. OpenWrt Bridge preference: look for "br-lan" or bridge interface
    if let Ok(interface_list) = network_interface::NetworkInterface::show() {
        for iface in &interface_list {
            if (iface.name == "br-lan" || iface.name == "lan") && effective_wan != Some(iface.name.as_str()) {
                return vec![iface.name.clone()];
            }
        }

        // 2. Multi-NIC router setup: collect active interfaces that are not WAN, loopback, or virtual
        let mut candidates: Vec<String> = Vec::new();
        for iface in &interface_list {
            let name = &iface.name;
            if name == "lo"
                || name == "dae0"
                || name == "dae0peer"
                || name.starts_with("docker")
                || name.starts_with("veth")
                || name.starts_with("tun")
                || name.starts_with("tailscale")
                || name.starts_with("wg")
                || name.starts_with("ppp")
                || name.starts_with("pppoe")
                || effective_wan == Some(name.as_str())
            {
                continue;
            }

            let has_non_local_ip = iface.addr.iter().any(|a| {
                let ip = a.ip();
                !ip.is_loopback() && !ip.is_unspecified()
            });

            if has_non_local_ip {
                candidates.push(name.clone());
            }
        }

        if !candidates.is_empty() {
            return candidates;
        }
    }

    // 3. Fallback: single-NIC / on-a-stick topology (use effective_wan as LAN too)
    if let Some(wan) = effective_wan {
        if !wan.is_empty() {
            return vec![wan.to_string()];
        }
    }

    Vec::new()
}

#[allow(dead_code)]
fn detect_interface_ips(lan: &[String], wan: Option<&str>) -> Vec<String> {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};
    let mut target_ifaces: Vec<&str> = lan.iter().map(|s| s.as_str()).collect();
    if let Some(w) = wan {
        if !w.is_empty() && w != "auto" {
            target_ifaces.push(w);
        }
    }
    let mut ips = Vec::new();
    if let Ok(interface_list) = NetworkInterface::show() {
        for iface in interface_list {
            let matched = target_ifaces.is_empty() || target_ifaces.iter().any(|&name| name == iface.name.as_str());
            if matched && iface.name != "dae0" && iface.name != "dae0peer" {
                for addr in iface.addr {
                    let ip_str = addr.ip().to_string();
                    if !ip_str.is_empty() && !ip_str.starts_with("127.") && ip_str != "::1" {
                        ips.push(ip_str);
                    }
                }
            }
        }
    }
    ips
}


