use crate::config::EbpfConfig;
use crate::listener::{EbpfListener, ListenerError};
use crate::netns::{DaeNs, NetNsError};
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
    bpf_manager: Arc<tokio::sync::Mutex<crate::bpf::BpfProgramManager>>,
}

impl EbpfManager {
    pub fn new(config: EbpfConfig) -> Self {
        Self {
            config,
            netns: None,
            listener: None,
            bpf_manager: Arc::new(tokio::sync::Mutex::new(crate::bpf::BpfProgramManager::new())),
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

            let mut all_dst_ips = self.config.bypass_dst_ips.clone();
            let detected_ips = detect_interface_ips(&self.config.lan_interface, self.config.wan_interface.as_deref());
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

            let has_proxy_src_ips = if !self.config.proxy_ips.is_empty() || !self.config.proxy_src_ips.is_empty() { 1 } else { 0 };
            let has_proxy_dst_ips = if !self.config.proxy_ips.is_empty() || !self.config.proxy_dst_ips.is_empty() { 1 } else { 0 };
            let has_proxy_src_ports = if !self.config.proxy_ports.is_empty() || !self.config.proxy_src_ports.is_empty() { 1 } else { 0 };
            let has_proxy_dst_ports = if !self.config.proxy_ports.is_empty() || !self.config.proxy_dst_ports.is_empty() { 1 } else { 0 };
            let direct_offload_enabled = if self.config.auto_direct_offload { 1 } else { 0 };

            // Initialize eBPF programs and attach TC/cgroup hooks via Aya
            let bpf_param = clash_ebpf_common::DaeParam {
                tproxy_port: self.config.tproxy_port as u32,
                dae0_ifindex: dae0_idx,
                wan_ifindex: 0,
                dae0peer_mac,
                use_redirect_peer: 0,
                _pad0: 0,
                dae_socket_mark: clash_ebpf_common::DAE_BYPASS_MARK,
                control_plane_pid: std::process::id(),
                local_ip: local_ip_u32,
                has_proxy_src_ips,
                has_proxy_dst_ips,
                has_proxy_src_ports,
                has_proxy_dst_ports,
                direct_offload_enabled,
                _pad1: [0; 3],
            };

            let mut bpf_guard = self.bpf_manager.lock().await;
            if let Err(e) = bpf_guard.load_and_attach(
                crate::bpf::EMBEDDED_BPF_OBJECT,
                &bpf_param,
                &self.config.lan_interface,
                self.config.wan_interface.as_deref(),
                &self.config.bypass_ports,
                &self.config.bypass_src_ports,
                &self.config.bypass_dst_ports,
                &self.config.bypass_ips,
                &self.config.bypass_src_ips,
                &all_dst_ips,
                &self.config.proxy_ports,
                &self.config.proxy_src_ports,
                &self.config.proxy_dst_ports,
                &self.config.proxy_ips,
                &self.config.proxy_src_ips,
                &self.config.proxy_dst_ips,
                Some(&ns),
            ) {


                tracing::warn!("eBPF hooks attachment: {e}");
            }

            // Publish listener socket fds into LISTEN_SOCKET_MAP for bpf_sk_assign.
            // This must happen after both listener binding and BPF loading.
            if let Err(e) = bpf_guard.publish_listener_sockets(
                listener.tcp_v4_raw_fd(),
                listener.tcp_v6_raw_fd(),
                listener.udp_v4_raw_fd(),
                listener.udp_v6_raw_fd(),
            ) {
                tracing::warn!("Failed to publish listener sockets to SOCKMAP: {e}");
            }


            drop(bpf_guard);

            self.netns = Some(ns);
            self.listener = Some(listener.clone());

            info!(
                "clash-ebpf started: TCP port {}, UDP port {}, LAN interfaces: {:?}",
                self.config.tproxy_port, self.config.tproxy_udp_port, self.config.lan_interface
            );

            Ok(listener)

        }
    }


    /// Stops the eBPF datapath and cleans up all hooks, interfaces and namespaces.
    pub async fn stop(&mut self) {
        info!("Stopping clash-ebpf datapath...");
        self.bpf_manager.lock().await.unload();
        self.listener.take();
        self.netns.take();

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

    /// Dynamically add a direct bypass IPv4 destination.
    pub async fn add_dynamic_bypass_ip4(&self, ip: std::net::Ipv4Addr) -> Result<(), String> {
        self.bpf_manager.lock().await.add_dynamic_bypass_ip4(ip)
    }

    /// Dynamically add a direct bypass IPv6 destination.
    pub async fn add_dynamic_bypass_ip6(&self, ip: std::net::Ipv6Addr) -> Result<(), String> {
        self.bpf_manager.lock().await.add_dynamic_bypass_ip6(ip)
    }

    /// Dynamically add a direct bypass IP (v4 or v6) destination.
    pub async fn add_dynamic_bypass_ip(&self, ip: std::net::IpAddr) -> Result<(), String> {
        match ip {
            std::net::IpAddr::V4(v4) => self.add_dynamic_bypass_ip4(v4).await,
            std::net::IpAddr::V6(v6) => self.add_dynamic_bypass_ip6(v6).await,
        }
    }
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


