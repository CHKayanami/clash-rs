//! eBPF program management and TC/cgroup attachment using Aya.

pub use clash_ebpf_common as common;
pub use clash_ebpf_common::{DaeParam, DAE_BYPASS_MARK, DAE_TPROXY_MARK};

pub const EMBEDDED_BPF_OBJECT: &[u8] = include_bytes!(env!("CLASH_EBPF_OBJECT"));

#[cfg(target_os = "linux")]
pub mod linux {
    use super::DaeParam;
    use aya::maps::lpm_trie::Key;
    use aya::maps::{Array, HashMap, LpmTrie, MapData, RingBuf, SockMap};
    use aya::programs::cgroup_sock::CgroupSockLink;
    use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
    use aya::programs::sk_lookup::{SkLookup, SkLookupLink};
    use aya::programs::tc::SchedClassifierLink;
    use aya::programs::{
        CgroupAttachMode, CgroupSock, CgroupSockAddr, SchedClassifier, TcAttachType,
    };
    use aya::{Ebpf, EbpfLoader};
    use std::fs::File;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsFd, AsRawFd, RawFd};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU8, Ordering};
    use tracing::{debug, error, info, warn};

    const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
    const BPF_MAP_DELETE_ELEM: libc::c_long = 3;
    const BPF_MAP_UPDATE_BATCH: libc::c_long = 26;
    const BPF_MAP_DELETE_BATCH: libc::c_long = 27;

    #[repr(C)]
    struct BpfElemAttr {
        map_fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    #[repr(C)]
    struct BpfBatchAttr {
        in_batch: u64,
        out_batch: u64,
        keys: u64,
        values: u64,
        count: u32,
        map_fd: u32,
        elem_flags: u64,
        flags: u64,
    }

    fn bpf_update_elem_raw<K, V>(map_fd: RawFd, key: &K, value: &V) -> Result<(), i64> {
        let mut attr: BpfElemAttr = unsafe { core::mem::zeroed() };
        attr.map_fd = map_fd as u32;
        attr.key = key as *const K as u64;
        attr.value = value as *const V as u64;
        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_UPDATE_ELEM,
                &mut attr as *mut BpfElemAttr as *mut libc::c_void,
                core::mem::size_of::<BpfElemAttr>(),
            )
        };
        if ret < 0 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) as i64)
        } else {
            Ok(())
        }
    }

    fn bpf_delete_elem_raw<K>(map_fd: RawFd, key: &K) -> Result<(), i64> {
        let mut attr: BpfElemAttr = unsafe { core::mem::zeroed() };
        attr.map_fd = map_fd as u32;
        attr.key = key as *const K as u64;
        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_DELETE_ELEM,
                &mut attr as *mut BpfElemAttr as *mut libc::c_void,
                core::mem::size_of::<BpfElemAttr>(),
            )
        };
        if ret < 0 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) as i64)
        } else {
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct BatchCapability(AtomicU8);

    impl BatchCapability {
        const UNKNOWN: u8 = 0;
        const SUPPORTED: u8 = 1;
        const UNSUPPORTED: u8 = 2;

        pub const fn new() -> Self {
            Self(AtomicU8::new(Self::UNKNOWN))
        }

        pub fn is_unsupported(&self) -> bool {
            self.0.load(Ordering::Relaxed) == Self::UNSUPPORTED
        }

        pub fn observe(&self, result: Result<(), i64>) -> bool {
            match result {
                Ok(()) => {
                    self.0.store(Self::SUPPORTED, Ordering::Relaxed);
                    true
                }
                Err(e) if e == libc::ENOENT as i64 => {
                    self.0.store(Self::SUPPORTED, Ordering::Relaxed);
                    true
                }
                Err(e) if is_capability_errno(e) => {
                    self.0.store(Self::UNSUPPORTED, Ordering::Relaxed);
                    false
                }
                Err(_) => true,
            }
        }
    }

    fn is_capability_errno(errno: i64) -> bool {
        errno == libc::EINVAL as i64
            || errno == libc::EOPNOTSUPP as i64
            || errno == libc::EPERM as i64
            || errno == libc::ENOSYS as i64
    }

    unsafe fn bpf_batch_syscall(cmd: libc::c_long, attr: &mut BpfBatchAttr) -> Result<(), i64> {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                cmd,
                attr as *mut BpfBatchAttr as *mut libc::c_void,
                core::mem::size_of::<BpfBatchAttr>(),
            )
        };
        if ret < 0 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) as i64)
        } else {
            Ok(())
        }
    }

    fn map_raw_fd(map: &aya::maps::Map) -> RawFd {
        use aya::maps::Map;
        let data: &aya::maps::MapData = match map {
            Map::Array(d)
            | Map::ArrayOfMaps(d)
            | Map::BloomFilter(d)
            | Map::CgroupArray(d)
            | Map::CgroupStorage(d)
            | Map::CgrpStorage(d)
            | Map::CpuMap(d)
            | Map::DevMap(d)
            | Map::DevMapHash(d)
            | Map::HashMap(d)
            | Map::HashOfMaps(d)
            | Map::InodeStorage(d)
            | Map::LpmTrie(d)
            | Map::LruHashMap(d)
            | Map::PerCpuArray(d)
            | Map::PerCpuCgroupStorage(d)
            | Map::PerCpuHashMap(d)
            | Map::PerCpuLruHashMap(d)
            | Map::PerfEventArray(d)
            | Map::ProgramArray(d)
            | Map::Queue(d)
            | Map::ReusePortSockArray(d)
            | Map::RingBuf(d)
            | Map::SockHash(d)
            | Map::SockMap(d)
            | Map::SkStorage(d)
            | Map::Stack(d)
            | Map::StackTraceMap(d)
            | Map::Unsupported(d)
            | Map::XskMap(d) => d,
        };
        data.fd().as_fd().as_raw_fd()
    }

    fn bpf_update_batch_raw<K, V>(
        cap: &BatchCapability,
        map_fd: RawFd,
        keys: &[K],
        values: &[V],
    ) -> Result<bool, String> {
        if cap.is_unsupported() || keys.is_empty() {
            return Ok(false);
        }
        let mut attr: BpfBatchAttr = unsafe { core::mem::zeroed() };
        attr.map_fd = map_fd as u32;
        attr.keys = keys.as_ptr() as u64;
        attr.values = values.as_ptr() as u64;
        attr.count = keys.len() as u32;
        let result = unsafe { bpf_batch_syscall(BPF_MAP_UPDATE_BATCH, &mut attr) };
        if !cap.observe(result) {
            debug!("BPF_MAP_UPDATE_BATCH unsupported on this kernel, falling back to per-element insert");
            return Ok(false);
        }
        result.map_err(|e| format!("BPF_MAP_UPDATE_BATCH failed with errno={e}"))?;
        Ok(true)
    }

    fn bpf_delete_batch_raw<K>(
        cap: &BatchCapability,
        map_fd: RawFd,
        keys: &[K],
    ) -> Result<bool, String> {
        if cap.is_unsupported() || keys.is_empty() {
            return Ok(false);
        }
        let mut attr: BpfBatchAttr = unsafe { core::mem::zeroed() };
        attr.map_fd = map_fd as u32;
        attr.keys = keys.as_ptr() as u64;
        attr.count = keys.len() as u32;
        let result = unsafe { bpf_batch_syscall(BPF_MAP_DELETE_BATCH, &mut attr) };
        if !cap.observe(result) {
            debug!("BPF_MAP_DELETE_BATCH unsupported on this kernel, falling back to per-element remove");
            return Ok(false);
        }
        match result {
            Ok(()) => Ok(true),
            Err(e) if e == libc::ENOENT as i64 => Ok(true),
            Err(e) => Err(format!("BPF_MAP_DELETE_BATCH failed with errno={e}")),
        }
    }

    pub struct BpfProgramManager {
        bpf: Option<Ebpf>,
        tc_links: std::sync::Mutex<Vec<SchedClassifierLink>>,
        cgroup_sock_links: std::sync::Mutex<Vec<CgroupSockLink>>,
        cgroup_sock_addr_links: std::sync::Mutex<Vec<CgroupSockAddrLink>>,
        sk_lookup_link: std::sync::Mutex<Option<SkLookupLink>>,
        event_abort: Option<tokio::task::AbortHandle>,
        cap_batch_update: BatchCapability,
        cap_batch_delete: BatchCapability,
    }

    impl BpfProgramManager {
        pub fn new() -> Self {
            Self {
                bpf: None,
                tc_links: std::sync::Mutex::new(Vec::new()),
                cgroup_sock_links: std::sync::Mutex::new(Vec::new()),
                cgroup_sock_addr_links: std::sync::Mutex::new(Vec::new()),
                sk_lookup_link: std::sync::Mutex::new(None),
                event_abort: None,
                cap_batch_update: BatchCapability::new(),
                cap_batch_delete: BatchCapability::new(),
            }
        }

        /// Detect the root cgroup2 mount point from /proc/mounts.
        fn detect_cgroup_path() -> Option<String> {
            let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
            for line in mounts.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 3 && fields[2] == "cgroup2" {
                    return Some(fields[1].to_string());
                }
            }
            None
        }

        /// Load eBPF programs and attach TC and cgroup hooks.
        pub fn load_and_attach(
            &mut self,
            obj_bytes: &[u8],
            param: &DaeParam,
            lan_interfaces: &[String],
            wan_interface: Option<&str>,
            bypass_src_ports: &[u16],
            bypass_dst_ports: &[u16],
            bypass_src_ips: &[String],
            bypass_dst_ips: &[String],
            proxy_src_ports: &[u16],
            proxy_dst_ports: &[u16],
            proxy_src_ips: &[String],
            proxy_dst_ips: &[String],
            proxy_processes: &[String],
            bypass_processes: &[String],
            netns: Option<&crate::netns::linux::DaeNs>,
        ) -> Result<(), String> {
            if obj_bytes.is_empty() {
                warn!("eBPF ELF bytecode is empty; skipping eBPF kernel hooks attachment");
                return Ok(());
            }

            info!("Loading embedded eBPF programs ({} bytes)...", obj_bytes.len());
            let mut loader = EbpfLoader::new();
            let mut bpf = loader
                .load(obj_bytes)
                .map_err(|e| format!("Failed to load eBPF object: {e}"))?;

            // 1. Initialize parameter map
            if let Some(map) = bpf.map_mut("DAE_PARAM") {
                if let Ok(mut param_map) = Array::<_, DaeParam>::try_from(map) {
                    let _ = param_map.set(0, *param, 0);
                    debug!("DAE_PARAM map initialized: tproxy_port={}, dae0_ifindex={}", param.tproxy_port, param.dae0_ifindex);
                }
            }

            // 2. Populate BYPASS_SRC_PORTS map (e.g., local server ports)
            if let Some(map) = bpf.map_mut("BYPASS_SRC_PORTS") {
                if let Ok(mut port_map) = HashMap::<_, u16, u8>::try_from(map) {
                    let _ = port_map.insert(param.tproxy_port as u16, 1, 0);
                    for &port in bypass_src_ports {
                        let _ = port_map.insert(port, 1, 0);
                    }
                    debug!("Configured {} source bypass ports in BPF map", bypass_src_ports.len() + 1);
                }
            }

            // 3. Populate BYPASS_DST_PORTS map (e.g., direct destination service ports)
            if let Some(map) = bpf.map_mut("BYPASS_DST_PORTS") {
                if let Ok(mut port_map) = HashMap::<_, u16, u8>::try_from(map) {
                    let _ = port_map.insert(param.tproxy_port as u16, 1, 0);
                    for &port in bypass_dst_ports {
                        let _ = port_map.insert(port, 1, 0);
                    }
                    debug!("Configured {} dest bypass ports in BPF map", bypass_dst_ports.len() + 1);
                }
            }

            // 4. Populate BYPASS_SRC_IPS and BYPASS_SRC_IP6S maps
            if let Some(map) = bpf.map_mut("BYPASS_SRC_IPS") {
                if let Ok(mut ip_trie) = LpmTrie::<_, u32, u8>::try_from(map) {
                    for ip_str in bypass_src_ips {
                        if let Ok(net) = ipnet::Ipv4Net::from_str(ip_str) {
                            let ip_u32 = u32::from_ne_bytes(net.network().octets());
                            let key = Key::new(net.prefix_len() as u32, ip_u32);
                            let _ = ip_trie.insert(&key, 1, 0);
                        } else if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
                            let ip_u32 = u32::from_ne_bytes(ip.octets());
                            let key = Key::new(32, ip_u32);
                            let _ = ip_trie.insert(&key, 1, 0);
                        }
                    }
                    debug!("Configured {} source bypass IPv4 IP/CIDRs in BPF Trie map", bypass_src_ips.len());
                }
            }
            if let Some(map) = bpf.map_mut("BYPASS_SRC_IP6S") {
                if let Ok(mut ip_trie) = LpmTrie::<_, [u8; 16], u8>::try_from(map) {
                    for ip_str in bypass_src_ips {
                        if let Ok(net) = ipnet::Ipv6Net::from_str(ip_str) {
                            let key = Key::new(net.prefix_len() as u32, net.network().octets());
                            let _ = ip_trie.insert(&key, 1, 0);
                        } else if let Ok(ip) = Ipv6Addr::from_str(ip_str) {
                            let key = Key::new(128, ip.octets());
                            let _ = ip_trie.insert(&key, 1, 0);
                        }
                    }
                    debug!("Configured {} source bypass IPv6 IP/CIDRs in BPF Trie map", bypass_src_ips.len());
                }
            }

            // 5. Populate BYPASS_DST_IPS and BYPASS_DST_IP6S maps
            if let Some(map) = bpf.map_mut("BYPASS_DST_IPS") {
                if let Ok(mut ip_trie) = LpmTrie::<_, u32, u8>::try_from(map) {
                    for ip_str in bypass_dst_ips {
                        if let Ok(net) = ipnet::Ipv4Net::from_str(ip_str) {
                            let ip_u32 = u32::from_ne_bytes(net.network().octets());
                            let key = Key::new(net.prefix_len() as u32, ip_u32);
                            let _ = ip_trie.insert(&key, 1, 0);
                        } else if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
                            let ip_u32 = u32::from_ne_bytes(ip.octets());
                            let key = Key::new(32, ip_u32);
                            let _ = ip_trie.insert(&key, 1, 0);
                        }
                    }
                    debug!("Configured {} dest bypass IPv4 IP/CIDRs in BPF Trie map", bypass_dst_ips.len());
                }
            }
            if let Some(map) = bpf.map_mut("BYPASS_DST_IP6S") {
                if let Ok(mut ip_trie) = LpmTrie::<_, [u8; 16], u8>::try_from(map) {
                    for ip_str in bypass_dst_ips {
                        if let Ok(net) = ipnet::Ipv6Net::from_str(ip_str) {
                            let key = Key::new(net.prefix_len() as u32, net.network().octets());
                            let _ = ip_trie.insert(&key, 1, 0);
                        } else if let Ok(ip) = Ipv6Addr::from_str(ip_str) {
                            let key = Key::new(128, ip.octets());
                            let _ = ip_trie.insert(&key, 1, 0);
                        }
                    }
                    debug!("Configured {} dest bypass IPv6 IP/CIDRs in BPF Trie map", bypass_dst_ips.len());
                }
            }

            // 6. Populate PROXY_SRC_PORTS map
            if let Some(map) = bpf.map_mut("PROXY_SRC_PORTS") {
                if let Ok(mut port_map) = HashMap::<_, u16, u8>::try_from(map) {
                    for &port in proxy_src_ports {
                        let _ = port_map.insert(port, 1, 0);
                    }
                }
            }

            // 7. Populate PROXY_DST_PORTS map
            if let Some(map) = bpf.map_mut("PROXY_DST_PORTS") {
                if let Ok(mut port_map) = HashMap::<_, u16, u8>::try_from(map) {
                    for &port in proxy_dst_ports {
                        let _ = port_map.insert(port, 1, 0);
                    }
                }
            }

            // 8. Populate PROXY_SRC_IPS and PROXY_SRC_IP6S maps
            if let Some(map) = bpf.map_mut("PROXY_SRC_IPS") {
                if let Ok(mut ip_trie) = LpmTrie::<_, u32, u8>::try_from(map) {
                    for ip_str in proxy_src_ips {
                        if let Ok(net) = ipnet::Ipv4Net::from_str(ip_str) {
                            let ip_u32 = u32::from_ne_bytes(net.network().octets());
                            let key = Key::new(net.prefix_len() as u32, ip_u32);
                            let _ = ip_trie.insert(&key, 1, 0);
                        } else if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
                            let ip_u32 = u32::from_ne_bytes(ip.octets());
                            let key = Key::new(32, ip_u32);
                            let _ = ip_trie.insert(&key, 1, 0);
                        }
                    }
                }
            }
            if let Some(map) = bpf.map_mut("PROXY_SRC_IP6S") {
                if let Ok(mut ip_trie) = LpmTrie::<_, [u8; 16], u8>::try_from(map) {
                    for ip_str in proxy_src_ips {
                        if let Ok(net) = ipnet::Ipv6Net::from_str(ip_str) {
                            let key = Key::new(net.prefix_len() as u32, net.network().octets());
                            let _ = ip_trie.insert(&key, 1, 0);
                        } else if let Ok(ip) = Ipv6Addr::from_str(ip_str) {
                            let key = Key::new(128, ip.octets());
                            let _ = ip_trie.insert(&key, 1, 0);
                        }
                    }
                }
            }

            // 9. Populate PROXY_DST_IPS and PROXY_DST_IP6S maps
            if let Some(map) = bpf.map_mut("PROXY_DST_IPS") {
                if let Ok(mut ip_trie) = LpmTrie::<_, u32, u8>::try_from(map) {
                    for ip_str in proxy_dst_ips {
                        if let Ok(net) = ipnet::Ipv4Net::from_str(ip_str) {
                            let ip_u32 = u32::from_ne_bytes(net.network().octets());
                            let key = Key::new(net.prefix_len() as u32, ip_u32);
                            let _ = ip_trie.insert(&key, 1, 0);
                        } else if let Ok(ip) = Ipv4Addr::from_str(ip_str) {
                            let ip_u32 = u32::from_ne_bytes(ip.octets());
                            let key = Key::new(32, ip_u32);
                            let _ = ip_trie.insert(&key, 1, 0);
                        }
                    }
                }
            }
            if let Some(map) = bpf.map_mut("PROXY_DST_IP6S") {
                if let Ok(mut ip_trie) = LpmTrie::<_, [u8; 16], u8>::try_from(map) {
                    for ip_str in proxy_dst_ips {
                        if let Ok(net) = ipnet::Ipv6Net::from_str(ip_str) {
                            let key = Key::new(net.prefix_len() as u32, net.network().octets());
                            let _ = ip_trie.insert(&key, 1, 0);
                        } else if let Ok(ip) = Ipv6Addr::from_str(ip_str) {
                            let key = Key::new(128, ip.octets());
                            let _ = ip_trie.insert(&key, 1, 0);
                        }
                    }
                }
            }

            // 10. Populate PROXY_PROCESSES map
            if let Some(map) = bpf.map_mut("PROXY_PROCESSES") {
                if let Ok(mut proc_map) = HashMap::<_, [u8; 16], u8>::try_from(map) {
                    for proc in proxy_processes {
                        let mut key = [0u8; 16];
                        let bytes = proc.as_bytes();
                        let len = bytes.len().min(16);
                        key[..len].copy_from_slice(&bytes[..len]);
                        let _ = proc_map.insert(key, 1, 0);
                    }
                    debug!("Configured {} proxy processes in BPF map", proxy_processes.len());
                }
            }

            // 11. Populate BYPASS_PROCESSES map
            if let Some(map) = bpf.map_mut("BYPASS_PROCESSES") {
                if let Ok(mut proc_map) = HashMap::<_, [u8; 16], u8>::try_from(map) {
                    for proc in bypass_processes {
                        let mut key = [0u8; 16];
                        let bytes = proc.as_bytes();
                        let len = bytes.len().min(16);
                        key[..len].copy_from_slice(&bytes[..len]);
                        let _ = proc_map.insert(key, 1, 0);
                    }
                    debug!("Configured {} bypass processes in BPF map", bypass_processes.len());
                }
            }

            // 12. Spawn RingBuf consumer for kernel events
            if let Some(map) = bpf.take_map("EVENT_RINGBUF") {
                if let Ok(ring_buf) = RingBuf::try_from(map) {
                    match tokio::io::unix::AsyncFd::with_interest(
                        ring_buf,
                        tokio::io::Interest::READABLE,
                    ) {
                        Ok(async_fd) => {
                            let task = tokio::spawn(consume_dae_events(async_fd));
                            self.event_abort = Some(task.abort_handle());
                            debug!("Started eBPF EVENT_RINGBUF event consumer task");
                        }
                        Err(e) => {
                            warn!("Failed to setup AsyncFd for EVENT_RINGBUF: {e}");
                        }
                    }
                }
            }

            self.bpf = Some(bpf);

            // 13. Attach cgroup bypass and process tracking hooks
            if let Err(e) = self.attach_cgroup() {
                warn!("cgroup bypass attachment: {e}");
            }

            // 14. Attach TC Ingress on configured/detected LAN interfaces (局域网入站拦截)
            let detected_lan_fallback;
            let effective_lan = if lan_interfaces.is_empty() || lan_interfaces.iter().any(|s| s == "auto") {
                detected_lan_fallback = crate::manager::detect_lan_interfaces(lan_interfaces, wan_interface);
                &detected_lan_fallback[..]
            } else {
                lan_interfaces
            };

            for lan in effective_lan {
                if !lan.is_empty() {
                    let prog_name = if Self::iface_is_ethernet(lan) { "lan_ingress_l2" } else { "lan_ingress_l3" };
                    if let Err(e) = self.attach_tc_interface(lan, true, prog_name) {
                        warn!("Failed to attach TC ingress ({}) on {}: {}", prog_name, lan, e);
                    } else {
                        info!("Attached TC ingress ({}) on {}", prog_name, lan);
                    }
                }
            }

            // 15. Attach TC Egress on configured WAN interface (or primary LAN interface in single-homed setups)
            let detected_wan_fallback;
            let effective_wan = match wan_interface {
                Some("auto") | None | Some("") => {
                    detected_wan_fallback = crate::manager::detect_default_wan_interface(lan_interfaces);
                    detected_wan_fallback.as_deref().or_else(|| lan_interfaces.first().map(|s| s.as_str()))
                }
                Some(wan) => Some(wan),
            };
            if let Some(wan) = effective_wan {
                if !wan.is_empty() {
                    let prog_name = if Self::iface_is_ethernet(wan) { "wan_egress_l2" } else { "wan_egress_l3" };
                    if let Err(e) = self.attach_tc_interface(wan, false, prog_name) {
                        warn!("Failed to attach TC egress ({}) on {}: {}", prog_name, wan, e);
                    } else {
                        info!("Attached TC egress ({}) on {}", prog_name, wan);
                    }
                }
            }

            // 16. Attach TC Ingress on dae0 for reply short-circuit and MAC restoration (in host netns)
            if let Err(e) = self.attach_tc_interface("dae0", true, "dae0_ingress") {
                warn!("Failed to attach TC ingress on dae0: {}", e);
            }

            // 17. Attach sk_lookup and TC Ingress on dae0peer inside daens
            if let Some(ns) = netns {
                if let Err(e) = self.attach_sk_lookup(ns) {
                    warn!("Failed to attach sk_lookup in daens: {}", e);
                }
                let _ = ns.with_daens(|| -> Result<(), String> {
                    if let Err(e) = self.attach_tc_interface("dae0peer", true, "dae0peer_ingress") {
                        warn!("Failed to attach TC ingress on dae0peer inside daens: {}", e);
                    }
                    Ok(())
                });
            }

            info!("eBPF programs and TC/cgroup hooks successfully attached");
            Ok(())
        }

        pub fn update_dynamic_bypass_batch(
            &self,
            add_v4: &[Ipv4Addr],
            add_v6: &[Ipv6Addr],
            remove_v4: &[Ipv4Addr],
            remove_v6: &[Ipv6Addr],
        ) -> Result<(), String> {
            let Some(bpf) = self.bpf.as_ref() else {
                return Err("eBPF not loaded".to_string());
            };

            static ONES: [u8; 1024] = [1u8; 1024];

            // 1. IPv4 Dynamic Bypass
            if !add_v4.is_empty() || !remove_v4.is_empty() {
                let map = bpf
                    .map("DYNAMIC_BYPASS_DST_IPS")
                    .ok_or_else(|| "map 'DYNAMIC_BYPASS_DST_IPS' not found".to_string())?;
                let raw_fd = map_raw_fd(map);

                if !add_v4.is_empty() {
                    let mut handled = false;
                    if !self.cap_batch_update.is_unsupported() {
                        let mut keys = Vec::with_capacity(add_v4.len());
                        for ip in add_v4 {
                            keys.push(u32::from_ne_bytes(ip.octets()));
                        }
                        let values = if keys.len() <= ONES.len() {
                            &ONES[..keys.len()]
                        } else {
                            &vec![1u8; keys.len()][..]
                        };
                        handled = bpf_update_batch_raw(&self.cap_batch_update, raw_fd, &keys, values)?;
                        if handled {
                            debug!("Batch updated {} dynamic bypass IPv4s via BPF_MAP_UPDATE_BATCH", add_v4.len());
                        }
                    }
                    if !handled {
                        for ip in add_v4 {
                            let k = u32::from_ne_bytes(ip.octets());
                            if let Err(e) = bpf_update_elem_raw(raw_fd, &k, &1u8) {
                                debug!("Failed to insert dynamic bypass IPv4 {}: errno={}", ip, e);
                            }
                        }
                    }
                }

                if !remove_v4.is_empty() {
                    let mut handled = false;
                    if !self.cap_batch_delete.is_unsupported() {
                        let mut keys = Vec::with_capacity(remove_v4.len());
                        for ip in remove_v4 {
                            keys.push(u32::from_ne_bytes(ip.octets()));
                        }
                        handled = bpf_delete_batch_raw(&self.cap_batch_delete, raw_fd, &keys)?;
                        if handled {
                            debug!("Batch removed {} dynamic bypass IPv4s via BPF_MAP_DELETE_BATCH", remove_v4.len());
                        }
                    }
                    if !handled {
                        for ip in remove_v4 {
                            let k = u32::from_ne_bytes(ip.octets());
                            let _ = bpf_delete_elem_raw(raw_fd, &k);
                        }
                    }
                }
            }

            // 2. IPv6 Dynamic Bypass
            if !add_v6.is_empty() || !remove_v6.is_empty() {
                let map = bpf
                    .map("DYNAMIC_BYPASS_DST_IP6S")
                    .ok_or_else(|| "map 'DYNAMIC_BYPASS_DST_IP6S' not found".to_string())?;
                let raw_fd = map_raw_fd(map);

                if !add_v6.is_empty() {
                    let mut handled = false;
                    if !self.cap_batch_update.is_unsupported() {
                        let keys: &[[u8; 16]] = unsafe {
                            std::slice::from_raw_parts(add_v6.as_ptr() as *const [u8; 16], add_v6.len())
                        };
                        let values = if keys.len() <= ONES.len() {
                            &ONES[..keys.len()]
                        } else {
                            &vec![1u8; keys.len()][..]
                        };
                        handled = bpf_update_batch_raw(&self.cap_batch_update, raw_fd, keys, values)?;
                        if handled {
                            debug!("Batch updated {} dynamic bypass IPv6s via BPF_MAP_UPDATE_BATCH", add_v6.len());
                        }
                    }
                    if !handled {
                        for ip in add_v6 {
                            let k = ip.octets();
                            if let Err(e) = bpf_update_elem_raw(raw_fd, &k, &1u8) {
                                debug!("Failed to insert dynamic bypass IPv6 {}: errno={}", ip, e);
                            }
                        }
                    }
                }

                if !remove_v6.is_empty() {
                    let mut handled = false;
                    if !self.cap_batch_delete.is_unsupported() {
                        let keys: &[[u8; 16]] = unsafe {
                            std::slice::from_raw_parts(remove_v6.as_ptr() as *const [u8; 16], remove_v6.len())
                        };
                        handled = bpf_delete_batch_raw(&self.cap_batch_delete, raw_fd, keys)?;
                        if handled {
                            debug!("Batch removed {} dynamic bypass IPv6s via BPF_MAP_DELETE_BATCH", remove_v6.len());
                        }
                    }
                    if !handled {
                        for ip in remove_v6 {
                            let k = ip.octets();
                            let _ = bpf_delete_elem_raw(raw_fd, &k);
                        }
                    }
                }
            }

            Ok(())
        }

        /// Publish listener socket fds into LISTEN_SOCKET_MAP for bpf_sk_assign.
        /// Keys: 0=TCP4, 1=TCP6, 2=UDP4, 3=UDP6
        pub fn publish_listener_sockets(
            &mut self,
            tcp4_fd: std::os::fd::RawFd,
            tcp6_fd: Option<std::os::fd::RawFd>,
            udp4_fd: std::os::fd::RawFd,
            udp6_fd: Option<std::os::fd::RawFd>,
        ) -> Result<(), String> {
            use std::os::fd::BorrowedFd;

            let Some(bpf) = self.bpf.as_mut() else {
                return Err("eBPF not loaded".to_string());
            };

            let map = bpf.map_mut("LISTEN_SOCKET_MAP")
                .ok_or_else(|| "map 'LISTEN_SOCKET_MAP' not found".to_string())?;
            let mut sockets = SockMap::try_from(map)
                .map_err(|e| format!("map 'LISTEN_SOCKET_MAP': {e}"))?;

            // TCP4 at key 0
            let tcp4_bfd = unsafe { BorrowedFd::borrow_raw(tcp4_fd) };
            sockets.set(0, &tcp4_bfd, 0)
                .map_err(|e| format!("LISTEN_SOCKET_MAP set[0/TCP4]: {e}"))?;
            info!(fd = tcp4_fd, key = 0, "Published TCP4 listener to LISTEN_SOCKET_MAP");

            // TCP6 at key 1
            if let Some(fd6) = tcp6_fd {
                let tcp6_bfd = unsafe { BorrowedFd::borrow_raw(fd6) };
                sockets.set(1, &tcp6_bfd, 0)
                    .map_err(|e| format!("LISTEN_SOCKET_MAP set[1/TCP6]: {e}"))?;
                info!(fd = fd6, key = 1, "Published TCP6 listener to LISTEN_SOCKET_MAP");
            }

            // UDP4 at key 2
            let udp4_bfd = unsafe { BorrowedFd::borrow_raw(udp4_fd) };
            sockets.set(2, &udp4_bfd, 0)
                .map_err(|e| format!("LISTEN_SOCKET_MAP set[2/UDP4]: {e}"))?;
            info!(fd = udp4_fd, key = 2, "Published UDP4 listener to LISTEN_SOCKET_MAP");

            // UDP6 at key 3
            if let Some(fd6) = udp6_fd {
                let udp6_bfd = unsafe { BorrowedFd::borrow_raw(fd6) };
                sockets.set(3, &udp6_bfd, 0)
                    .map_err(|e| format!("LISTEN_SOCKET_MAP set[3/UDP6]: {e}"))?;
                info!(fd = fd6, key = 3, "Published UDP6 listener to LISTEN_SOCKET_MAP");
            }

            Ok(())
        }


        /// Attach cgroup socket programs to root cgroup2 for process bypass and tracking.
        fn attach_cgroup(&mut self) -> Result<(), String> {
            let Some(bpf) = self.bpf.as_mut() else {
                return Err("eBPF not loaded".to_string());
            };

            let Some(cgroup_path) = Self::detect_cgroup_path() else {
                warn!("cgroup2 not mounted; cgroup bypass & process tracking hooks skipped");
                return Ok(());
            };

            let cgroup_file = File::open(&cgroup_path)
                .map_err(|e| format!("Failed to open cgroup {}: {e}", cgroup_path))?;

            let mut attached_count = 0;

            for name in &["tproxy_wan_cg_sock_create", "tproxy_wan_cg_sock_release"] {
                let Some(prog) = bpf.program_mut(name) else {
                    error!("Cgroup program '{}' not found in eBPF object", name);
                    continue;
                };
                let p: &mut CgroupSock = match prog.try_into() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to convert program '{}' to CgroupSock: {e}", name);
                        continue;
                    }
                };
                if let Err(e) = p.load() {
                    error!("Failed to load cgroup program '{}': {e}", name);
                    continue;
                }
                let (link_id, mode_name) = match p.attach(&cgroup_file, CgroupAttachMode::AllowMultiple) {
                    Ok(id) => (id, "AllowMultiple"),
                    Err(e1) => match p.attach(&cgroup_file, CgroupAttachMode::Single) {
                        Ok(id) => (id, "Single"),
                        Err(e2) => {
                            error!(
                                "Failed to attach cgroup hook '{}' (AllowMultiple: {e1}, Single: {e2})",
                                name
                            );
                            continue;
                        }
                    },
                };
                match p.take_link(link_id) {
                    Ok(link) => {
                        if let Ok(mut guard) = self.cgroup_sock_links.lock() {
                            guard.push(link);
                        }
                        attached_count += 1;
                        info!("Attached cgroup hook '{}' (mode: {})", name, mode_name);
                    }
                    Err(e) => {
                        error!("Failed to take link for cgroup hook '{}': {e}", name);
                    }
                }
            }

            for name in &[
                "tproxy_wan_cg_connect4",
                "tproxy_wan_cg_connect6",
                "tproxy_wan_cg_sendmsg4",
                "tproxy_wan_cg_sendmsg6",
            ] {
                let Some(prog) = bpf.program_mut(name) else {
                    error!("Cgroup program '{}' not found in eBPF object", name);
                    continue;
                };
                let p: &mut CgroupSockAddr = match prog.try_into() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to convert program '{}' to CgroupSockAddr: {e}", name);
                        continue;
                    }
                };
                if let Err(e) = p.load() {
                    error!("Failed to load cgroup program '{}': {e}", name);
                    continue;
                }
                let (link_id, mode_name) = match p.attach(&cgroup_file, CgroupAttachMode::AllowMultiple) {
                    Ok(id) => (id, "AllowMultiple"),
                    Err(e1) => match p.attach(&cgroup_file, CgroupAttachMode::Single) {
                        Ok(id) => (id, "Single"),
                        Err(e2) => {
                            error!(
                                "Failed to attach cgroup hook '{}' (AllowMultiple: {e1}, Single: {e2})",
                                name
                            );
                            continue;
                        }
                    },
                };
                match p.take_link(link_id) {
                    Ok(link) => {
                        if let Ok(mut guard) = self.cgroup_sock_addr_links.lock() {
                            guard.push(link);
                        }
                        attached_count += 1;
                        info!("Attached cgroup hook '{}' (mode: {})", name, mode_name);
                    }
                    Err(e) => {
                        error!("Failed to take link for cgroup hook '{}': {e}", name);
                    }
                }
            }

            if attached_count > 0 {
                info!("Successfully attached {attached_count} cgroup programs to {}", cgroup_path);
            } else {
                warn!("No cgroup programs were successfully attached to {}", cgroup_path);
            }

            Ok(())
        }
        /// Check whether a network interface is an Ethernet device (ARPHRD_ETHER = 1).
        fn iface_is_ethernet(iface: &str) -> bool {
            std::fs::read_to_string(format!("/sys/class/net/{iface}/type"))
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok())
                .map(|kind| kind == 1) // ARPHRD_ETHER
                .unwrap_or(false)
        }

        /// Attach TC ingress/egress filter to a network interface.
        fn attach_tc_interface(&mut self, iface: &str, is_ingress: bool, prog_name: &str) -> Result<(), String> {
            let Some(bpf) = self.bpf.as_mut() else {
                return Err("eBPF not loaded".to_string());
            };

            let _ = aya::programs::tc::qdisc_add_clsact(iface);

            let attach_type = if is_ingress {
                TcAttachType::Ingress
            } else {
                TcAttachType::Egress
            };

            let Some(prog) = bpf.program_mut(prog_name) else {
                return Err(format!("TC program '{prog_name}' not found in eBPF object"));
            };

            let p: &mut SchedClassifier = prog
                .try_into()
                .map_err(|e| format!("Program '{prog_name}' is not a SchedClassifier: {e}"))?;

            p.load()
                .map_err(|e| format!("Failed to load TC program '{prog_name}': {e}"))?;

            let link_id = p
                .attach(iface, attach_type)
                .map_err(|e| format!("Failed to attach TC program '{prog_name}' to {iface}: {e}"))?;

            let link = p
                .take_link(link_id)
                .map_err(|e| format!("Failed to take TC link: {e}"))?;

            if let Ok(mut guard) = self.tc_links.lock() {
                guard.push(link);
            }

            info!("Attached TC {} program '{}' on {}", if is_ingress { "ingress" } else { "egress" }, prog_name, iface);
            Ok(())
        }

        /// Attach sk_lookup program to daens namespace for transparent listener routing.
        fn attach_sk_lookup(&mut self, netns: &crate::netns::DaeNs) -> Result<(), String> {
            let Some(bpf) = self.bpf.as_mut() else {
                return Err("eBPF not loaded".to_string());
            };

            let Some(prog) = bpf.program_mut("tproxy_sk_lookup") else {
                return Err("Program 'tproxy_sk_lookup' not found in eBPF object".to_string());
            };

            let p: &mut SkLookup = prog
                .try_into()
                .map_err(|e| format!("Program 'tproxy_sk_lookup' is not a SkLookup: {e}"))?;

            p.load()
                .map_err(|e| format!("Failed to load 'tproxy_sk_lookup': {e}"))?;

            let netns_file = netns
                .dae_file()
                .map_err(|e| format!("Failed to get daens fd: {e}"))?;

            let link_id = p
                .attach(&netns_file)
                .map_err(|e| format!("Failed to attach sk_lookup to daens: {e}"))?;

            let link = p
                .take_link(link_id)
                .map_err(|e| format!("Failed to take sk_lookup link: {e}"))?;

            if let Ok(mut guard) = self.sk_lookup_link.lock() {
                *guard = Some(link);
            }
            info!("Attached sk_lookup program 'tproxy_sk_lookup' to daens namespace");
            Ok(())
        }

        /// Detach all active TC and cgroup links and stop event consumer.
        pub fn unload(&self) {
            info!("Unloading all eBPF TC and cgroup links...");
            if let Some(handle) = &self.event_abort {
                handle.abort();
            }
            if let Ok(mut guard) = self.tc_links.lock() {
                guard.clear();
            }
            if let Ok(mut guard) = self.cgroup_sock_links.lock() {
                guard.clear();
            }
            if let Ok(mut guard) = self.cgroup_sock_addr_links.lock() {
                guard.clear();
            }
            if let Ok(mut guard) = self.sk_lookup_link.lock() {
                *guard = None;
            }
            info!("All eBPF links detached successfully");
        }
    }

    /// Drain `EVENT_RINGBUF` into rate-limited structured logs.
    async fn consume_dae_events(
        mut async_fd: tokio::io::unix::AsyncFd<RingBuf<MapData>>,
    ) {
        use clash_ebpf_common::{DaeEvent, DaeEventType};
        let mut window = std::time::Instant::now();
        let mut emitted: u32 = 0;
        let mut suppressed: u64 = 0;
        const EVENT_LOG_MAX_PER_SEC: u32 = 32;

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    debug!("DaeEvent ringbuf AsyncFd wait failed: {e}");
                    break;
                }
            };

            {
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() < core::mem::size_of::<DaeEvent>() {
                        continue;
                    }
                    let ev: DaeEvent = unsafe {
                        core::ptr::read_unaligned(bytes.as_ptr() as *const DaeEvent)
                    };

                    if window.elapsed() >= std::time::Duration::from_secs(1) {
                        if suppressed > 0 {
                            warn!("eBPF datapath events suppressed: {suppressed} in the last second");
                        }
                        window = std::time::Instant::now();
                        emitted = 0;
                        suppressed = 0;
                    }

                    if emitted >= EVENT_LOG_MAX_PER_SEC {
                        suppressed += 1;
                        continue;
                    }
                    emitted += 1;

                    let pname_end = ev
                        .pname
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(ev.pname.len());
                    let pname = String::from_utf8_lossy(&ev.pname[..pname_end]);

                    let sip = if ev.sip[1] == 0 && ev.sip[2] == 0 && ev.sip[3] == 0 {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(ev.sip[0]))
                    } else {
                        let mut b = [0u8; 16];
                        for (i, c) in ev.sip.iter().enumerate() {
                            b[i * 4..i * 4 + 4].copy_from_slice(&c.to_ne_bytes());
                        }
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))
                    };
                    let dip = if ev.dip[1] == 0 && ev.dip[2] == 0 && ev.dip[3] == 0 {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(ev.dip[0]))
                    } else {
                        let mut b = [0u8; 16];
                        for (i, c) in ev.dip.iter().enumerate() {
                            b[i * 4..i * 4 + 4].copy_from_slice(&c.to_ne_bytes());
                        }
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))
                    };

                    match ev.type_ {
                        t if t == DaeEventType::Redirected as u32 => {
                            let dir = if ev.outbound == 1 {
                                "WAN-Egress(Local)"
                            } else {
                                "LAN-Ingress(Forward)"
                            };
                            info!(
                                target: "clash-ebpf",
                                dir = dir,
                                pid = ev.pid,
                                pname = %pname,
                                proto = ev.l4proto,
                                %sip,
                                sport = ev.sport,
                                %dip,
                                dport = ev.dport,
                                "eBPF packet redirected to tproxy"
                            );
                        }
                        t if t == DaeEventType::Blocked as u32 => {
                            warn!(
                                target: "clash-ebpf",
                                pid = ev.pid,
                                pname = %pname,
                                "eBPF packet blocked"
                            );
                        }
                        t if t == DaeEventType::TcpConnOverflow as u32 => {
                            warn!(
                                target: "clash-ebpf",
                                pid = ev.pid,
                                pname = %pname,
                                "eBPF TCP conntrack overflow"
                            );
                        }
                        t if t == DaeEventType::UdpConnOverflow as u32 => {
                            warn!(
                                target: "clash-ebpf",
                                pid = ev.pid,
                                pname = %pname,
                                "eBPF UDP conntrack overflow"
                            );
                        }
                        _ => {
                            debug!(
                                target: "clash-ebpf",
                                type_ = ev.type_,
                                pid = ev.pid,
                                pname = %pname,
                                "eBPF datapath event"
                            );
                        }
                    }
                }
            }
            guard.clear_ready();
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub mod non_linux {
    use super::DaeParam;

    pub struct BpfProgramManager;

    impl BpfProgramManager {
        pub fn new() -> Self {
            Self
        }
        pub fn load_and_attach(
            &mut self,
            _obj_bytes: &[u8],
            _param: &DaeParam,
            _lan_interfaces: &[String],
            _wan_interface: Option<&str>,
            _bypass_src_ports: &[u16],
            _bypass_dst_ports: &[u16],
            _bypass_src_ips: &[String],
            _bypass_dst_ips: &[String],
            _proxy_src_ports: &[u16],
            _proxy_dst_ports: &[u16],
            _proxy_src_ips: &[String],
            _proxy_dst_ips: &[String],
            _proxy_processes: &[String],
            _bypass_processes: &[String],
            _netns: Option<&crate::netns::non_linux::DaeNs>,
        ) -> Result<(), String> {
            Ok(())
        }
        pub fn update_dynamic_bypass_batch(
            &self,
            _add_v4: &[std::net::Ipv4Addr],
            _add_v6: &[std::net::Ipv6Addr],
            _remove_v4: &[std::net::Ipv4Addr],
            _remove_v6: &[std::net::Ipv6Addr],
        ) -> Result<(), String> {
            Ok(())
        }
        pub fn publish_listener_sockets(
            &mut self,
            _tcp4_fd: std::os::raw::c_int,
            _tcp6_fd: Option<std::os::raw::c_int>,
            _udp4_fd: std::os::raw::c_int,
            _udp6_fd: Option<std::os::raw::c_int>,
        ) -> Result<(), String> {
            Ok(())
        }
        pub fn unload(&self) {}
    }
}

#[cfg(target_os = "linux")]
pub type BpfProgramManager = linux::BpfProgramManager;

#[cfg(not(target_os = "linux"))]
pub type BpfProgramManager = non_linux::BpfProgramManager;
