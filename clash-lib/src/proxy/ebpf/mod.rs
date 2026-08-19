use crate::app::dispatcher::Dispatcher;
use crate::app::dns::ThreadSafeDNSResolver;
use crate::app::remote_content_manager::providers::rule_provider::CidrTrie;
use crate::config::def::EbpfConfig;
#[cfg(target_os = "linux")]
use crate::proxy::datagram::{ChannelDatagram, UdpPacket};
use crate::proxy::inbound::InboundHandlerTrait;
use async_trait::async_trait;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use tokio::sync::{Mutex, OnceCell};
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

pub mod runner;
pub use runner::EbpfRunner;

/// A lightweight, memory-efficient two-generation rotating Bloom filter for IP deduplication.
/// Total memory is fixed at ~4KB (2 generations of 2048 bytes / 16384 bits each), with zero GC/heap churn.
#[allow(dead_code)]
#[derive(Clone)]
pub struct RotatingBloomFilter {
    curr: [u64; 256],
    prev: [u64; 256],
    last_rotation: std::time::Instant,
    interval: std::time::Duration,
}

impl RotatingBloomFilter {
    pub fn new(interval: std::time::Duration) -> Self {
        Self {
            curr: [0; 256],
            prev: [0; 256],
            last_rotation: std::time::Instant::now(),
            interval,
        }
    }

    fn maybe_rotate(&mut self) {
        if self.last_rotation.elapsed() >= self.interval {
            self.prev = self.curr;
            self.curr = [0; 256];
            self.last_rotation = std::time::Instant::now();
        }
    }

    /// Computes 4 bit positions using Kirsch-Mitzenmacher dual hashing.
    fn hash_indexes(ip: &std::net::IpAddr) -> [usize; 4] {
        let (h1, h2) = match ip {
            std::net::IpAddr::V4(v4) => {
                let u = u32::from_ne_bytes(v4.octets()) as u64;
                let h1 = u.wrapping_mul(0x9E3779B97F4A7C15);
                let h2 = (u ^ 0x85EBCA6B).wrapping_mul(0xC2B2AE35);
                (h1, h2)
            }
            std::net::IpAddr::V6(v6) => {
                let bytes = v6.octets();
                let lo = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
                let hi = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
                let h1 = lo.wrapping_mul(0x9E3779B97F4A7C15) ^ hi;
                let h2 = hi.wrapping_mul(0xC2B2AE35) ^ lo;
                (h1, h2)
            }
        };

        const NUM_BITS: u64 = 256 * 64; // 16384 bits
        [
            (h1 % NUM_BITS) as usize,
            (h1.wrapping_add(h2) % NUM_BITS) as usize,
            (h1.wrapping_add(h2.wrapping_mul(2)) % NUM_BITS) as usize,
            (h1.wrapping_add(h2.wrapping_mul(3)) % NUM_BITS) as usize,
        ]
    }

    /// Checks if `ip` was recently recorded. If not, records it in the current generation.
    /// Returns `true` if `ip` was already present (or likely present), `false` if it was newly inserted.
    pub fn check_and_insert(&mut self, ip: std::net::IpAddr) -> bool {
        self.maybe_rotate();
        let idxs = Self::hash_indexes(&ip);

        let in_curr = idxs.iter().all(|&idx| {
            let word = idx / 64;
            let bit = idx % 64;
            (self.curr[word] & (1 << bit)) != 0
        });

        let in_prev = idxs.iter().all(|&idx| {
            let word = idx / 64;
            let bit = idx % 64;
            (self.prev[word] & (1 << bit)) != 0
        });

        if in_curr || in_prev {
            return true;
        }

        for &idx in &idxs {
            let word = idx / 64;
            let bit = idx % 64;
            self.curr[word] |= 1 << bit;
        }

        false
    }
}

#[allow(dead_code)]
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct DirectOffloader {
    tx: tokio::sync::mpsc::UnboundedSender<std::net::IpAddr>,
    resolver: ThreadSafeDNSResolver,
    bypass_dst_trie: Arc<CidrTrie>,
}

#[cfg(target_os = "linux")]
impl DirectOffloader {
    pub fn new(
        manager: Arc<Mutex<Option<clash_ebpf::EbpfManager>>>,
        resolver: ThreadSafeDNSResolver,
        bypass_dst_trie: Arc<CidrTrie>,
    ) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<std::net::IpAddr>();
        let resolver_clone = resolver.clone();
        let bypass_dst_trie_clone = bypass_dst_trie.clone();

        tokio::spawn(async move {
            let mut bloom_filter = RotatingBloomFilter::new(std::time::Duration::from_secs(300));
            while let Some(ip) = rx.recv().await {
                // Dynamically check against DNS module's configured Fake-IP pool, reserved IPs, and static bypass list
                if is_reserved_ip(ip) || resolver_clone.is_fake_ip(ip).await || bypass_dst_trie_clone.contains(ip) {
                    continue;
                }
                if bloom_filter.check_and_insert(ip) {
                    continue;
                }

                let mgr_guard = manager.lock().await;
                if let Some(mgr) = mgr_guard.as_ref() {
                    if let Err(e) = mgr.add_dynamic_bypass_ip(ip).await {
                        tracing::debug!("eBPF dynamic bypass failed for {ip}: {e}");
                    }
                }
            }
        });

        Self {
            tx,
            resolver,
            bypass_dst_trie,
        }
    }

    pub async fn offload(&self, ip: std::net::IpAddr) {
        if !is_reserved_ip(ip) && !self.resolver.is_fake_ip(ip).await && !self.bypass_dst_trie.contains(ip) {
            let _ = self.tx.send(ip);
        }
    }
}

/// Check if an IP is in the standard reserved/loopback/broadcast range.
#[allow(dead_code)]
fn is_reserved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 (multicast), 255.255.255.255
            octets[0] == 0 
                || octets[0] == 127 
                || (octets[0] == 169 && octets[1] == 254) 
                || (octets[0] >= 224 && octets[0] <= 239) 
                || octets == [255, 255, 255, 255]
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
        }
    }
}

#[allow(dead_code)]
fn extract_ips_from_dns_response(resp: &hickory_proto::op::Message) -> Vec<std::net::IpAddr> {
    use hickory_proto::rr::RData;
    let mut ips = Vec::new();
    for record in &resp.answers {
        match &record.data {
            RData::A(a) => {
                let ip = std::net::IpAddr::V4(a.0);
                if !is_reserved_ip(ip) {
                    ips.push(ip);
                }
            }
            RData::AAAA(aaaa) => {
                let ip = std::net::IpAddr::V6(aaaa.0);
                if !is_reserved_ip(ip) {
                    ips.push(ip);
                }
            }
            _ => {}
        }
    }
    ips
}

#[allow(dead_code)]
pub struct EbpfInbound {
    config: EbpfConfig,
    dispatcher: Arc<Dispatcher>,
    dns_resolver: ThreadSafeDNSResolver,
    #[cfg(target_os = "linux")]
    manager: Arc<Mutex<Option<clash_ebpf::EbpfManager>>>,
    #[cfg(target_os = "linux")]
    listener: Arc<OnceCell<Arc<clash_ebpf::EbpfListener>>>,
    #[cfg(target_os = "linux")]
    offloader: Arc<OnceCell<DirectOffloader>>,
}

/// Resolves raw IP/CIDR strings and `rule-set:` / `ruleset:` references against rule providers,
/// then performs deduplication and aggregation (merging subnets) using ipnet.
pub fn resolve_and_aggregate_ip_cidrs(
    entries: &[String],
    rule_providers: &std::collections::HashMap<String, crate::app::router::ThreadSafeRuleProvider>,
) -> Vec<String> {
    use std::str::FromStr;

    let mut v4_nets = Vec::new();
    let mut v6_nets = Vec::new();

    for item in entries {
        let s = item.trim();
        if s.is_empty() {
            continue;
        }

        let rs_name_opt = if let Some(name) = s.strip_prefix("rule-set:") {
            Some(name)
        } else if let Some(name) = s.strip_prefix("ruleset:") {
            Some(name)
        } else if let Some(name) = s.strip_prefix("RULE-SET:") {
            Some(name)
        } else if let Some(name) = s.strip_prefix("RULESET:") {
            Some(name)
        } else {
            None
        };

        if let Some(rs_name) = rs_name_opt {
            let rs_name = rs_name.trim();
            if let Some(rp) = rule_providers.get(rs_name) {
                let nets = rp.get_ip_cidrs();
                info!(
                    "Resolved eBPF ruleset '{}' with {} IP/CIDR entries",
                    rs_name,
                    nets.len()
                );
                for net in nets {
                    match net {
                        ipnet::IpNet::V4(v4) => v4_nets.push(v4),
                        ipnet::IpNet::V6(v6) => v6_nets.push(v6),
                    }
                }
            } else {
                warn!(
                    "eBPF config references rule-set '{}', but it was not found in rule providers",
                    rs_name
                );
            }
        } else if let Ok(net) = ipnet::IpNet::from_str(s) {
            match net {
                ipnet::IpNet::V4(v4) => v4_nets.push(v4),
                ipnet::IpNet::V6(v6) => v6_nets.push(v6),
            }
        } else if let Ok(ip) = std::net::IpAddr::from_str(s) {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    if let Ok(net) = ipnet::Ipv4Net::new(v4, 32) {
                        v4_nets.push(net);
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    if let Ok(net) = ipnet::Ipv6Net::new(v6, 128) {
                        v6_nets.push(net);
                    }
                }
            }
        } else {
            warn!("eBPF config encountered invalid IP/CIDR or ruleset entry: '{}'", s);
        }
    }

    let agg_v4 = ipnet::Ipv4Net::aggregate(&v4_nets);
    let agg_v6 = ipnet::Ipv6Net::aggregate(&v6_nets);

    let mut result = Vec::with_capacity(agg_v4.len() + agg_v6.len());
    for n in agg_v4 {
        result.push(n.to_string());
    }
    for n in agg_v6 {
        result.push(n.to_string());
    }
    result
}

impl EbpfInbound {
    pub fn new(
        config: EbpfConfig,
        dispatcher: Arc<Dispatcher>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> Self {
        Self {
            config,
            dispatcher,
            dns_resolver,
            #[cfg(target_os = "linux")]
            manager: Arc::new(Mutex::new(None)),
            #[cfg(target_os = "linux")]
            listener: Arc::new(OnceCell::new()),
            #[cfg(target_os = "linux")]
            offloader: Arc::new(OnceCell::new()),
        }
    }

    #[cfg(target_os = "linux")]
    async fn get_or_init_offloader(&self) -> DirectOffloader {
        self.offloader
            .get_or_init(|| async {
                let rule_providers = self.dispatcher.router().get_rule_providers();
                let bypass_ips = resolve_and_aggregate_ip_cidrs(&self.config.bypass_ips, rule_providers);
                let bypass_dst_ips = resolve_and_aggregate_ip_cidrs(&self.config.bypass_dst_ips, rule_providers);

                let mut trie = CidrTrie::new();
                for ip in bypass_ips.iter().chain(bypass_dst_ips.iter()) {
                    trie.insert(ip);
                }

                DirectOffloader::new(self.manager.clone(), self.dns_resolver.clone(), Arc::new(trie))
            })
            .await
            .clone()
    }

    #[cfg(target_os = "linux")]
    async fn get_or_init_listener(&self) -> std::io::Result<Arc<clash_ebpf::EbpfListener>> {
        self.listener
            .get_or_try_init(|| async {
                use clash_ebpf::{EbpfConfig as CoreEbpfConfig, EbpfManager};

                let rule_providers = self.dispatcher.router().get_rule_providers();

                let bypass_ips = resolve_and_aggregate_ip_cidrs(&self.config.bypass_ips, rule_providers);
                let bypass_src_ips = resolve_and_aggregate_ip_cidrs(&self.config.bypass_src_ips, rule_providers);
                let bypass_dst_ips = resolve_and_aggregate_ip_cidrs(&self.config.bypass_dst_ips, rule_providers);
                let proxy_ips = resolve_and_aggregate_ip_cidrs(&self.config.proxy_ips, rule_providers);
                let proxy_src_ips = resolve_and_aggregate_ip_cidrs(&self.config.proxy_src_ips, rule_providers);
                let proxy_dst_ips = resolve_and_aggregate_ip_cidrs(&self.config.proxy_dst_ips, rule_providers);

                info!(
                    "eBPF IP configs resolved & aggregated -> bypass_ips: {}, bypass_src_ips: {}, bypass_dst_ips: {}, proxy_ips: {}, proxy_src_ips: {}, proxy_dst_ips: {}",
                    bypass_ips.len(),
                    bypass_src_ips.len(),
                    bypass_dst_ips.len(),
                    proxy_ips.len(),
                    proxy_src_ips.len(),
                    proxy_dst_ips.len()
                );

                let core_config = CoreEbpfConfig {
                    enable: self.config.enable,
                    lan_interface: self.config.lan_interface.clone(),
                    wan_interface: self.config.wan_interface.clone(),
                    tproxy_port: self.config.tproxy_port,
                    tproxy_udp_port: self.config.tproxy_udp_port,
                    bypass_ports: self.config.bypass_ports.clone(),
                    bypass_src_ports: self.config.bypass_src_ports.clone(),
                    bypass_dst_ports: self.config.bypass_dst_ports.clone(),
                    bypass_ips,
                    bypass_src_ips,
                    bypass_dst_ips,
                    proxy_ports: self.config.proxy_ports.clone(),
                    proxy_src_ports: self.config.proxy_src_ports.clone(),
                    proxy_dst_ports: self.config.proxy_dst_ports.clone(),
                    proxy_ips,
                    proxy_src_ips,
                    proxy_dst_ips,
                    auto_direct_offload: self.config.auto_direct_offload,
                };

                let mut manager = EbpfManager::new(core_config);
                let listener = manager
                    .start()
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                let mut manager_guard = self.manager.lock().await;
                *manager_guard = Some(manager);

                Ok(listener)
            })
            .await
            .cloned()
    }

    pub async fn stop(&self) {
        #[cfg(target_os = "linux")]
        {
            let mut manager_guard = self.manager.lock().await;
            if let Some(mut mgr) = manager_guard.take() {
                mgr.stop().await;
            }
        }
    }

}


#[cfg(target_os = "linux")]
async fn handle_tcp_dns(
    mut stream: tokio::net::TcpStream,
    resolver: ThreadSafeDNSResolver,
    dispatcher: Arc<Dispatcher>,
    offloader: Option<DirectOffloader>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    debug!("error reading TCP DNS length prefix: {e}");
                }
                break;
            }
        }
        let length = u16::from_be_bytes(len_buf) as usize;
        if length == 0 || length > 4096 {
            debug!("invalid TCP DNS message length: {length}");
            break;
        }
        let mut query_buf = vec![0u8; length];
        if let Err(e) = stream.read_exact(&mut query_buf).await {
            debug!("error reading TCP DNS message body: {e}");
            break;
        }

        match hickory_proto::op::Message::from_vec(&query_buf) {
            Ok(msg) => {
                trace!("eBPF intercepted TCP DNS query: {:?}", msg);
                match crate::app::dns::exchange_with_resolver(&resolver, &msg, true).await {
                    Ok(mut resp) => {
                        resp.metadata.id = msg.metadata.id;

                        // Async Direct Offload learning
                        if let Some(offloader) = &offloader {
                            let ips = extract_ips_from_dns_response(&resp);
                            if !ips.is_empty() {
                                let router = dispatcher.router().clone();
                                let offloader = offloader.clone();
                                let query_name = msg.queries.first().map(|q| q.name().to_utf8()).unwrap_or_default();
                                tokio::spawn(async move {
                                    let domain_clean = query_name.trim_end_matches('.');
                                    if router.is_domain_direct(domain_clean).await {
                                        for ip in ips {
                                            offloader.offload(ip).await;
                                        }
                                    }
                                });
                            }
                        }

                        match resp.to_vec() {
                            Ok(resp_bytes) => {
                                let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                                if let Err(e) = stream.write_all(&resp_len).await {
                                    debug!("failed to write TCP DNS response length: {e}");
                                    break;
                                }
                                if let Err(e) = stream.write_all(&resp_bytes).await {
                                    debug!("failed to write TCP DNS response body: {e}");
                                    break;
                                }
                                if let Err(e) = stream.flush().await {
                                    debug!("failed to flush TCP DNS response: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("failed to serialize TCP DNS response: {e}");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("failed to exchange TCP DNS query with resolver: {e}");
                        break;
                    }
                }
            }
            Err(e) => {
                warn!("failed to parse TCP DNS query message: {e}");
                break;
            }
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for EbpfInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            warn!("eBPF inbound is only supported on Linux");
            futures::future::pending::<()>().await;
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            use crate::session::{Network, Session, Type};

            let listener = self.get_or_init_listener().await?;
            let offloader = if self.config.auto_direct_offload {
                Some(self.get_or_init_offloader().await)
            } else {
                None
            };
            info!("clash-ebpf TCP inbound worker running");

            loop {
                match listener.accept_tcp().await {
                    Ok((stream, session_info)) => {
                        let dst = session_info.destination;

                        // 1. Intercept TCP port 53 (DNS-over-TCP)
                        if dst.port() == 53 {
                            let resolver = self.dns_resolver.clone();
                            let dispatcher = self.dispatcher.clone();
                            let offloader = offloader.clone();
                            tokio::spawn(async move {
                                handle_tcp_dns(stream, resolver, dispatcher, offloader).await;
                            });
                            continue;
                        }

                        // 2. Regular TCP proxy stream
                        info!("[eBPF TCP] Intercepted: {} -> {}", session_info.source, dst);
                        let session = Session {
                            network: Network::Tcp,
                            typ: Type::Ebpf,
                            source: session_info.source,
                            destination: dst.into(),
                            ..Default::default()
                        };


                        let dispatcher = self.dispatcher.clone();
                        tokio::spawn(async move {
                            dispatcher.dispatch_stream(session, Box::new(stream)).await;
                        });
                    }
                    Err(err) => {
                        error!("eBPF TCP accept error: {err}");
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            futures::future::pending::<()>().await;
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            use crate::session::{Network, Session, Type};

            let listener = self.get_or_init_listener().await?;
            let offloader = if self.config.auto_direct_offload {
                Some(self.get_or_init_offloader().await)
            } else {
                None
            };
            info!("clash-ebpf UDP inbound worker running");

            const UDP_CHANNEL_CAPACITY: usize = 1024;
            let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(UDP_CHANNEL_CAPACITY);
            let (d_tx, d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(UDP_CHANNEL_CAPACITY);

            let udp_stream = ChannelDatagram::new(l_tx, d_rx);

            let default_outbound = crate::app::net::DEFAULT_OUTBOUND_INTERFACE.read().await;
            let sess = Session {
                network: Network::Udp,
                typ: Type::Ebpf,
                iface: default_outbound.clone(),
                ..Default::default()
            };


            let _closer = self.dispatcher.dispatch_datagram(sess, Box::new(udp_stream)).await;

            let listener_for_send = listener.clone();
            // Dispatcher -> client outbound reply task
            let send_task = tokio::spawn(async move {
                while let Some(packet) = l_rx.recv().await {
                    if let Some(target) = packet.src_addr.try_into_socket_addr() {
                        if let Some(orig_dst) = packet.dst_addr.try_into_socket_addr() {
                            if let Ok(reply_sock) = listener_for_send.create_reply_socket(orig_dst) {
                                let _ = reply_sock.send_to(&packet.data, target).await;
                                continue;
                            }
                        }
                        let socket = listener_for_send.udp_socket();
                        let _ = socket.send_to(&packet.data, target).await;
                    }
                }
            });

            // Client inbound receive tasks -> Dispatcher / DNS (aligned with honk architecture)
            let v4_socket = listener.udp_socket_v4();
            let v4_task = tokio::spawn(udp_listener_loop(
                v4_socket,
                "IPv4",
                d_tx.clone(),
                self.dns_resolver.clone(),
                self.dispatcher.clone(),
                listener.clone(),
                offloader.clone(),
            ));

            let v6_task = if let Some(v6_socket) = listener.udp_socket_v6() {
                Some(tokio::spawn(udp_listener_loop(
                    v6_socket,
                    "IPv6",
                    d_tx,
                    self.dns_resolver.clone(),
                    self.dispatcher.clone(),
                    listener.clone(),
                    offloader,
                )))
            } else {
                None
            };

            tokio::select! {
                _ = send_task => {},
                _ = v4_task => {},
                _ = async {
                    if let Some(t) = v6_task {
                        let _ = t.await;
                    } else {
                        futures::future::pending::<()>().await;
                    }
                } => {},
            }

            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
async fn udp_listener_loop(
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    family: &'static str,
    d_tx: tokio::sync::mpsc::Sender<UdpPacket>,
    resolver: crate::app::dns::ThreadSafeDNSResolver,
    dispatcher: Arc<Dispatcher>,
    listener_for_dns: std::sync::Arc<clash_ebpf::EbpfListener>,
    offloader: Option<DirectOffloader>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match clash_ebpf::EbpfListener::recv_from_socket(&socket, &mut buf).await {
            Ok((n, src, dst)) => {
                let data = &buf[..n];
                // 1. Intercept UDP port 53 (DNS)
                if dst.port() == 53 {
                    if let Ok(msg) = hickory_proto::op::Message::from_vec(data) {
                        let q_info = msg
                            .queries
                            .first()
                            .map(|q| format!("{}({:?})", q.name(), q.query_type()))
                            .unwrap_or_default();
                        info!(
                            "[eBPF DNS] Intercepted DNS query {} from {} to {}",
                            q_info, src, dst
                        );

                        let resolver = resolver.clone();
                        let dispatcher = dispatcher.clone();
                        let listener_for_dns = listener_for_dns.clone();
                        let offloader = offloader.clone();
                        tokio::spawn(async move {
                            match crate::app::dns::exchange_with_resolver(&resolver, &msg, true).await {
                                Ok(mut resp) => {
                                    resp.metadata.id = msg.metadata.id;

                                    // Async Direct Offload learning
                                    if let Some(offloader) = &offloader {
                                        let ips = extract_ips_from_dns_response(&resp);
                                        if !ips.is_empty() {
                                            let router = dispatcher.router().clone();
                                            let offloader = offloader.clone();
                                            let query_name = msg.queries.first().map(|q| q.name().to_utf8()).unwrap_or_default();
                                            tokio::spawn(async move {
                                                let domain_clean = query_name.trim_end_matches('.');
                                                if router.is_domain_direct(domain_clean).await {
                                                    for ip in ips {
                                                        offloader.offload(ip).await;
                                                    }
                                                }
                                            });
                                        }
                                    }

                                    match resp.to_vec() {
                                        Ok(resp_bytes) => {
                                            match listener_for_dns.send_dns_reply(&resp_bytes, dst, src).await {
                                                Ok(_) => {
                                                    tracing::info!("[eBPF DNS] Replied {} -> {}", dst, src);
                                                }
                                                Err(e) => {
                                                    tracing::warn!("[eBPF DNS] send_dns_reply {} -> {} failed: {}", dst, src, e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("[eBPF DNS] failed to serialize DNS response for {}: {}", q_info, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("[eBPF DNS] Resolution failed for {}: {}", q_info, e);
                                }
                            }
                        });
                        continue;
                    } else {
                        info!("[eBPF DNS] Intercepted raw DNS from {} to {}", src, dst);
                    }
                }

                // 2. Regular UDP packet -> Dispatcher
                info!("[eBPF UDP] Intercepted: {} -> {}", src, dst);
                let payload = bytes::Bytes::copy_from_slice(data);
                let packet = UdpPacket::new(payload, src.into(), dst.into());

                if d_tx.send(packet).await.is_err() {
                    break;
                }
            }
            Err(err) => {
                error!("eBPF {} UDP recv error: {err}", family);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::remote_content_manager::providers::{
        Provider,
        rule_provider::{RuleProviderImpl, RuleSetBehavior, RuleSetFormat},
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_resolve_and_aggregate_with_rule_provider() {
        let mut providers = HashMap::new();

        let rp_direct = Arc::new(RuleProviderImpl::new(
            "direct-ips".to_string(),
            RuleSetBehavior::Ipcidr,
            RuleSetFormat::Text,
            None,
            None,
            None,
            None,
            Some(vec![
                "192.168.1.0/24".to_string(),
                "192.168.1.100/32".to_string(),
                "10.0.0.0/24".to_string(),
                "10.0.1.0/24".to_string(),
                "fe80::/10".to_string(),
            ]),
        ));
        let _ = rp_direct.initialize().await;
        providers.insert("direct-ips".to_string(), rp_direct as crate::app::router::ThreadSafeRuleProvider);

        let input = vec![
            "10.0.2.0/24".to_string(),
            "10.0.3.0/24".to_string(),
            "rule-set:direct-ips".to_string(),
            "1.1.1.1".to_string(),
            "::1".to_string(),
        ];

        let result = resolve_and_aggregate_ip_cidrs(&input, &providers);

        // 10.0.0.0/24 + 10.0.1.0/24 from ruleset + 10.0.2.0/24 + 10.0.3.0/24 from input => 10.0.0.0/22
        assert!(result.contains(&"10.0.0.0/22".to_string()));
        // 192.168.1.0/24 subsumes 192.168.1.100/32
        assert!(result.contains(&"192.168.1.0/24".to_string()));
        assert!(!result.contains(&"192.168.1.100/32".to_string()));
        // 1.1.1.1/32
        assert!(result.contains(&"1.1.1.1/32".to_string()));
        // IPv6
        assert!(result.contains(&"::1/128".to_string()));
        assert!(result.contains(&"fe80::/10".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_and_aggregate_missing_provider() {
        let providers = HashMap::new();
        let input = vec![
            "rule-set:non-existent".to_string(),
            "192.168.0.1".to_string(),
        ];

        let result = resolve_and_aggregate_ip_cidrs(&input, &providers);
        assert_eq!(result, vec!["192.168.0.1/32".to_string()]);
    }

    #[test]
    fn test_bypass_dst_trie_filtering() {
        let mut trie = CidrTrie::new();
        trie.insert("192.168.1.0/24");
        trie.insert("10.0.0.0/8");
        trie.insert("fe80::/10");

        let ip_in_1: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        let ip_in_2: std::net::IpAddr = "10.20.30.40".parse().unwrap();
        let ip_in_3: std::net::IpAddr = "fe80::1".parse().unwrap();
        let ip_out_1: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        let ip_out_2: std::net::IpAddr = "192.168.2.1".parse().unwrap();

        assert!(trie.contains(ip_in_1));
        assert!(trie.contains(ip_in_2));
        assert!(trie.contains(ip_in_3));
        assert!(!trie.contains(ip_out_1));
        assert!(!trie.contains(ip_out_2));
    }

    #[test]
    fn test_rotating_bloom_filter() {
        let mut bf = RotatingBloomFilter::new(std::time::Duration::from_millis(50));
        let ip1: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: std::net::IpAddr = "5.6.7.8".parse().unwrap();
        let ip3: std::net::IpAddr = "2001:db8::1".parse().unwrap();

        // Initial insertions
        assert!(!bf.check_and_insert(ip1)); // false = newly inserted
        assert!(bf.check_and_insert(ip1));  // true = already present
        assert!(!bf.check_and_insert(ip2));
        assert!(bf.check_and_insert(ip2));
        assert!(!bf.check_and_insert(ip3));

        // Sleep to trigger first generation rotation
        std::thread::sleep(std::time::Duration::from_millis(60));

        // In second generation, previous generation elements should still be recognized
        assert!(bf.check_and_insert(ip1));
        assert!(bf.check_and_insert(ip2));
        assert!(bf.check_and_insert(ip3));

        let ip4: std::net::IpAddr = "9.10.11.12".parse().unwrap();
        assert!(!bf.check_and_insert(ip4));

        // Sleep again to trigger second rotation (old generation evicted)
        std::thread::sleep(std::time::Duration::from_millis(60));

        // ip4 is in prev generation, so recognized
        assert!(bf.check_and_insert(ip4));

        // Sleep once more to evict ip4
        std::thread::sleep(std::time::Duration::from_millis(60));
        // Force check
        bf.maybe_rotate();
        std::thread::sleep(std::time::Duration::from_millis(60));
        bf.maybe_rotate();

        // Now ip1, ip2, ip3 should have expired
        assert!(!bf.check_and_insert(ip1));
    }
}
