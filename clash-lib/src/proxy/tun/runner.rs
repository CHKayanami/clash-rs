use std::{sync::Arc, time::Duration};

use futures::{FutureExt, SinkExt, StreamExt, future::BoxFuture};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::{
    Error,
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::config::TunConfig,
    proxy::tun::{datagram::handle_inbound_datagram, routes},
    runner::Runner,
};

/// Maximum number of attempts to wait for a newly created TUN interface to
/// become visible via NetworkInterface::show().
const TUN_VISIBILITY_MAX_ATTEMPTS: u32 = 40;
/// Interval in milliseconds between each visibility poll attempt.
const TUN_VISIBILITY_POLL_INTERVAL_MS: u64 = 50;

#[derive(Default)]
struct TunInitializationConfig {
    fd: Option<u32>,
    tun_name: Option<String>,
    #[cfg(target_os = "windows")]
    guid: Option<u128>,
}

pub struct TunRunner {
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    cancellation_token: CancellationToken,
}

impl TunRunner {
    pub fn new(
        cfg: TunConfig,
        dispatcher: Arc<Dispatcher>,
        resolver: ThreadSafeDNSResolver,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<TunRunner, Error> {
        Ok(Self {
            cfg,
            dispatcher,
            resolver,
            cancellation_token: cancellation_token.unwrap_or_default(),
        })
    }

    async fn new_internal(
        cfg: &TunConfig,
    ) -> Result<
        (
            tun_rs::AsyncDevice,
            watfaq_netstack::NetStack,
            watfaq_netstack::TcpListener,
            watfaq_netstack::UdpSocket,
        ),
        Error,
    > {
        let mut tun_init_config = TunInitializationConfig::default();
        match Url::parse(&cfg.device_id) {
            Ok(u) => match u.scheme() {
                "fd" => {
                    let fd = u
                        .host()
                        .expect("tun fd must be provided")
                        .to_string()
                        .parse()
                        .map_err(|x| Error::InvalidConfig(format!("tun fd {x}")))?;
                    tun_init_config.fd = Some(fd);
                }
                "dev" => {
                    let dev =
                        u.host().expect("tun dev must be provided").to_string();
                    if cfg!(target_os = "macos") && !dev.starts_with("utun") {
                        warn!(
                            "tun device id '{}' is not supported on macOS (must start with 'utun'), falling back to 'utun1989'",
                            dev
                        );
                        tun_init_config.tun_name = Some("utun1989".to_string());
                    } else {
                        tun_init_config.tun_name = Some(dev);
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let guid = u.query_pairs().find(|(k, _)| k == "guid");
                        if let Some((_, v)) = guid {
                            let guid = uuid::Uuid::parse_str(&v).map_err(|x| {
                                Error::InvalidConfig(format!("invalid guid: {x}"))
                            })?;
                            tun_init_config.guid = Some(guid.as_u128());
                        }
                    }
                }
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "invalid device id: {}",
                        cfg.device_id
                    )));
                }
            },
            Err(_) => {
                let dev = cfg.device_id.clone();
                if cfg!(target_os = "macos") && !dev.starts_with("utun") {
                    warn!(
                        "tun device id '{}' is not supported on macOS (must start with 'utun'), falling back to 'utun1989'",
                        dev
                    );
                    tun_init_config.tun_name = Some("utun1989".to_string());
                } else {
                    tun_init_config.tun_name = Some(dev);
                }
            }
        };

        let tun =
            if let Some(fd) = tun_init_config.fd {
                #[cfg(target_family = "unix")]
                {
                    info!("tun started with fd {}", fd);
                    unsafe { tun_rs::AsyncDevice::from_fd(fd as _)? }
                }

                #[cfg(not(target_family = "unix"))]
                {
                    return Err(Error::InvalidConfig(format!(
                        "tun fd({fd}) is only supported on Unix-like systems"
                    )));
                }
            } else {
                #[cfg(not(any(target_os = "ios", target_os = "android")))]
                {
                    use crate::proxy::tun::routes::maybe_add_routes;
                    use network_interface::NetworkInterfaceConfig;
                    use tun_rs::DeviceBuilder;

                    let tun_name =
                        tun_init_config.tun_name.expect("tun name must be provided");
                    let tun_exist = network_interface::NetworkInterface::show()
                        .map(|ifs| ifs.into_iter().any(|x| x.name == tun_name))
                        .unwrap_or_default();

                    if tun_exist {
                        info!("tun device {} already exists, using it.", &tun_name);
                    } else {
                        info!("tun device {} does not exist, creating.", &tun_name);
                    }

                    let mut tun_builder = DeviceBuilder::new();
                    #[cfg(not(target_os = "linux"))]
                    let gso_enabled = {
                        if cfg.gso.unwrap_or(false) {
                            warn!("GSO is only supported on Linux, ignoring on this platform");
                        }
                        false
                    };
                    #[cfg(target_os = "linux")]
                    let gso_enabled = cfg.gso.unwrap_or(false);

                    let gso_max_size = cfg.gso_max_size.unwrap_or(65536) as usize;
                    let stack_mtu = cfg.mtu.unwrap_or(1500) as usize;
                    let effective_mtu = if gso_enabled {
                        (gso_max_size.min(65535)) as u16
                    } else {
                        cfg.mtu.unwrap_or(if cfg!(windows) { 65535u16 } else { 1500u16 })
                    };

                    if gso_enabled {
                        info!(
                            "TUN GSO enabled (gso_max_size: {}, standard MTU: {})",
                            gso_max_size, stack_mtu
                        );
                    }

                    tun_builder = tun_builder.name(&tun_name).mtu(effective_mtu);

                    #[cfg(target_os = "linux")]
                    if gso_enabled {
                        tun_builder = tun_builder.offload(true);
                    }

                    if !tun_exist {
                        debug!("setting tun ipv4 addr: {:?}", cfg.gateway);
                        tun_builder = tun_builder.ipv4(
                            cfg.gateway.addr(),
                            cfg.gateway.netmask(),
                            None,
                        );

                        if let Some(gateway_v6) = cfg.gateway_v6 {
                            debug!("setting tun ipv6 addr: {:?}", cfg.gateway_v6);
                            tun_builder = tun_builder
                                .ipv6(gateway_v6.addr(), gateway_v6.netmask());
                        }
                    }
                    #[cfg(target_os = "windows")]
                    {
                        // Use the explicitly configured GUID, or derive a
                        // deterministic one from the device name so that the
                        // same adapter is reused across restarts instead of
                        // creating a new one every time.
                        let guid = tun_init_config.guid.unwrap_or_else(|| {
                            uuid::Uuid::new_v5(
                                &uuid::Uuid::NAMESPACE_DNS,
                                tun_name.as_bytes(),
                            )
                            .as_u128()
                        });
                        tun_builder = tun_builder.device_guid(guid);
                    }

                    let dev = tun_builder.build_async()?;

                    if !tun_exist {
                        // After build_async(), the new TUN interface may not be
                        // immediately visible via NetworkInterface::show(). Poll up
                        // to TUN_VISIBILITY_MAX_ATTEMPTS times (≈2 s) before
                        // setting up routes, but never sleep after the final check.
                        let mut tun_visible = false;
                        let mut last_show_err: Option<String> = None;
                        let mut attempt = 0u32;
                        loop {
                            match network_interface::NetworkInterface::show() {
                                Ok(ifs) => {
                                    if ifs.into_iter().any(|x| x.name == tun_name) {
                                        tun_visible = true;
                                        break;
                                    }
                                }
                                Err(e) => {
                                    last_show_err = Some(e.to_string());
                                }
                            }
                            attempt += 1;
                            if attempt >= TUN_VISIBILITY_MAX_ATTEMPTS {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(
                                TUN_VISIBILITY_POLL_INTERVAL_MS,
                            ))
                            .await;
                        }

                        if !tun_visible {
                            let total_ms = TUN_VISIBILITY_MAX_ATTEMPTS as u64
                                * TUN_VISIBILITY_POLL_INTERVAL_MS;
                            let err_msg = match last_show_err {
                                Some(e) => format!(
                                    "tun device {} not visible after waiting {}ms \
                                     (last error: {})",
                                    tun_name, total_ms, e
                                ),
                                None => format!(
                                    "tun device {} not visible after waiting {}ms",
                                    tun_name, total_ms
                                ),
                            };
                            return Err(Error::Operation(err_msg));
                        }

                        info!("setting up routes for tun {}", &tun_name);
                        maybe_add_routes(cfg, &tun_name)?;
                    } else {
                        info!("skipping route setup for existing tun {}", &tun_name);
                    }

                    dev
                }
                #[cfg(any(target_os = "ios", target_os = "android"))]
                {
                    return Err(Error::InvalidConfig(
                        "only fd is supported on mobile platforms".to_string(),
                    ));
                }
            };

        let pool_limit = cfg.max_pooled_buffers.or_else(|| {
            std::env::var("CLASH_NETSTACK_MAX_POOLED_BUFFERS")
                .or_else(|_| std::env::var("TUN_MAX_POOLED_BUFFERS"))
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
        });
        if let Some(limit) = pool_limit {
            watfaq_netstack::set_max_pooled_buffers(limit);
        }

        let (stack, tcp_listener, udp_socket) = watfaq_netstack::NetStack::new();
        Ok((tun, stack, tcp_listener, udp_socket))
    }
}

impl Runner for TunRunner {
    fn run_async(&self) {
        if !self.cfg.enable {
            info!("tun is disabled, skipping");
            return;
        }

        let cfg = self.cfg.clone();
        let so_mark = self.cfg.so_mark;
        let dispatcher = self.dispatcher.clone();
        let resolver = self.resolver.clone();
        let dns_hijack = self.cfg.dns_hijack.clone();
        let cancellation_token = self.cancellation_token.clone();

        tokio::spawn(async move {
            let (tun, stack, mut tcp_listener, udp_socket) =
                TunRunner::new_internal(&cfg)
                    .await
                    .inspect_err(|e| match e {
                        Error::Io(e) => {
                            if e.kind() == std::io::ErrorKind::PermissionDenied {
                                error!(
                                    "tun initialization failed: permission denied. \
                                     Please make sure the program has the \
                                     necessary permissions to create and manage \
                                     TUN interfaces."
                                );
                            } else {
                                error!("tun initialization I/O error: {}", e);
                            }
                        }
                        _ => {
                            error!("tun initialization error: {}", e);
                        }
                    })?;

            let tun = Arc::new(tun);
            let tun_for_writer = tun.clone();
            let (mut stack_sink, mut stack_stream) = stack.split();

            let auto_detect_cancel = cancellation_token.clone();
            if cfg.auto_detect_interface {
                tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(std::time::Duration::from_secs(3));
                    while !auto_detect_cancel.is_cancelled() {
                        tokio::select! {
                            _ = auto_detect_cancel.cancelled() => break,
                            _ = interval.tick() => {
                                if let Some(new_iface) =
                                    crate::app::net::get_outbound_interface()
                                {
                                    let mut current =
                                        crate::app::net::DEFAULT_OUTBOUND_INTERFACE
                                            .write()
                                            .await;
                                    let changed = match &*current {
                                        Some(old) => {
                                            old.name != new_iface.name
                                                || old.index != new_iface.index
                                        }
                                        None => true,
                                    };
                                    if changed {
                                        info!(
                                            "auto-detected default outbound interface \
                                             changed to {} (index: {})",
                                            new_iface.name, new_iface.index
                                        );
                                        *current = Some(new_iface);
                                    }
                                }
                            }
                        }
                    }
                });
            }

            let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(4096);
            let tun_tx_for_dispatcher = tun_tx.clone();
            let tun_tx_for_system_tcp = tun_tx.clone();

            let mut fut_tun_writer = async || {
                while let Some(pkt) = tun_rx.recv().await {
                    if let Err(e) = tun_for_writer.send(&pkt).await {
                        if e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::InvalidInput
                            || e.raw_os_error() == Some(22)
                        {
                            warn!(
                                "failed to send pkt to tun, dropping packet: {}",
                                e
                            );
                            continue;
                        }
                        error!("failed to send pkt to tun: {}", e);
                        break;
                    }
                }

                Err(Error::Operation("tun stopped unexpectedly 0".to_string()))
            };

            // dispatcher -> stack -> tun
            let mut fut_dispatcher_tun = async || {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) =
                                tun_tx_for_dispatcher.send(pkt.into_bytes()).await
                            {
                                error!("failed to send pkt to tun writer: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stack error: {}", e);
                            break;
                        }
                    }
                }

                Err(Error::Operation("tun stopped unexpectedly 0".to_string()))
            };

            let stack_type = cfg.stack.as_deref().unwrap_or("system");
            let use_system_stack = stack_type.eq_ignore_ascii_case("system")
                || stack_type.eq_ignore_ascii_case("mixed");

            if use_system_stack {
                info!("TUN stack initialized in 'system' mode (kernel native TCP NAT loopback + userspace UDP)");
            } else if stack_type.eq_ignore_ascii_case("gvisor") {
                info!("TUN stack initialized in 'smoltcp' mode (via 'gvisor' compatibility alias)");
            } else {
                info!("TUN stack initialized in 'smoltcp' mode (pure userspace NetStack)");
            }

            let (server_v4, client_v4) = {
                let server = cfg.gateway.addr();
                let octets = server.octets();
                let client = std::net::Ipv4Addr::new(
                    octets[0],
                    octets[1],
                    octets[2],
                    octets[3].wrapping_add(1),
                );
                (server, client)
            };

            let v4_tcp_info = if use_system_stack && cfg.enable_tcp {
                match tokio::net::TcpListener::bind((server_v4, 0)).await {
                    Ok(l) => {
                        let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
                        info!(
                            "System stack IPv4 TCP listener active at {}:{}",
                            server_v4, port
                        );
                        Some((l, (server_v4, client_v4, port)))
                    }
                    Err(e) => {
                        warn!("Failed to bind system stack IPv4 TCP listener: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            let (listener_v4, v4_nat_info) = match v4_tcp_info {
                Some((l, info)) => (Some(l), Some(info)),
                None => (None, None),
            };

            let v6_tcp_info = if use_system_stack && cfg.enable_tcp && cfg.gateway_v6.is_some() {
                let server_v6 = cfg.gateway_v6.as_ref().unwrap().addr();
                let mut octets = server_v6.octets();
                octets[15] = octets[15].wrapping_add(1);
                let client_v6 = std::net::Ipv6Addr::from(octets);

                match tokio::net::TcpListener::bind((server_v6, 0)).await {
                    Ok(l) => {
                        let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
                        info!(
                            "System stack IPv6 TCP listener active at [{}]:{}",
                            server_v6, port
                        );
                        Some((l, (server_v6, client_v6, port)))
                    }
                    Err(e) => {
                        warn!("Failed to bind system stack IPv6 TCP listener: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            let (listener_v6, v6_nat_info) = match v6_tcp_info {
                Some((l, info)) => (Some(l), Some(info)),
                None => (None, None),
            };

            let system_nat = Arc::new(super::system_stack::SystemTcpNat::new());

            let gso_enabled = cfg.gso.unwrap_or(false);
            let stack_mtu = cfg.mtu.unwrap_or(1500) as usize;

            // tun -> stack -> dispatcher
            let nat = system_nat.clone();
            let enable_tcp = cfg.enable_tcp;
            let mut fut_tun_dispatcher = async || {
                macro_rules! dispatch_bytes_mut {
                    ($single_pkt:expr) => {{
                        let mut single_pkt = $single_pkt;
                        if let Ok(version) = smoltcp::wire::IpVersion::of_packet(&single_pkt) {
                            let is_tcp = match version {
                                smoltcp::wire::IpVersion::Ipv4 => {
                                    smoltcp::wire::Ipv4Packet::new_checked(&single_pkt[..])
                                        .map(|p| p.next_header() == smoltcp::wire::IpProtocol::Tcp)
                                        .unwrap_or(false)
                                }
                                smoltcp::wire::IpVersion::Ipv6 => {
                                    smoltcp::wire::Ipv6Packet::new_checked(&single_pkt[..])
                                        .map(|p| p.next_header() == smoltcp::wire::IpProtocol::Tcp)
                                        .unwrap_or(false)
                                }
                            };

                            if is_tcp {
                                if !enable_tcp {
                                    // TCP disabled on TUN, drop incoming TCP packet
                                } else if use_system_stack
                                    && super::system_stack::process_system_tcp_packet(
                                        &mut single_pkt,
                                        v4_nat_info,
                                        v6_nat_info,
                                        &nat,
                                    ) == Some(true)
                                {
                                    if let Err(e) = tun_tx_for_system_tcp
                                        .send(single_pkt.freeze())
                                        .await
                                    {
                                        error!(
                                            "failed to write system TCP packet to tun channel: {}",
                                            e
                                        );
                                        break;
                                    }
                                } else if let Err(e) = stack_sink
                                    .send(watfaq_netstack::Packet::new(single_pkt.freeze()))
                                    .await
                                {
                                    error!("failed to send pkt to stack: {}", e);
                                    return Err(Error::Operation(
                                        "tun stopped unexpectedly 1".to_string(),
                                    ));
                                }
                            } else if let Err(e) = stack_sink
                                .send(watfaq_netstack::Packet::new(single_pkt.freeze()))
                                .await
                            {
                                error!("failed to send pkt to stack: {}", e);
                                return Err(Error::Operation(
                                    "tun stopped unexpectedly 1".to_string(),
                                ));
                            }
                        } else if let Err(e) = stack_sink
                            .send(watfaq_netstack::Packet::new(single_pkt.freeze()))
                            .await
                        {
                            error!("failed to send pkt to stack: {}", e);
                            return Err(Error::Operation(
                                "tun stopped unexpectedly 1".to_string(),
                            ));
                        }
                    }};
                }

                macro_rules! dispatch_pooled {
                    ($pooled:expr) => {{
                        let mut pooled = $pooled;
                        if let Ok(version) = smoltcp::wire::IpVersion::of_packet(pooled.as_ref()) {
                            let is_tcp = match version {
                                smoltcp::wire::IpVersion::Ipv4 => {
                                    smoltcp::wire::Ipv4Packet::new_checked(pooled.as_ref())
                                        .map(|p| p.next_header() == smoltcp::wire::IpProtocol::Tcp)
                                        .unwrap_or(false)
                                }
                                smoltcp::wire::IpVersion::Ipv6 => {
                                    smoltcp::wire::Ipv6Packet::new_checked(pooled.as_ref())
                                        .map(|p| p.next_header() == smoltcp::wire::IpProtocol::Tcp)
                                        .unwrap_or(false)
                                }
                            };

                            if is_tcp {
                                if !enable_tcp {
                                    // TCP disabled on TUN, drop incoming TCP packet
                                } else if use_system_stack
                                    && super::system_stack::process_system_tcp_packet(
                                        pooled.as_mut_slice(),
                                        v4_nat_info,
                                        v6_nat_info,
                                        &nat,
                                    ) == Some(true)
                                {
                                    if let Err(e) = tun_tx_for_system_tcp
                                        .send(pooled.into_bytes())
                                        .await
                                    {
                                        error!(
                                            "failed to write system TCP packet to tun channel: {}",
                                            e
                                        );
                                        break;
                                    }
                                } else if let Err(e) = stack_sink
                                    .send(watfaq_netstack::Packet::new(pooled.into_bytes()))
                                    .await
                                {
                                    error!("failed to send pkt to stack: {}", e);
                                    return Err(Error::Operation(
                                        "tun stopped unexpectedly 1".to_string(),
                                    ));
                                }
                            } else if let Err(e) = stack_sink
                                .send(watfaq_netstack::Packet::new(pooled.into_bytes()))
                                .await
                            {
                                error!("failed to send pkt to stack: {}", e);
                                return Err(Error::Operation(
                                    "tun stopped unexpectedly 1".to_string(),
                                ));
                            }
                        } else if let Err(e) = stack_sink
                            .send(watfaq_netstack::Packet::new(pooled.into_bytes()))
                            .await
                        {
                            error!("failed to send pkt to stack: {}", e);
                            return Err(Error::Operation(
                                "tun stopped unexpectedly 1".to_string(),
                            ));
                        }
                    }};
                }

                let read_cap = if gso_enabled { 65535 } else { stack_mtu.max(2048) };
                loop {
                    let mut pooled = crate::common::io::PooledBuffer::acquire(read_cap);
                    pooled.resize(read_cap, 0);
                    match tun.recv(pooled.as_mut_slice()).await {
                        Ok(0) => {
                            info!("tun reader reached EOF");
                            break;
                        }
                        Ok(n) => {
                            pooled.truncate(n);
                            if gso_enabled && pooled.len() > stack_mtu {
                                let pkt = pooled.into_bytes();
                                for single_pkt in
                                    super::gso::split_gso_packet(pkt, stack_mtu)
                                {
                                    dispatch_bytes_mut!(single_pkt);
                                }
                            } else {
                                dispatch_pooled!(pooled);
                            }
                        }
                        Err(e) => {
                            error!("tun stream recv error: {}", e);
                            break;
                        }
                    }
                }

                Err(Error::Operation("tun stopped unexpectedly 1".to_string()))
            };

            let dsp = dispatcher.clone();
            let res = resolver.clone();
            let strict_route = cfg.strict_route;
            let exclude_routes = Arc::new(cfg.route_exclude_address.clone());
            let exclude_routes_tcp = exclude_routes.clone();
            let dh = dns_hijack.clone();
            let udp_timeout_secs = cfg.udp_timeout.unwrap_or(300);

            let fut_tcp_dispatch = async || {
                if !enable_tcp {
                    futures::future::pending::<Result<(), Error>>().await
                } else if use_system_stack {
                    if let Some(l4) = listener_v4 {
                        let nat_clone = system_nat.clone();
                        let dsp_clone = dsp.clone();
                        let res_clone = res.clone();
                        let dh_clone = dh.clone();
                        let ex_clone = exclude_routes_tcp.clone();
                        tokio::spawn(async move {
                            super::system_stack::start_system_tcp_listener(
                                l4,
                                nat_clone,
                                dsp_clone,
                                res_clone,
                                so_mark,
                                dh_clone,
                                strict_route,
                                ex_clone,
                            )
                            .await;
                        });
                    }

                    if let Some(l6) = listener_v6 {
                        let nat_clone = system_nat.clone();
                        let dsp_clone = dsp.clone();
                        let res_clone = res.clone();
                        let dh_clone = dh.clone();
                        let ex_clone = exclude_routes_tcp.clone();
                        tokio::spawn(async move {
                            super::system_stack::start_system_tcp_listener(
                                l6,
                                nat_clone,
                                dsp_clone,
                                res_clone,
                                so_mark,
                                dh_clone,
                                strict_route,
                                ex_clone,
                            )
                            .await;
                        });
                    }

                    let nat_cleaner = system_nat.clone();
                    let timeout = Duration::from_secs(udp_timeout_secs);
                    let mut interval =
                        tokio::time::interval(Duration::from_secs(30));
                    loop {
                        interval.tick().await;
                        nat_cleaner.cleanup_timeout(timeout);
                    }
                } else {
                    while let Some(stream) = tcp_listener.next().await {
                        debug!(
                            "new tun TCP connection: {} -> {}",
                            stream.local_addr(),
                            stream.remote_addr()
                        );

                        tokio::spawn(super::stream::handle_inbound_netstack_stream(
                            stream,
                            dsp.clone(),
                            res.clone(),
                            so_mark,
                            dh.clone(),
                            strict_route,
                            exclude_routes_tcp.clone(),
                        ));
                    }

                    Err(Error::Operation("tun stopped unexpectedly 2".to_string()))
                }
            };
            let udp_timeout = cfg.udp_timeout;
            let fut_udp_dispatch = async || {
                handle_inbound_datagram(
                    udp_socket,
                    dispatcher.clone(),
                    resolver.clone(),
                    so_mark,
                    dns_hijack,
                    udp_timeout,
                    strict_route,
                    exclude_routes,
                )
                .await;
                Err(Error::Operation("tun stopped unexpectedly 3".to_string()))
            };

            let run_res = tokio::select! {
                res = fut_tun_writer() => res,
                res = fut_dispatcher_tun() => res,
                res = fut_tun_dispatcher() => res,
                res = fut_tcp_dispatch() => res,
                res = fut_udp_dispatch() => res,
                _ = cancellation_token.cancelled() => {
                    info!("tun stop signal received");
                    Ok(())
                },
            };

            if let Err(ref e) = run_res {
                error!("tun runner error: {}", e);
            }
            if let Err(e) = routes::maybe_routes_clean_up(&cfg) {
                warn!("error cleaning up routes during tun runner shutdown: {}", e);
            }
            info!("tun runner exited");
            run_res
        });
    }

    fn shutdown(&self) {
        info!("shutting down tun runner");
        match routes::maybe_routes_clean_up(&self.cfg) {
            Ok(_) => {}
            Err(e) => {
                error!("failed to clean up routes: {}", e);
            }
        }
        self.cancellation_token.cancel();
    }

    fn join(&self) -> BoxFuture<'_, Result<(), Error>> {
        async move { Ok(()) }.boxed()
    }
}
