use std::{sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use url::Url;
use tun_rs::AsyncDevice;
use watfaq_netstack::NetStack;

use crate::{
    Error,
    app::{
        dispatcher::Dispatcher,
        dns::ThreadSafeDNSResolver,
    },
    config::config::TunConfig,
    proxy::tun::datagram::handle_inbound_datagram,
    runner::{AsyncService, ServiceContext},
};
use async_trait::async_trait;
use super::{
    device_io::{self, DEVICE_BATCH},
    packet_queue,
    packet::PacketDispatcher,
    stream::TcpContext,
    tcp::TcpListeners,
};
#[cfg(not(target_os = "macos"))]
use super::routes;
#[cfg(not(target_os = "macos"))]
use crate::app::net::{
    get_outbound_interface, update_default_outbound_interface_if_changed,
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
    ) -> Result<AsyncDevice, Error> {
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

        let tun = if let Some(fd) = tun_init_config.fd {
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
                #[cfg(not(target_os = "macos"))]
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
                        warn!(
                            "GSO is only supported on Linux, ignoring on this platform"
                        );
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
                    cfg.mtu
                        .unwrap_or(if cfg!(windows) { 65535u16 } else { 1500u16 })
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
                        tokio::time::sleep(Duration::from_millis(
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
                }

                info!("setting up routes for tun {}", &tun_name);
                #[cfg(not(target_os = "macos"))]
                maybe_add_routes(cfg, &tun_name)?;

                dev
            }
            #[cfg(any(target_os = "ios", target_os = "android"))]
            {
                return Err(Error::InvalidConfig(
                    "only fd is supported on mobile platforms".to_string(),
                ));
            }
        };

        Ok(tun)
    }

    pub fn shutdown(&self) {
        info!("shutting down tun runner");
        self.cancellation_token.cancel();
        #[cfg(not(target_os = "macos"))]
        match routes::maybe_routes_clean_up(&self.cfg) {
            Ok(_) => {}
            Err(e) => {
                error!("failed to clean up routes: {}", e);
            }
        }
    }
}

#[async_trait]
impl AsyncService for TunRunner {
    async fn start(&self, ctx: &ServiceContext) -> Result<(), Error> {
        if !self.cfg.enable {
            info!("tun is disabled, skipping");
            return Ok(());
        }

        let cfg = self.cfg.clone();
        let so_mark = self.cfg.so_mark;
        let dispatcher = self.dispatcher.clone();
        let resolver = self.resolver.clone();
        let dns_hijack = self.cfg.dns_hijack.clone();
        let cancellation_token = self.cancellation_token.clone();

        let tun = TunRunner::new_internal(&cfg)
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

        // Bind all fallible TCP listeners before publishing platform routes/DNS
        // or spawning the packet pipeline. Failure releases both listeners.
        let listeners = TcpListeners::bind(&cfg).await.inspect_err(|_| {
            #[cfg(not(target_os = "macos"))]
            if let Err(error) = routes::maybe_routes_clean_up(&cfg) {
                warn!("failed to roll back TUN routes after TCP initialization failure: {error}");
            }
        })?;

        let (stack, tcp_listener, udp_socket) =
            NetStack::new_with_protocols(cfg.enable_tcp && !listeners.system, cfg.enable_tcp);

        // Externally supplied descriptors belong to their platform host; it
        // remains responsible for routes and DNS (e.g. NetworkExtension).
        let tun = Arc::new(tun);
        #[cfg(target_os = "macos")]
        let platform = if !cfg.device_id.starts_with("fd://") || cfg.auto_detect_interface {
            Some(super::macos::start(cfg.clone(), tun.clone(),
                !cfg.device_id.starts_with("fd://"), ctx, &cancellation_token).await?)
        } else { None };

        let frame_size = usize::from(tun.mtu()?);
        let (mut device_reader, mut device_writer) = device_io::split(
            &tun, frame_size, !cfg.device_id.starts_with("fd://"),
        )?;
        let tun_for_writer = tun.clone();
        let (mut stack_sink, mut stack_stream) = stack.split();

        #[cfg(not(target_os = "macos"))]
        let auto_detect_cancel = cancellation_token.clone();
        #[cfg(not(target_os = "macos"))]
        if cfg.auto_detect_interface {
            ctx.spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(3));
                while !auto_detect_cancel.is_cancelled() {
                    tokio::select! {
                        _ = auto_detect_cancel.cancelled() => break,
                        _ = interval.tick() => {
                            if let Some(new_iface) = get_outbound_interface() {
                                if update_default_outbound_interface_if_changed(
                                    new_iface.clone(),
                                ) {
                                    info!(
                                        "auto-detected default outbound interface \
                                         changed to {} (index: {})",
                                        new_iface.name, new_iface.index
                                    );
                                }
                            }
                        }
                    }
                }
            });
        }

        let lifecycle_token = cancellation_token.clone();
        ctx.spawn_critical_with_token("tun_packet_pipeline", lifecycle_token, async move {
            #[cfg(target_os = "macos")]
            let _platform = platform;
            let (tun_tx, mut tun_rx) = packet_queue::channel();
            let tun_tx_for_dispatcher = tun_tx.clone();
            let tun_tx_for_system_tcp = tun_tx.clone();

            let mut fut_tun_writer = async || {
                let mut queued = Vec::with_capacity(DEVICE_BATCH);
                let mut batch = Vec::with_capacity(DEVICE_BATCH);
                let mut budgets = Vec::with_capacity(DEVICE_BATCH);
                while tun_rx.recv_many(&mut queued, DEVICE_BATCH).await > 0 {
                    for packet_queue::Packet { bytes, budget } in queued.drain(..) {
                        batch.push(bytes);
                        budgets.push(budget);
                    }
                    let result = device_writer.send(&tun_for_writer, &batch).await;
                    batch.clear();
                    budgets.clear();
                    if let Err(e) = result {
                        if matches!(e.kind(), std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock | std::io::ErrorKind::InvalidInput)
                            || e.raw_os_error() == Some(libc::ENOBUFS) {
                            warn!("failed to write TUN batch, dropping unsent packets: {e}");
                            continue;
                        }
                        error!("failed to send batch to tun: {e}");
                        break;
                    }
                }
                Err(Error::Operation("tun stopped unexpectedly 0".to_string()))
            };

            // dispatcher -> stack -> tun
            let mut fut_dispatcher_tun = async || {
                let mut packets = Vec::with_capacity(DEVICE_BATCH);
                while stack_stream.recv_many(&mut packets, DEVICE_BATCH).await? > 0 {
                    if let Err(error) = tun_tx_for_dispatcher.send_batch(&mut packets).await {
                        error!("failed to enqueue TUN reply batch: {error}");
                        break;
                    }
                }
                Err(Error::Operation("tun stopped unexpectedly 0".to_string()))
            };

            let use_system_stack = listeners.system;
            let v4_nat_info = listeners.ipv4.as_ref().map(|bound| bound.nat);
            let v6_nat_info = listeners.ipv6.as_ref().map(|bound| bound.nat);
            info!("TUN stack initialized (system TCP: {})", use_system_stack);

            let system_nat = Arc::new(super::system_stack::SystemTcpNat::new());

            // tun -> stack -> dispatcher
            let enable_tcp = cfg.enable_tcp;
            let packets = PacketDispatcher {
                enable_tcp, system_tcp: use_system_stack, ipv4: v4_nat_info, ipv6: v6_nat_info,
                nat: system_nat.clone(), replies: tun_tx_for_system_tcp,
            };
            let mut fut_tun_dispatcher = async || {
                let mut batch = Vec::with_capacity(DEVICE_BATCH);
                loop {
                    match device_reader.recv(&tun, &mut batch).await {
                        Ok(0) => { info!("tun reader reached EOF"); break; }
                        Ok(_) => {
                            for packet in batch.drain(..) { packets.dispatch(packet, &mut stack_sink).await?; }
                        }
                        Err(error) => { error!("tun stream recv error: {error}"); break; }
                    }
                }

                Err(Error::Operation("tun stopped unexpectedly 1".to_string()))
            };

            let strict_route = cfg.strict_route;
            let exclude_routes = Arc::new(cfg.route_exclude_address.clone());
            let tcp_context = Arc::new(TcpContext {
                dispatcher: dispatcher.clone(), resolver: resolver.clone(), so_mark,
                dns_hijack: dns_hijack.clone(), strict_route, exclude_routes: exclude_routes.clone(),
            });
            let fut_tcp_dispatch = async || {
                listeners.run(tcp_listener, system_nat.clone(), tcp_context, enable_tcp).await
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
            #[cfg(not(target_os = "macos"))]
            if let Err(e) = routes::maybe_routes_clean_up(&cfg) {
                warn!("error cleaning up routes during tun runner shutdown: {}", e);
            }
            info!("tun runner exited");
            run_res
        });

        Ok(())
    }

    async fn stop(&self) -> Result<(), Error> {
        self.shutdown();
        Ok(())
    }
}
