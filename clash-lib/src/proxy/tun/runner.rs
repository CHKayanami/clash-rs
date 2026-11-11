use std::sync::Arc;
#[cfg(not(target_os = "android"))]
use std::time::Duration;

use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tracing::debug;
use tun_rs::AsyncDevice;
use clash_netstack::{NetStack, TcpDriver};

use crate::{
    Error,
    app::{
        dispatcher::Dispatcher,
        dns::ThreadSafeDNSResolver,
    },
    config::{config::TunConfig, internal::tun::{TunDevice, parse_device_id}},
    proxy::tun::datagram::handle_inbound_datagram,
    runner::{AsyncService, ServiceContext},
};
use async_trait::async_trait;
#[cfg(any(target_os = "android", target_os = "linux"))]
use super::icmp;
#[cfg(target_os = "linux")]
use super::auto_redirect::{AutoRedirect, address_sets::RouteAddressSets, tcp as redirect_tcp};
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use crate::app::remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider;
use super::{
    device_io::{self, DeviceIo},
    device_loop::{DeviceLoop, Protocols},
    packet_queue,
    pipeline::PacketPipeline,
    packet::PacketDispatcher,
    stream::TcpContext,
    tcp::TcpListeners,
};
#[cfg(not(any(target_os = "macos", target_os = "android")))]
use super::routes;
#[cfg(not(any(target_os = "macos", target_os = "android")))]
use crate::app::net::{
    get_outbound_interface, update_default_outbound_interface_if_changed,
};

/// Maximum number of attempts to wait for a newly created TUN interface to
/// become visible via NetworkInterface::show().
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const TUN_VISIBILITY_MAX_ATTEMPTS: u32 = 40;
/// Interval in milliseconds between each visibility poll attempt.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const TUN_VISIBILITY_POLL_INTERVAL_MS: u64 = 50;

#[derive(Default)]
struct TunInitializationConfig {
    fd: Option<u32>,
    tun_name: Option<String>,
    #[cfg(target_os = "windows")]
    guid: Option<u128>,
}

pub struct TunRunner {
    #[cfg(target_os = "linux")]
    address_sets: RouteAddressSets,
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    cancellation_token: CancellationToken,
    pipeline_task: Mutex<Option<JoinHandle<Result<(), Error>>>>,
}

impl TunRunner {
    pub fn new(
        cfg: TunConfig,
        dispatcher: Arc<Dispatcher>,
        resolver: ThreadSafeDNSResolver,
        cancellation_token: Option<CancellationToken>,
        #[cfg(target_os = "linux")] rule_providers: &HashMap<String, ThreadSafeRuleProvider>,
    ) -> Result<TunRunner, Error> {
        Ok(Self {
            #[cfg(target_os = "linux")]
            address_sets: RouteAddressSets::new(&cfg, rule_providers)?,
            cfg,
            dispatcher,
            resolver,
            cancellation_token: cancellation_token.unwrap_or_default(),
            pipeline_task: Mutex::new(None),
        })
    }

    async fn new_internal(
        cfg: &TunConfig,
    ) -> Result<(AsyncDevice, bool), Error> {
        #[cfg(target_os = "android")]
        super::mobile::validate(cfg)?;
        let mut tun_init_config = TunInitializationConfig::default();
        let device = parse_device_id(&cfg.device_id)?;
        let manage_network = matches!(device, TunDevice::Interface { .. });
        match device {
            TunDevice::FileDescriptor(fd) => tun_init_config.fd = Some(fd),
            TunDevice::Interface { name, #[cfg(windows)] guid } => {
                if cfg!(target_os = "macos") && !name.starts_with("utun") {
                    warn!(
                        "tun device id '{}' is not supported on macOS (must start with 'utun'), falling back to 'utun1989'",
                        name
                    );
                    tun_init_config.tun_name = Some("utun1989".to_string());
                } else {
                    tun_init_config.tun_name = Some(name);
                }
                #[cfg(windows)]
                { tun_init_config.guid = guid; }
            }
        };

        let tun = if let Some(fd) = tun_init_config.fd {
            #[cfg(target_os = "android")]
            let fd = {
                use std::os::fd::IntoRawFd;
                use crate::android::take_registered_tun_fd;
                match take_registered_tun_fd(fd as i32)? {
                    Some(owned) => owned.into_raw_fd() as u32,
                    None => fd,
                }
            };
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
                #[cfg(not(any(target_os = "macos", target_os = "android")))]
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

                // GSO frames carry segmentation metadata and may exceed the
                // link MTU; enabling offload must not change the configured MTU.
                let mtu = cfg.mtu
                    .unwrap_or(if cfg!(windows) { 65535u16 } else { 1500u16 });
                if gso_enabled {
                    info!("TUN GSO enabled (MTU: {})", mtu);
                }

                tun_builder = tun_builder.name(&tun_name).mtu(mtu);

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
                #[cfg(not(any(target_os = "macos", target_os = "android")))]
                maybe_add_routes(cfg, &tun_name).inspect_err(|_| {
                    if let Err(error) = routes::maybe_routes_clean_up(cfg) {
                        warn!("failed to roll back TUN routes: {error}");
                    }
                })?;

                dev
            }
            #[cfg(any(target_os = "ios", target_os = "android"))]
            {
                return Err(Error::InvalidConfig(
                    "only fd is supported on mobile platforms".to_string(),
                ));
            }
        };

        Ok((tun, manage_network))
    }

    pub fn shutdown(&self) {
        info!("shutting down tun runner");
        self.cancellation_token.cancel();
        // The pipeline owns external state and cleans nftables before routes.
        // AsyncService::stop awaits it; this synchronous method only signals.

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
        #[cfg(target_os = "linux")]
        let dns_hijack = super::auto_redirect::dns::hijack_config(&cfg, dns_hijack);
        let cancellation_token = self.cancellation_token.clone();

        let (tun, manage_network) = TunRunner::new_internal(&cfg)
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
        let rollback_routes = || {
            #[cfg(not(any(target_os = "macos", target_os = "android")))]
            if manage_network {
                if let Err(error) = routes::maybe_routes_clean_up(&cfg) {
                    warn!("failed to roll back TUN routes after initialization failure: {error}");
                }
            }
        };
        let listeners = TcpListeners::bind(&cfg).await.inspect_err(|_| rollback_routes())?;
        #[cfg(target_os = "linux")]
        let redirect_listener = redirect_tcp::bind(&cfg)
            .inspect_err(|_| rollback_routes())?;

        #[cfg(target_os = "android")]
        let frame_size = usize::from(super::mobile::validate(&cfg).inspect_err(|_| rollback_routes())?);
        #[cfg(not(target_os = "android"))]
        let frame_size = usize::from(tun.mtu().inspect_err(|_| rollback_routes())?);

        let (tcp_driver, tcp_listener) = if cfg.enable_tcp && !listeners.system {
            let (driver, listener) = TcpDriver::new(frame_size, 32)
                .inspect_err(|_| rollback_routes())?;
            #[cfg(target_os = "linux")]
            let driver = {
                let mut driver = driver;
                if tun.tcp_gso() { driver.enable_tcp_gso(); }
                driver
            };
            (Some(driver), Some(listener))
        } else { (None, None) };
        let (stack, _, udp_socket) = NetStack::new_with_mtu(false, cfg.enable_tcp, frame_size)
            .inspect_err(|_| rollback_routes())?;

        #[cfg(target_os = "linux")]
        let udp_socket = {
            let mut socket = udp_socket;
            if !listeners.system && tun.udp_gso() { socket.enable_output_offload(); }
            socket
        };

        // Externally supplied descriptors belong to their platform host; it
        // remains responsible for routes and DNS (e.g. NetworkExtension).
        let tun = Arc::new(tun);
        #[cfg(target_os = "macos")]
        let platform = if manage_network || cfg.auto_detect_interface {
            Some(super::macos::start(cfg.clone(), tun.clone(),
                manage_network, ctx, &cancellation_token).await?)
        } else { None };

        let (device_reader, device_writer) = device_io::split(
            &tun, frame_size, manage_network,
        ).inspect_err(|_| rollback_routes())?;
        #[cfg(target_os = "linux")]
        let device_writer = {
            let mut writer = device_writer;
            if !listeners.system && tun.tcp_gso() { writer.enable_native_offload(); }
            writer
        };
        #[cfg(target_os = "linux")]
        let address_sets = self.address_sets.clone();
        #[cfg(target_os = "linux")]
        let address_set_updates = address_sets.subscribe();
        #[cfg(target_os = "linux")]
        let auto_redirect = if cfg.auto_redirect {
            let name = tun.name().inspect_err(|_| rollback_routes())?;
            let port = redirect_listener.as_ref()
                .map(|listener| listener.local_addr().map(|addr| addr.port()))
                .transpose().inspect_err(|_| rollback_routes())?;
            let cfg = cfg.clone();
            let sets = address_sets.clone();
            tokio::task::spawn_blocking(move || {
                AutoRedirect::start(&sets.snapshot(&cfg), &name, port)
                    .map(|guard| guard.map(Arc::new))
            }).await.map_err(|error| Error::Operation(format!(
                "TUN auto-redirect initialization task failed: {error}",
            ))).inspect_err(|_| rollback_routes())?
                .inspect_err(|_| rollback_routes())?
        } else { None };
        let (stack_sink, stack_stream) = stack.split();

        #[cfg(not(any(target_os = "macos", target_os = "android")))]
        let auto_detect_cancel = cancellation_token.clone();
        #[cfg(not(any(target_os = "macos", target_os = "android")))]
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
        let task = ctx.spawn_critical_with_token("tun_packet_pipeline", lifecycle_token, async move {
            #[cfg(target_os = "macos")]
            let _platform = platform;
            #[cfg(target_os = "linux")]
            let auto_redirect_guard = auto_redirect.clone();
            let mut pipeline = PacketPipeline::default();
            #[cfg(target_os = "linux")]
            if let Some(guard) = auto_redirect
                && (!cfg.route_address_set.is_empty() || !cfg.route_exclude_address_set.is_empty())
            {
                let cfg = cfg.clone();
                pipeline.spawn("route_address_sets", async move {
                    address_sets.run(cfg, guard, address_set_updates).await
                });
            }
            #[cfg(any(target_os = "linux", target_os = "android", test))]
            let (_tun_tx, tun_rx) = packet_queue::channel();
            #[cfg(not(any(target_os = "linux", target_os = "android", test)))]
            let tun_rx = packet_queue::closed();
            #[cfg(target_os = "linux")]
            let udp_mtu = (!listeners.system && tun.udp_gso()).then_some(frame_size);
            #[cfg(not(target_os = "linux"))]
            let udp_mtu = None;
            let udp_direct = super::datagram::direct_path(udp_mtu);
            #[cfg(any(target_os = "android", target_os = "linux"))]
            let direct_icmp = if cfg.enable_tcp {
                let (client, relay) = icmp::channel(frame_size, _tun_tx.clone(), so_mark);
                pipeline.spawn("icmp", async move {
                    relay.run().await?;
                    Err(Error::Operation("TUN ICMP relay stopped unexpectedly".into()))
                });
                Some(client)
            } else { None };
            #[cfg(any(target_os = "android", target_os = "linux"))]
            let icmp_resolver = resolver.clone();
            #[cfg(any(target_os = "android", target_os = "linux"))]
            let icmp_gateway = (cfg.gateway, cfg.gateway_v6);

            let use_system_stack = listeners.system;
            let v4_nat_info = listeners.ipv4.as_ref().map(|bound| bound.nat);
            let v6_nat_info = listeners.ipv6.as_ref().map(|bound| bound.nat);
            info!("TUN stack initialized (system TCP: {})", use_system_stack);

            let system_nat = Arc::new(super::system_stack::SystemTcpNat::new());

            // tun -> stack -> dispatcher
            let enable_tcp = cfg.enable_tcp;
            let packets = PacketDispatcher {
                enable_tcp, system_tcp: use_system_stack, ipv4: v4_nat_info, ipv6: v6_nat_info,
                nat: system_nat.clone(), direct: udp_direct.clone(), uploads: Default::default(),
            };
            let intercept = move |packet: &[u8]| {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                if let Some(icmp) = &direct_icmp
                    && icmp.intercept(packet, |address| {
                        let local = icmp::is_gateway(address, icmp_gateway.0, icmp_gateway.1);
                        local || icmp_resolver.is_fake_ip(address)
                    }) { return true; }
                #[cfg(not(any(target_os = "android", target_os = "linux")))]
                let _ = packet;
                false
            };
            let device_tun = tun.clone();
            #[cfg(target_os = "linux")]
            let native_tcp = !use_system_stack && device_tun.tcp_gso();
            #[cfg(not(target_os = "linux"))]
            let native_tcp = false;
            pipeline.spawn("device", async move {
                let device = DeviceLoop::new(
                    DeviceIo::new(device_tun, device_reader, device_writer, native_tcp),
                    Protocols { tcp: tcp_driver, sink: stack_sink, stream: stack_stream },
                    packets, tun_rx, intercept,
                );
                device.run().await
            });

            let strict_route = cfg.strict_route;
            let exclude_routes = Arc::new(cfg.route_exclude_address.clone());
            let tcp_context = Arc::new(TcpContext {
                dispatcher: dispatcher.clone(), resolver: resolver.clone(), so_mark,
                dns_hijack: dns_hijack.clone(), strict_route, exclude_routes: exclude_routes.clone(),
            });
            #[cfg(target_os = "linux")]
            if let Some(listener) = redirect_listener {
                let context = tcp_context.clone();
                pipeline.spawn("auto_redirect_tcp", async move {
                    redirect_tcp::run(listener, context).await
                });
            }
            pipeline.spawn("tcp", async move {
                listeners.run(tcp_listener, system_nat.clone(), tcp_context, enable_tcp).await
            });
            let udp_timeout = cfg.udp_timeout;
            pipeline.spawn("udp", async move {
                handle_inbound_datagram(
                    udp_socket,
                    dispatcher.clone(),
                    resolver.clone(),
                    so_mark,
                    dns_hijack,
                    udp_timeout,
                    strict_route,
                    exclude_routes,
                    udp_direct,
                )
                .await;
                Err(Error::Operation("tun stopped unexpectedly 3".to_string()))
            });

            let run_res = pipeline.run(cancellation_token).await;

            if let Err(ref e) = run_res {
                error!("tun runner error: {}", e);
            }
            #[cfg(target_os = "linux")]
            if let Some(guard) = auto_redirect_guard {
                match tokio::task::spawn_blocking(move || guard.close()).await {
                    Ok(Ok(())) => {}
                    // Keep the policy/blackhole rules if nft removal failed.
                    // Removing them while packets are still marked can leak.
                    Ok(Err(error)) => {
                        warn!("failed to remove TUN nftables rules; retaining policy routes: {error}");
                        return Err(error.into());
                    }
                    Err(error) => {
                        warn!("TUN nftables cleanup task failed; retaining policy routes: {error}");
                        return Err(Error::Operation(format!("TUN auto-redirect cleanup task failed: {error}")));
                    }
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "android")))]
            if manage_network {
                if let Err(e) = routes::maybe_routes_clean_up(&cfg) {
                    warn!("error cleaning up routes during tun runner shutdown: {}", e);
                }
            }
            // Keep the device alive until children stop and routes are cleaned up.
            drop(tun);
            info!("tun runner exited");
            run_res
        });
        *self.pipeline_task.lock().await = Some(task);

        Ok(())
    }

    async fn stop(&self) -> Result<(), Error> {
        self.shutdown();
        // Keep the handle in the slot while awaiting it: a cancelled stop
        // future must not orphan cleanup, and concurrent stops must also wait.
        let mut task = self.pipeline_task.lock().await;
        let result = if let Some(handle) = task.as_mut() {
            handle.await.unwrap_or_else(|error| Err(Error::Operation(format!(
                "TUN pipeline shutdown task failed: {error}",
            ))))
        } else { Ok(()) };
        *task = None;
        result
    }
}

#[cfg(all(test, target_os = "linux"))]
mod route_rollback_tests {
    use std::process::Command;
    use super::*;

    fn ip(args: &[&str]) -> String {
        let output = Command::new("ip").args(args).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TUN and an isolated network namespace"]
    async fn tun_route_setup_failure_rolls_back_both_modes() {
        ip(&["link", "add", "wan-test", "type", "dummy"]);
        ip(&["link", "set", "wan-test", "up"]);
        ip(&["-6", "route", "add", "default", "dev", "wan-test", "table", "2022"]);
        ip(&["-4", "route", "add", "198.51.100.0/24", "dev", "wan-test", "table", "2022"]);
        // A persistent device keeps kernel routes alive when initialization's
        // descriptor closes, so the test detects missing explicit rollback.
        ip(&["tuntap", "add", "dev", "tun-test", "mode", "tun"]);
        ip(&["addr", "add", "198.18.0.1/30", "dev", "tun-test"]);
        ip(&["-6", "addr", "add", "fd00::1/64", "dev", "tun-test", "nodad"]);
        ip(&["link", "set", "tun-test", "up"]);
        for auto_redirect in [false, true] {
            let cfg = TunConfig { enable: true, route_all: true, auto_redirect,
                device_id: "tun-test".into(), route_table: 2022,
                gateway: "198.18.0.1/30".parse().unwrap(),
                gateway_v6: Some("fd00::1/64".parse().unwrap()), ..Default::default() };
            let error = TunRunner::new_internal(&cfg).await.err().unwrap().to_string();
            assert!(error.contains("default route") && error.contains("expected"), "{error}");
            let remaining = ip(&["-4", "route", "show", "table", "2022"]);
            assert!(!remaining.contains("default"));
            assert!(remaining.contains("198.51.100.0/24"));
            assert!(ip(&["-6", "route", "show", "table", "2022"]).contains("wan-test"));
            assert!(!ip(&["rule", "show"]).contains("9000:"));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod shutdown_tests {
    use std::{collections::HashMap, process::Command, sync::Arc, time::Duration};
    use tokio::{sync::oneshot, time::timeout};
    use tun_rs::DeviceBuilder;
    use crate::{
        app::{dispatcher::StatisticsManager, dns::MockClashResolver,
            outbound::manager::OutboundManager, router::Router},
        config::def::RunMode,
    };
    use super::*;

    fn rules() -> String {
        let output = Command::new("ip").args(["rule", "show"]).output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TUN and an isolated network namespace"]
    async fn auto_redirect_shutdown_waits_for_nft_before_route_cleanup() {
        let _tun = DeviceBuilder::new().name("tun0").ipv4("198.18.0.1", 24, None)
            .enable(true).offload(false).build_async().unwrap();
        let cfg = TunConfig { enable: true, route_all: true, auto_redirect: true,
            strict_route: true, device_id: "tun0".into(), route_table: 2022,
            ..Default::default() };
        routes::maybe_add_routes(&cfg, "tun0").unwrap();
        let guard = AutoRedirect::start(&cfg, "tun0", None).unwrap().unwrap();
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let router = Arc::new(Router::new(Vec::new(), HashMap::new(), resolver.clone(),
            None, None, None, None, None, String::new()).await.unwrap());
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::new(OutboundManager::new_for_test(HashMap::new())), router,
            resolver.clone(), RunMode::Direct, StatisticsManager::new(), None, None, true,
        ));
        let runner = TunRunner::new(cfg.clone(), dispatcher, resolver, None, &HashMap::new()).unwrap();
        let token = runner.cancellation_token.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            token.cancelled().await;
            started_tx.send(()).unwrap();
            release_rx.await.unwrap();
            tokio::task::spawn_blocking(move || {
                guard.close()?;
                routes::maybe_routes_clean_up(&cfg)
            }).await.unwrap().map_err(Error::Io)
        });
        *runner.pipeline_task.lock().await = Some(task);
        runner.shutdown();
        started_rx.await.unwrap();
        // Hold pipeline drain open: synchronous shutdown must not remove the
        // lookup or strict blackhole while nftables can still mark packets.
        let before = rules();
        assert!(before.contains("0x163/0x167"));
        assert!(before.contains("9001:"));
        // Cancelling a stop future must leave the task handle available so a
        // later caller can still await the same cleanup operation.
        assert!(timeout(Duration::from_millis(50), runner.stop()).await.is_err());
        release_tx.send(()).unwrap();
        timeout(Duration::from_secs(3), runner.stop()).await.unwrap().unwrap();
        let after = rules();
        assert!(!after.contains("9000:") && !after.contains("9001:"));
        runner.stop().await.unwrap();
    }
}
