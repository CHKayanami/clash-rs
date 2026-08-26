#![feature(ip)]
#![feature(duration_millis_float)]

#[cfg(feature = "tun")]
use crate::proxy::tun;
use crate::{
    app::{
        dispatcher::{Dispatcher, StatisticsManager},
        dns::{self, SystemResolver, ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        logging::LogEvent,
        net::init_net_config,
        outbound::manager::OutboundManager,
        profile,
        router::Router,
    },
    common::{
        auth, dashboard,
        geodata::{DEFAULT_GEOSITE_DOWNLOAD_URL, GeoDataLookup},
        http::new_http_client,
        mmdb::{
            self, DEFAULT_ASN_MMDB_DOWNLOAD_URL, DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL,
        },
    },
    config::{
        InternalConfig,
        def::{self, LogLevel},
        internal::proxy::OutboundProxy,
    },
    runner::Runner,
};

use std::{
    io,
    path::PathBuf,
    sync::{Arc, OnceLock},
};
use thiserror::Error;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};

pub mod app;
pub mod config;

mod common;
mod proxy;
mod runner;
mod session;

use crate::common::{geodata, mmdb::MmdbLookup};
pub use config::{
    DNSListen as ClashDNSListen, RuntimeConfig as ClashRuntimeConfig,
    def::{Config as ClashConfigDef, DNS as ClashDNSConfigDef},
};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IpNet(#[from] ipnet::AddrParseError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("profile error: {0}")]
    ProfileError(String),
    #[error("dns error: {0}")]
    DNSError(String),
    #[error(transparent)]
    DNSServerError(#[from] watfaq_dns::DNSError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("operation error: {0}")]
    Operation(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

type ArcRunner = Arc<dyn Runner>;

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
    /// The original config file path, used to support "reload current config"
    /// from the dashboard. Set this when starting from a file; leave `None`
    /// for string/inline configs (e.g. FFI).
    pub config_path: Option<String>,
    pub dns_collect_file: Option<String>,
}

pub enum TokioRuntime {
    MultiThread,
    SingleThread,
}

#[allow(clippy::large_enum_variant)]
pub enum Config {
    Def(ClashConfigDef),
    Internal(InternalConfig),
    File(String),
    Str(String),
}

impl Config {
    pub fn try_parse(self) -> Result<InternalConfig> {
        match self {
            Config::Def(c) => c.try_into(),
            Config::Internal(c) => Ok(c),
            Config::File(file) => {
                TryInto::<def::Config>::try_into(PathBuf::from(file))?.try_into()
            }
            Config::Str(s) => s.parse::<def::Config>()?.try_into(),
        }
    }

    /// Like [`try_parse`] but additionally validates that the YAML source
    /// contains no unknown top-level or `dns`-section fields, returning an
    /// error when any unrecognised key is found.
    ///
    /// Enable this via the `--strict-config` CLI flag.
    pub fn try_parse_strict(self) -> Result<InternalConfig> {
        let yaml = match self {
            Config::File(file) => std::fs::read_to_string(file)?,
            Config::Str(s) => s,
            // Def/Internal are already structured Rust values — no YAML to
            // check for unknown fields.
            other => return other.try_parse(),
        };
        def::check_unknown_fields(&yaml)?.try_into()
    }
}

pub struct GlobalState {
    log_level: LogLevel,
    #[cfg(feature = "tun")]
    tunnel_runner: ArcRunner,
    dns_listener: ArcRunner,
    reload_tx:
        mpsc::Sender<(Config, oneshot::Sender<std::result::Result<(), String>>)>,
    cwd: String,
    /// Path to the config file used at startup. Used by the dashboard "Reload"
    /// button which sends an empty path to mean "reload current config".
    config_path: Option<String>,
}

pub fn start_scaffold(opts: Options) -> Result<()> {
    let Options {
        config,
        cwd,
        rt,
        log_file,
        config_path,
        dns_collect_file,
    } = opts;

    let rt = match rt.unwrap_or(TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };
    let config_path = config_path.or_else(|| {
        if let Config::File(p) = &config {
            Some(p.clone())
        } else {
            None
        }
    });
    let config: InternalConfig = config.try_parse()?;
    let cwd = cwd.unwrap_or_else(|| ".".to_string());
    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    app::logging::setup_logging(
        config.general.log_level,
        log_collector,
        &cwd,
        log_file,
    );

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    {
        let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
        token_guard.push(shutdown_token.clone());
    }
    rt.block_on(async {
        match start(
            config,
            cwd,
            config_path,
            dns_collect_file,
            log_tx,
            shutdown_token,
        )
        .await
        {
            Err(e) => {
                eprintln!("start error: {e}");
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    })
}

/// Start a Clash instance in a background thread with independent lifecycle.
/// Returns the thread handle and a CancellationToken to shut it down.
/// Unlike `start_scaffold`, this does NOT register in the global
/// SHUTDOWN_TOKEN.
pub fn start_scaffold_instance(
    opts: Options,
) -> Result<(
    std::thread::JoinHandle<()>,
    tokio_util::sync::CancellationToken,
)> {
    let Options {
        config,
        cwd,
        rt,
        log_file: _,
        config_path,
        dns_collect_file,
    } = opts;

    let config_path = config_path.or_else(|| {
        if let Config::File(p) = &config {
            Some(p.clone())
        } else {
            None
        }
    });
    let config: InternalConfig = config.try_parse()?;
    let cwd = cwd.unwrap_or_else(|| ".".to_string());
    let rt_kind = rt.unwrap_or(TokioRuntime::MultiThread);

    let token = tokio_util::sync::CancellationToken::new();
    let token_clone = token.clone();

    let handle = std::thread::spawn(move || {
        let rt = match rt_kind {
            TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread(),
            TokioRuntime::SingleThread => {
                tokio::runtime::Builder::new_current_thread()
            }
        }
        .enable_all()
        .build()
        .expect("Failed to build runtime");

        let (log_tx, _) = tokio::sync::broadcast::channel(100);

        if let Err(e) = rt.block_on(start(
            config,
            cwd,
            config_path,
            dns_collect_file,
            log_tx,
            token_clone,
        )) {
            eprintln!("Clash instance error: {}", e);
        }
    });

    Ok((handle, token))
}

static SHUTDOWN_TOKEN: std::sync::Mutex<Vec<tokio_util::sync::CancellationToken>> =
    std::sync::Mutex::new(Vec::new());

pub fn shutdown() -> bool {
    let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
    if !token_guard.is_empty() {
        for token in token_guard.drain(..) {
            token.cancel();
        }
        warn!("Shutdown signal sent, waiting for shutdown to complete...");
        true
    } else {
        warn!("Shutdown token not initialized, cannot shutdown");
        false
    }
}

static CRYPTO_PROVIDER_LOCK: OnceLock<()> = OnceLock::new();

pub fn setup_default_crypto_provider() {
    CRYPTO_PROVIDER_LOCK.get_or_init(|| {
        #[cfg(feature = "aws-lc-rs")]
        {
            _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        {
            _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

pub async fn start(
    config: InternalConfig,
    cwd: String,
    config_path: Option<String>,
    dns_collect_file: Option<String>,
    log_tx: broadcast::Sender<LogEvent>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<()> {
    setup_default_crypto_provider();

    let os = match env!("CLASH_TARGET_OS") {
        "macos" => "darwin",
        other => other,
    };
    let arch = match env!("CLASH_TARGET_ARCH") {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" | "i686" => "386",
        other => other,
    };
    let target = env!("CLASH_TARGET_TRIPLE");
    let author = env!("CLASH_FORK_AUTHOR");
    let features = option_env!("CLASH_FEATURES").unwrap_or("");
    let features_str = if features.is_empty() {
        "none"
    } else {
        features
    };
    if target.is_empty() {
        info!(
            "starting clash-rs {} (fork by {}) {}/{} features: {}",
            env!("CLASH_VERSION_OVERRIDE"),
            author,
            os,
            arch,
            features_str
        );
    } else {
        info!(
            "starting clash-rs {} (fork by {}) {}/{} ({}) features: {}",
            env!("CLASH_VERSION_OVERRIDE"),
            author,
            os,
            arch,
            target,
            features_str
        );
    }

    let cwd_path = PathBuf::from(cwd.clone());

    // things we need to clone before consuming config
    let controller_cfg = config.general.controller.clone();
    let log_level = config.general.log_level;

    let mut components =
        create_components(cwd_path.clone(), config, None, dns_collect_file.clone())
            .await?;

    let (reload_tx, mut reload_rx) = mpsc::channel(1);

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level,
        #[cfg(feature = "tun")]
        tunnel_runner: components.tun_runner.clone(),
        dns_listener: components.dns_listener.clone(),
        reload_tx,
        cwd: cwd.clone(),
        config_path,
    }));

    let mut api_listener: ArcRunner = Arc::new(app::api::ApiRunner::new(
        controller_cfg.clone(),
        log_tx.clone(),
        components.inbound_manager.clone(),
        components.dispatcher.clone(),
        global_state.clone(),
        components.dns_resolver.clone(),
        components.outbound_manager.clone(),
        components.statistics_manager.clone(),
        components.cache_store.clone(),
        components.router.clone(),
        cwd.clone(),
        Some(shutdown_token.child_token()),
        components.dns_listen.clone(),
        components.dns_enabled,
    ));

    // api_listener is not part of components because it requires components to be
    // initialized before it can be initialized. start it manually.
    api_listener.run_async();

    {
        let mut g = global_state.lock().await;
        #[cfg(feature = "tun")]
        {
            g.tunnel_runner = components.tun_runner.clone();
        }
        g.dns_listener = components.dns_listener.clone();
    }

    components.start_all();

    let cwd_clone = cwd.clone();
    let reload_token = shutdown_token.child_token();
    let shutdown_token_clone = shutdown_token.clone();
    let reload_handle = tokio::spawn(async move {
        // Listen for config reload signal and reload config
        loop {
            tokio::select! {
                res = reload_rx.recv() => {
                    match res {
                        Some((config, done)) => {
                            info!("reloading config");
                            let config = match config.try_parse() {
                                Ok(c) => c,
                                Err(e) => {
                                    error!("failed to reload config: {}", e);
                                    let _ = done.send(Err(e.to_string()));
                                    continue;
                                }
                            };

                            let controller_cfg = config.general.controller.clone();

                            let new_components = match create_components(PathBuf::from(&cwd_clone), config, Some(&components), dns_collect_file.clone()).await {
                                Ok(nc) => nc,
                                Err(e) => {
                                    error!("failed to reload config: {}", e);
                                    let _ = done.send(Err(e.to_string()));
                                    continue;
                                }
                            };

                            let _ = done.send(Ok(()));

                            components.stop_all();
                            new_components.start_all();

                            // TODO: every reload is causing the API server to restart, we should
                            // make the API server reloadable instead of restarting it.
                            // maybe adding APIs to replace components
                            // and only recreate the listeners when necessary (e.g. when the listen
                            // address or port is changed)
                            let new_api_listener: ArcRunner = Arc::new(app::api::ApiRunner::new(
                                controller_cfg,
                                log_tx.clone(),
                                new_components.inbound_manager.clone(),
                                new_components.dispatcher.clone(),
                                global_state.clone(),
                                new_components.dns_resolver.clone(),
                                new_components.outbound_manager.clone(),
                                new_components.statistics_manager.clone(),
                                new_components.cache_store.clone(),
                                new_components.router.clone(),
                                cwd_clone.clone(),
                                Some(reload_token.child_token()),
                                new_components.dns_listen.clone(),
                                new_components.dns_enabled,
                            ));
                            let mut g = global_state.lock().await;

                            #[cfg(feature = "tun")]
                            {
                                g.tunnel_runner = new_components.tun_runner.clone();
                            }
                            g.dns_listener = new_components.dns_listener.clone();

                            api_listener.shutdown();
                            // Wait for the old API server to fully stop before starting the new
                            // one, to avoid EADDRINUSE on the same port.
                            api_listener.join().await.ok();
                            new_api_listener.run_async();
                            api_listener = new_api_listener;
                            components = new_components;
                        }
                        None => {
                            break;
                        }
                    }
                }
                _ = shutdown_token_clone.cancelled() => {
                    break;
                }
            }
        }
        components.stop_all();
        api_listener.shutdown();
        api_listener.join().await.ok();
        Ok::<(), Error>(())
    });

    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(Error::Io)?;

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            shutdown_token.cancel();
            result.map_err(Error::Io)?;
        }
        _ = async {
            #[cfg(unix)]
            {
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::info!("received SIGTERM, shutting down gracefully");
            shutdown_token.cancel();
        }
        _ = shutdown_token.cancelled() => {}
    }
    let _ = reload_handle.await;
    Ok(())
}

struct RuntimeComponents {
    cache_store: profile::ThreadSafeCacheFile,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,

    #[cfg(feature = "tun")]
    tun_runner: ArcRunner,
    #[cfg(feature = "ebpf")]
    ebpf_runner: ArcRunner,
    dns_listener: ArcRunner,
    inbound_manager: Arc<InboundManager>,
    dns_listen: DNSListenAddr,
    dns_enabled: bool,

    country_mmdb: Option<MmdbLookup>,
    country_mmdb_path: Option<PathBuf>,
    asn_mmdb: Option<MmdbLookup>,
    asn_mmdb_path: Option<PathBuf>,
    geodata: Option<GeoDataLookup>,
    geosite_path: Option<PathBuf>,
}

impl RuntimeComponents {
    fn start_all(&self) {
        #[cfg(feature = "tun")]
        self.tun_runner.run_async();
        #[cfg(feature = "ebpf")]
        self.ebpf_runner.run_async();
        self.dns_listener.run_async();
        self.inbound_manager.run_async();
    }

    fn stop_all(&self) {
        #[cfg(feature = "tun")]
        self.tun_runner.shutdown();
        #[cfg(feature = "ebpf")]
        self.ebpf_runner.shutdown();
        self.dns_listener.shutdown();
        self.inbound_manager.shutdown();
    }
}

async fn create_components(
    cwd: PathBuf,
    config: InternalConfig,
    old_components: Option<&RuntimeComponents>,
    dns_collect_file: Option<String>,
) -> Result<RuntimeComponents> {
    if config.tun.enable {
        let explicit_iface = config
            .general
            .interface
            .as_ref()
            .and_then(|i| i.clone().into_iface_name());
        let need_iface = explicit_iface.is_some()
            || config.tun.route_all
            || config.tun.auto_detect_interface;
        if need_iface {
            debug!(
                "tun enabled with auto-route or explicit interface, initializing default outbound interface"
            );
            init_net_config(explicit_iface.as_deref(), config.tun.so_mark).await;
        } else {
            debug!(
                "tun enabled without auto-route/auto-detect, skipping default outbound interface binding"
            );
            *crate::app::net::TUN_SOMARK.write().await = config.tun.so_mark;
        }
    }

    #[cfg(feature = "ebpf")]
    if let Some(ebpf_cfg) = &config.ebpf
        && ebpf_cfg.enable
    {
        debug!("ebpf enabled, setting default outbound SO_MARK to DAE_BYPASS_MARK");
        *crate::app::net::TUN_SOMARK.write().await = Some(clash_ebpf::DAE_BYPASS_MARK);
    }

    let cancellation_token = tokio_util::sync::CancellationToken::new();
    let cwd_str = cwd.to_string_lossy().to_string();

    debug!("initializing cache store");
    let cache_store = profile::ThreadSafeCacheFile::new(
        &cwd.join("cache.db").to_string_lossy(),
        config.profile.store_selected,
    );

    let system_resolver = Arc::new(
        SystemResolver::new(config.dns.ipv6)
            .map_err(|x| Error::DNSError(x.to_string()))?,
    );

    debug!("initializing bootstrap outbounds");

    let plain_outbounds = OutboundManager::load_plain_outbounds(
        config
            .proxies
            .into_values()
            .filter_map(|x| match x {
                OutboundProxy::ProxyServer(s) => Some(s),
                _ => None,
            })
            .collect(),
    );

    let outbound_registry = Arc::new(parking_lot::RwLock::new(
        plain_outbounds
            .iter()
            .map(|x| (x.name().to_string(), x.clone()))
            .collect(),
    ));

    let client =
        new_http_client(system_resolver.clone(), Some(outbound_registry.clone()))
            .map_err(|x| Error::DNSError(x.to_string()))?;

    if let (Some(ui_path), Some(download_url)) = (
        &config.general.controller.external_ui,
        &config.general.controller.external_ui_download_url,
    ) {
        let dir = cwd.join(ui_path);
        let url = download_url.clone();
        dashboard::download_dashboard(dir, &url, &client)
            .await
            .unwrap_or_else(|e| warn!("dashboard download failed: {}", e));
    }

    debug!("initializing dns resolver");
    let dns_listen = config.dns.listen.clone();
    let dns_enable = config.dns.enable;

    let country_mmdb_file = config.general.mmdb;
    let country_mmdb_download_url = config.general.mmdb_download_url;

    let pending_country_mmdb: Option<dns::PendingMmdb> = country_mmdb_file
        .as_ref()
        .map(|_| Arc::new(OnceLock::new()));

    let rule_dispatch: Option<Arc<dns::RuleDispatch>> = if config.dns.respect_rules {
        Some(dns::RuleDispatch::new())
    } else {
        None
    };

    let dns_collector = if let Some(file_str) = &dns_collect_file {
        let path = PathBuf::from(file_str);
        let resolved_path = if path.is_relative() {
            cwd.join(path)
        } else {
            path
        };
        if resolved_path.exists() {
            match dns::DnsCollector::new(resolved_path) {
                Ok(collector) => Some(collector),
                Err(e) => {
                    warn!("failed to initialize DNS collector: {e}");
                    None
                }
            }
        } else {
            debug!(
                "DNS collect file {:?} does not exist, DNS statistics collection disabled",
                resolved_path
            );
            None
        }
    } else {
        None
    };

    let dns_resolver = dns::new_resolver(
        config.dns,
        Some(cache_store.clone()),
        pending_country_mmdb.clone(),
        outbound_registry.clone(),
        rule_dispatch.clone(),
        dns_collector,
    )
    .await;

    debug!("initializing outbound manager");
    let outbound_manager = Arc::new(
        OutboundManager::new(
            plain_outbounds,
            config
                .proxy_groups
                .into_values()
                .filter_map(|x| match x {
                    OutboundProxy::ProxyGroup(g) => Some(g),
                    _ => None,
                })
                .collect(),
            config.proxy_providers,
            config.proxy_names,
            dns_resolver.clone(),
            Some(system_resolver.clone()),
            cache_store.clone(),
            cwd_str.clone(),
            config.general.routing_mask,
            outbound_registry.clone(),
        )
        .await?,
    );

    if let Some(rd) = &rule_dispatch
        && rd.outbound_manager.set(outbound_manager.clone()).is_err()
    {
        warn!(
            "RuleDispatch outbound_manager OnceLock was already set — this is \
             unexpected and indicates a double-initialization bug"
        );
    }

    debug!("initializing mmdb");
    let country_mmdb_path = country_mmdb_file.as_ref().map(|f| cwd.join(f));
    let country_mmdb = if let Some(ref mmdb_path) = country_mmdb_path {
        let mmdb = if let Some(old) = old_components
            && old.country_mmdb_path.as_ref() == Some(mmdb_path)
            && let Some(ref old_mmdb) = old.country_mmdb
        {
            debug!("reusing country mmdb from {:?}", mmdb_path);
            old_mmdb.clone()
        } else {
            Arc::new(
                mmdb::Mmdb::new(
                    mmdb_path.clone(),
                    country_mmdb_download_url
                        .unwrap_or(DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string()),
                    client.clone(),
                )
                .await?,
            ) as MmdbLookup
        };
        if let Some(pending) = &pending_country_mmdb
            && pending.set(mmdb.clone()).is_err()
        {
            warn!(
                "country MMDB OnceLock was already set — this is unexpected and \
                 indicates a double-initialization bug"
            );
        }
        Some(mmdb)
    } else {
        debug!("country mmdb not set, skipping");
        None
    };

    debug!("initializing geosite");
    let geosite_path = config.general.geosite.as_ref().map(|f| cwd.join(f));
    let geodata = if let Some(ref path) = geosite_path {
        let gd = if let Some(old) = old_components
            && old.geosite_path.as_ref() == Some(path)
            && let Some(ref old_geodata) = old.geodata
        {
            debug!("reusing geosite from {:?}", path);
            old_geodata.clone()
        } else {
            Arc::new(
                geodata::GeoData::new(
                    path.clone(),
                    config
                        .general
                        .geosite_download_url
                        .unwrap_or(DEFAULT_GEOSITE_DOWNLOAD_URL.to_string()),
                    client.clone(),
                )
                .await?,
            ) as GeoDataLookup
        };
        Some(gd)
    } else {
        debug!("geosite not set, skipping");
        None
    };

    debug!("initializing country asn mmdb");
    let asn_mmdb_path = config.general.asn_mmdb.as_ref().map(|f| cwd.join(f));
    let asn_mmdb = if let Some(ref path) = asn_mmdb_path {
        let mmdb = if let Some(old) = old_components
            && old.asn_mmdb_path.as_ref() == Some(path)
            && let Some(ref old_asn_mmdb) = old.asn_mmdb
        {
            debug!("reusing asn mmdb from {:?}", path);
            old_asn_mmdb.clone()
        } else {
            Arc::new(
                mmdb::Mmdb::new(
                    path.clone(),
                    config
                        .general
                        .asn_mmdb_download_url
                        .unwrap_or(DEFAULT_ASN_MMDB_DOWNLOAD_URL.to_string()),
                    client.clone(),
                )
                .await?,
            ) as MmdbLookup
        };
        Some(mmdb)
    } else {
        debug!("ASN mmdb not found and not configured for download, skipping");
        None
    };

    debug!("initializing router");
    let router = Arc::new(
        Router::new(
            config.rules,
            config.rule_providers,
            dns_resolver.clone(),
            Some(system_resolver.clone()),
            Some(outbound_registry.clone()),
            country_mmdb.clone(),
            asn_mmdb.clone(),
            geodata.clone(),
            cwd_str.clone(),
        )
        .await,
    );

    if let Some(rd) = &rule_dispatch
        && rd.router.set(router.clone()).is_err()
    {
        warn!(
            "RuleDispatch router OnceLock was already set — this is unexpected and \
             indicates a double-initialization bug"
        );
    }

    dns_resolver.after_router_inited(router.clone()).await;

    let statistics_manager = StatisticsManager::new();

    let sniffer = config
        .sniffer
        .map(|c| Arc::new(crate::app::sniffer::Sniffer::new(c)));

    debug!("initializing dispatcher");
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
        statistics_manager.clone(),
        config.experimental.and_then(|e| e.tcp_buffer_size),
        sniffer,
    ));

    debug!("initializing authenticator");
    let authenticator = Arc::new(auth::PlainAuthenticator::new(config.users));

    debug!("initializing inbound manager");
    let inbound_manager = Arc::new(
        InboundManager::new(
            dispatcher.clone(),
            authenticator,
            config.listeners,
            Some(cancellation_token.child_token()),
        )
        .await,
    );
    if !config.inbound_providers.is_empty() {
        debug!("loading inbound providers");
        inbound_manager
            .load_inbound_providers(
                cwd_str.clone(),
                config.inbound_providers,
                dns_resolver.clone(),
            )
            .await;
    }

    #[cfg(feature = "tun")]
    debug!("initializing tun runner");
    #[cfg(feature = "tun")]
    let tun_runner: ArcRunner = Arc::new(tun::TunRunner::new(
        config.tun,
        dispatcher.clone(),
        dns_resolver.clone(),
        Some(cancellation_token.child_token()),
    )?);

    #[cfg(feature = "ebpf")]
    debug!("initializing ebpf runner");
    #[cfg(feature = "ebpf")]
    let ebpf_runner: ArcRunner = Arc::new(proxy::ebpf::EbpfRunner::new(
        config.ebpf.unwrap_or_default(),
        dispatcher.clone(),
        dns_resolver.clone(),
        Some(cancellation_token.child_token()),
    ));

    debug!("initializing dns listener");
    let dns_listener: ArcRunner = Arc::new(dns::DnsRunner::new(
        dns_enable,
        dns_listen.clone(),
        dns_resolver.clone(),
        &cwd,
        Some(cancellation_token.child_token()),
    ));

    info!("all components initialized");
    Ok(RuntimeComponents {
        cache_store,
        dns_resolver,
        outbound_manager,
        router,
        dispatcher,
        statistics_manager,
        inbound_manager,
        #[cfg(feature = "tun")]
        tun_runner,
        #[cfg(feature = "ebpf")]
        ebpf_runner,
        dns_listener,
        dns_listen,
        dns_enabled: dns_enable,
        country_mmdb,
        country_mmdb_path,
        asn_mmdb,
        asn_mmdb_path,
        geodata,
        geosite_path,
    })
}

#[cfg(test)]
mod tests {
    use crate::{Config, Options, shutdown, start_scaffold};
    use std::{sync::Once, thread, time::Duration};

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            env_logger::init();
            crate::setup_default_crypto_provider();
        });
    }

    #[test]
    fn start_and_stop() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "tests/data/Country.mmdb"
        proxies:
          - {name: DIRECT_alias, type: direct}
          - {name: REJECT_alias, type: reject}
        "#;

        let handle = thread::spawn(|| {
            start_scaffold(Options {
                config: Config::Str(conf.to_string()),
                cwd: None,
                rt: None,
                log_file: None,
                config_path: None,
                dns_collect_file: None,
            })
            .unwrap()
        });

        thread::spawn(|| {
            thread::sleep(Duration::from_secs(3));
            assert!(shutdown());
        });

        handle.join().unwrap();
    }
}
