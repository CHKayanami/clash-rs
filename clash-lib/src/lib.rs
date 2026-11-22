#![recursion_limit = "256"]
#![cfg_attr(not(target_os = "macos"), feature(ip))]
#![feature(duration_millis_float)]

use arc_swap::ArcSwap;

#[cfg(feature = "tun")]
use crate::proxy::tun;
use crate::{
    app::{
        api::{ApiRunner, RestartController, RuntimeContext},
        dispatcher::{Dispatcher, StatisticsManager},
        dns::{self, SystemResolver, ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        logging::LogEvent,
        net::apply_network_config,
        outbound::manager::OutboundManager,
        profile,
        router::Router,
        sniffer::Sniffer,
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
        internal::{listener::InboundProviderDef, proxy::OutboundProxy},
    },
    runner::{ArcService, AsyncService, ServiceContext},
};

use std::{
    collections::HashMap,
    future::{Future, pending},
    io,
    path::PathBuf,
    sync::{Arc, OnceLock},
};
use thiserror::Error;
#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub mod app;
#[cfg(any(target_os = "android", all(test, unix)))]
pub mod android;
pub mod config;

mod common;
mod proxy;
#[cfg(unix)]
mod restart_signal;
mod runner;
mod session;

#[cfg(unix)]
pub use restart_signal::commit_process_restart;

#[cfg(feature = "allocation-tests")]
#[path = "proxy/dispatch_measurement.rs"]
pub mod dispatch_measurement;

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
    DNSServerError(#[from] clash_dns::DNSError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("operation error: {0}")]
    Operation(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

type ArcRunner = ArcService;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunExit {
    Shutdown,
    Restart,
}

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
    /// Allow `POST /restart` to trigger a graceful shutdown returning
    /// [`RunExit::Restart`]. Keep `false` in embedded / FFI hosts.
    pub enable_restart: bool,
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
                let config = TryInto::<def::Config>::try_into(PathBuf::from(&file))?;
                config.try_into().map_err(|e| {
                    Error::InvalidConfig(format!("config file '{file}': {e}"))
                })
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
        let (yaml, source) = match self {
            Config::File(file) => (
                std::fs::read_to_string(&file).map_err(|e| {
                    Error::InvalidConfig(format!("could not read config file '{file}': {e}"))
                })?,
                Some(file),
            ),
            Config::Str(s) => (s, None),
            // Def/Internal are already structured Rust values — no YAML to
            // check for unknown fields.
            other => return other.try_parse(),
        };
        let config = def::check_unknown_fields(&yaml).map_err(|e| match source.as_deref() {
            Some(file) => Error::InvalidConfig(format!("config file '{file}': {e}")),
            None => e,
        })?;
        config.try_into().map_err(|e| match source {
            Some(file) => Error::InvalidConfig(format!("config file '{file}': {e}")),
            None => e,
        })
    }
}

pub struct GlobalState {
    log_level: LogLevel,
}

pub fn start_scaffold(opts: Options) -> Result<RunExit> {
    let Options {
        config,
        cwd,
        rt,
        log_file,
        enable_restart,
    } = opts;

    let rt = match rt.unwrap_or(TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };
    let config: InternalConfig = config.try_parse()?;
    let cwd = cwd.unwrap_or_else(|| ".".to_string());
    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    let _logging_guard = app::logging::setup_logging(
        config.general.log_level,
        log_collector,
        &cwd,
        log_file,
    )?;

    let shutdown_token = CancellationToken::new();
    {
        let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
        token_guard.retain(|t| !t.is_cancelled());
        token_guard.push(shutdown_token.clone());
    }
    let result = rt.block_on(async {
        match start(
            config,
            cwd,
            enable_restart,
            log_tx,
            shutdown_token.clone(),
        )
        .await
        {
            Err(e) => {
                eprintln!("start error: {e}");
                Err(e)
            }
            Ok(exit) => Ok(exit),
        }
    });
    shutdown_token.cancel();
    {
        let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
        token_guard.retain(|t| !t.is_cancelled());
    }
    result
}

/// Start a Clash instance in a background thread with independent lifecycle.
/// Returns the thread handle and a CancellationToken to shut it down.
/// Unlike `start_scaffold`, this does NOT register in the global
/// SHUTDOWN_TOKEN.
pub fn start_scaffold_instance(
    opts: Options,
) -> Result<(std::thread::JoinHandle<Result<RunExit>>, CancellationToken)> {
    let Options {
        config,
        cwd,
        rt,
        log_file: _,
        enable_restart,
    } = opts;

    let config: InternalConfig = config.try_parse()?;
    let cwd = cwd.unwrap_or_else(|| ".".to_string());
    let rt_kind = rt.unwrap_or(TokioRuntime::MultiThread);

    let token = CancellationToken::new();
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

        let (log_tx, _) = broadcast::channel(100);

        let result = rt.block_on(start(
            config,
            cwd,
            enable_restart,
            log_tx,
            token_clone,
        ));
        if let Err(e) = &result {
            eprintln!("Clash instance error: {}", e);
        }
        result
    });

    Ok((handle, token))
}

static SHUTDOWN_TOKEN: std::sync::Mutex<Vec<CancellationToken>> =
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

async fn wait_restart(rx: Option<oneshot::Receiver<()>>) {
    match rx {
        Some(rx) => match rx.await {
            Ok(()) => {}
            Err(_) => pending().await,
        },
        None => pending().await,
    }
}

async fn wait_shutdown_signal(
    shutdown_token: &CancellationToken,
    #[cfg(unix)] sigterm: &mut Signal,
    #[cfg(unix)] sigint: &mut Signal,
) -> Result<()> {
    #[cfg(unix)]
    {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down gracefully");
            }
            _ = sigint.recv() => {
                info!("received SIGINT, shutting down gracefully");
            }
            _ = shutdown_token.cancelled() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(Error::Io)?;
            }
            _ = shutdown_token.cancelled() => {}
        }
    }
    Ok(())
}

async fn finalize_exit<F, S>(
    mut exit_reason: RunExit,
    stop: F,
    shutdown_signal: S,
) -> Result<RunExit>
where
    F: Future<Output = ()>,
    S: Future<Output = Result<()>>,
{
    if exit_reason == RunExit::Restart {
        tokio::pin!(stop);
        tokio::select! {
            biased;
            result = shutdown_signal => {
                info!(
                    "received shutdown signal during restart cleanup, cancelling restart"
                );
                exit_reason = RunExit::Shutdown;
                stop.await;
                result?;
            }
            _ = &mut stop => {}
        }
    } else {
        stop.await;
    }
    Ok(exit_reason)
}

pub async fn start(
    config: InternalConfig,
    cwd: String,
    enable_restart: bool,
    log_tx: broadcast::Sender<LogEvent>,
    shutdown_token: CancellationToken,
) -> Result<RunExit> {
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
    let (fatal_tx, mut fatal_rx) = mpsc::channel(16);

    // The mobile host may revoke the VPN while initial providers are loading.
    // Cancelling here drops pending initialization instead of waiting for every
    // remote resource before the shutdown loop becomes reachable.
    let components = tokio::select! {
        biased;
        _ = shutdown_token.cancelled() => return Ok(RunExit::Shutdown),
        result = create_components(
            cwd_path,
            config,
            shutdown_token.child_token(),
            Some(fatal_tx),
        ) => result?,
    };

    let (restart_controller, restart_rx) = if enable_restart {
        let (tx, rx) = oneshot::channel();
        (Some(Arc::new(RestartController::new(tx))), Some(rx))
    } else {
        (None, None)
    };

    let global_state = Arc::new(Mutex::new(GlobalState { log_level }));

    let runtime_ctx = RuntimeContext::new(
        components.inbound_manager.clone(),
        components.dispatcher.clone(),
        global_state,
        components.dns_resolver.clone(),
        components.outbound_manager.clone(),
        components.statistics_manager.clone(),
        components.cache_store.clone(),
        components.router.clone(),
        cwd,
        components.dns_listen.clone(),
        components.dns_enabled,
        restart_controller,
    );

    let api_listener = Arc::new(ApiRunner::from_context(
        controller_cfg,
        log_tx,
        runtime_ctx,
    ));

    if let Err(e) = components.start_all().await {
        components.stop_all().await;
        return Err(e);
    }
    if let Err(e) = api_listener.start(&components.service_context).await {
        components.stop_all().await;
        return Err(e);
    }

    #[cfg(unix)]
    let mut sigterm = signal(SignalKind::terminate()).map_err(Error::Io)?;
    #[cfg(unix)]
    let mut sigint = signal(SignalKind::interrupt()).map_err(Error::Io)?;
    #[cfg(unix)]
    if enable_restart && let Err(error) = restart_signal::install() {
        components.stop_all().await;
        return Err(error.into());
    }

    let exit_reason = tokio::select! {
        Some(fatal_err) = fatal_rx.recv() => {
            tracing::error!(
                "FATAL: critical task failed: {fatal_err}. Shutting down gracefully to prevent zombie state"
            );
            RunExit::Shutdown
        }
        () = wait_restart(restart_rx) => {
            info!("received graceful restart request, stopping services");
            RunExit::Restart
        }
        result = wait_shutdown_signal(
            &shutdown_token,
            #[cfg(unix)]
            &mut sigterm,
            #[cfg(unix)]
            &mut sigint,
        ) => {
            result?;
            RunExit::Shutdown
        }
    };

    let exit_reason = finalize_exit(
        exit_reason,
        components.stop_all(),
        wait_shutdown_signal(
            &shutdown_token,
            #[cfg(unix)]
            &mut sigterm,
            #[cfg(unix)]
            &mut sigint,
        ),
    )
    .await?;
    shutdown_token.cancel();
    Ok(exit_reason)
}

struct RuntimeComponents {
    cache_store: profile::ThreadSafeCacheFile,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,

    #[cfg(feature = "tun")]
    tun_runner: ArcService,
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    ebpf_runner: ArcService,
    dns_listener: ArcService,
    inbound_manager: Arc<InboundManager>,
    dns_listen: DNSListenAddr,
    dns_enabled: bool,
    service_context: ServiceContext,
    inbound_providers: HashMap<String, InboundProviderDef>,
    cwd: String,
}

impl RuntimeComponents {
    async fn start_all(&self) -> Result<()> {
        #[cfg(feature = "tun")]
        self.tun_runner.start(&self.service_context).await?;
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        self.ebpf_runner.start(&self.service_context).await?;
        self.dns_listener.start(&self.service_context).await?;
        self.inbound_manager.start(&self.service_context).await?;
        if !self.inbound_providers.is_empty() {
            self.inbound_manager.load_inbound_providers(
                self.cwd.clone(), self.inbound_providers.clone(),
                self.dns_resolver.clone(),
            ).await?;
        }
        Ok(())
    }

    async fn stop_all(&self) {
        self.service_context.cancellation_token().cancel();
        #[cfg(feature = "tun")]
        let _ = self.tun_runner.stop().await;
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        let _ = self.ebpf_runner.stop().await;
        let _ = self.dns_listener.stop().await;
        let _ = self.inbound_manager.stop().await;

        self.service_context.tracker().close();
        self.service_context.tracker().wait().await;
    }
}

async fn create_components(
    cwd: PathBuf,
    config: InternalConfig,
    cancellation_token: CancellationToken,
    fatal_tx: Option<mpsc::Sender<Error>>,
) -> Result<RuntimeComponents> {
    let mut dns_listen_resolved = if config.dns.enable {
        config.dns.listen.clone()
    } else {
        DNSListenAddr::default()
    };
    dns_listen_resolved.resolve_certificate_paths(&cwd);

    let explicit_iface = config.tun.enable.then(|| {
        config.general.interface.as_ref()
            .and_then(|i| i.clone().into_iface_name())
    }).flatten();
    let detect_interface = config.tun.enable
        && (config.tun.route_all || config.tun.auto_detect_interface);
    let so_mark = config.tun.enable.then_some(config.tun.so_mark).flatten();
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    let so_mark = match &config.ebpf {
        Some(ebpf) if ebpf.enable => config.tun.so_mark.or(ebpf.routing_mark)
            .or(Some(clash_ebpf::DAE_BYPASS_MARK)),
        _ => so_mark,
    };
    apply_network_config(
        explicit_iface.as_deref(),
        detect_interface,
        so_mark,
        config.general.tcp_keepalive,
    );

    let cwd_str = cwd.to_string_lossy().to_string();

    debug!("initializing cache store");
    let cache_store = profile::ThreadSafeCacheFile::new(
        &cwd.join("cache.db").to_string_lossy(),
        config.profile.store_selected,
    )
    .map_err(|e| Error::ProfileError(e.to_string()))?;

    let system_resolver = Arc::new(
        SystemResolver::new(config.dns.ipv6)
            .map_err(|x| Error::DNSError(x.to_string()))?,
    );

    debug!("initializing bootstrap outbounds");

    let outbound_registry = Arc::new(ArcSwap::from_pointee(HashMap::new()));

    let plain_outbounds = OutboundManager::load_plain_outbounds(
        config
            .proxies
            .into_values()
            .filter_map(|x| match x {
                OutboundProxy::ProxyServer(s) => Some(s),
                _ => None,
            })
            .collect(),
        &outbound_registry,
    )?;

    outbound_registry.store(Arc::new(
        plain_outbounds.iter().map(|x| (x.name().to_string(), x.clone())).collect(),
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

    let dns_resolver = dns::new_resolver(
        config.dns,
        Some(cache_store.clone()),
        pending_country_mmdb.clone(),
        outbound_registry.clone(),
        rule_dispatch.clone(),
    )
    .await?;

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
        && rd.outbound_manager.set(Arc::downgrade(&outbound_manager)).is_err()
    {
        warn!(
            "RuleDispatch outbound_manager OnceLock was already set — this is \
             unexpected and indicates a double-initialization bug"
        );
    }

    debug!("initializing mmdb");
    let country_mmdb_path = country_mmdb_file.as_ref().map(|f| cwd.join(f));
    let country_mmdb = if let Some(mmdb_path) = country_mmdb_path {
        let mmdb = Arc::new(
            mmdb::Mmdb::new(
                mmdb_path,
                country_mmdb_download_url
                    .unwrap_or(DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as MmdbLookup;
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
    let geodata = if let Some(path) = geosite_path {
        let gd = Arc::new(
            geodata::GeoData::new(
                path,
                config
                    .general
                    .geosite_download_url
                    .unwrap_or(DEFAULT_GEOSITE_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as GeoDataLookup;
        Some(gd)
    } else {
        debug!("geosite not set, skipping");
        None
    };

    debug!("initializing country asn mmdb");
    let asn_mmdb_path = config.general.asn_mmdb.as_ref().map(|f| cwd.join(f));
    let asn_mmdb = if let Some(path) = asn_mmdb_path {
        let mmdb = Arc::new(
            mmdb::Mmdb::new(
                path,
                config
                    .general
                    .asn_mmdb_download_url
                    .unwrap_or(DEFAULT_ASN_MMDB_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as MmdbLookup;
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
            country_mmdb,
            asn_mmdb,
            geodata,
            cwd_str.clone(),
        )
        .await?,
    );

    if let Some(rd) = &rule_dispatch
        && rd.router.set(Arc::downgrade(&router)).is_err()
    {
        warn!(
            "RuleDispatch router OnceLock was already set — this is unexpected and \
             indicates a double-initialization bug"
        );
    }

    dns_resolver.after_router_inited(router.clone()).await;

    let statistics_manager = StatisticsManager::new();

    let sniffer = config.sniffer.map(|c| Arc::new(Sniffer::new(c)));

    debug!("initializing dispatcher");
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
        statistics_manager.clone(),
        config.experimental.and_then(|e| e.tcp_buffer_size),
        sniffer,
        config.general.quic,
    ));

    debug!("initializing authenticator");
    let authenticator = Arc::new(auth::PlainAuthenticator::new(config.users));

    debug!("initializing inbound manager");
    let inbound_manager = Arc::new(
        InboundManager::new(
            dispatcher.clone(),
            authenticator,
            config.listeners,
        )
        .await,
    );
    #[cfg(feature = "tun")]
    debug!("initializing tun runner");
    #[cfg(feature = "tun")]
    let tun_runner: ArcRunner = Arc::new(tun::TunRunner::new(
        config.tun,
        dispatcher.clone(),
        dns_resolver.clone(),
        #[cfg(target_os = "linux")]
        router.get_rule_providers(),
    )?);

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    debug!("initializing ebpf runner");
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    let ebpf_runner: ArcRunner = Arc::new(proxy::ebpf::EbpfRunner::new(
        config.ebpf.unwrap_or_default(),
        dispatcher.clone(),
        dns_resolver.clone(),
    ));

    debug!("initializing dns listener");
    let dns_listener: ArcRunner = Arc::new(dns::DnsRunner::new(
        dns_enable,
        dns_listen_resolved,
        dns_resolver.clone(),
    ));

    info!("all components initialized");
    let service_context = if let Some(tx) = fatal_tx {
        ServiceContext::with_fatal_tx(cancellation_token, tx)
    } else {
        ServiceContext::new(cancellation_token)
    };
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
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        ebpf_runner,
        dns_listener,
        dns_listen,
        dns_enabled: dns_enable,
        service_context,
        inbound_providers: config.inbound_providers,
        cwd: cwd_str,
    })
}

#[cfg(test)]
mod tests {
    use super::finalize_exit;
    use crate::{Config, Options, RunExit, shutdown, start_scaffold};
    use std::{
        future::pending,
        sync::{
            Arc, Once,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };
    use tokio::sync::Notify;

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            env_logger::init();
            crate::setup_default_crypto_provider();
        });
    }

    #[tokio::test]
    async fn restart_cleanup_cancelled_by_shutdown_signal_finishes_cleanup() {
        let stop_gate = Arc::new(Notify::new());
        let shutdown_gate = Arc::new(Notify::new());
        let stop_finished = Arc::new(AtomicBool::new(false));

        let stop_gate_clone = stop_gate.clone();
        let stop_finished_clone = stop_finished.clone();
        let shutdown_gate_clone = shutdown_gate.clone();

        let task = tokio::spawn(async move {
            finalize_exit(
                RunExit::Restart,
                async move {
                    stop_gate_clone.notified().await;
                    stop_finished_clone.store(true, Ordering::SeqCst);
                },
                async move {
                    shutdown_gate_clone.notified().await;
                    Ok(())
                },
            )
            .await
        });

        tokio::task::yield_now().await;
        shutdown_gate.notify_one();
        tokio::task::yield_now().await;
        assert!(
            !stop_finished.load(Ordering::SeqCst),
            "cleanup should still be awaited before returning"
        );

        stop_gate.notify_one();
        let exit = task.await.unwrap().unwrap();
        assert!(stop_finished.load(Ordering::SeqCst));
        assert_eq!(exit, RunExit::Shutdown);
    }

    #[tokio::test]
    async fn restart_cleanup_without_shutdown_signal_returns_restart() {
        let stop_finished = Arc::new(AtomicBool::new(false));
        let stop_finished_clone = stop_finished.clone();

        let exit = finalize_exit(
            RunExit::Restart,
            async move {
                stop_finished_clone.store(true, Ordering::SeqCst);
            },
            pending(),
        )
        .await
        .unwrap();

        assert!(stop_finished.load(Ordering::SeqCst));
        assert_eq!(exit, RunExit::Restart);
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
                enable_restart: false,
            })
            .unwrap()
        });

        thread::spawn(|| {
            thread::sleep(Duration::from_secs(3));
            assert!(shutdown());
        });

        assert_eq!(handle.join().unwrap(), RunExit::Shutdown);
    }
}
