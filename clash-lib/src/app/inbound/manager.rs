use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::ThreadSafeDNSResolver,
        inbound::network_listener::build_network_listeners,
        remote_content_manager::providers::{
            file_vehicle, http_vehicle, inbound_provider::InboundSetProvider,
        },
    },
    common::auth::ThreadSafeAuthenticator,
    config::internal::{
        config::BindAddress,
        listener::{
            InboundFileProvider, InboundHttpProvider, InboundOpts,
            InboundProviderDef, InboundUser,
        },
    },
    runner::{AsyncService, ServiceContext},
};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

/// Per-listener handle entry: the spawned task plus an optional channel to
/// push user-list updates without restarting the listener.
struct ProviderHandleEntry {
    handle: Option<JoinHandle<()>>,
    stop_token: tokio_util::sync::CancellationToken,
    /// Present only for Shadowsocks and AnyTLS listeners — used to push updated
    /// user lists without restarting the listener.
    /// lists into the running listener without a restart.
    #[allow(dead_code)]
    users_tx: Option<tokio::sync::watch::Sender<Vec<InboundUser>>>,
}

/// Per-listener handle entry for static (non-provider) inbounds.
struct StaticHandleEntry {
    handle: Option<JoinHandle<()>>,
    stop_token: tokio_util::sync::CancellationToken,
    /// Present only for AnyTLS (and Shadowsocks) listeners — used to push
    /// updated user lists without restarting the listener.
    #[allow(dead_code)]
    users_tx: Option<tokio::sync::watch::Sender<Vec<InboundUser>>>,
}

type ProviderHandles =
    Arc<RwLock<HashMap<String, HashMap<InboundOpts, ProviderHandleEntry>>>>;
use tracing::{error, info, warn};

/// Legacy ports configuration for inbounds.
/// Newer inbounds have their own port configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ports {
    pub port: Option<u16>,
    #[serde(rename = "socks-port")]
    pub socks_port: Option<u16>,
    #[serde(rename = "redir-port")]
    pub redir_port: Option<u16>,
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: Option<u16>,
    #[serde(rename = "mixed-port")]
    pub mixed_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundEndpoint {
    pub name: String,
    #[serde(rename = "type")]
    pub inbound_type: String,
    pub port: u16,
    pub active: bool,
}

pub struct InboundManager {
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,

    /// Inbound options for each inbound type -> listening Task
    inbound_handlers: Arc<RwLock<HashMap<InboundOpts, StaticHandleEntry>>>,

    /// provider name -> (InboundOpts -> JoinHandle) for provider-owned
    /// listeners
    provider_handles: ProviderHandles,

    /// provider name -> provider (kept alive for lifecycle management)
    inbound_providers: Arc<RwLock<HashMap<String, Arc<InboundSetProvider>>>>,

    cancellation_token: tokio_util::sync::CancellationToken,
    service_context: Arc<RwLock<Option<ServiceContext>>>,
}

#[async_trait]
impl AsyncService for InboundManager {
    async fn start(&self, ctx: &ServiceContext) -> Result<(), crate::Error> {
        let inbound_handlers = self.inbound_handlers.clone();
        let dispatcher = self.dispatcher.clone();
        let authenticator = self.authenticator.clone();
        let cancellation_token = self.cancellation_token.clone();
        let ctx_clone = ctx.clone();
        *self.service_context.write() = Some(ctx.clone());

        ctx.spawn(async move {
            Self::start_all_listeners(
                dispatcher,
                authenticator,
                inbound_handlers,
                cancellation_token,
                Some(ctx_clone),
            )
            .await;
        });

        Ok(())
    }

    async fn stop(&self) -> Result<(), crate::Error> {
        self.shutdown();
        self.join_all_listeners().await
    }
}

impl InboundManager {
    pub fn shutdown(&self) {
        self.cancellation_token.cancel();
    }
    pub async fn new(
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        inbounds_opt: HashSet<InboundOpts>,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            inbound_handlers: Arc::new(RwLock::new(
                inbounds_opt
                    .into_iter()
                    .map(|opts| {
                        (
                            opts,
                            StaticHandleEntry {
                                handle: None,
                                stop_token: tokio_util::sync::CancellationToken::new(
                                ),
                                users_tx: None,
                            },
                        )
                    })
                    .collect(),
            )),
            provider_handles: Arc::new(RwLock::new(HashMap::new())),
            inbound_providers: Arc::new(RwLock::new(HashMap::new())),
            dispatcher,
            authenticator,
            cancellation_token: cancellation_token.unwrap_or_default(),
            service_context: Arc::new(RwLock::new(None)),
        }
    }

    /// Load and initialise inbound providers (http/file), analogous to
    /// `OutboundManager::load_proxy_providers`. Should be called once after
    /// `new()`, before `run_async()`.
    pub async fn load_inbound_providers(
        &self,
        cwd: String,
        providers: HashMap<String, InboundProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
    ) {
        for (name, def) in providers {
            let (vehicle, interval): (
                Arc<dyn crate::app::remote_content_manager::providers::ProviderVehicle + Send + Sync>,
                Duration,
            ) = match def {
                InboundProviderDef::Http(InboundHttpProvider {
                    url,
                    path,
                    interval,
                    header,
                    ..
                }) => {
                    let uri = match url.parse::<hyper::Uri>() {
                        Ok(u) => u,
                        Err(e) => {
                            error!(provider = %name, "invalid inbound provider URL: {e}");
                            continue;
                        }
                    };
                    let path = path
                        .filter(|p| !p.trim().is_empty())
                        .unwrap_or_else(|| {
                            let md5 = crate::common::utils::md5_str(url.as_bytes());
                            format!("inbound_providers/{md5}")
                        });
                    let v = http_vehicle::Vehicle::new(
                        uri,
                        path,
                        Some(cwd.clone()),
                        dns_resolver.clone(),
                        None,
                        None,
                        header,
                    );
                    (Arc::new(v), Duration::from_secs(interval))
                }
                InboundProviderDef::File(InboundFileProvider { path, interval, .. }) => {
                    let v = file_vehicle::Vehicle::new(&path);
                    (Arc::new(v), Duration::from_secs(interval.unwrap_or(0)))
                }
            };

            let provider_handles = self.provider_handles.clone();
            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();
            let cancellation_token = self.cancellation_token.clone();
            let provider_name = name.clone();
            let service_context = self.service_context.clone();

            let on_update = move |new_opts: Vec<InboundOpts>| {
                let provider_handles = provider_handles.clone();
                let dispatcher = dispatcher.clone();
                let authenticator = authenticator.clone();
                let cancellation_token = cancellation_token.clone();
                let provider_name = provider_name.clone();
                let service_context = service_context.clone();

                Box::pin(async move {
                    let mut old_handles = {
                        let mut guard = provider_handles.write();
                        guard.remove(&provider_name).unwrap_or_default()
                    };

                    // Partition new_opts: reuse or user-update existing listeners,
                    // collect truly new opts that need a fresh listener.
                    let mut new_handles: HashMap<InboundOpts, ProviderHandleEntry> =
                        HashMap::new();
                    let mut opts_to_start: Vec<InboundOpts> = Vec::new();

                    for opts in new_opts {
                        if let Some(entry) = old_handles.remove(&opts) {
                            // Structural key matched (same port/cipher/password).
                            // Push updated user list via watch channel if present —
                            // this avoids restarting the listener entirely.
                            #[cfg(feature = "shadowsocks")]
                            if let (InboundOpts::Shadowsocks { users, .. }, Some(tx)) =
                                (&opts, &entry.users_tx)
                                && tx.send(users.clone()).is_ok()
                            {
                                info!(
                                    "inbound provider {provider_name}: user list \
                                     updated in place ({} users)",
                                    users.len()
                                );
                            }
                            if let (InboundOpts::Anytls { users, .. }, Some(tx)) =
                                (&opts, &entry.users_tx)
                                && tx.send(users.clone()).is_ok()
                            {
                                info!(
                                    "inbound provider {provider_name}: anytls user \
                                     list updated in place ({} users)",
                                    users.len()
                                );
                            }
                            new_handles.insert(opts, entry);
                        } else {
                            opts_to_start.push(opts);
                        }
                    }

                    // Stop removed handles before starting new ones so their
                    // sockets are released without reporting a fatal task exit.
                    for (removed_opts, entry) in old_handles {
                        info!(
                            "inbound provider {provider_name}: removing listener \
                             '{}'",
                            removed_opts.common_opts().name
                        );
                        entry.stop_token.cancel();
                        if let Some(h) = entry.handle
                            && let Err(e) = h.await
                        {
                            warn!(
                                "provider inbound '{}' stopped with error: {}",
                                removed_opts.common_opts().name,
                                e
                            );
                        }
                    }

                    // Start listeners for new opts.
                    for opts in opts_to_start {
                        let stop_token = cancellation_token.child_token();
                        let task_stop_token = stop_token.clone();
                        let listener_name = opts.common_opts().name.clone();
                        info!(
                            "inbound provider {provider_name}: starting listener \
                             '{listener_name}'"
                        );

                        // For Shadowsocks and AnyTLS, create a watch channel so
                        // future user-list updates can be pushed without a restart.
                        #[cfg(feature = "shadowsocks")]
                        let (users_rx, users_tx) =
                            if let InboundOpts::Shadowsocks { users, .. } = &opts {
                                let (tx, rx) =
                                    tokio::sync::watch::channel(users.clone());
                                (Some(rx), Some(tx))
                            } else if let InboundOpts::Anytls { users, .. } = &opts {
                                let (tx, rx) =
                                    tokio::sync::watch::channel(users.clone());
                                (Some(rx), Some(tx))
                            } else {
                                (None, None)
                            };
                        #[cfg(not(feature = "shadowsocks"))]
                        let (users_rx, users_tx) = if let InboundOpts::Anytls {
                            users,
                            ..
                        } = &opts
                        {
                            let (tx, rx) =
                                tokio::sync::watch::channel(users.clone());
                            (Some(rx), Some(tx))
                        } else {
                            (
                                None::<tokio::sync::watch::Receiver<Vec<InboundUser>>>,
                                None,
                            )
                        };

                        let handle = build_network_listeners(
                            &opts,
                            dispatcher.clone(),
                            authenticator.clone(),
                            users_rx,
                        )
                        .map(|runners| {
                            let critical_name = format!("provider_inbound_{listener_name}");
                            let task = async move {
                                tokio::select! {
                                    _ = futures::future::join_all(runners) => {
                                        warn!("Provider inbound {} exited unexpectedly", listener_name);
                                    }
                                    _ = task_stop_token.cancelled() => {
                                        info!("Provider inbound {} closed", listener_name);
                                    }
                                }
                            };
                            if let Some(ref ctx) = *service_context.read() {
                                ctx.spawn_critical_with_token(
                                    critical_name,
                                    stop_token.clone(),
                                    task,
                                )
                            } else {
                                tokio::spawn(task)
                            }
                        });
                        new_handles.insert(
                            opts,
                            ProviderHandleEntry {
                                handle,
                                stop_token,
                                users_tx,
                            },
                        );
                    }

                    {
                        let mut guard = provider_handles.write();
                        guard.insert(provider_name, new_handles);
                    }
                }) as BoxFuture<'static, ()>
            };

            match InboundSetProvider::new(name.clone(), interval, vehicle, on_update)
            {
                Ok(provider) => {
                    let provider = Arc::new(provider);
                    match provider.initialize().await {
                        Ok(initial_opts) => {
                            info!(
                                "inbound provider '{name}' initialised ({} \
                                 listeners)",
                                initial_opts.len()
                            );
                            self.inbound_providers.write().insert(name, provider);
                        }
                        Err(e) => {
                            error!(provider = %name, "inbound provider init failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!(provider = %name, "failed to create inbound provider: {e}")
                }
            }
        }
    }

    async fn start_all_listeners(
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        inbound_handlers: Arc<RwLock<HashMap<InboundOpts, StaticHandleEntry>>>,
        cancellation_token: tokio_util::sync::CancellationToken,
        ctx: Option<ServiceContext>,
    ) {
        for (opts, entry) in inbound_handlers.write().iter_mut() {
            let stop_token = cancellation_token.child_token();
            let task_stop_token = stop_token.clone();
            let name = opts.common_opts().name.clone();

            // For AnyTLS (and Shadowsocks), create a watch channel so user-list
            // updates can be pushed without a full restart.
            #[cfg(feature = "shadowsocks")]
            let (users_rx, users_tx) =
                if let InboundOpts::Shadowsocks { users, .. } = opts {
                    let (tx, rx) = tokio::sync::watch::channel(users.clone());
                    (Some(rx), Some(tx))
                } else if let InboundOpts::Anytls { users, .. } = opts {
                    let (tx, rx) = tokio::sync::watch::channel(users.clone());
                    (Some(rx), Some(tx))
                } else {
                    (None, None)
                };
            #[cfg(not(feature = "shadowsocks"))]
            let (users_rx, users_tx) =
                if let InboundOpts::Anytls { users, .. } = opts {
                    let (tx, rx) = tokio::sync::watch::channel(users.clone());
                    (Some(rx), Some(tx))
                } else {
                    (None::<tokio::sync::watch::Receiver<Vec<InboundUser>>>, None)
                };

            entry.users_tx = users_tx;
            entry.handle = build_network_listeners(
                opts,
                dispatcher.clone(),
                authenticator.clone(),
                users_rx,
            )
            .map(|r| {
                let critical_name = format!("inbound_{name}");
                let task = async move {
                    tokio::select! {
                        _ = futures::future::join_all(r) => {
                            warn!("Inbound handler {} has exited unexpectedly", name);
                        },
                        _ = task_stop_token.cancelled() => {
                            info!("Inbound handler {} is closed", name);
                        },
                    }
                };
                if let Some(ref ctx) = ctx {
                    ctx.spawn_critical_with_token(
                        critical_name,
                        stop_token.clone(),
                        task,
                    )
                } else {
                    tokio::spawn(task)
                }
            });
            entry.stop_token = stop_token;
        }
    }

    async fn stop_all_listeners(&self) {
        let mut handles = Vec::new();
        {
            let mut guard = self.inbound_handlers.write();
            for (opt, entry) in guard.iter_mut() {
                if let Some(h) = entry.handle.take() {
                    warn!(
                        "Shutting down inbound handler: {}",
                        opt.common_opts().name
                    );
                    entry.stop_token.cancel();
                    handles.push(h);
                }
            }
        }
        for h in handles {
            let _ = h.await;
        }

        let mut provider_handles = Vec::new();
        {
            let mut guard = self.provider_handles.write();
            for handles in guard.values_mut() {
                for (opt, entry) in handles.iter_mut() {
                    if let Some(h) = entry.handle.take() {
                        warn!(
                            "Shutting down provider inbound handler: {}",
                            opt.common_opts().name
                        );
                        entry.stop_token.cancel();
                        provider_handles.push(h);
                    }
                }
            }
        }
        for h in provider_handles {
            let _ = h.await;
        }
    }

    #[allow(dead_code)]
    async fn join_all_listeners(&self) -> Result<(), crate::Error> {
        let mut last_join_error = None;
        let mut handles = Vec::new();
        {
            let mut guard = self.inbound_handlers.write();
            for (opt, entry) in guard.iter_mut() {
                if let Some(h) = entry.handle.take() {
                    entry.stop_token.cancel();
                    handles.push((opt.common_opts().name.clone(), h));
                }
            }
        }
        for (name, h) in handles {
            warn!("Shutting down inbound handler: {}", name);
            h.await.unwrap_or_else(|e| {
                warn!("Inbound handler {} shutdown with error: {}", name, e);
                last_join_error = Some(e);
            });
        }

        let mut provider_handles = Vec::new();
        {
            let mut guard = self.provider_handles.write();
            for handles in guard.values_mut() {
                for (opt, entry) in handles.iter_mut() {
                    if let Some(h) = entry.handle.take() {
                        entry.stop_token.cancel();
                        provider_handles.push((opt.common_opts().name.clone(), h));
                    }
                }
            }
        }
        for (name, h) in provider_handles {
            warn!("Shutting down provider inbound handler: {}", name);
            h.await.unwrap_or_else(|e| {
                warn!(
                    "Provider inbound handler {} shutdown with error: {}",
                    name, e
                );
                last_join_error = Some(e);
            });
        }

        last_join_error
            .map(|e| Err(std::io::Error::other(e).into()))
            .unwrap_or(Ok(()))
    }

    // RESTFUL API handlers below
    pub async fn restart(&self) -> Result<(), crate::Error> {
        self.stop_all_listeners().await;

        let inbound_handlers = self.inbound_handlers.clone();
        let dispatcher = self.dispatcher.clone();
        let authenticator = self.authenticator.clone();
        let cancellation_token = self.cancellation_token.clone();
        let ctx = self.service_context.read().clone();
        Self::start_all_listeners(
            dispatcher,
            authenticator,
            inbound_handlers,
            cancellation_token,
            ctx,
        )
        .await;
        Ok(())
    }

    pub async fn get_ports(&self) -> Ports {
        let mut ports = Ports::default();
        let guard = self.inbound_handlers.read();
        for opts in guard.keys() {
            match &opts {
                InboundOpts::Http { common_opts } => {
                    ports.port = Some(common_opts.port)
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port = Some(common_opts.port)
                }
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port = Some(common_opts.port)
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { common_opts, .. } => {
                    ports.tproxy_port = Some(common_opts.port)
                }
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port = Some(common_opts.port)
                }
                _ => {}
            }
        }
        ports
    }

    pub async fn get_allow_lan(&self) -> bool {
        let guard = self.inbound_handlers.read();
        if let Some((opts, _)) = guard.iter().next() {
            opts.common_opts().allow_lan
        } else {
            false
        }
    }

    pub async fn set_allow_lan(&self, allow_lan: bool) {
        let mut guard = self.inbound_handlers.write();
        let new_map = guard
            .drain()
            .map(|(mut opts, entry)| {
                opts.common_opts_mut().allow_lan = allow_lan;
                (opts, entry)
            })
            .collect::<HashMap<_, _>>();
        *guard = new_map;
    }

    pub async fn get_bind_address(&self) -> BindAddress {
        let guard = self.inbound_handlers.read();
        if let Some((opts, _)) = guard.iter().next() {
            opts.common_opts().listen
        } else {
            BindAddress::default()
        }
    }

    pub async fn get_listeners(&self) -> Vec<InboundEndpoint> {
        let mut result: Vec<InboundEndpoint> = self
            .inbound_handlers
            .read()
            .iter()
            .map(|(opts, entry)| {
                let common = opts.common_opts();
                let active = entry.handle.as_ref().is_some_and(|h| !h.is_finished());
                InboundEndpoint {
                    name: common.name.clone(),
                    inbound_type: opts.type_name().to_string(),
                    port: common.port,
                    active,
                }
            })
            .collect();

        for handles in self.provider_handles.read().values() {
            for (opts, entry) in handles {
                let common = opts.common_opts();
                let active = entry.handle.as_ref().is_some_and(|h| !h.is_finished());
                result.push(InboundEndpoint {
                    name: common.name.clone(),
                    inbound_type: opts.type_name().to_string(),
                    port: common.port,
                    active,
                });
            }
        }

        result
    }

    pub async fn set_bind_address(&self, bind_address: BindAddress) {
        let mut guard = self.inbound_handlers.write();
        let new_map = guard
            .drain()
            .map(|(mut opts, entry)| {
                opts.common_opts_mut().listen = bind_address;
                (opts, entry)
            })
            .collect::<HashMap<_, _>>();
        *guard = new_map;
    }

    // returns true if any listener ports were changed (i.e. a restart is needed)
    pub async fn change_ports(&self, ports: Ports) -> bool {
        let mut guard = self.inbound_handlers.write();

        let listeners: HashMap<InboundOpts, StaticHandleEntry> = guard
            .extract_if(|opts, _| match &opts {
                InboundOpts::Http { common_opts } => {
                    ports.port.is_some() && Some(common_opts.port) != ports.port
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port.is_some()
                        && Some(common_opts.port) != ports.socks_port
                }
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port.is_some()
                        && Some(common_opts.port) != ports.mixed_port
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { common_opts, .. } => {
                    ports.tproxy_port.is_some()
                        && Some(common_opts.port) != ports.tproxy_port
                }
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port.is_some()
                        && Some(common_opts.port) != ports.redir_port
                }
                _ => false,
            })
            .collect();

        let changed = !listeners.is_empty();

        for (mut opts, entry) in listeners {
            // extract_if already guarantees the matching port field is Some.
            // Use a plain match + if-let (stable) rather than if-let guards
            // in match arms (which require the nightly `if_let_guard` feature).
            let new_port = match &opts {
                InboundOpts::Http { .. } => ports.port,
                InboundOpts::Socks { .. } => ports.socks_port,
                InboundOpts::Mixed { .. } => ports.mixed_port,
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { .. } => ports.tproxy_port,
                #[cfg(feature = "redir")]
                InboundOpts::Redir { .. } => ports.redir_port,
                _ => {
                    warn!(
                        "Port for listener '{}' is not changed",
                        opts.common_opts().name
                    );
                    continue;
                }
            };
            let Some(port) = new_port else {
                warn!(
                    "Port for listener '{}' is not changed",
                    opts.common_opts().name
                );
                continue;
            };
            opts.common_opts_mut().port = port;
            guard.insert(opts, entry);
        }

        changed
    }
}
