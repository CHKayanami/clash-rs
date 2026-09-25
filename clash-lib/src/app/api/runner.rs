use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, post},
};
use http::{Method, header};
use tokio::sync::broadcast::Sender;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{debug, error, info, warn};

use super::context::RuntimeContext;
use crate::{
    GlobalState,
    app::{
        api::{AppState, handlers, ipc, middlewares, websocket},
        dns::config::DNSListenAddr,
        inbound::manager::InboundManager,
        logging::LogEvent,
        outbound::manager::ThreadSafeOutboundManager,
        profile::ThreadSafeCacheFile,
        router::ArcRouter,
    },
    config::config::Controller,
    runner::{AsyncService, ServiceContext},
};

pub struct ApiRunner {
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    ctx: RuntimeContext,
    cancellation_token: tokio_util::sync::CancellationToken,
}

impl ApiRunner {
    /// Modern constructor accepting an aggregated [`RuntimeContext`].
    pub fn from_context(
        controller_cfg: Controller,
        log_source: Sender<LogEvent>,
        ctx: RuntimeContext,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            controller_cfg,
            log_source,
            ctx,
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }

    /// Backwards-compatible constructor mapping legacy parameter lists into [`RuntimeContext`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        controller_cfg: Controller,
        log_source: Sender<LogEvent>,
        inbound_manager: Arc<InboundManager>,
        dispatcher: Arc<crate::app::dispatcher::Dispatcher>,
        global_state: Arc<tokio::sync::Mutex<GlobalState>>,
        dns_resolver: crate::app::dns::ThreadSafeDNSResolver,
        outbound_manager: ThreadSafeOutboundManager,
        statistics_manager: Arc<crate::app::dispatcher::StatisticsManager>,
        cache_store: ThreadSafeCacheFile,
        router: ArcRouter,
        cwd: String,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
        dns_listen_addr: DNSListenAddr,
        dns_enabled: bool,
    ) -> Self {
        let ctx = RuntimeContext::new(
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
            outbound_manager,
            statistics_manager,
            cache_store,
            router,
            cwd,
            dns_listen_addr,
            dns_enabled,
        );
        Self::from_context(controller_cfg, log_source, ctx, cancellation_token)
    }

    pub fn shutdown(&self) {
        info!("Shutting down API server");
        self.cancellation_token.cancel();
    }

    pub fn cancellation_token(&self) -> &tokio_util::sync::CancellationToken {
        &self.cancellation_token
    }

    pub fn controller_config(&self) -> &Controller {
        &self.controller_cfg
    }

    fn build_cors_layer(&self) -> CorsLayer {
        let origins: AllowOrigin = if let Some(origins) =
            &self.controller_cfg.cors_allow_origins
        {
            let has_wildcard = origins.iter().any(|origin| origin.trim() == "*");
            if has_wildcard {
                if origins.iter().any(|origin| origin.trim() != "*") {
                    warn!(
                        "CORS origin '*' enables all origins; ignoring additional configured origins"
                    );
                }
                Any.into()
            } else {
                origins
                    .iter()
                    .filter_map(|v| match v.parse() {
                        Ok(origin) => Some(origin),
                        Err(e) => {
                            warn!("ignored invalid CORS origin '{}': {}", v, e);
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .into()
            }
        } else {
            Any.into()
        };

        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .allow_private_network(true)
            .allow_origin(origins)
    }
}

#[async_trait]
impl AsyncService for ApiRunner {
    async fn start(&self, ctx: &ServiceContext) -> Result<(), crate::Error> {
        let controller_cfg = self.controller_cfg.clone();
        let current_ctx = &self.ctx;

        let ipc_addr = controller_cfg.external_controller_ipc.clone();
        let tcp_addr = controller_cfg.external_controller.clone();

        if tcp_addr.is_none() && ipc_addr.is_none() {
            info!("API server: no listener configured, skipping");
            return Ok(());
        }

        let cors = self.build_cors_layer();
        let samplers = Arc::new(crate::app::api::StreamSamplers::new());
        let app_state = Arc::new(AppState {
            log_source_tx: self.log_source.clone(),
            statistics_manager: current_ctx.statistics_manager.clone(),
            samplers: samplers.clone(),
        });

        let mut router = Router::new()
            .route("/", get(handlers::hello::handle))
            .route("/logs", get(handlers::log::handle))
            .route("/traffic", get(handlers::traffic::handle))
            .route("/user-stats", get(handlers::user_stats::handle))
            .route("/version", get(handlers::version::handle))
            .route("/memory", get(handlers::memory::handle))
            .route("/restart", post(handlers::restart::handle))
            .nest("/ws", websocket::routes(app_state.clone()))
            .nest(
                "/configs",
                handlers::config::routes(
                    current_ctx.inbound_manager.clone(),
                    current_ctx.dispatcher.clone(),
                    current_ctx.global_state.clone(),
                    current_ctx.dns_resolver.clone(),
                    current_ctx.dns_listen_addr.clone(),
                    current_ctx.dns_enabled,
                ),
            )
            .nest("/rules", handlers::rule::routes(current_ctx.router.clone()))
            .nest(
                "/group",
                handlers::group::routes(current_ctx.outbound_manager.clone()),
            )
            .nest(
                "/proxies",
                handlers::proxy::routes(
                    current_ctx.outbound_manager.clone(),
                    current_ctx.cache_store.clone(),
                ),
            )
            .nest(
                "/providers/proxies",
                handlers::provider::routes(current_ctx.outbound_manager.clone()),
            )
            .nest(
                "/providers/rules",
                handlers::provider::rule_routes(current_ctx.router.clone()),
            )
            .nest(
                "/connections",
                handlers::connection::routes(
                    current_ctx.statistics_manager.clone(),
                    samplers.clone(),
                ),
            )
            .nest(
                "/flows",
                handlers::flows::routes(current_ctx.statistics_manager.clone()),
            )
            .nest(
                "/dns",
                handlers::dns::routes(current_ctx.dns_resolver.clone()),
            )
            .layer(middleware::from_fn(
                middlewares::fix_json_content_type::fix_content_type,
            ))
            .route_layer(cors)
            .with_state(app_state)
            .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

        async fn ui_redirect(uri: http::Uri) -> Redirect {
            if let Some(query) = uri.query() {
                Redirect::to(&format!("/ui/?{}", query))
            } else {
                Redirect::to("/ui/")
            }
        }

        router = router
            .route("/ui", get(ui_redirect))
            .route("/dashboard", get(ui_redirect));

        if let Some(dashboard_dir) = &controller_cfg.external_ui {
            let p = PathBuf::from(dashboard_dir);
            let dir = if p.is_relative() {
                PathBuf::from(&current_ctx.cwd).join(p)
            } else {
                p
            };
            if dir.exists() {
                info!("Serving dashboard from: {:?}", dir);
                router = router.nest_service("/ui", ServeDir::new(dir));
            } else {
                warn!("Dashboard dir {:?} does not exist, skipping", dir);
            }
        } else {
            #[cfg(feature = "dashboard")]
            {
                router = router
                    .route("/ui/", get(super::embedded_dashboard::serve_index))
                    .route(
                        "/ui/{*path}",
                        get(super::embedded_dashboard::serve_asset),
                    );
            }
        }

        let tcp_addr_display = tcp_addr.clone();
        let ipc_addr_display = ipc_addr.clone();

        let cancellation_token = self.cancellation_token.clone();
        let cancel_child = cancellation_token.child_token();
        let ctx_cancel = ctx.cancellation_token().clone();
        let lifecycle_tokens = vec![cancellation_token.clone(), ctx_cancel.clone()];

        ctx.spawn_critical_with_tokens("api_server", lifecycle_tokens, async move {
            let tcp_cancel = cancel_child.child_token();
            let ipc_cancel = cancel_child.child_token();

            let tcp_handle = tcp_addr.map(|bind_addr| {
                let bind_addr = if bind_addr.starts_with(':') {
                    info!(
                        "TCP API Server address not supplied, listening on \
                         `127.0.0.1`"
                    );
                    format!("127.0.0.1{bind_addr}")
                } else {
                    bind_addr
                };
                let auth_secret = controller_cfg.secret.clone().unwrap_or_default();
                let cors_allow_origins = controller_cfg.cors_allow_origins.clone();
                let router = router.clone();
                let cancel = tcp_cancel.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        res = super::tcp::serve_tcp(
                            bind_addr,
                            router,
                            auth_secret,
                            cors_allow_origins,
                        ) => res,
                        _ = cancel.cancelled() => {
                            debug!("TCP API server gracefully cancelled");
                            Ok(())
                        }
                    }
                })
            });

            let ipc_handle = ipc_addr.as_ref().map(|ipc_path| {
                let ipc_path = ipc_path.clone();
                let router = router.clone();
                let cancel = ipc_cancel.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        res = ipc::serve_ipc(router, &ipc_path) => res,
                        _ = cancel.cancelled() => {
                            debug!("IPC API server gracefully cancelled");
                            Ok(())
                        }
                    }
                })
            });

            match (tcp_addr_display.as_deref(), ipc_addr_display.as_deref()) {
                (Some(tcp), Some(ipc)) => debug!(
                    "API server is running on both TCP {} and IPC {}",
                    tcp, ipc
                ),
                (Some(tcp), None) => debug!("API server is running on TCP {}", tcp),
                (None, Some(ipc)) => debug!("API server is running on IPC {}", ipc),
                (None, None) => unreachable!(),
            }

            let mut tcp_running = tcp_handle.is_some();
            let mut ipc_running = ipc_handle.is_some();

            let mut tcp_task = futures::future::OptionFuture::from(tcp_handle);
            let mut ipc_task = futures::future::OptionFuture::from(ipc_handle);

            tokio::select! {
                Some(res) = &mut tcp_task => {
                    tcp_running = false;
                    match res {
                        Ok(Err(e)) => {
                            error!("TCP API server failed: {}", e);
                        }
                        Err(join_err) => {
                            error!("TCP API server task panicked: {}", join_err);
                        }
                        Ok(Ok(())) => {
                            info!("TCP API server stopped");
                        }
                    }
                }
                Some(res) = &mut ipc_task => {
                    ipc_running = false;
                    match res {
                        Ok(Err(e)) => {
                            error!("IPC API server failed: {}", e);
                        }
                        Err(join_err) => {
                            error!("IPC API server task panicked: {}", join_err);
                        }
                        Ok(Ok(())) => {
                            info!("IPC API server stopped");
                        }
                    }
                }
                _ = cancel_child.cancelled() => {
                    info!("API server closed gracefully");
                }
                _ = ctx_cancel.cancelled() => {
                    info!("API server closed gracefully via context");
                }
            }

            tcp_cancel.cancel();
            ipc_cancel.cancel();

            if tcp_running {
                let _ = tcp_task.await;
            }
            if ipc_running {
                let _ = ipc_task.await;
            }
        });

        Ok(())
    }

    async fn stop(&self) -> Result<(), crate::Error> {
        self.shutdown();
        Ok(())
    }
}
