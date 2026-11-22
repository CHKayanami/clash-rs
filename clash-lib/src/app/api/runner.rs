use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use axum::{
    Router, middleware,
    response::Redirect,
    routing::get,
};
use http::{Method, header};
use tokio::sync::broadcast::Sender;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use uuid::Uuid;

use super::context::RuntimeContext;
use crate::{
    app::{
        api::{AppState, handlers, ipc, middlewares, websocket},
        logging::LogEvent,
    },
    config::config::Controller,
    runner::{AsyncService, ServiceContext, prepare_service},
};

pub struct ApiRunner {
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    ctx: RuntimeContext,
}

impl ApiRunner {
    pub fn from_context(
        controller_cfg: Controller,
        log_source: Sender<LogEvent>,
        ctx: RuntimeContext,
    ) -> Self {
        Self {
            controller_cfg,
            log_source,
            ctx,
        }
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
        let instance_id = Uuid::new_v4().to_string();
        let samplers = Arc::new(crate::app::api::StreamSamplers::new());
        let app_state = Arc::new(AppState {
            instance_id: instance_id.clone(),
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
            .route("/memory/details", get(handlers::memory::details))
            .merge(handlers::restart::routes(
                current_ctx.restart.clone(),
                instance_id,
            ))
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
                router = router.nest_service("/ui/", ServeDir::new(dir));
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

        let mut listeners = Vec::new();
        if let Some(bind_addr) = tcp_addr {
            let bind_addr = if bind_addr.starts_with(':') {
                format!("127.0.0.1{bind_addr}")
            } else {
                bind_addr
            };
            let auth_secret = controller_cfg.secret.clone().unwrap_or_default();
            let origins = controller_cfg.cors_allow_origins.clone();
            let router = router.clone();
            listeners.push(prepare_service(move |ready| async move {
                super::tcp::serve_tcp(
                    bind_addr, router, auth_secret, origins, ready,
                ).await
            }).await?);
        }
        if let Some(path) = ipc_addr {
            listeners.push(prepare_service(move |ready| async move {
                ipc::serve_ipc(router, &path, ready).await
            }).await?);
        }

        let ctx_cancel = ctx.cancellation_token().clone();
        ctx.spawn_critical("api_server", async move {
            tokio::select! {
                result = futures::future::try_join_all(listeners) => {
                    if let Err(e) = result {
                        error!("API server failed: {}", e);
                    }
                }
                _ = ctx_cancel.cancelled() => {
                    info!("API server closed gracefully");
                }
            }
        });
        Ok(())
    }
}
