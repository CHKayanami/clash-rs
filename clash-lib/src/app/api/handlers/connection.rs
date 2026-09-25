use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{FromRequest, Path, Query, Request, State, WebSocketUpgrade},
    response::IntoResponse,
    routing::{delete, get},
};
use http::HeaderMap;
use serde::Deserialize;

use crate::app::{
    api::{AppState, StreamSamplers, handlers::utils::is_request_websocket},
    dispatcher::StatisticsManager,
};

#[derive(Clone)]
struct ConnectionState {
    statistics_manager: Arc<StatisticsManager>,
    samplers: Arc<StreamSamplers>,
}

pub fn routes(
    statistics_manager: Arc<StatisticsManager>,
    samplers: Arc<StreamSamplers>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_connections).delete(close_all_connection))
        .route("/{id}", delete(close_connection))
        .with_state(ConnectionState {
            statistics_manager,
            samplers,
        })
}

#[derive(Deserialize)]
pub struct GetConnectionsQuery {
    pub interval: Option<u64>,
}

async fn get_connections(
    headers: HeaderMap,
    State(state): State<ConnectionState>,
    q: Query<GetConnectionsQuery>,
    req: Request<Body>,
) -> impl IntoResponse {
    if is_request_websocket(&headers) {
        if let Ok(ws) = WebSocketUpgrade::from_request(req, &state).await {
            let interval = std::time::Duration::from_secs(q.interval.unwrap_or(2).max(1));
            let frames = state
                .samplers
                .subscribe_connections(state.statistics_manager.clone(), interval);
            return crate::app::api::websocket::serve_connections(ws, frames)
                .into_response();
        }
    }

    let mgr = state.statistics_manager;
    let snapshot = mgr.snapshot();
    Json(snapshot).into_response()
}

async fn close_connection(
    State(state): State<ConnectionState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager;
    let Ok(num_id) = id.parse::<u64>() else {
        return (
            http::StatusCode::BAD_REQUEST,
            format!("invalid connection id: {id}"),
        )
            .into_response();
    };
    mgr.close(num_id);
    (http::StatusCode::OK, format!("connection {id} closed")).into_response()
}

async fn close_all_connection(
    State(state): State<ConnectionState>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager;
    mgr.close_all();
    (http::StatusCode::OK, "all connections closed").into_response()
}
