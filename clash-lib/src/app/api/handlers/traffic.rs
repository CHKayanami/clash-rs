use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{FromRequest, Request, State, WebSocketUpgrade},
    http::HeaderMap,
    response::IntoResponse,
};
use serde::Serialize;

use crate::app::api::{AppState, handlers::utils::is_request_websocket, websocket};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficResponse {
    pub up: u64,
    pub down: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub conn_count: usize,
}

pub async fn handle(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> impl IntoResponse {
    if is_request_websocket(&headers) {
        if let Ok(ws) = WebSocketUpgrade::from_request(req, &state).await {
            return websocket::traffic(ws, State(state)).await.into_response();
        }
    }

    let (up, down, upload_total, download_total, conn_count) =
        state.statistics_manager.traffic_summary();
    Json(TrafficResponse {
        up,
        down,
        upload_total,
        download_total,
        conn_count,
    })
    .into_response()
}
