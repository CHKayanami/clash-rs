use std::sync::Arc;

use axum::{
    body::Body,
    extract::{FromRequest, Request, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::app::api::{AppState, handlers::utils::is_request_websocket, websocket};

pub async fn handle(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> impl IntoResponse {
    if is_request_websocket(&headers) {
        if let Ok(ws) = WebSocketUpgrade::from_request(req, &state).await {
            return websocket::log(ws, State(state)).await.into_response();
        }
    }

    (
        StatusCode::UPGRADE_REQUIRED,
        "WebSocket upgrade required for /logs",
    )
        .into_response()
}
