use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{
        FromRequest, Path, Query, Request, State, WebSocketUpgrade, ws::Message,
    },
    response::IntoResponse,
    routing::{delete, get},
};
use http::HeaderMap;
use serde::Deserialize;
use tracing::{debug, warn};

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
    if !is_request_websocket(&headers) {
        let mgr = state.statistics_manager.clone();
        let snapshot = mgr.snapshot();
        return Json(snapshot).into_response();
    }

    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("ws upgrade error: {}", e);
            return e.into_response();
        }
    };

    let interval = std::time::Duration::from_secs(q.interval.unwrap_or(2).max(1));
    let mut frames = state
        .samplers
        .subscribe_connections(state.statistics_manager.clone(), interval);

    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        loop {
            tokio::select! {
                res = frames.recv() => {
                    match res {
                        Ok(frame) => {
                            if let Err(e) = socket.send(Message::Text(frame.as_ref().into())).await {
                                debug!("ws connection closed with error: {}", e);
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                msg = socket.recv() => {
                    match msg {
                        Some(Ok(Message::Close(_))) | None => {
                            debug!("ws connection client disconnected");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!("ws connection receive error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    })
}

async fn close_connection(
    State(state): State<ConnectionState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager;
    if let Ok(num_id) = id.parse::<u64>() {
        mgr.close(num_id);
    }
    format!("connection {id} closed").into_response()
}

async fn close_all_connection(
    State(state): State<ConnectionState>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager;
    mgr.close_all();
    "all connections closed".into_response()
}
