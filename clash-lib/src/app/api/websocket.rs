use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
    routing::get,
};
use tracing::{debug, warn};

use crate::app::api::{
    AppState,
    handlers::{
        connection::GetConnectionsQuery,
        flows::ws_handle as flows_ws_handle,
        memory::GetMemoryQuery,
        traffic::TrafficResponse,
    },
};

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/connections", get(connections))
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
        .route("/logs", get(log))
        .route("/flows", get(flows_ws_handle))
        .with_state(state)
}

pub async fn connections(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    query: Query<GetConnectionsQuery>,
) -> impl IntoResponse {
    let interval = Duration::from_secs(query.interval.unwrap_or(2).max(1));
    let frames = state
        .samplers
        .subscribe_connections(state.statistics_manager.clone(), interval);

    serve_connections(ws, frames)
}

pub fn serve_connections(
    ws: WebSocketUpgrade,
    mut frames: tokio::sync::broadcast::Receiver<axum::extract::ws::Utf8Bytes>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket: WebSocket| async move {
        loop {
            tokio::select! {
                res = frames.recv() => {
                    match res {
                        Ok(frame) => {
                            if let Err(e) = socket.send(Message::Text(frame)).await {
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
                            debug!("ws client disconnected");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!("ws receive error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    })
}

pub async fn traffic(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket: WebSocket| async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let (up, down, upload_total, download_total, conn_count) =
                        state.statistics_manager.traffic_summary();
                    let res = TrafficResponse {
                        up,
                        down,
                        upload_total,
                        download_total,
                        conn_count,
                    };
                    let body = match serde_json::to_string(&res) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("failed to serialize traffic stats: {}", e);
                            continue;
                        }
                    };

                    if let Err(e) = socket.send(Message::Text(body.into())).await {
                        debug!("ws connection closed with error: {}", e);
                        break;
                    }
                }
                msg = socket.recv() => {
                    match msg {
                        Some(Ok(Message::Close(_))) | None => {
                            debug!("ws traffic client disconnected");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!("ws traffic receive error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    })
}

pub async fn memory(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    query: Query<GetMemoryQuery>,
) -> impl IntoResponse {
    let interval_secs = query.interval.unwrap_or(1).max(1);
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket: WebSocket| async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let inuse = state.statistics_manager.memory_usage();
                    let body = format!(r#"{{"inuse":{inuse},"oslimit":0}}"#);

                    if let Err(e) = socket.send(Message::Text(body.into())).await {
                        debug!("ws connection closed with error: {}", e);
                        break;
                    }
                }
                msg = socket.recv() => {
                    match msg {
                        Some(Ok(Message::Close(_))) | None => {
                            debug!("ws memory client disconnected");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!("ws memory receive error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    })
}

pub async fn log(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket: WebSocket| async move {
        let mut rx = state.log_source_tx.subscribe();
        loop {
            tokio::select! {
                res = rx.recv() => {
                    match res {
                        Ok(evt) => {
                            let body = match serde_json::to_string(&evt) {
                                Ok(b) => b,
                                Err(e) => {
                                    warn!("Failed to serialize log event: {}", e);
                                    continue;
                                }
                            };

                            if let Err(e) = socket.send(Message::Text(body.into())).await {
                                debug!("ws send error: {}", e);
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
                            debug!("ws log client disconnected");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!("ws log receive error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    })
}
