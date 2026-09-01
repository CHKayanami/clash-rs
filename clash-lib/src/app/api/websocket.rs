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
    let callback = async move |mut socket: WebSocket| {
        let interval = query.interval.unwrap_or(1).max(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = Vec::with_capacity(8192);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let snapshot = state.statistics_manager.snapshot().await;

                    buf.clear();
                    if let Err(e) = serde_json::to_writer(&mut buf, &snapshot) {
                        debug!("failed to serialize snapshot for ws connection: {}", e);
                        break;
                    }

                    let Ok(body) = std::str::from_utf8(&buf) else {
                        debug!("failed to parse utf-8 for ws connection");
                        break;
                    };

                    if let Err(e) = socket.send(Message::Text(body.into())).await {
                        debug!("ws connection closed with error: {}", e);
                        break;
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
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await;
    })
}

pub async fn traffic(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;
            let (up, down) = state.statistics_manager.now();
            let body = format!(r#"{{"up":{up},"down":{down}}}"#);

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                debug!("ws connection closed with error: {}", e);
                break;
            }
        }
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await;
    })
}

pub async fn memory(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    query: Query<GetMemoryQuery>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = query.interval.unwrap_or(1).max(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval));

        loop {
            interval.tick().await;
            let inuse = state.statistics_manager.memory_usage();
            let body = format!(r#"{{"inuse":{inuse},"oslimit":0}}"#);

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                debug!("ws connection closed with error: {}", e);
                break;
            }
        }
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await;
    })
}

pub async fn log(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let mut rx = state.log_source_tx.subscribe();
        while let Ok(evt) = rx.recv().await {
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
    })
}
