use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};

use tracing::{debug, warn};

use crate::app::api::AppState;

pub async fn handle(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {} with {}", e, addr);
    })
    .on_upgrade(move |mut socket| async move {
        let mut rx = state.log_source_tx.subscribe();
        let mut buf = Vec::with_capacity(512);
        while let Ok(evt) = rx.recv().await {
            buf.clear();
            if let Err(e) = serde_json::to_writer(&mut buf, &evt) {
                warn!("Failed to serialize log event: {}", e);
                continue; // Skip this event but keep the connection open
            }

            let Ok(res_str) = std::str::from_utf8(&buf) else {
                continue;
            };

            if let Err(e) = socket.send(Message::Text(res_str.into())).await {
                debug!("ws send error: {}", e);
                break;
            }
        }
    })
}
