use std::{sync::Arc, time::Duration};

use axum::{Json, Router, extract::State, response::IntoResponse, routing::post};
use http::StatusCode;
use serde_json::{Map, json};
use tokio::{
    sync::{Mutex, oneshot},
    time::sleep,
};
use tracing::info;

use crate::app::api::AppState;

const RESTART_RESPONSE_GRACE: Duration = Duration::from_millis(150);

/// Signals a graceful shutdown so the outer CLI process can `exec` a fresh
/// instance with the current configuration.
pub struct RestartController {
    tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl RestartController {
    pub fn new(tx: oneshot::Sender<()>) -> Self {
        Self {
            tx: Mutex::new(Some(tx)),
        }
    }

    async fn trigger(&self) -> Result<(), (StatusCode, &'static str)> {
        let mut guard = self.tx.lock().await;
        let Some(tx) = guard.take() else {
            return Err((StatusCode::CONFLICT, "restart already in progress"));
        };
        info!("graceful process restart scheduled");
        tokio::spawn(async move {
            sleep(RESTART_RESPONSE_GRACE).await;
            let _ = tx.send(());
        });
        Ok(())
    }
}

#[derive(Clone)]
struct RestartState {
    controller: Option<Arc<RestartController>>,
    instance_id: String,
}

pub fn routes(
    restart: Option<Arc<RestartController>>,
    instance_id: String,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/restart", post(handle))
        .with_state(RestartState {
            controller: restart,
            instance_id,
        })
}

async fn handle(State(state): State<RestartState>) -> impl IntoResponse {
    let Some(restart) = state.controller else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({ "message": "restart is not supported in this runtime" })),
        )
            .into_response();
    };

    match restart.trigger().await {
        Ok(()) => {
            let mut map = Map::new();
            map.insert("status".to_owned(), "ok".into());
            map.insert("instance_id".to_owned(), state.instance_id.into());
            Json(map).into_response()
        }
        Err((status, message)) => {
            (status, Json(json!({ "message": message }))).into_response()
        }
    }
}
