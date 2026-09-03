use std::sync::Arc;

use tokio::sync::broadcast::Sender;

use super::{dispatcher::StatisticsManager, logging::LogEvent};

#[cfg(feature = "dashboard")]
mod embedded_dashboard;
mod handlers;
mod ipc;
mod middlewares;
mod runner;
pub mod stream_samplers;
mod tcp;
mod websocket;

pub use runner::ApiRunner;
pub use stream_samplers::StreamSamplers;

pub struct AppState {
    pub log_source_tx: Sender<LogEvent>,
    pub statistics_manager: Arc<StatisticsManager>,
    pub samplers: Arc<StreamSamplers>,
}

