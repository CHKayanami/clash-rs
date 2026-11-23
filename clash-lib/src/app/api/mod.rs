use std::sync::Arc;

use tokio::sync::broadcast::Sender;

use super::{dispatcher::StatisticsManager, logging::LogEvent};

pub mod context;
#[cfg(feature = "dashboard")]
mod embedded_dashboard;
pub(crate) mod handlers;
mod ipc;
mod middlewares;
mod runner;
pub mod stream_samplers;
mod tcp;
mod websocket;

pub use context::RuntimeContext;
pub use handlers::ebpf::EbpfInspectHandle;
pub use handlers::restart::RestartController;
pub use runner::ApiRunner;
pub use stream_samplers::StreamSamplers;

pub struct AppState {
    pub instance_id: String,
    pub log_source_tx: Sender<LogEvent>,
    pub statistics_manager: Arc<StatisticsManager>,
    pub samplers: Arc<StreamSamplers>,
}
