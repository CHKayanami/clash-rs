use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    GlobalState,
    app::{
        dispatcher::{Dispatcher, StatisticsManager},
        dns::{ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        outbound::manager::ThreadSafeOutboundManager,
        profile::ThreadSafeCacheFile,
        router::ArcRouter,
    },
};

/// Aggregated runtime context for API handlers and control plane services.
///
/// Encapsulates all dynamic components that can be updated during configuration reload,
/// eliminating parameter explosion across the API and runner layers.
#[derive(Clone)]
pub struct RuntimeContext {
    pub inbound_manager: Arc<InboundManager>,
    pub dispatcher: Arc<Dispatcher>,
    pub global_state: Arc<Mutex<GlobalState>>,
    pub dns_resolver: ThreadSafeDNSResolver,
    pub outbound_manager: ThreadSafeOutboundManager,
    pub statistics_manager: Arc<StatisticsManager>,
    pub cache_store: ThreadSafeCacheFile,
    pub router: ArcRouter,
    pub cwd: String,
    pub dns_listen_addr: DNSListenAddr,
    pub dns_enabled: bool,
}

impl RuntimeContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inbound_manager: Arc<InboundManager>,
        dispatcher: Arc<Dispatcher>,
        global_state: Arc<Mutex<GlobalState>>,
        dns_resolver: ThreadSafeDNSResolver,
        outbound_manager: ThreadSafeOutboundManager,
        statistics_manager: Arc<StatisticsManager>,
        cache_store: ThreadSafeCacheFile,
        router: ArcRouter,
        cwd: String,
        dns_listen_addr: DNSListenAddr,
        dns_enabled: bool,
    ) -> Self {
        Self {
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
            outbound_manager,
            statistics_manager,
            cache_store,
            router,
            cwd,
            dns_listen_addr,
            dns_enabled,
        }
    }
}
