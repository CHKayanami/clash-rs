use std::collections::HashMap;
use std::sync::Arc;
use arc_swap::ArcSwap;

use crate::proxy::OutboundNode;

pub type OutboundNodeRegistry = Arc<ArcSwap<HashMap<String, OutboundNode>>>;

/// One committed provider generation, shared by membership and named dialing.
#[derive(Debug, Default)]
pub struct ProviderSnapshot {
    pub proxies: Arc<Vec<OutboundNode>>,
    pub entries: HashMap<String, OutboundNode>,
}

impl ProviderSnapshot {
    pub fn new(proxies: Vec<OutboundNode>) -> Self {
        let entries = proxies.iter().map(|node| (node.name().to_owned(), node.clone())).collect();
        Self { proxies: Arc::new(proxies), entries }
    }
}

pub type ProviderRegistry = Arc<ArcSwap<ProviderSnapshot>>;
