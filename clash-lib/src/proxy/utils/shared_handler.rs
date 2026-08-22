use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

use crate::proxy::AnyOutboundHandler;

pub type OutboundHandlerRegistry = Arc<RwLock<HashMap<String, AnyOutboundHandler>>>;
