use std::collections::HashMap;
use std::sync::Arc;
use arc_swap::ArcSwap;

use crate::proxy::AnyOutboundHandler;

pub type OutboundHandlerRegistry = Arc<ArcSwap<HashMap<String, AnyOutboundHandler>>>;
