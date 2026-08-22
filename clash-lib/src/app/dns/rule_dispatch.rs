use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use crate::app::dns::endpoint::DnsEndpoint;
use crate::app::{outbound::manager::ThreadSafeOutboundManager, router::ArcRouter};
use crate::proxy::AnyOutboundHandler;
use crate::session::{Network, Session, SocksAddr, Type};

/// Late-bound reference to `Router`. Populated by `lib.rs` after the router
/// is constructed; the DNS resolver itself is built earlier.
pub type PendingRouter = Arc<OnceLock<ArcRouter>>;

/// Late-bound reference to `OutboundManager`. Populated by `lib.rs` after the
/// outbound manager is constructed.
pub type PendingOutboundManager = Arc<OnceLock<ThreadSafeOutboundManager>>;

/// Bundle of late-bound handles consulted by DNS upstreams when
/// `dns.respect-rules` is enabled, allowing upstream DNS dials to be routed
/// through the rule engine.
///
/// Both `OnceLock`s start empty and are filled exactly once during startup.
/// Until both are set, callers fall back to the static `outbound` handler —
/// this keeps early DNS lookups (during startup before the rule engine
/// exists) working.
pub struct RuleDispatch {
    pub router: PendingRouter,
    pub outbound_manager: PendingOutboundManager,
}

impl RuleDispatch {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            router: Arc::new(OnceLock::new()),
            outbound_manager: Arc::new(OnceLock::new()),
        })
    }

    pub async fn resolve_outbound(
        &self,
        endpoint: &DnsEndpoint,
        network: Network,
    ) -> Option<AnyOutboundHandler> {
        let router = self.router.get()?.clone();
        let outbound_manager = self.outbound_manager.get()?.clone();

        let dst = if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
            SocksAddr::from((ip, endpoint.port))
        } else {
            SocksAddr::Domain(endpoint.host.clone(), endpoint.port)
        };

        let mut sess = Session {
            destination: dst,
            network,
            typ: Type::Ignore,
            ..Default::default()
        };

        let (target, _) = router.match_route(&mut sess).await;
        outbound_manager.get_outbound(&target)
    }
}
