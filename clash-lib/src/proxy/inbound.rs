use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::warn;

use crate::proxy::utils::{ToCanonical, apply_tcp_options};

#[async_trait]
pub trait InboundHandlerTrait: Sync + Send {
    /// support tcp or not
    fn handle_tcp(&self) -> bool;
    /// support udp or not
    fn handle_udp(&self) -> bool;
    async fn listen_tcp(&self) -> std::io::Result<()>;
    async fn listen_udp(&self) -> std::io::Result<()>;
}

/// Accept-time gate shared by every TCP inbound.
///
/// Canonicalizes the peer address, enforces `allow_lan`, and applies the
/// standard socket options. Returns the canonical source address, or `None` if
/// the connection was rejected and should be dropped.
///
/// Note this rejects after `accept()` rather than by binding to loopback — the
/// listen address stays exactly what the config asked for.
pub(crate) fn accept_tcp(
    socket: &TcpStream,
    peer_addr: SocketAddr,
    allow_lan: bool,
    who: &str,
) -> Option<SocketAddr> {
    let src_addr = peer_addr.to_canonical();

    let local_ip = match socket.local_addr() {
        Ok(addr) => addr.ip().to_canonical(),
        Err(e) => {
            warn!("{who} failed to get local address for {src_addr}: {e}");
            return None;
        }
    };

    if !allow_lan && src_addr.ip() != local_ip {
        warn!("{who}: connection from {src_addr} is not allowed");
        return None;
    }

    if let Err(e) = apply_tcp_options(socket) {
        warn!("{who} failed to apply tcp options for {src_addr}: {e}");
        return None;
    }

    Some(src_addr)
}
