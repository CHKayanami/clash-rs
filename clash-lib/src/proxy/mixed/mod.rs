use crate::{
    Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    proxy::utils::try_create_dualstack_tcplistener,
    session::{Network, Session},
};

use super::{
    http,
    inbound::{InboundHandlerTrait, accept_tcp},
    socks,
};
use crate::common::errors::new_io_error;
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{debug, warn};

/// Bound on how long a connection may sit accepted without revealing which
/// protocol it speaks.
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);

pub struct MixedInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
}

impl Drop for MixedInbound {
    fn drop(&mut self) {
        debug!("MixedPort inbound listener on {} stopped", self.addr);
    }
}

impl MixedInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for MixedInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;

        loop {
            let (socket, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("failed to accept socket on {}: {:?}", self.addr, e);
                    continue;
                }
            };

            let Some(src_addr) =
                accept_tcp(&socket, peer_addr, self.allow_lan, "mixed inbound")
            else {
                continue;
            };

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();
            let fw_mark = self.fw_mark;
            let listen_addr = self.addr;

            // The protocol sniff reads from the client, so it must happen in the
            // spawned task. Peeking here would let one connection that never
            // sends a byte stall the whole accept loop.
            tokio::spawn(async move {
                let mut p = [0; 1];
                let n = match tokio::time::timeout(PEEK_TIMEOUT, socket.peek(&mut p))
                    .await
                {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        warn!(
                            "failed to peek socket on mixed listener {}: {:?}",
                            listen_addr, e
                        );
                        return;
                    }
                    Err(_) => {
                        warn!(
                            "timed out peeking {src_addr} on mixed listener {}",
                            listen_addr
                        );
                        return;
                    }
                };
                if n != 1 {
                    warn!("failed to peek socket on mixed listener {}", listen_addr);
                    return;
                }

                match p[0] {
                    socks::SOCKS5_VERSION => {
                        let mut sess = Session {
                            network: Network::Tcp,
                            source: src_addr,
                            so_mark: fw_mark,
                            ..Default::default()
                        };

                        let _ = socks::inbound::handle_tcp(
                            &mut sess,
                            socket,
                            dispatcher,
                            authenticator,
                        )
                        .await;
                    }

                    _ => {
                        http::handle_http(
                            TokioIo::new(Box::new(socket) as _),
                            src_addr,
                            dispatcher,
                            authenticator,
                            fw_mark,
                        )
                        .await;
                    }
                }
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(new_io_error("UDP is not supported"))
    }
}
