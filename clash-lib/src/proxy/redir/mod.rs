use crate::runner::ListenerReady;
use crate::proxy::AnyStream;
use super::inbound::InboundHandlerTrait;
use crate::{
    app::dispatcher::Dispatcher,
    common::errors::new_io_error,
    proxy::utils::{
        ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener,
        get_original_destination_addr,
    },
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use tracing::{trace, warn};

pub struct RedirInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
}

impl Drop for RedirInbound {
    fn drop(&mut self) {
        warn!("Redir inbound listener on {} stopped", self.addr);
    }
}

impl RedirInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for RedirInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self, ready: ListenerReady) -> std::io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;

        ready.notify();

        loop {
            let (socket, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("redir inbound accept error: {e}");
                    continue;
                }
            };
            let src_addr = peer_addr.to_canonical();

            let local_addr = match socket.local_addr() {
                Ok(addr) => addr.to_canonical(),
                Err(e) => {
                    warn!("redir failed to get local address for {src_addr}: {e}");
                    continue;
                }
            };

            if !self.allow_lan && src_addr.ip() != local_addr.ip() {
                warn!("Connection from {} is not allowed", src_addr);
                continue;
            }

            if let Err(e) = apply_tcp_options(&socket) {
                warn!("redir failed to apply tcp options for {src_addr}: {e}");
                continue;
            }

            // get redirect traffic original destination
            let orig_dst = match get_original_destination_addr(&socket) {
                Ok(addr) => addr.to_canonical(),
                Err(e) => {
                    warn!(
                        "redir failed to get original destination for {src_addr}: {e}"
                    );
                    continue;
                }
            };

            // SO_ORIGINAL_DST also returns a destination for connections that
            // were not redirected. Dispatching one aimed at this listener
            // would connect straight back to it and repeat indefinitely.
            if orig_dst == local_addr {
                warn!(
                    "redir rejected connection from {src_addr} to its own listener at {orig_dst}"
                );
                continue;
            }

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Redir,
                source: src_addr,
                destination: orig_dst.into(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            trace!("redir new tcp conn {}", sess);

            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                dispatcher
                    .dispatch_stream(sess, AnyStream::Tcp(socket))
                    .await;
            });
        }
    }

    async fn listen_udp(&self, _ready: ListenerReady) -> std::io::Result<()> {
        Err(new_io_error("unsupported UDP protocol for Redir inbound"))
    }
}
