mod auth;
mod connector;
mod proxy;

use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    proxy::{
        inbound::{InboundHandlerTrait, accept_tcp},
        utils::try_create_dualstack_tcplistener,
    },
};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
pub use proxy::handle as handle_http;
use std::{net::SocketAddr, sync::Arc};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct HttpInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
}

impl Drop for HttpInbound {
    fn drop(&mut self) {
        debug!("HTTP inbound listener on {} stopped", self.addr);
    }
}

impl HttpInbound {
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
impl InboundHandlerTrait for HttpInbound {
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
                    warn!("http inbound accept error: {e}");
                    continue;
                }
            };
            let Some(src_addr) =
                accept_tcp(&socket, peer_addr, self.allow_lan, "http inbound")
            else {
                continue;
            };

            let dispatcher = self.dispatcher.clone();
            let author = self.authenticator.clone();
            let fw_mark = self.fw_mark;
            tokio::spawn(async move {
                proxy::handle(
                    TokioIo::new(Box::new(socket)),
                    src_addr,
                    dispatcher,
                    author,
                    fw_mark,
                )
                .await
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(new_io_error("unsupported UDP protocol for HTTP inbound"))
    }
}
