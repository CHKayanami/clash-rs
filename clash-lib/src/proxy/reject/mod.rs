use crate::{
    app::dns::ThreadSafeDNSResolver,
    config::internal::proxy::PROXY_REJECT,
    proxy::{AnyOutboundDatagram, AnyStream, OutboundHandler},
    session::Session,
};
use erased_serde::Serialize as ErasedSerialize;
use serde::Serialize;
use std::{collections::HashMap, io};

use super::{DialWithConnector, OutboundType, PlainProxyAPIResponse};

#[derive(Serialize)]
pub struct Handler {
    pub name: String,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reject").field("name", &self.name).finish()
    }
}

impl Handler {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

impl DialWithConnector for Handler {}

impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_REJECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Reject
    }

    fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        Err(io::Error::other("REJECT"))
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        Err(io::Error::other("REJECT"))
    }



}

impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::new()
    }
}
