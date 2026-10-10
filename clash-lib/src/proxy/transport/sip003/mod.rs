use std::{future::Future, io};
use super::Transport;
use crate::proxy::AnyStream;

pub trait Plugin: Send + Sync {
    fn proxy_stream(&self, stream: AnyStream) -> impl Future<Output = io::Result<AnyStream>> + Send;
}

impl<T: Transport> Plugin for T {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        Transport::proxy_stream(self, stream).await
    }
}
