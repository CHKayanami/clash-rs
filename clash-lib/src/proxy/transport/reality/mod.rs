use async_trait::async_trait;
use std::{
    io,
    ops::Deref,
    sync::{Arc, atomic::AtomicBool},
};

use crate::proxy::{
    AnyStream,
    transport::{Transport, VisionOptions, splice_tls::SplicableTlsStream},
};

pub mod aead;
pub mod auth;
pub mod cipher_suite;
pub mod client_connection;
pub mod client_verify;
pub mod common;
pub mod stream;
pub mod tls13_keys;
pub mod tls13_messages;

pub use client_connection::{RealityClientConfig, RealityClientConnection};
pub use stream::RealityTlsStream;

#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

impl Client {
    pub fn new(sni: String, public_key: [u8; 32], short_id: Vec<u8>) -> Self {
        Self(Arc::new(ClientInner {
            sni,
            public_key,
            short_id,
        }))
    }
}

impl Deref for Client {
    type Target = ClientInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Client {
    pub async fn connect_tls(
        &self,
        stream: AnyStream,
    ) -> io::Result<RealityTlsStream> {
        if self.short_id.len() > 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "short_id cannot exceed 8 bytes",
            ));
        }

        if self.sni.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SNI hostname cannot be empty",
            ));
        }

        let mut short_id_arr = [0u8; 8];
        let copy_len = std::cmp::min(self.short_id.len(), 8);
        short_id_arr[..copy_len].copy_from_slice(&self.short_id[..copy_len]);

        let config = RealityClientConfig {
            public_key: self.public_key,
            short_id: short_id_arr,
            server_name: self.sni.clone(),
            cipher_suites: vec![],
        };

        let conn = RealityClientConnection::new(config)?;
        Ok(RealityTlsStream::new(stream, conn))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        self.connect_tls(stream)
            .await
            .map(|x| Box::new(x) as AnyStream)
    }

    async fn proxy_stream_spliced(
        &self,
        stream: AnyStream,
    ) -> io::Result<(AnyStream, Option<VisionOptions>)> {
        let read_flag = Arc::new(AtomicBool::new(false));
        let write_flag = Arc::new(AtomicBool::new(false));
        let tls_stream = self.connect_tls(stream).await?;
        let splittable = SplicableTlsStream::new(
            tls_stream,
            Arc::clone(&read_flag),
            Arc::clone(&write_flag),
        );
        let opts = VisionOptions {
            read_flag,
            write_flag,
        };
        Ok((Box::new(splittable), Some(opts)))
    }
}

pub struct ClientInner {
    sni: String,
    public_key: [u8; 32],
    short_id: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stream() -> AnyStream {
        let (client, _server) = tokio::io::duplex(1024);
        Box::new(client)
    }

    #[test]
    fn test_new() {
        let c = Client::new("example.com".to_string(), [1u8; 32], vec![0xab, 0xcd]);
        assert_eq!(c.sni, "example.com");
        assert_eq!(c.public_key, [1u8; 32]);
        assert_eq!(c.short_id, vec![0xab, 0xcd]);
    }

    #[tokio::test]
    async fn test_short_id_too_long() {
        let c = Client::new("example.com".to_string(), [0u8; 32], vec![0u8; 9]);
        let err = c.proxy_stream(make_stream()).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_invalid_sni() {
        let c = Client::new("".to_string(), [0u8; 32], vec![0u8; 4]);
        let err = c.proxy_stream(make_stream()).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
