//! REALITY transport layer module.
//!
//! Provides the REALITY client implementation with BoringSSL hooks and
//! XTLS-Vision Direct splice capability.

mod handshake;
mod splice;

use std::{
    io,
    ops::Deref,
    sync::{
        Arc,
        atomic::AtomicBool,
    },
};

use async_trait::async_trait;

use crate::proxy::{AnyStream, transport::Transport};

pub use handshake::reality_connect;
pub use splice::{SplicableTlsStream, VisionOptions};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Parsed REALITY handshake parameters for one node.
#[derive(Clone, Debug)]
pub struct RealityConfig {
    /// Server's X25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// Short ID, right-zero-padded to 8 bytes.
    pub short_id: [u8; 8],
    /// SNI sent in the ClientHello.
    pub server_name: String,
}

impl RealityConfig {
    pub fn new(server_name: String, public_key: [u8; 32], short_id: [u8; 8]) -> Self {
        Self {
            public_key,
            short_id,
            server_name,
        }
    }
}

// ---------------------------------------------------------------------------
// Reality Client (Transport implementation)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

pub struct ClientInner {
    pub config: RealityConfig,
    pub chrome: bool,
}

impl Client {
    #[allow(dead_code)]
    pub fn new(sni: String, public_key: [u8; 32], short_id: Vec<u8>) -> Self {
        Self::new_advanced(sni, public_key, short_id, true)
    }

    pub fn new_advanced(
        sni: String,
        public_key: [u8; 32],
        short_id: Vec<u8>,
        chrome: bool,
    ) -> Self {
        let mut short_id_arr = [0u8; 8];
        let copy_len = std::cmp::min(short_id.len(), 8);
        short_id_arr[..copy_len].copy_from_slice(&short_id[..copy_len]);

        Self(Arc::new(ClientInner {
            config: RealityConfig::new(sni, public_key, short_id_arr),
            chrome,
        }))
    }
}

impl Deref for Client {
    type Target = ClientInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        if self.config.server_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SNI hostname cannot be empty",
            ));
        }

        let tls = reality_connect(stream, &self.config, self.chrome).await?;
        Ok(Box::new(tls) as AnyStream)
    }

    async fn proxy_stream_spliced(
        &self,
        stream: AnyStream,
    ) -> io::Result<(AnyStream, Option<VisionOptions>)> {
        if self.config.server_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SNI hostname cannot be empty",
            ));
        }

        let tls = reality_connect(stream, &self.config, self.chrome).await?;
        let read_flag = Arc::new(AtomicBool::new(false));
        let write_flag = Arc::new(AtomicBool::new(false));
        let splicable = SplicableTlsStream::new(
            tls,
            Arc::clone(&read_flag),
            Arc::clone(&write_flag),
        );
        let opts = VisionOptions {
            read_flag,
            write_flag,
        };
        Ok((Box::new(splicable) as AnyStream, Some(opts)))
    }
}
