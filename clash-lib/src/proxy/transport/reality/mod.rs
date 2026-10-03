//! REALITY transport layer module.
//!
//! Provides the REALITY client implementation with BoringSSL hooks and
//! XTLS-Vision Direct splice capability.

mod handshake;
mod splice;

use std::{
    io,
    sync::{
        Arc,
        atomic::AtomicBool,
    },
};

use async_trait::async_trait;

use crate::{common::tls::validate_alpn,
    proxy::{AnyStream, transport::Transport}};

use handshake::reality_connect;
pub use splice::{SplicableTlsStream, VisionOptions};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Parsed REALITY handshake parameters for one node.
#[derive(Clone, Debug)]
struct RealityConfig {
    /// Server's X25519 public key (32 bytes).
    public_key: [u8; 32],
    /// Short ID, right-zero-padded to 8 bytes.
    short_id: [u8; 8],
    /// SNI sent in the ClientHello.
    server_name: String,
    /// Explicit ALPN override; `None` keeps the fingerprint defaults.
    alpn: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Reality Client (Transport implementation)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

struct ClientInner {
    config: RealityConfig,
    chrome: bool,
}

impl Client {
    pub fn new(
        sni: String,
        public_key: [u8; 32],
        short_id: [u8; 8],
        chrome: bool,
        alpn: Option<Vec<String>>,
    ) -> io::Result<Self> {
        if let Some(protocols) = &alpn {
            validate_alpn(protocols)?;
        }
        if sni.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput, "SNI hostname cannot be empty",
            ));
        }
        let config = RealityConfig { public_key, short_id, server_name: sni, alpn };
        Ok(Self(Arc::new(ClientInner {
            config,
            chrome,
        })))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let tls = reality_connect(stream, &self.0.config, self.0.chrome).await?;
        Ok(AnyStream::new(tls))
    }

    async fn proxy_stream_spliced(
        &self,
        stream: AnyStream,
    ) -> io::Result<(AnyStream, Option<VisionOptions>)> {
        let tls = reality_connect(stream, &self.0.config, self.0.chrome).await?;
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
        Ok((AnyStream::new(splicable), Some(opts)))
    }
}
