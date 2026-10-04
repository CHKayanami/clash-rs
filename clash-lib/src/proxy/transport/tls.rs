use async_trait::async_trait;
use serde::Serialize;
use std::{
    io,
    sync::{Arc, LazyLock, atomic::AtomicBool},
};
use tracing::warn;

use super::{SplicableTlsStream, Transport, VisionOptions};
use crate::{
    common::{
        errors::map_io_error,
        tls::{
            boring::BoringTlsConnector,
            build_tls_client_config,
            parse_fingerprint_sha256,
            validate_alpn,
            DefaultTlsVerifier,
        },
    },
    proxy::AnyStream,
};

#[derive(Serialize, Clone, Default)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub fingerprint: Option<String>,
    pub client_fingerprint: Option<String>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls_key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls_cert`.
    pub tls_key: Option<String>,
}

impl TryFrom<TLSOptions> for Client {
    type Error = io::Error;

    fn try_from(opt: TLSOptions) -> Result<Self, Self::Error> {
        Client::new_advanced(
            opt.skip_cert_verify,
            opt.sni,
            opt.alpn,
            None,
            opt.fingerprint.as_deref(),
            opt.client_fingerprint.as_deref(),
            opt.tls_cert.as_deref(),
            opt.tls_key.as_deref(),
        )
    }
}

#[derive(Clone)]
enum ConnectorBackend {
    Rustls(Arc<RustlsBackend>),
    Boring(BoringTlsConnector),
}

struct RustlsBackend {
    connector: tokio_rustls::TlsConnector,
    spliced: SplicedConnector,
}

type SplicedConnector = LazyLock<io::Result<BoringTlsConnector>,
    Box<dyn FnOnce() -> io::Result<BoringTlsConnector> + Send + Sync>>;

impl RustlsBackend {
    fn spliced_connector(&self) -> io::Result<&BoringTlsConnector> {
        self.spliced.as_ref().map_err(|e| io::Error::new(e.kind(), e.to_string()))
    }
}

#[derive(Clone)]
pub struct Client {
    pub sni: String,
    pub expected_alpn: Option<String>,
    backend: ConnectorBackend,
}

impl Client {
    /// Create a standard TLS client using rustls backend.
    pub fn new(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Self> {
        Self::new_advanced(
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
            None,
            None,
            tls_cert,
            tls_key,
        )
    }

    /// Create a TLS client with optional certificate pinning and browser fingerprinting.
    pub fn new_advanced(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        fingerprint: Option<&str>,
        client_fingerprint: Option<&str>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Self> {
        if let Some(protocols) = &alpn {
            validate_alpn(protocols)?;
        }
        if fingerprint.is_some_and(|pin| parse_fingerprint_sha256(pin).is_none()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "invalid certificate fingerprint (expected SHA-256 hex)"));
        }
        if let Some(fp) = client_fingerprint {
            let fp_lower = fp.trim().to_ascii_lowercase();
            if !fp_lower.is_empty() && fp_lower != "none" {
                if !fp_lower.starts_with("chrome") && fp_lower != "utls" {
                    warn!(
                        "client-fingerprint '{}' mapped to Chrome uTLS profile",
                        fp
                    );
                }
                let boring_connector = BoringTlsConnector::new(
                    true,
                    skip_cert_verify,
                    fingerprint,
                    alpn.as_deref(),
                    tls_cert,
                    tls_key,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

                return Ok(Self {
                    sni,
                    expected_alpn,
                    backend: ConnectorBackend::Boring(boring_connector),
                });
            }
        }

        let verifier = Arc::new(DefaultTlsVerifier::new(
            fingerprint.map(ToOwned::to_owned),
            skip_cert_verify,
        ));
        let mut tls_config = build_tls_client_config(verifier, tls_cert, tls_key)?;

        tls_config.alpn_protocols = alpn.as_deref().unwrap_or_default()
            .iter()
            .map(|x| x.as_bytes().to_vec())
            .collect();

        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let fingerprint = fingerprint.map(ToOwned::to_owned);
        let tls_cert = tls_cert.map(ToOwned::to_owned);
        let tls_key = tls_key.map(ToOwned::to_owned);
        // LazyLock consumes the initializer after use, releasing the copied
        // PEM/config strings once the shared BoringSSL context exists.
        let spliced: SplicedConnector = LazyLock::new(Box::new(move || {
            BoringTlsConnector::new(
                false, skip_cert_verify, fingerprint.as_deref(),
                alpn.as_deref(), tls_cert.as_deref(), tls_key.as_deref(),
            ).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
        }));

        Ok(Self {
            sni,
            expected_alpn,
            backend: ConnectorBackend::Rustls(Arc::new(RustlsBackend {
                connector,
                spliced,
            })),
        })
    }

    fn check_alpn(&self, negotiated: Option<&[u8]>) -> io::Result<()> {
        if let Some(expected) = &self.expected_alpn
            && negotiated != Some(expected.as_bytes())
        {
            return Err(io::Error::other(format!(
                "unexpected alpn protocol: {:?}, expected: {:?}",
                negotiated, expected
            )));
        }
        Ok(())
    }

    async fn connect_boring(
        &self,
        connector: &BoringTlsConnector,
        stream: AnyStream,
    ) -> io::Result<tokio_boring::SslStream<AnyStream>> {
        let tls = connector.connect(&self.sni, stream).await?;
        self.check_alpn(tls.ssl().selected_alpn_protocol())?;
        Ok(tls)
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream_spliced(
        &self,
        stream: AnyStream,
    ) -> io::Result<(AnyStream, Option<VisionOptions>)> {
        // Vision needs access to raw IO after CMD_PADDING_DIRECT, including
        // when browser fingerprinting is disabled.
        let connector = match &self.backend {
            ConnectorBackend::Boring(connector) => connector,
            ConnectorBackend::Rustls(backend) => backend.spliced_connector()?,
        };
        let tls = self.connect_boring(connector, stream).await?;
        let read_flag = Arc::new(AtomicBool::new(false));
        let write_flag = Arc::new(AtomicBool::new(false));
        let tls = SplicableTlsStream::new(tls, read_flag.clone(), write_flag.clone());
        Ok((AnyStream::new(tls), Some(VisionOptions { read_flag, write_flag })))
    }

    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        match &self.backend {
            ConnectorBackend::Rustls(backend) => {
                let dns_name =
                    rustls::pki_types::ServerName::try_from(self.sni.as_str().to_owned())
                        .map_err(map_io_error)?;

                let c = backend.connector
                    .connect(dns_name, stream)
                    .await?;
                self.check_alpn(c.get_ref().1.alpn_protocol())?;
                Ok(AnyStream::new(c))
            }
            ConnectorBackend::Boring(connector) => {
                let s = self.connect_boring(connector, stream).await?;
                Ok(AnyStream::new(s))
            }
        }
    }
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
