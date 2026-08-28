use async_trait::async_trait;
use serde::Serialize;
use std::{io, sync::Arc};
use tracing::warn;

use super::Transport;
use crate::{
    common::{
        errors::map_io_error,
        tls::{
            boring::BoringTlsConnector,
            build_tls_client_config,
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

enum ConnectorBackend {
    Rustls(tokio_rustls::TlsConnector),
    Boring(BoringTlsConnector),
}

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

        tls_config.alpn_protocols = alpn
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.as_bytes().to_vec())
            .collect();

        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            sni,
            expected_alpn,
            backend: ConnectorBackend::Rustls(connector),
        })
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        match &self.backend {
            ConnectorBackend::Rustls(connector) => {
                let dns_name =
                    rustls::pki_types::ServerName::try_from(self.sni.as_str().to_owned())
                        .map_err(map_io_error)?;

                let c = connector
                    .connect(dns_name, stream)
                    .await
                    .and_then(|x| {
                        if let Some(expected_alpn) = self.expected_alpn.as_ref()
                            && x.get_ref().1.alpn_protocol()
                                != Some(expected_alpn.as_bytes())
                        {
                            return Err(io::Error::other(format!(
                                "unexpected alpn protocol: {:?}, expected: {:?}",
                                x.get_ref().1.alpn_protocol(),
                                expected_alpn
                            )));
                        }

                        Ok(x)
                    })?;
                Ok(Box::new(c) as _)
            }
            ConnectorBackend::Boring(connector) => {
                let s = connector.connect(&self.sni, stream).await.and_then(|x| {
                    if let Some(expected_alpn) = self.expected_alpn.as_ref()
                        && x.ssl().selected_alpn_protocol() != Some(expected_alpn.as_bytes())
                    {
                        return Err(io::Error::other(format!(
                            "unexpected alpn protocol: {:?}, expected: {:?}",
                            x.ssl().selected_alpn_protocol(),
                            expected_alpn
                        )));
                    }

                    Ok(x)
                })?;
                Ok(Box::new(s) as _)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::ssl::{SslAcceptor, SslMethod, SslStream};
    use boring::x509::X509;
    use std::net::TcpListener;
    use std::thread;
    use tokio::io::AsyncWriteExt;

    fn generate_test_cert() -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn spawn_server(cert_pem: &str, key_pem: &str) -> (u16, thread::JoinHandle<Vec<u8>>) {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        let pkey = boring::pkey::PKey::private_key_from_pem(key_pem.as_bytes()).unwrap();
        acceptor.set_private_key(&pkey).unwrap();
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
            use std::io::Read;
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).ok();
            buf
        });
        (port, handle)
    }

    #[tokio::test]
    async fn test_transport_tls_client_chrome_fingerprint() {
        let (cert, key) = generate_test_cert();
        let (port, server) = spawn_server(&cert, &key);

        let opts = TLSOptions {
            skip_cert_verify: true,
            sni: "localhost".to_string(),
            alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
            client_fingerprint: Some("chrome".to_string()),
            ..Default::default()
        };

        let client: Client = opts.try_into().unwrap();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream = client.proxy_stream(Box::new(tcp)).await.unwrap();

        stream.write_all(b"ping from chrome").await.unwrap();
        stream.shutdown().await.unwrap();

        let received = server.join().unwrap();
        assert_eq!(received, b"ping from chrome");
    }
}
