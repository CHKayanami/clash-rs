//! BoringSSL TLS client — real Chrome fingerprint (uTLS-grade).
//!
//! Replicates real Chrome ClientHello: GREASE, permuted extensions,
//! X25519MLKEM768 hybrid key share, ALPS, brotli certificate compression,
//! and ECH GREASE.

use std::io;
use std::sync::LazyLock;

use anyhow::Context as _;
use boring::error::ErrorStack;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
    SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use boring::x509::store::{X509Store, X509StoreBuilder};
use foreign_types::ForeignTypeRef;

// Chrome's TLS 1.3 signature-algorithm list (order matters).
pub const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
     ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
     rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
// Chrome 131+: MLKEM hybrid first. Requires boring's `mlkem` feature.
pub const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";
pub const CHROME_ALPN_WIRE: &[u8] = b"\x02h2\x08http/1.1";
#[allow(dead_code)]
pub const HTTP11_ALPN_WIRE: &[u8] = b"\x08http/1.1";

/// Chrome's TLS 1.2 cipher list (TLS 1.3 ciphers are implicit and always lead).
pub const CHROME_CIPHER_LIST: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:\
     ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
     ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
     ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
     AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

// BoringSSL group IDs (ssl.h) for SSL_set1_client_key_shares: Chrome sends
// exactly two shares, MLKEM hybrid then X25519.
const SSL_GROUP_X25519_MLKEM768: u16 = 0x11ec;
const SSL_GROUP_X25519: u16 = 29;

/// Brotli certificate-compression algorithm (RFC 8879), as advertised by Chrome.
pub struct BrotliCertCompression;

impl CertificateCompressor for BrotliCertCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: io::Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut writer = brotli::CompressorWriter::new(output, 4096, 5, 22);
        io::Write::write_all(&mut writer, input)
    }

    fn decompress<W: io::Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut reader = brotli::Decompressor::new(input, 4096);
        io::copy(&mut reader, output)?;
        Ok(())
    }
}

/// Mozilla root CAs (full DER certs) loaded into a BoringSSL store.
pub fn root_store() -> Result<X509Store, ErrorStack> {
    static ROOT_STORE: LazyLock<Option<X509Store>> =
        LazyLock::new(|| build_root_store().ok());
    match &*ROOT_STORE {
        Some(store) => Ok(store.clone()),
        None => build_root_store(),
    }
}

fn build_root_store() -> Result<X509Store, ErrorStack> {
    let mut builder = X509StoreBuilder::new()?;
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(cert) = X509::from_der(der.as_ref()) {
            builder.add_cert(cert)?;
        }
    }
    Ok(builder.build())
}

/// Chrome sends two key shares: X25519MLKEM768 and X25519, in that order.
fn set_chrome_key_shares(cfg: &mut ConnectConfiguration) -> anyhow::Result<()> {
    let ssl: &boring::ssl::SslRef = cfg;
    let shares = [SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519];
    let ok = unsafe {
        boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_key_shares");
    }
    Ok(())
}

/// Chrome sends ALPS for h2 with an empty settings payload whenever ALPN
/// offers h2. Chrome uses the old ALPS codepoint (0x4469) on TCP+h2.
fn add_chrome_alps(cfg: &mut ConnectConfiguration) -> anyhow::Result<()> {
    let ssl: &boring::ssl::SslRef = cfg;
    let ok = unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 0);
        boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            b"h2".as_ptr(),
            2,
            std::ptr::null(),
            0,
        )
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_add_application_settings");
    }
    Ok(())
}

/// Parse a SHA-256 fingerprint value (hex, optionally colon-separated) into 32 bytes.
pub fn parse_fingerprint_sha256(s: &str) -> Option<[u8; 32]> {
    let hex: String = s
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Custom verify callback matching the peer leaf certificate's SHA-256
pub fn pin_sha256_custom_verify(
    pin: [u8; 32],
) -> impl Fn(&mut boring::ssl::SslRef) -> Result<(), boring::ssl::SslVerifyError> + Send + Sync + 'static
{
    move |ssl| {
        let matches = ssl
            .peer_certificate()
            .and_then(|cert| cert.digest(boring::hash::MessageDigest::sha256()).ok())
            .is_some_and(|digest| digest.as_ref() == pin);
        if matches {
            Ok(())
        } else {
            Err(boring::ssl::SslVerifyError::Invalid(
                boring::ssl::SslAlert::BAD_CERTIFICATE,
            ))
        }
    }
}

pub fn apply_chrome_ctx(builder: &mut SslContextBuilder) -> anyhow::Result<()> {
    builder.set_grease_enabled(true);
    builder.set_sigalgs_list(CHROME_SIGALGS)?;
    builder.set_curves_list(CHROME_CURVES)?;
    builder.set_cipher_list(CHROME_CIPHER_LIST)?;
    builder.add_certificate_compression_algorithm(BrotliCertCompression)?;
    Ok(())
}

pub fn add_chrome_alps_public(cfg: &mut ConnectConfiguration) -> anyhow::Result<()> {
    add_chrome_alps(cfg)
}

pub fn build_reality_connector(chrome: bool) -> anyhow::Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_verify(SslVerifyMode::NONE);
    if chrome {
        apply_chrome_ctx(&mut builder)?;
        builder.set_cipher_list(CHROME_CIPHER_LIST)?;
        builder.set_alpn_protos(CHROME_ALPN_WIRE)?;
        builder.enable_ocsp_stapling();
        builder.enable_signed_cert_timestamps();
    }
    Ok(builder.build())
}

static REALITY_CONNECTOR_CHROME: LazyLock<anyhow::Result<SslConnector>> =
    LazyLock::new(|| build_reality_connector(true));

static REALITY_CONNECTOR_PLAIN: LazyLock<anyhow::Result<SslConnector>> =
    LazyLock::new(|| build_reality_connector(false));

pub fn get_reality_connector(chrome: bool) -> anyhow::Result<&'static SslConnector> {
    if chrome {
        REALITY_CONNECTOR_CHROME
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e}"))
    } else {
        REALITY_CONNECTOR_PLAIN
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// BoringSSL connector carrying Chrome fingerprint settings and certificate options.
#[derive(Clone)]
pub struct BoringTlsConnector {
    connector: SslConnector,
    chrome: bool,
    alps: bool,
}

impl BoringTlsConnector {
    pub fn new(
        chrome: bool,
        skip_cert_verify: bool,
        fingerprint: Option<&str>,
        alpn: Option<&[String]>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> anyhow::Result<Self> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        let pin = match fingerprint {
            Some(s) => Some(parse_fingerprint_sha256(s).ok_or_else(|| {
                anyhow::anyhow!("invalid certificate fingerprint (expected 64 hex chars)")
            })?),
            None => None,
        };

        if skip_cert_verify || pin.is_some() {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
            builder.set_verify_cert_store(root_store()?)?;
        }

        if let Some(pin) = pin {
            builder.set_custom_verify_callback(SslVerifyMode::PEER, pin_sha256_custom_verify(pin));
        }

        // mTLS client certificates
        if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
            if cert.contains("-----BEGIN") {
                let x509 = X509::from_pem(cert.as_bytes())?;
                builder.set_certificate(&x509)?;
            } else {
                builder.set_certificate_file(cert, SslFiletype::PEM)?;
            }

            if key.contains("-----BEGIN") {
                let pkey = boring::pkey::PKey::private_key_from_pem(key.as_bytes())?;
                builder.set_private_key(&pkey)?;
            } else {
                builder.set_private_key_file(key, SslFiletype::PEM)?;
            }
        }

        let mut offers_h2 = false;
        if chrome {
            apply_chrome_ctx(&mut builder)?;
            if let Some(alpn_list) = alpn {
                let mut wire = Vec::new();
                for proto in alpn_list {
                    if proto == "h2" {
                        offers_h2 = true;
                    }
                    let bytes = proto.as_bytes();
                    if bytes.len() <= 255 {
                        wire.push(bytes.len() as u8);
                        wire.extend_from_slice(bytes);
                    }
                }
                builder.set_alpn_protos(&wire)?;
            } else {
                builder.set_alpn_protos(CHROME_ALPN_WIRE)?;
                offers_h2 = true;
            }
        } else if let Some(alpn_list) = alpn {
            let mut wire = Vec::new();
            for proto in alpn_list {
                let bytes = proto.as_bytes();
                if bytes.len() <= 255 {
                    wire.push(bytes.len() as u8);
                    wire.extend_from_slice(bytes);
                }
            }
            builder.set_alpn_protos(&wire)?;
        }

        Ok(Self {
            connector: builder.build(),
            chrome,
            alps: chrome && offers_h2,
        })
    }

    fn configuration(&self) -> anyhow::Result<ConnectConfiguration> {
        let mut cfg = self.connector.configure()?;
        if self.chrome {
            cfg.set_permute_extensions(true);
            set_chrome_key_shares(&mut cfg)?;
            if self.alps {
                add_chrome_alps(&mut cfg)?;
            }
            cfg.set_enable_ech_grease(true);
        }
        Ok(cfg)
    }

    pub async fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> io::Result<tokio_boring::SslStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let cfg = self
            .configuration()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        tokio_boring::connect(cfg, domain, stream).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("BoringSSL TLS handshake with {domain} failed: {e}"),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::ssl::{SslAcceptor, SslStream};
    use std::net::TcpListener;
    use std::thread;
    use tokio::io::AsyncWriteExt;

    fn generate_test_cert() -> (String, String, [u8; 32]) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_der = cert.der().to_vec();
        let hash = boring::hash::hash(boring::hash::MessageDigest::sha256(), &cert_der).unwrap();
        let mut pin = [0u8; 32];
        pin.copy_from_slice(hash.as_ref());
        (cert.pem(), key.serialize_pem(), pin)
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

    #[test]
    fn test_brotli_compression() {
        let compressor = BrotliCertCompression;
        let original = b"Chrome uTLS Brotli Certificate Compression Test Data 123456789";
        let mut compressed = Vec::new();
        compressor.compress(&original[..], &mut compressed).unwrap();
        assert!(!compressed.is_empty());

        let mut decompressed = Vec::new();
        compressor.decompress(&compressed[..], &mut decompressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[tokio::test]
    async fn test_boring_chrome_handshake() {
        let (cert, key, _) = generate_test_cert();
        let (port, server) = spawn_server(&cert, &key);

        let connector = BoringTlsConnector::new(
            true, // chrome mode
            true, // skip cert verify for self-signed
            None,
            Some(&["h2".to_string(), "http/1.1".to_string()]),
            None,
            None,
        )
        .unwrap();

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls = connector.connect("localhost", tcp).await.unwrap();

        tls.write_all(b"hello chrome").await.unwrap();
        tls.shutdown().await.unwrap();

        let received = server.join().unwrap();
        assert_eq!(received, b"hello chrome");
    }

    #[tokio::test]
    async fn test_boring_pin_sha256_verification() {
        let (cert, key, pin) = generate_test_cert();
        let pin_hex = pin.iter().map(|b| format!("{b:02x}")).collect::<String>();

        // 1. Success with correct pin
        let (port1, server1) = spawn_server(&cert, &key);
        let connector1 = BoringTlsConnector::new(
            true,
            false,
            Some(&pin_hex),
            None,
            None,
            None,
        )
        .unwrap();
        let tcp1 = tokio::net::TcpStream::connect(("127.0.0.1", port1)).await.unwrap();
        let mut tls1 = connector1.connect("localhost", tcp1).await.unwrap();
        tls1.write_all(b"pin ok").await.unwrap();
        tls1.shutdown().await.unwrap();
        assert_eq!(server1.join().unwrap(), b"pin ok");

        // 2. Failure with wrong pin
        let wrong_pin_hex = "00".repeat(32);
        let (port2, _server2) = spawn_server(&cert, &key);
        let connector2 = BoringTlsConnector::new(
            true,
            false,
            Some(&wrong_pin_hex),
            None,
            None,
            None,
        )
        .unwrap();
        let tcp2 = tokio::net::TcpStream::connect(("127.0.0.1", port2)).await.unwrap();
        let res = connector2.connect("localhost", tcp2).await;
        assert!(res.is_err(), "Handshake must fail on cert pin mismatch");
    }
}
