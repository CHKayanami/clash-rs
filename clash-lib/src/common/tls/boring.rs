//! BoringSSL TLS client — real Chrome fingerprint (uTLS-grade).
//!
//! Replicates real Chrome ClientHello: GREASE, permuted extensions,
//! X25519MLKEM768 hybrid key share, ALPS, brotli certificate compression,
//! and ECH GREASE.

use std::io;
use std::net::IpAddr;
use std::sync::LazyLock;

use anyhow::Context as _;
use super::{encode_alpn, load_cert_and_key, parse_fingerprint_sha256};
use boring::error::ErrorStack;
use boring::hash::MessageDigest;
use boring::pkey::PKey;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, Ssl, SslAlert, SslContext,
    SslContextBuilder, SslMethod, SslMode, SslOptions, SslRef, SslVerifyError, SslVerifyMode,
    SslVersion,
};
use boring::x509::X509;
use boring::x509::store::{X509Store, X509StoreBuilder};
use boring::x509::verify::X509CheckFlags;
use foreign_types::ForeignTypeRef;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring::{SslStream as AsyncSslStream, SslStreamBuilder};

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

/// Default client TLS 1.2 cipher list (matches boring's `SslConnector::builder`).
const DEFAULT_CIPHER_LIST: &str =
    "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK";

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
        builder.add_cert(X509::from_der(der.as_ref())?)?;
    }
    Ok(builder.build())
}

/// Chrome sends two key shares: X25519MLKEM768 and X25519, in that order.
fn set_chrome_key_shares(ssl: &mut SslRef) -> anyhow::Result<()> {
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
pub(crate) fn add_chrome_alps(ssl: &mut SslRef) -> anyhow::Result<()> {
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

/// Custom verify callback matching the peer leaf certificate's SHA-256
pub fn pin_sha256_custom_verify(
    pin: [u8; 32],
) -> impl Fn(&mut SslRef) -> Result<(), SslVerifyError> + Send + Sync + 'static {
    move |ssl| {
        let matches = ssl
            .peer_certificate()
            .and_then(|cert| cert.digest(MessageDigest::sha256()).ok())
            .is_some_and(|digest| digest.as_ref() == pin);
        if matches {
            Ok(())
        } else {
            Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))
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

pub fn configure_client_server_identity(
    ssl: &mut SslRef,
    domain: &str,
) -> Result<(), ErrorStack> {
    match domain.parse::<IpAddr>() {
        Ok(ip) => {
            let param = ssl.param_mut();
            param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
            param.set_ip(ip)?;
        }
        Err(_) => {
            ssl.set_hostname(domain)?;
            let param = ssl.param_mut();
            param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
            param.set_host(domain)?;
        }
    }
    Ok(())
}

pub fn build_reality_context(chrome: bool) -> anyhow::Result<SslContext> {
    let mut builder = build_client_context_builder()?;
    builder.set_verify(SslVerifyMode::NONE);
    if chrome {
        apply_chrome_ctx(&mut builder)?;
        builder.set_alpn_protos(CHROME_ALPN_WIRE)?;
        builder.enable_ocsp_stapling();
        builder.enable_signed_cert_timestamps();
    } else {
        builder.set_cipher_list(DEFAULT_CIPHER_LIST)?;
    }
    Ok(builder.build())
}

static REALITY_CONTEXT_CHROME: LazyLock<anyhow::Result<SslContext>> =
    LazyLock::new(|| build_reality_context(true));

static REALITY_CONTEXT_PLAIN: LazyLock<anyhow::Result<SslContext>> =
    LazyLock::new(|| build_reality_context(false));

pub fn get_reality_context(chrome: bool) -> anyhow::Result<&'static SslContext> {
    if chrome {
        REALITY_CONTEXT_CHROME
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e}"))
    } else {
        REALITY_CONTEXT_PLAIN
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// Builds a client `SslContextBuilder` with secure TLS options and I/O modes
/// without loading system root CAs via `set_default_verify_paths`.
fn build_client_context_builder() -> Result<SslContextBuilder, ErrorStack> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;
    let mut opts = SslOptions::ALL
        | SslOptions::NO_COMPRESSION
        | SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::SINGLE_DH_USE
        | SslOptions::SINGLE_ECDH_USE;
    opts &= !SslOptions::DONT_INSERT_EMPTY_FRAGMENTS;
    builder.set_options(opts);
    builder.set_mode(
        SslMode::AUTO_RETRY
            | SslMode::ACCEPT_MOVING_WRITE_BUFFER
            | SslMode::ENABLE_PARTIAL_WRITE
            | SslMode::RELEASE_BUFFERS,
    );
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    Ok(builder)
}

/// BoringSSL connector carrying Chrome fingerprint settings and certificate options.
#[derive(Clone)]
pub struct BoringTlsConnector {
    context: SslContext,
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
        let mut builder = build_client_context_builder()?;

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
            builder.set_cert_store(root_store()?);
        }

        if let Some(pin) = pin {
            builder.set_custom_verify_callback(SslVerifyMode::PEER, pin_sha256_custom_verify(pin));
        }

        match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => {
                let (certs, key) = load_cert_and_key(cert, key)?;
                let leaf = X509::from_der(certs[0].as_ref())?;
                builder.set_certificate(&leaf)?;
                for cert in &certs[1..] {
                    builder.add_extra_chain_cert(X509::from_der(cert.as_ref())?)?;
                }
                let key = PKey::private_key_from_der(key.secret_der())?;
                builder.set_private_key(&key)?;
                builder.check_private_key()?;
            }
            (None, None) => {}
            _ => anyhow::bail!("tls-cert and tls-key must both be set or both omitted"),
        }

        if chrome {
            apply_chrome_ctx(&mut builder)?;
        } else {
            builder.set_cipher_list(DEFAULT_CIPHER_LIST)?;
        }

        let offers_h2 = if let Some(protocols) = alpn {
            builder.set_alpn_protos(&encode_alpn(protocols)?)?;
            protocols.iter().any(|protocol| protocol == "h2")
        } else if chrome {
            builder.set_alpn_protos(CHROME_ALPN_WIRE)?;
            true
        } else {
            false
        };

        Ok(Self {
            context: builder.build(),
            chrome,
            alps: chrome && offers_h2,
        })
    }

    fn configure_ssl(&self, domain: &str) -> anyhow::Result<Ssl> {
        let mut ssl = Ssl::new(&self.context)?;
        configure_client_server_identity(&mut ssl, domain)?;
        if self.chrome {
            ssl.set_permute_extensions(true);
            set_chrome_key_shares(&mut ssl)?;
            if self.alps {
                add_chrome_alps(&mut ssl)?;
            }
            ssl.set_enable_ech_grease(true);
        }
        Ok(ssl)
    }

    pub async fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> io::Result<AsyncSslStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = self
            .configure_ssl(domain)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        SslStreamBuilder::new(ssl, stream)
            .connect()
            .await
            .map_err(|e| {
                let kind = e.as_io_error().map_or_else(
                    || {
                        if e.code().is_none() {
                            io::ErrorKind::InvalidInput
                        } else {
                            io::ErrorKind::InvalidData
                        }
                    },
                    io::Error::kind,
                );
                io::Error::new(
                    kind,
                    format!("BoringSSL TLS handshake with {domain} failed: {e}"),
                )
            })
    }
    #[cfg(test)]
    fn new_with_store(chrome: bool, store: X509Store) -> anyhow::Result<Self> {
        let mut builder = build_client_context_builder()?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_cert_store(store);
        if chrome {
            apply_chrome_ctx(&mut builder)?;
            builder.set_alpn_protos(CHROME_ALPN_WIRE)?;
        } else {
            builder.set_cipher_list(DEFAULT_CIPHER_LIST)?;
        }
        Ok(Self {
            context: builder.build(),
            chrome,
            alps: chrome,
        })
    }
}

#[cfg(test)]
#[path = "boring_mtls_tests.rs"]
mod mtls_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use boring::ssl::{NameType, SslAcceptor, SslStream};
    use boring::stack::StackRef;
    use boring::x509::X509Object;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use std::net::TcpListener;
    use std::thread;
    use tokio::io::{duplex, AsyncWriteExt};
    use tokio_boring::accept;

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
        assert_eq!(res.err().unwrap().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn handshake_preserves_transport_error_kind() {
        let connector = BoringTlsConnector::new(false, true, None, None, None, None).unwrap();
        let (client, server) = duplex(1024);
        drop(server);
        let error = connector.connect("localhost", client).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn reuses_shared_mozilla_root_store_without_loading_system_cas() {
        let shared = root_store().unwrap();
        let c1 = BoringTlsConnector::new(false, false, None, None, None, None).unwrap();
        let c2 = BoringTlsConnector::new(true, false, None, None, None, None).unwrap();
        let skip = BoringTlsConnector::new(false, true, None, None, None, None).unwrap();
        let pin = "11".repeat(32);
        let pinned = BoringTlsConnector::new(true, false, Some(&pin), None, None, None).unwrap();

        unsafe {
            assert_eq!(
                boring_sys::SSL_CTX_get_cert_store(c1.context.as_ptr()),
                shared.as_ptr()
            );
            assert_eq!(
                boring_sys::SSL_CTX_get_cert_store(c2.context.as_ptr()),
                shared.as_ptr()
            );

            for context in [
                &skip.context,
                &pinned.context,
                get_reality_context(true).unwrap(),
                get_reality_context(false).unwrap(),
            ] {
                let store = boring_sys::SSL_CTX_get_cert_store(context.as_ptr());
                assert!(!store.is_null());
                let objects = boring_sys::X509_STORE_get0_objects(store);
                assert_eq!(StackRef::<X509Object>::from_ptr(objects).len(), 0);
            }
        }
    }

    fn generate_ca_and_leaf(san: &str) -> (X509Store, SslAcceptor) {
        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name.push(DnType::CommonName, "test-ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut leaf_params = CertificateParams::new(vec![san.to_string()]).unwrap();
        leaf_params.distinguished_name = DistinguishedName::new();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
            .unwrap();

        let mut store_builder = X509StoreBuilder::new().unwrap();
        store_builder
            .add_cert(X509::from_der(ca_cert.der()).unwrap())
            .unwrap();

        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_der(leaf_cert.der()).unwrap())
            .unwrap();
        let pkey = PKey::private_key_from_pem(leaf_key.serialize_pem().as_bytes()).unwrap();
        acceptor.set_private_key(&pkey).unwrap();

        (store_builder.build(), acceptor.build())
    }

    #[tokio::test]
    async fn verifies_dns_sni_and_hostname() {
        let (store, acceptor) = generate_ca_and_leaf("example.test");
        let connector = BoringTlsConnector::new_with_store(true, store).unwrap();

        let (client_io, server_io) = duplex(65536);
        let (client, server) = tokio::join!(
            connector.connect("example.test", client_io),
            accept(&acceptor, server_io),
        );
        let _client = client.unwrap();
        let server = server.unwrap();
        assert_eq!(
            server.ssl().servername(NameType::HOST_NAME),
            Some("example.test")
        );

        let (client_io, server_io) = duplex(65536);
        let (client, _server) = tokio::join!(
            connector.connect("wrong.test", client_io),
            accept(&acceptor, server_io),
        );
        let err = client.err().expect("hostname mismatch must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn verifies_ip_cert_without_sni() {
        let (store, acceptor) = generate_ca_and_leaf("127.0.0.1");
        let connector = BoringTlsConnector::new_with_store(false, store).unwrap();

        let (client_io, server_io) = duplex(65536);
        let (client, server) = tokio::join!(
            connector.connect("127.0.0.1", client_io),
            accept(&acceptor, server_io),
        );
        let _client = client.unwrap();
        let server = server.unwrap();
        assert_eq!(server.ssl().servername(NameType::HOST_NAME), None);

        let (client_io, server_io) = duplex(65536);
        let (client, _server) = tokio::join!(
            connector.connect("127.0.0.2", client_io),
            accept(&acceptor, server_io),
        );
        let err = client.err().expect("IP mismatch must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
