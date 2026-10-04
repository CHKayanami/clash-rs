pub mod boring;

use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use tracing::warn;

use super::utils::{encode_hex, sha256};

use std::{io, sync::{Arc, LazyLock}};

pub(crate) fn validate_alpn(protocols: &[String]) -> io::Result<usize> {
    let mut length = 0usize;
    for protocol in protocols {
        if !(1..=255).contains(&protocol.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "ALPN protocol names must contain 1 to 255 bytes"));
        }
        length = length.checked_add(protocol.len() + 1)
            .filter(|length| *length <= u16::MAX as usize - 2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput,
                "ALPN protocol list exceeds 65533 bytes"))?;
    }
    Ok(length)
}

pub(crate) fn encode_alpn(protocols: &[String]) -> io::Result<Vec<u8>> {
    let mut wire = Vec::with_capacity(validate_alpn(protocols)?);
    for protocol in protocols {
        wire.push(protocol.len() as u8);
        wire.extend_from_slice(protocol.as_bytes());
    }
    Ok(wire)
}

#[cfg(test)]
mod alpn_tests {
    use super::{encode_alpn, validate_alpn};

    #[test]
    fn alpn_encoding_preserves_order_and_explicit_empty_list() {
        assert_eq!(encode_alpn(&["http/1.1".into(), "h2".into()]).unwrap(),
            b"\x08http/1.1\x02h2");
        assert!(encode_alpn(&[]).unwrap().is_empty());
        assert!(validate_alpn(&["x".repeat(255)]).is_ok());
        let mut boundary = vec!["x".repeat(255); 255];
        boundary.push("y".repeat(252));
        assert_eq!(validate_alpn(&boundary).unwrap(), 65533);
        boundary.last_mut().unwrap().push('y');
        assert!(validate_alpn(&boundary).is_err());
    }

    #[test]
    fn alpn_rejects_invalid_names_and_oversized_lists() {
        for protocols in [vec![String::new()], vec!["x".repeat(256)],
            vec!["x".repeat(255); 256]] {
            assert!(validate_alpn(&protocols).is_err());
            assert!(encode_alpn(&protocols).is_err());
        }
    }
}

pub static GLOBAL_ROOT_STORE: LazyLock<Arc<RootCertStore>> =
    LazyLock::new(global_root_store);

fn global_root_store() -> Arc<RootCertStore> {
    let root_store = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(root_store)
}

/// Load a PEM certificate chain and private key from either inline PEM strings
/// or file paths. A string containing `-----BEGIN` is treated as inline PEM;
/// otherwise it is interpreted as a file path.
///
/// Returns `(cert_chain, private_key)` suitable for both rustls client auth
/// (mTLS, via `with_client_auth_cert`) and rustls server config
/// (`with_single_cert`).
pub fn load_cert_and_key(
    cert: &str,
    key: &str,
) -> std::io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = if cert.contains("-----BEGIN") {
        cert.to_owned()
    } else {
        std::fs::read_to_string(cert).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("failed to read certificate '{cert}': {e}"),
            )
        })?
    };

    let key_pem = if key.contains("-----BEGIN") {
        key.to_owned()
    } else {
        std::fs::read_to_string(key).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("failed to read private key '{key}': {e}"),
            )
        })?
    };

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput,
                format!("failed to parse certificate chain: {e}")))?;

    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no valid certificates found in PEM",
        ));
    }

    let private_key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to parse private key: {e}"),
            )
        })?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no private key found in PEM",
            )
        })?;

    Ok((certs, private_key))
}

/// Build a `rustls` [`ClientConfig`] with a custom certificate verifier and
/// optional mTLS client certificate.
///
/// When `tls_cert` and `tls_key` are both `Some`, mutual TLS (mTLS) is
/// enabled by presenting the client certificate during the TLS handshake.
/// Both must be either `None` (no client auth) or `Some` (mTLS); mixing
/// them returns an [`io::Error`].
pub fn build_tls_client_config(
    verifier: Arc<dyn ServerCertVerifier>,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
) -> std::io::Result<rustls::ClientConfig> {
    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            let (certs, private_key) = load_cert_and_key(cert, key)?;
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_auth_cert(certs, private_key)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid mTLS client cert/key: {e}"),
                    )
                })
        }
        (None, None) => Ok(rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tls-cert and tls-key must both be set or both omitted",
        )),
    }
}

/// Parse a SHA-256 fingerprint value (hex, optionally colon-separated) into 32 bytes.
pub(crate) fn parse_fingerprint_sha256(s: &str) -> Option<[u8; 32]> {
    let mut hex = s
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace());
    let mut out = [0u8; 32];
    for b in &mut out {
        let high = hex.next()?.to_digit(16)?;
        let low = hex.next()?.to_digit(16)?;
        *b = ((high << 4) | low) as u8;
    }
    hex.next().is_none().then_some(out)
}

#[derive(Debug)]
pub struct DefaultTlsVerifier {
    fingerprint: Option<Result<[u8; 32], rustls::Error>>,
    skip: bool,
    pki: Arc<WebPkiServerVerifier>,
}

impl DefaultTlsVerifier {
    pub fn new(fingerprint: Option<String>, skip: bool) -> Self {
        Self {
            fingerprint: fingerprint.map(|pin| {
                parse_fingerprint_sha256(&pin).ok_or_else(|| {
                    rustls::Error::General(
                        "invalid certificate fingerprint (expected SHA-256 hex)".into(),
                    )
                })
            }),
            skip,
            pki: WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .unwrap(),
        }
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use ::boring::{hash::MessageDigest, pkey::PKey, sign::Signer};
    use rcgen::{CertificateParams, KeyPair};
    use rustls::{DigitallySignedStruct, internal::msgs::codec::Codec};
    use std::time::Duration;

    #[test]
    fn fingerprint_parser_preserves_formats_and_rejects_invalid_lengths() {
        let hex = "ab".repeat(32);
        let spaced = hex.as_bytes().chunks(2)
            .map(|pair| String::from_utf8(pair.to_vec()).unwrap())
            .collect::<Vec<_>>().join(":\u{2003}");
        assert_eq!(parse_fingerprint_sha256(&spaced), Some([0xab; 32]));
        for invalid in [hex[..63].to_owned(), format!("{hex}0"), "gg".repeat(32)] {
            assert!(parse_fingerprint_sha256(&invalid).is_none());
        }
    }

    #[test]
    fn skip_cert_verify_still_verifies_handshake_signatures() {
        crate::tests::initialize();
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pkey = PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap();
        let message = b"TLS handshake transcript";
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        let signature = signer.sign_oneshot_to_vec(message).unwrap();
        // ECDSA_NISTP256_SHA256 followed by the TLS u16-length signature.
        let mut wire = vec![0x04, 0x03];
        wire.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        wire.extend_from_slice(&signature);
        let signed = DigitallySignedStruct::read_bytes(&wire).unwrap();
        let pin = encode_hex(&sha256(cert.der().as_ref()));
        for fingerprint in [None, Some(pin)] {
            let verifier = DefaultTlsVerifier::new(fingerprint, true);
            assert!(verifier.verify_tls12_signature(message, cert.der(), &signed).is_ok());
            assert!(verifier.verify_tls13_signature(message, cert.der(), &signed).is_ok());
            assert!(verifier.verify_tls12_signature(b"tampered", cert.der(), &signed).is_err());
            assert!(verifier.verify_tls13_signature(b"tampered", cert.der(), &signed).is_err());
        }
    }

    #[test]
    fn malformed_certificate_chain_is_rejected() {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let chain = format!("{}-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n", cert.pem());
        let error = load_cert_and_key(&chain, &key.serialize_pem()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn certificate_pin_accepts_equivalent_hex_formats() {
        crate::tests::initialize();
        let cert = CertificateDer::from(b"test certificate".to_vec());
        let hash = encode_hex(&sha256(cert.as_ref()));
        let colon_hash = hash.as_bytes().chunks(2)
            .map(|pair| String::from_utf8(pair.to_vec()).unwrap().to_uppercase())
            .collect::<Vec<_>>().join(":");
        let name = ServerName::try_from("example.com").unwrap();
        for fingerprint in [hash, colon_hash] {
            let verifier = DefaultTlsVerifier::new(Some(fingerprint), false);
            assert!(verifier.verify_server_cert(
                &cert, &[], &name, &[], UnixTime::since_unix_epoch(Duration::ZERO),
            ).is_ok());
        }
        for fingerprint in ["00".repeat(32), "invalid".to_owned()] {
            let verifier = DefaultTlsVerifier::new(Some(fingerprint), true);
            assert!(verifier.verify_server_cert(
                &cert, &[], &name, &[], UnixTime::since_unix_epoch(Duration::ZERO),
            ).is_err());
        }
        let verifier = DefaultTlsVerifier::new(None, false);
        assert!(verifier.verify_server_cert(
            &cert, &[], &name, &[], UnixTime::since_unix_epoch(Duration::ZERO),
        ).is_err());
    }
}

impl ServerCertVerifier for DefaultTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(ref fingerprint) = self.fingerprint {
            let expected = fingerprint.as_ref().map_err(Clone::clone)?;
            let cert_hash = sha256(end_entity.as_ref());
            if expected.as_slice() != cert_hash.as_slice() {
                let cert_hex = encode_hex(&cert_hash);
                return Err(rustls::Error::General(format!(
                    "cert hash mismatch: found: {cert_hex}\nexpected: {}",
                    encode_hex(expected)
                )));
            }
            // An explicit certificate pin is the trust anchor, including for
            // self-signed certificates. TLS handshake signatures are still
            // verified by verify_tls12_signature / verify_tls13_signature.
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        if self.skip {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        self.pki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.pki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.pki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.pki.supported_verify_schemes()
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct NoHostnameTlsVerifier(Arc<WebPkiServerVerifier>);

#[allow(dead_code)]
impl NoHostnameTlsVerifier {
    pub fn new() -> Self {
        Self(
            WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .unwrap(),
        )
    }
}

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self.0.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(rustls::Error::UnsupportedNameType) => {
                warn!(
                    "skipping TLS cert name verification for server name: {:?}",
                    server_name
                );
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
