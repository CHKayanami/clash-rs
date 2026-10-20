use std::{fs, io, sync::Arc};
use rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}};
use crate::DNSError;

fn pem(value: &str) -> io::Result<Vec<u8>> {
    if value.contains("-----BEGIN") {
        Ok(value.as_bytes().to_vec())
    } else {
        fs::read(value).map_err(|error| io::Error::new(error.kind(),
            format!("failed to read DNS certificate/key file '{value}': {error}")))
    }
}

pub(super) fn config(
    certificate: Option<&str>, key: Option<&str>, alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, DNSError> {
    let (Some(certificate), Some(key)) = (certificate, key) else {
        return Err(DNSError::Configuration("certificate and private key are required".into()));
    };
    let cert_pem = pem(certificate)?;
    let key_pem = pem(key)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or_else(|| DNSError::Configuration("DNS private key is missing or invalid".into()))?;
    let mut config = ServerConfig::builder().with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| DNSError::Configuration(format!("DNS TLS configuration: {error}")))?;
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}
