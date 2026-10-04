use super::BoringTlsConnector;
use boring::{pkey::PKey, ssl::{SslAcceptor, SslMethod, SslVerifyMode}, x509::X509};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use std::io::Write;
use tempfile::NamedTempFile;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio_boring::accept;

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

#[test]
fn incomplete_and_mismatched_client_credentials_are_rejected() {
    let params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap().pem();
    let key = key.serialize_pem();
    let wrong_key = KeyPair::generate().unwrap().serialize_pem();
    for (cert, key) in [
        (Some(cert.as_str()), None),
        (None, Some(key.as_str())),
        (Some(cert.as_str()), Some(wrong_key.as_str())),
    ] {
        assert!(BoringTlsConnector::new(false, true, None, None, cert, key).is_err());
    }
}

#[tokio::test]
async fn mtls_sends_intermediate_chain_from_inline_pem_and_files() {
    let root_params = ca_params("test root");
    let root_key = KeyPair::generate().unwrap();
    let root = root_params.self_signed(&root_key).unwrap();
    let intermediate_params = ca_params("test intermediate");
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate = intermediate_params.signed_by(
        &intermediate_key, &Issuer::from_params(&root_params, &root_key),
    ).unwrap();
    let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(
        &leaf_key, &Issuer::from_params(&intermediate_params, &intermediate_key),
    ).unwrap();
    let chain = format!("{}{}", leaf.pem(), intermediate.pem());
    let key_pem = leaf_key.serialize_pem();
    let mut cert_file = NamedTempFile::new().unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    cert_file.write_all(chain.as_bytes()).unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();

    for (cert, key) in [
        (chain.as_str(), key_pem.as_str()),
        (cert_file.path().to_str().unwrap(), key_file.path().to_str().unwrap()),
    ] {
        let server_key = KeyPair::generate().unwrap();
        let server_cert = CertificateParams::new(vec!["localhost".into()]).unwrap()
            .self_signed(&server_key).unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&X509::from_der(server_cert.der()).unwrap()).unwrap();
        acceptor.set_private_key(&PKey::private_key_from_pem(server_key.serialize_pem().as_bytes()).unwrap()).unwrap();
        acceptor.cert_store_mut().add_cert(X509::from_der(root.der()).unwrap()).unwrap();
        acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let acceptor = acceptor.build();
        let connector = BoringTlsConnector::new(true, true, None, None, Some(cert), Some(key)).unwrap();
        let (client_io, server_io) = duplex(65536);
        let (client, server) = tokio::join!(
            connector.connect("localhost", client_io),
            accept(&acceptor, server_io),
        );
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        assert_eq!(server.ssl().peer_certificate().unwrap().to_der().unwrap(), leaf.der().as_ref());
        let sent_chain = server.ssl().peer_cert_chain().unwrap();
        assert_eq!(sent_chain.len(), 1);
        assert_eq!(sent_chain[0].to_der().unwrap(), intermediate.der().as_ref());
        client.write_all(b"ping").await.unwrap();
        let mut data = [0; 4];
        server.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
    }
}
