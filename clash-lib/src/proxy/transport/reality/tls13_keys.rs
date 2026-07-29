use super::cipher_suite::CipherSuite;
use aws_lc_rs::{digest, hmac};
use std::io::{Error, ErrorKind, Result};

#[derive(Debug, Clone)]
pub struct Tls13HandshakeKeys {
    pub client_handshake_traffic_secret: Vec<u8>,
    pub server_handshake_traffic_secret: Vec<u8>,
    pub master_secret: Vec<u8>,
}

pub fn hkdf_expand(
    hmac_algorithm: hmac::Algorithm,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let hash_len = hmac_algorithm.digest_algorithm().output_len();
    let n = length.div_ceil(hash_len);

    if n > 255 {
        return Err(Error::new(ErrorKind::InvalidData, "HKDF output too long"));
    }

    let mut output = Vec::new();
    let mut prev = Vec::new();

    for i in 1..=n {
        let key = hmac::Key::new(hmac_algorithm, prk);
        let mut ctx = hmac::Context::with_key(&key);

        ctx.update(&prev);
        ctx.update(info);
        ctx.update(&[i as u8]);
        let tag = ctx.sign();

        prev = tag.as_ref().to_vec();
        output.extend_from_slice(tag.as_ref());
    }

    output.truncate(length);
    Ok(output)
}

fn hkdf_expand_label_with_algorithm(
    hmac_algorithm: hmac::Algorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());

    let full_label = format!("tls13 {}", std::str::from_utf8(label).unwrap());
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());

    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand(hmac_algorithm, secret, &hkdf_label, length)
}

fn derive_secret_with_algorithm(
    hmac_algorithm: hmac::Algorithm,
    secret: &[u8],
    label: &[u8],
    messages_hash: &[u8],
) -> Result<Vec<u8>> {
    let hash_len = hmac_algorithm.digest_algorithm().output_len();
    hkdf_expand_label_with_algorithm(
        hmac_algorithm,
        secret,
        label,
        messages_hash,
        hash_len,
    )
}

fn hkdf_extract_with_algorithm(
    hmac_algorithm: hmac::Algorithm,
    salt: &[u8],
    ikm: &[u8],
) -> Vec<u8> {
    let key = hmac::Key::new(hmac_algorithm, salt);
    let tag = hmac::sign(&key, ikm);
    tag.as_ref().to_vec()
}

pub fn derive_traffic_keys(
    traffic_secret: &[u8],
    cipher_suite: CipherSuite,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_length = cipher_suite.key_len();
    let iv_length = cipher_suite.nonce_len();
    let hmac_algorithm = cipher_suite.hmac_algorithm();

    let key = hkdf_expand_label_with_algorithm(
        hmac_algorithm,
        traffic_secret,
        b"key",
        b"",
        key_length,
    )?;

    let iv = hkdf_expand_label_with_algorithm(
        hmac_algorithm,
        traffic_secret,
        b"iv",
        b"",
        iv_length,
    )?;

    Ok((key, iv))
}

/// Derive the next application traffic secret for a TLS 1.3 KeyUpdate
/// (RFC 8446 §7.2): `HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)`.
pub fn derive_next_traffic_secret(
    traffic_secret: &[u8],
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>> {
    let hash_len = cipher_suite.hash_len();
    hkdf_expand_label_with_algorithm(
        cipher_suite.hmac_algorithm(),
        traffic_secret,
        b"traffic upd",
        b"",
        hash_len,
    )
}

pub fn derive_handshake_keys(
    cipher_suite: CipherSuite,
    shared_secret: &[u8],
    _client_hello_hash: &[u8],
    server_hello_hash: &[u8],
) -> Result<Tls13HandshakeKeys> {
    let hash_len = cipher_suite.hash_len();
    let hmac_algorithm = cipher_suite.hmac_algorithm();
    let digest_algorithm = cipher_suite.digest_algorithm();

    if shared_secret.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Invalid shared_secret length: {} (expected 32)",
                shared_secret.len()
            ),
        ));
    }
    if server_hello_hash.len() != hash_len {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Hash length mismatch: {} (expected {})",
                server_hello_hash.len(),
                hash_len
            ),
        ));
    }

    let zero_salt = vec![0u8; hash_len];
    let early_secret =
        hkdf_extract_with_algorithm(hmac_algorithm, &zero_salt, &zero_salt);

    let mut empty_ctx = digest::Context::new(digest_algorithm);
    empty_ctx.update(b"");
    let empty_hash = empty_ctx.finish();
    let derived_secret = derive_secret_with_algorithm(
        hmac_algorithm,
        &early_secret,
        b"derived",
        empty_hash.as_ref(),
    )?;

    let handshake_secret =
        hkdf_extract_with_algorithm(hmac_algorithm, &derived_secret, shared_secret);

    let client_handshake_traffic_secret = derive_secret_with_algorithm(
        hmac_algorithm,
        &handshake_secret,
        b"c hs traffic",
        server_hello_hash,
    )?;

    let server_handshake_traffic_secret = derive_secret_with_algorithm(
        hmac_algorithm,
        &handshake_secret,
        b"s hs traffic",
        server_hello_hash,
    )?;

    let mut empty_ctx_2 = digest::Context::new(digest_algorithm);
    empty_ctx_2.update(b"");
    let empty_hash_2 = empty_ctx_2.finish();
    let derived_secret_2 = derive_secret_with_algorithm(
        hmac_algorithm,
        &handshake_secret,
        b"derived",
        empty_hash_2.as_ref(),
    )?;

    let master_secret =
        hkdf_extract_with_algorithm(hmac_algorithm, &derived_secret_2, &zero_salt);

    Ok(Tls13HandshakeKeys {
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
        master_secret,
    })
}

pub fn derive_application_secrets(
    cipher_suite: CipherSuite,
    master_secret: &[u8],
    handshake_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let hash_len = cipher_suite.hash_len();
    let hmac_algorithm = cipher_suite.hmac_algorithm();

    if master_secret.len() != hash_len || handshake_hash.len() != hash_len {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Master secret and handshake hash must be {} bytes",
                hash_len
            ),
        ));
    }

    let client_application_traffic_secret = derive_secret_with_algorithm(
        hmac_algorithm,
        master_secret,
        b"c ap traffic",
        handshake_hash,
    )?;

    let server_application_traffic_secret = derive_secret_with_algorithm(
        hmac_algorithm,
        master_secret,
        b"s ap traffic",
        handshake_hash,
    )?;

    Ok((
        client_application_traffic_secret,
        server_application_traffic_secret,
    ))
}

pub fn compute_finished_verify_data(
    cipher_suite: CipherSuite,
    base_key: &[u8],
    handshake_hash: &[u8],
) -> Result<Vec<u8>> {
    let hash_len = cipher_suite.hash_len();
    let hmac_algorithm = cipher_suite.hmac_algorithm();

    let finished_key = hkdf_expand_label_with_algorithm(
        hmac_algorithm,
        base_key,
        b"finished",
        b"",
        hash_len,
    )?;

    let key = hmac::Key::new(hmac_algorithm, &finished_key);
    let tag = hmac::sign(&key, handshake_hash);
    Ok(tag.as_ref().to_vec())
}
