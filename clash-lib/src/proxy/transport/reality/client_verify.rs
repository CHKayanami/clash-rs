use aws_lc_rs::hmac;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use std::io;

#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

/// Extract the DER-encoded certificate from a TLS 1.3 Certificate message
#[inline]
pub fn extract_certificate_der(certificate_message: &[u8]) -> io::Result<&[u8]> {
    if certificate_message.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message too short",
        ));
    }

    let mut pos = 4;

    if pos >= certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at context length",
        ));
    }
    let context_len = certificate_message[pos] as usize;
    pos += 1 + context_len;

    if pos + 3 > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at list length",
        ));
    }
    pos += 3;

    if pos + 3 > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at cert length",
        ));
    }
    let cert_len = u32::from_be_bytes([
        0,
        certificate_message[pos],
        certificate_message[pos + 1],
        certificate_message[pos + 2],
    ]) as usize;
    pos += 3;

    if pos + cert_len > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at cert data",
        ));
    }

    Ok(&certificate_message[pos..pos + cert_len])
}

/// Helper to parse DER TLV (Tag, Length, Value)
fn parse_der_tlv(input: &[u8]) -> io::Result<(u8, &[u8], &[u8])> {
    if input.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty DER data"));
    }
    let tag = input[0];
    let mut pos = 1;
    if pos >= input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Truncated DER length",
        ));
    }

    let len_byte = input[pos];
    pos += 1;

    let length = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_bytes = (len_byte & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || pos + num_bytes > input.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid DER length encoding",
            ));
        }
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | (input[pos + i] as usize);
        }
        pos += num_bytes;
        l
    };

    if pos + length > input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DER payload extends beyond input",
        ));
    }

    let value = &input[pos..pos + length];
    let remainder = &input[pos + length..];
    Ok((tag, value, remainder))
}

/// Extract SubjectPublicKey (Ed25519 32 bytes) and signature (64 bytes) from DER X.509 Certificate
pub fn parse_x509_ed25519_cert(cert_der: &[u8]) -> io::Result<([u8; 32], Vec<u8>)> {
    let (tag, cert_seq, _) = parse_der_tlv(cert_der)?;
    if tag != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected SEQUENCE tag for Certificate",
        ));
    }

    let (tag, tbs_seq, rem1) = parse_der_tlv(cert_seq)?;
    if tag != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected SEQUENCE for TBSCertificate",
        ));
    }
    let (tag, _sig_alg, rem2) = parse_der_tlv(rem1)?;
    if tag != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected SEQUENCE for SignatureAlgorithm",
        ));
    }
    let (tag, sig_val, _) = parse_der_tlv(rem2)?;
    if tag != 0x03 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected BIT STRING for SignatureValue",
        ));
    }

    let signature = if !sig_val.is_empty() && sig_val[0] == 0 {
        sig_val[1..].to_vec()
    } else {
        sig_val.to_vec()
    };

    // Now find SubjectPublicKeyInfo in tbs_seq
    // tbs_seq fields: version [0] (opt), serialNumber (0x02), signature (0x30), issuer (0x30), validity (0x30), subject (0x30), subjectPublicKeyInfo (0x30)
    let mut cursor = tbs_seq;
    // Skip version if present
    if !cursor.is_empty() && cursor[0] == 0xa0 {
        let (_, _, rem) = parse_der_tlv(cursor)?;
        cursor = rem;
    }
    // Skip serialNumber
    let (_, _, rem) = parse_der_tlv(cursor)?;
    cursor = rem;
    // Skip signature
    let (_, _, rem) = parse_der_tlv(cursor)?;
    cursor = rem;
    // Skip issuer
    let (_, _, rem) = parse_der_tlv(cursor)?;
    cursor = rem;
    // Skip validity
    let (_, _, rem) = parse_der_tlv(cursor)?;
    cursor = rem;
    // Skip subject
    let (_, _, rem) = parse_der_tlv(cursor)?;
    cursor = rem;

    // Now at subjectPublicKeyInfo
    let (tag, spki_val, _) = parse_der_tlv(cursor)?;
    if tag != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected SubjectPublicKeyInfo SEQUENCE",
        ));
    }

    // spki_val fields: algorithm (0x30), subjectPublicKey (0x03)
    let (_, _, spki_rem) = parse_der_tlv(spki_val)?;
    let (tag, pk_bit_str, _) = parse_der_tlv(spki_rem)?;
    if tag != 0x03 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected BIT STRING for SubjectPublicKey",
        ));
    }

    let pk_bytes = if !pk_bit_str.is_empty() && pk_bit_str[0] == 0 {
        &pk_bit_str[1..]
    } else {
        pk_bit_str
    };

    if pk_bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected Ed25519 public key (32 bytes), got {} bytes",
                pk_bytes.len()
            ),
        ));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(pk_bytes);

    Ok((pubkey, signature))
}

#[inline]
pub fn verify_certificate_hmac(
    cert_der: &[u8],
    auth_key: &[u8; 32],
) -> io::Result<()> {
    let (pubkey_bytes, signature) = parse_x509_ed25519_cert(cert_der)?;

    if signature.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected 64-byte signature for HMAC-SHA512 verification, got {} bytes",
                signature.len()
            ),
        ));
    }

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let hmac_tag = hmac::sign(&hmac_key, &pubkey_bytes);
    let expected_signature = hmac_tag.as_ref();

    if !constant_time_eq(expected_signature, &signature) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Certificate HMAC verification failed - not a REALITY-signed certificate",
        ));
    }

    Ok(())
}

#[inline]
pub fn extract_ed25519_public_key(cert_der: &[u8]) -> io::Result<[u8; 32]> {
    let (pubkey, _) = parse_x509_ed25519_cert(cert_der)?;
    Ok(pubkey)
}

#[inline]
pub fn extract_certificate_verify_signature(
    cert_verify_message: &[u8],
) -> io::Result<Vec<u8>> {
    if cert_verify_message.len() < 72 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CertificateVerify message too short: {} bytes",
                cert_verify_message.len()
            ),
        ));
    }

    if cert_verify_message[0] != 0x0f {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected CertificateVerify type (0x0f), got 0x{:02x}",
                cert_verify_message[0]
            ),
        ));
    }

    let pos = 4;
    let sig_alg =
        u16::from_be_bytes([cert_verify_message[pos], cert_verify_message[pos + 1]]);

    if sig_alg != 0x0807 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unsupported signature algorithm: 0x{:04x}, expected Ed25519 (0x0807)",
                sig_alg
            ),
        ));
    }

    let sig_len = u16::from_be_bytes([
        cert_verify_message[pos + 2],
        cert_verify_message[pos + 3],
    ]) as usize;

    if sig_len != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid Ed25519 signature length: {}, expected 64", sig_len),
        ));
    }

    let sig_start = pos + 4;
    if sig_start + sig_len > cert_verify_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CertificateVerify message truncated",
        ));
    }

    Ok(cert_verify_message[sig_start..sig_start + sig_len].to_vec())
}

#[inline]
pub fn verify_certificate_verify_signature(
    public_key: &[u8; 32],
    signature: &[u8],
    transcript_hash: &[u8],
) -> io::Result<()> {
    if signature.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid signature length: {}, expected 64", signature.len()),
        ));
    }

    let mut signed_content = Vec::with_capacity(64 + 34 + transcript_hash.len());
    signed_content.extend_from_slice(&[0x20u8; 64]);
    signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content.push(0x00);
    signed_content.extend_from_slice(transcript_hash);

    let peer_public_key = UnparsedPublicKey::new(&ED25519, public_key);
    peer_public_key
        .verify(&signed_content, signature)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "CertificateVerify signature verification failed",
            )
        })?;

    Ok(())
}
