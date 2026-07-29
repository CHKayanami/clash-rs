use super::common::{
    HANDSHAKE_TYPE_FINISHED, VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR,
};
use std::io::Result;

pub const DEFAULT_ALPN_PROTOCOLS: &[&str] = &["h2", "http/1.1"];

pub fn construct_client_hello(
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    client_public_key: &[u8],
    server_name: &str,
    cipher_suites: &[u16],
    alpn_protocols: &[&str],
) -> Result<Vec<u8>> {
    let mut hello = Vec::with_capacity(512);

    hello.push(0x01); // ClientHello

    let length_offset = hello.len();
    hello.extend_from_slice(&[0u8; 3]);

    hello.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]);
    hello.extend_from_slice(client_random);

    hello.push(32);
    hello.extend_from_slice(session_id);

    let cipher_suites_len = (cipher_suites.len() * 2) as u16;
    hello.extend_from_slice(&cipher_suites_len.to_be_bytes());
    for &suite in cipher_suites {
        hello.extend_from_slice(&suite.to_be_bytes());
    }

    hello.extend_from_slice(&[0x01, 0x00]);

    let extensions_offset = hello.len();
    hello.extend_from_slice(&[0u8; 2]);

    let mut extensions = Vec::new();

    // server_name extension (0)
    {
        let server_name_bytes = server_name.as_bytes();
        let server_name_len = server_name_bytes.len();

        extensions.extend_from_slice(&[0x00, 0x00]);
        let ext_len = 5 + server_name_len;
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&((server_name_len + 3) as u16).to_be_bytes());
        extensions.push(0x00);
        extensions.extend_from_slice(&(server_name_len as u16).to_be_bytes());
        extensions.extend_from_slice(server_name_bytes);
    }

    // supported_versions extension (43)
    {
        extensions.extend_from_slice(&[0x00, 0x2b]);
        extensions.extend_from_slice(&[0x00, 0x03]);
        extensions.push(0x02);
        extensions.extend_from_slice(&[0x03, 0x04]);
    }

    // supported_groups extension (10)
    {
        extensions.extend_from_slice(&[0x00, 0x0a]);
        extensions.extend_from_slice(&[0x00, 0x04]);
        extensions.extend_from_slice(&[0x00, 0x02]);
        extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
    }

    // key_share extension (51)
    {
        extensions.extend_from_slice(&[0x00, 0x33]);
        let key_share_len = 2 + 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_len as u16).to_be_bytes());
        extensions.extend_from_slice(&((key_share_len - 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x1d]); // Group: x25519
        extensions
            .extend_from_slice(&(client_public_key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(client_public_key);
    }

    // signature_algorithms extension (13)
    {
        extensions.extend_from_slice(&[0x00, 0x0d]);
        extensions.extend_from_slice(&[0x00, 0x08]);
        extensions.extend_from_slice(&[0x00, 0x06]);
        extensions.extend_from_slice(&[
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x04, 0x01, // rsa_pkcs1_sha256
        ]);
    }

    // ALPN extension (16)
    if !alpn_protocols.is_empty() {
        extensions.extend_from_slice(&[0x00, 0x10]);

        let mut alpn_list = Vec::new();
        for proto in alpn_protocols {
            let bytes = proto.as_bytes();
            alpn_list.push(bytes.len() as u8);
            alpn_list.extend_from_slice(bytes);
        }

        let alpn_ext_len = 2 + alpn_list.len();
        extensions.extend_from_slice(&(alpn_ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&alpn_list);
    }

    let ext_len = extensions.len() as u16;
    hello[extensions_offset..extensions_offset + 2]
        .copy_from_slice(&ext_len.to_be_bytes());
    hello.extend_from_slice(&extensions);

    let payload_len = (hello.len() - 4) as u32;
    hello[length_offset] = ((payload_len >> 16) & 0xff) as u8;
    hello[length_offset + 1] = ((payload_len >> 8) & 0xff) as u8;
    hello[length_offset + 2] = (payload_len & 0xff) as u8;

    Ok(hello)
}

pub fn construct_finished(verify_data: &[u8]) -> Result<Vec<u8>> {
    let mut finished = Vec::new();
    finished.push(HANDSHAKE_TYPE_FINISHED);
    finished.extend_from_slice(&[
        ((verify_data.len() >> 16) & 0xff) as u8,
        ((verify_data.len() >> 8) & 0xff) as u8,
        (verify_data.len() & 0xff) as u8,
    ]);
    finished.extend_from_slice(verify_data);
    Ok(finished)
}

pub fn write_record_header(
    buf: &mut Vec<u8>,
    content_type: u8,
    version: (u8, u8),
    length: u16,
) {
    buf.reserve(5 + length as usize);
    buf.push(content_type);
    buf.push(version.0);
    buf.push(version.1);
    buf.extend_from_slice(&length.to_be_bytes());
}
