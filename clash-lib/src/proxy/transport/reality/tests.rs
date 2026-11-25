use super::*;
use super::super::Client;
use crate::common::tls::encode_alpn;
use base64::{Engine as _, engine::general_purpose};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

#[test]
fn reality_client_rejects_empty_sni_before_connecting() {
    let error = match Client::new(String::new(), [7; 32], [0; 8], true, None) {
        Ok(_) => panic!("empty Reality SNI must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn reality_client_preencodes_alpn_and_alps_flag() {
    let default_chrome = Client::new("localhost".into(), [7; 32], [0; 8], true, None).unwrap();
    assert_eq!(default_chrome.0.config.alpn_wire, None);
    assert!(default_chrome.0.config.alps);

    let empty_chrome = Client::new("localhost".into(), [7; 32], [0; 8], true, Some(vec![])).unwrap();
    assert_eq!(empty_chrome.0.config.alpn_wire, Some(Vec::new()));
    assert!(!empty_chrome.0.config.alps);

    let h1_chrome = Client::new(
        "localhost".into(),
        [7; 32],
        [0; 8],
        true,
        Some(vec!["http/1.1".into()]),
    )
    .unwrap();
    assert_eq!(h1_chrome.0.config.alpn_wire, Some(b"\x08http/1.1".to_vec()));
    assert!(!h1_chrome.0.config.alps);

    let h2_plain = Client::new(
        "localhost".into(),
        [7; 32],
        [0; 8],
        false,
        Some(vec!["h2".into()]),
    )
    .unwrap();
    assert_eq!(h2_plain.0.config.alpn_wire, Some(b"\x02h2".to_vec()));
    assert!(!h2_plain.0.config.alps);
}

#[tokio::test]
async fn reality_alpn_is_present_in_client_hello() {
    for chrome in [false, true] {
        for protocols in [None, Some(vec![]),
            Some(vec!["http/1.1".to_owned()]),
            Some(vec!["h2".to_owned(), "http/1.1".to_owned()])] {
            let expected = match &protocols {
                Some(protocols) => encode_alpn(protocols).unwrap(),
                None if chrome => b"\x02h2\x08http/1.1".to_vec(),
                None => Vec::new(),
            };
            let client_cfg = Client::new(
                "localhost".to_owned(),
                [7; 32],
                [0; 8],
                chrome,
                protocols,
            )
            .unwrap();
            let (client, mut server) = tokio::io::duplex(8192);
            let capture = async move {
                let mut header = [0; 5];
                server.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22);
                let mut hello = vec![0; u16::from_be_bytes(
                    [header[3], header[4]],
                ) as usize];
                server.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 1);
                let mut offset = 39 + hello[38] as usize;
                offset += 2 + u16::from_be_bytes([
                    hello[offset], hello[offset + 1],
                ]) as usize;
                offset += 1 + hello[offset] as usize;
                let end = offset + 2 + u16::from_be_bytes([
                    hello[offset], hello[offset + 1],
                ]) as usize;
                offset += 2;
                while offset < end {
                    let kind = u16::from_be_bytes([
                        hello[offset], hello[offset + 1],
                    ]);
                    let size = u16::from_be_bytes([
                        hello[offset + 2], hello[offset + 3],
                    ]) as usize;
                    offset += 4;
                    if kind == 16 {
                        return hello[offset + 2..offset + size].to_vec();
                    }
                    offset += size;
                }
                Vec::new()
            };
            let (result, offered) = timeout(
                Duration::from_secs(5), async {
                    tokio::join!(reality_connect(client, &client_cfg.0.config, chrome), capture)
                },
            ).await.unwrap();
            assert!(result.is_err()); // The capture peer does not complete TLS.
            assert_eq!(offered, expected);
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn session_id_matches_reference_vector() {
    let eph_priv = [0x42u8; 32];
    let server_pub: [u8; 32] = general_purpose::URL_SAFE_NO_PAD
        .decode("ubLKoDOT4sSoWuztLwduKc9szHmp4lvmKbMk4-1O518")
        .unwrap()
        .try_into()
        .unwrap();
    let mut client_random = [0u8; 32];
    for (i, b) in client_random.iter_mut().enumerate() {
        *b = i as u8;
    }
    let short_id: [u8; 8] = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
    let mut msg = vec![0x01, 0x00, 0x00, 0x4d, 0x03, 0x03];
    msg.extend_from_slice(&client_random);
    msg.push(0x20);
    msg.extend_from_slice(&[0u8; 32]);
    msg.extend(0xa0u8..0xb0);

    let (session_id, auth_key) = reality_session_id(
        &eph_priv,
        &server_pub,
        &client_random,
        &short_id,
        1_754_300_000,
        &msg,
    )
    .unwrap();
    assert_eq!(
        auth_key.as_slice(),
        unhex("5becfd7970ef3964e9a57b8b5c5d45b6cb97644e88458e3c8d61f53e3ae4015e").as_slice()
    );
    assert_eq!(
        session_id.as_slice(),
        unhex("7cfcdadbd3a5640bceef2afc7951caf671f7a737b2ba3f30eadb2d32148c542d").as_slice()
    );
}

#[test]
fn session_id_binds_full_client_hello() {
    let eph_priv = [0x42u8; 32];
    let server_pub = [0x07u8; 32];
    let client_random = [0x33u8; 32];
    let short_id = [0u8; 8];
    let mut msg = vec![0x01, 0x00, 0x00, 0x4d, 0x03, 0x03];
    msg.extend_from_slice(&client_random);
    msg.push(0x20);
    msg.extend_from_slice(&[0u8; 32]);
    msg.extend(0xa0u8..0xb0);
    let (sid_a, _) =
        reality_session_id(&eph_priv, &server_pub, &client_random, &short_id, 1, &msg).unwrap();
    msg[80] ^= 1;
    let (sid_b, _) =
        reality_session_id(&eph_priv, &server_pub, &client_random, &short_id, 1, &msg).unwrap();
    assert_ne!(sid_a, sid_b);
}

#[test]
fn extract_auth_key_rejects_missing_state_and_underived_key() {
    let context = get_reality_context(false).unwrap();
    let ssl = Ssl::new(context).unwrap();

    let missing_err = extract_auth_key(&ssl).unwrap_err();
    assert_eq!(missing_err.kind(), io::ErrorKind::InvalidData);
    assert!(missing_err.to_string().contains("state missing"));

    let client = Client::new("localhost".into(), [7; 32], [0; 8], false, None).unwrap();
    setup_reality_ssl(&ssl, &client.0.config).unwrap();

    let underived_err = extract_auth_key(&ssl).unwrap_err();
    assert_eq!(underived_err.kind(), io::ErrorKind::InvalidData);
    assert!(underived_err.to_string().contains("not derived"));
}
