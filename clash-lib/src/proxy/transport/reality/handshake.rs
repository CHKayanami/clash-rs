//! BoringSSL hooks and cryptographic handshake routines for REALITY.

use std::{
    ffi::c_void,
    io,
    os::raw::{c_int, c_long},
    sync::LazyLock,
};

use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose;
use boring::error::ErrorStack;
use boring::pkey::Id;
use boring::ssl::SslRef;
use foreign_types::ForeignTypeRef as _;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};

use crate::common::tls::boring::{add_chrome_alps_public, get_reality_connector};
use super::RealityConfig;

const SSL_GROUP_X25519: u16 = 29;
const HKDF_INFO: &[u8] = b"REALITY";
const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;

/// TLS client handshake with a REALITY server over `stream`.
pub async fn reality_connect<S>(
    stream: S,
    config: &RealityConfig,
    chrome: bool,
) -> io::Result<tokio_boring::SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connector = get_reality_connector(chrome)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut cfg = connector
        .configure()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    if chrome {
        cfg.set_permute_extensions(true);
        cfg.set_enable_ech_grease(true);
        add_chrome_alps_public(&mut cfg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    }

    setup_reality_ssl(&cfg, config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let tls = tokio_boring::connect(cfg, &config.server_name, stream)
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("REALITY handshake with {} failed: {e}", config.server_name),
            )
        })?;

    let state = unsafe {
        boring_sys::SSL_get_ex_data(tls.ssl().as_ptr(), reality_ex_index())
            .cast::<RealityHandshake>()
    };
    if state.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY ClientHello fixup state missing",
        ));
    }
    let auth_key = unsafe { (*state).auth_key };
    verify_server_certificate(tls.ssl(), &auth_key)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;

    Ok(tls)
}

#[allow(dead_code)]
pub fn decode_public_key(encoded: &str) -> Option<[u8; 32]> {
    for engine in [
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::STANDARD,
    ] {
        if let Ok(bytes) = engine.decode(encoded.trim())
            && let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice())
        {
            return Some(key);
        }
    }
    None
}

#[allow(dead_code)]
pub fn parse_short_id(s: &str) -> Option<[u8; 8]> {
    let s = s.trim();
    if s.is_empty() {
        return Some([0u8; 8]);
    }
    if s.len() % 2 != 0 || s.len() > 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, b) in out.iter_mut().enumerate().take(s.len() / 2) {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub fn reality_session_id(
    eph_priv: &[u8; 32],
    server_pub: &[u8; 32],
    client_random: &[u8; 32],
    short_id: &[u8; 8],
    timestamp: u32,
    aad: &[u8],
) -> Option<([u8; 32], [u8; 32])> {
    let mut shared = [0u8; 32];
    let ok =
        unsafe { boring_sys::X25519(shared.as_mut_ptr(), eph_priv.as_ptr(), server_pub.as_ptr()) };
    if ok != 1 {
        return None;
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), &shared);
    let mut auth_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut auth_key).ok()?;

    let mut plain = [0u8; 16];
    plain[..3].copy_from_slice(&[1, 3, 3]); // client version, reality.go
    plain[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plain[8..].copy_from_slice(short_id);

    let ctx =
        boring::aead::AeadCtx::new_default_tag(&boring::aead::Algorithm::aes_256_gcm(), &auth_key)
            .ok()?;
    let mut tag = [0u8; 16];
    ctx.seal_in_place(&client_random[20..32], &mut plain, &mut tag, aad)
        .ok()?;
    let mut session_id = [0u8; 32];
    session_id[..16].copy_from_slice(&plain);
    session_id[16..].copy_from_slice(&tag);
    Some((session_id, auth_key))
}

struct RealityHandshake {
    eph_priv: [u8; 32],
    server_pub: [u8; 32],
    short_id: [u8; 8],
    auth_key: [u8; 32],
}

fn reality_ex_index() -> c_int {
    static INDEX: LazyLock<c_int> = LazyLock::new(|| unsafe {
        boring_sys::SSL_get_ex_new_index(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            None,
            Some(reality_state_free),
        )
    });
    *INDEX
}

unsafe extern "C" fn reality_state_free(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut boring_sys::CRYPTO_EX_DATA,
    _index: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr.cast::<RealityHandshake>()) });
    }
}

extern "C" fn reality_fixup_cb(ssl: *mut boring_sys::SSL, msg: *mut u8, msg_len: usize) -> c_int {
    unsafe {
        let state = boring_sys::SSL_get_ex_data(ssl, reality_ex_index()).cast::<RealityHandshake>();
        if state.is_null() || msg.is_null() || msg_len < SESSION_ID_OFFSET + SESSION_ID_LEN {
            return 0;
        }
        let state = &mut *state;
        let msg = std::slice::from_raw_parts_mut(msg, msg_len);
        if msg[0] != 1 || msg[38] != SESSION_ID_LEN as u8 {
            return 0;
        }
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&msg[6..38]);
        msg[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        match reality_session_id(
            &state.eph_priv,
            &state.server_pub,
            &client_random,
            &state.short_id,
            timestamp,
            msg,
        ) {
            Some((session_id, auth_key)) => {
                msg[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]
                    .copy_from_slice(&session_id);
                state.auth_key = auth_key;
                1
            }
            None => 0,
        }
    }
}

fn setup_reality_ssl(ssl: &SslRef, config: &RealityConfig) -> anyhow::Result<()> {
    let sigalgs = c"ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
    let ok = unsafe { boring_sys::SSL_set1_sigalgs_list(ssl.as_ptr(), sigalgs.as_ptr()) };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_sigalgs_list");
    }
    let mut state = Box::new(RealityHandshake {
        eph_priv: [0u8; 32],
        server_pub: config.public_key,
        short_id: config.short_id,
        auth_key: [0u8; 32],
    });
    let ok = unsafe { boring_sys::RAND_bytes(state.eph_priv.as_mut_ptr(), state.eph_priv.len()) };
    if ok != 1 {
        return Err(ErrorStack::get()).context("RAND_bytes");
    }
    let ok = unsafe {
        boring_sys::SSL_set1_client_x25519_private_key(ssl.as_ptr(), state.eph_priv.as_ptr())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_x25519_private_key");
    }
    let groups = c"X25519";
    let ok = unsafe { boring_sys::SSL_set1_groups_list(ssl.as_ptr(), groups.as_ptr()) };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_groups_list");
    }
    let shares = [SSL_GROUP_X25519];
    let ok = unsafe {
        boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_key_shares");
    }
    let raw_state = Box::into_raw(state);
    let ok = unsafe {
        boring_sys::SSL_set_ex_data(
            ssl.as_ptr(),
            reality_ex_index(),
            raw_state.cast(),
        )
    };
    if ok != 1 {
        unsafe { drop(Box::from_raw(raw_state)) };
        return Err(ErrorStack::get()).context("SSL_set_ex_data");
    }
    unsafe { boring_sys::SSL_set_client_hello_fixup_cb(ssl.as_ptr(), Some(reality_fixup_cb)) };
    Ok(())
}

fn verify_server_certificate(ssl: &SslRef, auth_key: &[u8; 32]) -> anyhow::Result<()> {
    let cert = ssl
        .peer_certificate()
        .context("REALITY server presented no certificate")?;
    let pkey = cert.public_key()?;
    anyhow::ensure!(
        pkey.id() == Id::ED25519,
        "REALITY server presented a non-ed25519 certificate (potential MITM or redirection)"
    );
    let mut raw_pub = [0u8; 32];
    let raw_pub = pkey
        .raw_public_key(&mut raw_pub)
        .context("read ed25519 public key")?;
    let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(raw_pub);
    mac.verify_slice(cert.signature().as_slice()).map_err(|_| {
        anyhow::anyhow!("REALITY certificate authentication failed (potential MITM or redirection)")
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_parse_short_id() {
        assert_eq!(parse_short_id(""), Some([0u8; 8]));
        assert_eq!(
            parse_short_id("01020304"),
            Some([0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0])
        );
        assert_eq!(
            parse_short_id("0102030405060708"),
            Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
        // Odd-length hex must fail
        assert_eq!(parse_short_id("123"), None);
        // Longer than 8 bytes (16 hex chars) must fail
        assert_eq!(parse_short_id("010203040506070809"), None);
    }

    #[test]
    fn test_decode_public_key() {
        let raw = [42u8; 32];
        let b64 = general_purpose::URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(decode_public_key(&b64), Some(raw));

        let b64_std = general_purpose::STANDARD.encode(raw);
        assert_eq!(decode_public_key(&b64_std), Some(raw));

        assert_eq!(decode_public_key("invalid"), None);
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
}
