//! BoringSSL hooks and cryptographic handshake routines for REALITY.

use std::{
    ffi::c_void,
    io,
    os::raw::{c_int, c_long},
    sync::LazyLock,
};

use anyhow::Context as _;
use boring::error::ErrorStack;
use boring::pkey::Id;
use boring::ssl::SslRef;
use foreign_types::ForeignTypeRef as _;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};

use crate::common::tls::{encode_alpn,
    boring::{add_chrome_alps_public, get_reality_connector}};
use super::RealityConfig;

const SSL_GROUP_X25519: u16 = 29;
const HKDF_INFO: &[u8] = b"REALITY";
const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;

/// TLS client handshake with a REALITY server over `stream`.
pub(super) async fn reality_connect<S>(
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

    if let Some(protocols) = &config.alpn {
        cfg.set_alpn_protos(&encode_alpn(protocols)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    }

    if chrome {
        cfg.set_permute_extensions(true);
        cfg.set_enable_ech_grease(true);
        if config.alpn.as_ref().is_none_or(|protocols| {
            protocols.iter().any(|protocol| protocol == "h2")
        }) {
            add_chrome_alps_public(&mut cfg)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        }
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

fn reality_session_id(
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
#[path = "tests.rs"]
mod tests;
