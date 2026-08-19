//! Configuration

use std::{
    collections::HashMap,
    fmt::{self, Debug, Display},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use base64::Engine as _;
use byte_string::ByteStr;
use bytes::Bytes;
use cfg_if::cfg_if;
use log::warn;
use thiserror::Error;

#[cfg(any(feature = "stream-cipher", feature = "aead-cipher"))]
use crate::crypto::v1::openssl_bytes_to_key;
use crate::{crypto::CipherKind, relay::socks5::Address};

const USER_KEY_BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

#[cfg(feature = "aead-cipher-2022")]
const AEAD2022_PASSWORD_BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Shadowsocks server type
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerType {
    /// Running as a local service
    Local,

    /// Running as a shadowsocks server
    Server,
}

impl ServerType {
    /// Check if it is `Local`
    pub fn is_local(self) -> bool {
        self == Self::Local
    }

    /// Check if it is `Server`
    pub fn is_server(self) -> bool {
        self == Self::Server
    }
}

/// Server's user
#[derive(Clone)]
pub struct ServerUser {
    name: String,
    key: Bytes,
    identity_hash: Bytes,
}

impl Debug for ServerUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerUser")
            .field("name", &self.name)
            .field("key", &USER_KEY_BASE64_ENGINE.encode(&self.key))
            .field("identity_hash", &ByteStr::new(&self.identity_hash))
            .finish()
    }
}

impl ServerUser {
    /// Create a user
    pub fn new<N, K>(name: N, key: K) -> Self
    where
        N: Into<String>,
        K: Into<Bytes>,
    {
        let name = name.into();
        let key = key.into();

        let hash = blake3::hash(&key);
        let identity_hash = Bytes::from(hash.as_bytes()[0..16].to_owned());

        Self {
            name,
            key,
            identity_hash,
        }
    }

    /// Create a user from encoded key
    pub fn with_encoded_key<N>(name: N, key: &str) -> Result<Self, ServerUserError>
    where
        N: Into<String>,
    {
        let key = USER_KEY_BASE64_ENGINE.decode(key)?;
        Ok(Self::new(name, key))
    }

    /// Name of the user
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Encryption key of user
    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// User's identity hash
    ///
    /// <https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md>
    pub fn identity_hash(&self) -> &[u8] {
        self.identity_hash.as_ref()
    }

    /// User's identity hash
    ///
    /// <https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md>
    pub fn clone_identity_hash(&self) -> Bytes {
        self.identity_hash.clone()
    }
}

/// ServerUser related errors
#[derive(Debug, Clone, Error)]
pub enum ServerUserError {
    /// Invalid User key encoding
    #[error("{0}")]
    InvalidKeyEncoding(#[from] base64::DecodeError),
}

/// Server multi-users manager
#[derive(Clone, Debug, Default)]
pub struct ServerUserManager {
    users: HashMap<Bytes, Arc<ServerUser>>,
}

impl ServerUserManager {
    /// Create a new manager
    pub fn new() -> Self {
        Self { users: HashMap::new() }
    }

    /// Add a new user
    pub fn add_user(&mut self, user: ServerUser) {
        self.users.insert(user.clone_identity_hash(), Arc::new(user));
    }

    /// Get user by hash key
    pub fn get_user_by_hash(&self, user_hash: &[u8]) -> Option<&ServerUser> {
        self.users.get(user_hash).map(AsRef::as_ref)
    }

    /// Get user by hash key cloned
    pub fn clone_user_by_hash(&self, user_hash: &[u8]) -> Option<Arc<ServerUser>> {
        self.users.get(user_hash).cloned()
    }

    /// Iterate users
    pub fn users_iter(&self) -> impl Iterator<Item = &ServerUser> {
        self.users.values().map(|v| v.as_ref())
    }
}

/// Errors when creating a new ServerConfig
#[derive(Debug, Clone, Error)]
pub enum ServerConfigError {
    /// Invalid base64 encoding of password
    #[error("invalid key encoding for {0}, {1}")]
    InvalidKeyEncoding(CipherKind, base64::DecodeError),

    /// Invalid user key encoding
    #[error("invalid iPSK encoding for {0}, {1}")]
    InvalidUserKeyEncoding(CipherKind, base64::DecodeError),

    /// Key length mismatch
    #[error("invalid key length for {0}, expecting {1} bytes, but found {2} bytes")]
    InvalidKeyLength(CipherKind, usize, usize),

    /// User Key (ipsk) length mismatch
    #[error("invalid user key length for {0}, expecting {1} bytes, but found {2} bytes")]
    InvalidUserKeyLength(CipherKind, usize, usize),
}

/// Configuration for a server
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Server address
    addr: ServerAddr,
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    method: CipherKind,
    /// Encryption key
    enc_key: Box<[u8]>,

    /// Extensible Identity Headers (AEAD-2022)
    ///
    /// For client, assemble EIH headers
    identity_keys: Arc<Vec<Bytes>>,

    /// Extensible Identity Headers (AEAD-2022)
    ///
    /// For server, support multi-users with EIH
    user_manager: Option<Arc<ServerUserManager>>,
}

#[inline]
fn make_derived_key(method: CipherKind, password: &str, enc_key: &mut [u8]) -> Result<(), ServerConfigError> {
    #[cfg(feature = "aead-cipher-2022")]
    if method.is_aead_2022() {
        // AEAD 2022 password is a base64 form of enc_key
        match AEAD2022_PASSWORD_BASE64_ENGINE.decode(password) {
            Ok(v) => {
                if v.len() != enc_key.len() {
                    return Err(ServerConfigError::InvalidKeyLength(method, enc_key.len(), v.len()));
                }
                enc_key.copy_from_slice(&v);
            }
            Err(err) => {
                return Err(ServerConfigError::InvalidKeyEncoding(method, err));
            }
        }

        return Ok(());
    }

    cfg_if! {
        if #[cfg(any(feature = "stream-cipher", feature = "aead-cipher"))] {
            let _ = method;
            openssl_bytes_to_key(password.as_bytes(), enc_key);

            Ok(())
        } else {
            // No default implementation.
            let _ = password;
            let _ = enc_key;
            unreachable!("{method} don't know how to make a derived key");
        }
    }
}

/// Check if method supports Extended Identity Header
///
/// <https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md>
#[cfg(feature = "aead-cipher-2022")]
#[inline]
pub fn method_support_eih(method: CipherKind) -> bool {
    matches!(
        method,
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
    )
}

#[allow(clippy::type_complexity)]
fn password_to_keys<P>(method: CipherKind, password: P) -> Result<(String, Box<[u8]>, Vec<Bytes>), ServerConfigError>
where
    P: Into<String>,
{
    let password = password.into();

    match method {
        CipherKind::NONE => {
            // NONE method's key length is 0
            debug_assert_eq!(method.key_len(), 0);

            if !password.is_empty() {
                warn!(
                    "method \"none\" doesn't need a password, which should be set as an empty String, but password.len() = {}",
                    password.len()
                );
            }

            return Ok((password, Vec::new().into_boxed_slice(), Vec::new()));
        }

        #[cfg(feature = "stream-cipher")]
        CipherKind::SS_TABLE => {
            let enc_key = password.clone().into_bytes().into_boxed_slice();
            return Ok((password, enc_key, Vec::new()));
        }

        #[allow(unreachable_patterns)]
        _ => {}
    }

    #[cfg(feature = "aead-cipher-2022")]
    if method_support_eih(method) {
        // Extensible Identity Headers
        // iPSK1:iPSK2:iPSK3:...:uPSK

        let mut identity_keys = Vec::new();

        let mut split_iter = password.rsplit(':');

        let upsk = split_iter.next().expect("uPSK");

        let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
        make_derived_key(method, upsk, &mut enc_key)?;

        for ipsk in split_iter {
            match USER_KEY_BASE64_ENGINE.decode(ipsk) {
                Ok(v) => {
                    // Double check identity key's length
                    match method {
                        CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
                            // AES-128
                            if v.len() != 16 {
                                return Err(ServerConfigError::InvalidUserKeyLength(method, 16, v.len()));
                            }
                        }
                        CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                            // AES-256
                            if v.len() != 32 {
                                return Err(ServerConfigError::InvalidUserKeyLength(method, 32, v.len()));
                            }
                        }
                        _ => unreachable!("{} doesn't support EIH", method),
                    }
                    identity_keys.push(Bytes::from(v));
                }
                Err(err) => {
                    return Err(ServerConfigError::InvalidUserKeyEncoding(method, err));
                }
            }
        }

        identity_keys.reverse();

        return Ok((upsk.to_owned(), enc_key, identity_keys));
    }

    let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
    make_derived_key(method, &password, &mut enc_key)?;

    Ok((password, enc_key, Vec::new()))
}

impl ServerConfig {
    /// Create a new `ServerConfig`
    pub fn new<A, P>(addr: A, password: P, method: CipherKind) -> Result<Self, ServerConfigError>
    where
        A: Into<ServerAddr>,
        P: Into<String>,
    {
        let (password, enc_key, identity_keys) = password_to_keys(method, password)?;

        Ok(Self {
            addr: addr.into(),
            password,
            method,
            enc_key,
            identity_keys: Arc::new(identity_keys),
            user_manager: None,
        })
    }

    /// Get server address
    pub fn addr(&self) -> &ServerAddr {
        &self.addr
    }

    /// Get encryption key
    pub fn key(&self) -> &[u8] {
        self.enc_key.as_ref()
    }

    /// Get password (uPSK only; does not include identity keys)
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    /// Get identity keys (Client)
    pub fn identity_keys(&self) -> &[Bytes] {
        &self.identity_keys
    }

    /// Clone identity keys (Client)
    pub fn clone_identity_keys(&self) -> Arc<Vec<Bytes>> {
        self.identity_keys.clone()
    }

    /// Set user manager, enable Server's multi-user support with EIH
    pub fn set_user_manager(&mut self, user_manager: ServerUserManager) {
        self.user_manager = Some(Arc::new(user_manager));
    }

    /// Get user manager (Server)
    pub fn user_manager(&self) -> Option<&ServerUserManager> {
        self.user_manager.as_deref()
    }

    /// Clone user manager (Server)
    pub fn clone_user_manager(&self) -> Option<Arc<ServerUserManager>> {
        self.user_manager.clone()
    }

    /// Get method
    pub fn method(&self) -> CipherKind {
        self.method
    }
}

/// Server address
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServerAddr {
    /// IP Address
    SocketAddr(SocketAddr),
    /// Domain name address, eg. example.com:8080
    DomainName(String, u16),
}

impl ServerAddr {
    /// Get string representation of domain
    pub fn host(&self) -> String {
        match *self {
            Self::SocketAddr(ref s) => s.ip().to_string(),
            Self::DomainName(ref dm, _) => dm.clone(),
        }
    }

    /// Get port
    pub fn port(&self) -> u16 {
        match *self {
            Self::SocketAddr(ref s) => s.port(),
            Self::DomainName(_, p) => p,
        }
    }
}

impl Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SocketAddr(ref a) => write!(f, "{a}"),
            Self::DomainName(ref d, port) => write!(f, "{d}:{port}"),
        }
    }
}

impl From<SocketAddr> for ServerAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::SocketAddr(addr)
    }
}

impl<I: Into<String>> From<(I, u16)> for ServerAddr {
    fn from((dname, port): (I, u16)) -> Self {
        Self::DomainName(dname.into(), port)
    }
}

impl From<Address> for ServerAddr {
    fn from(addr: Address) -> Self {
        match addr {
            Address::SocketAddress(sa) => Self::SocketAddr(sa),
            Address::DomainNameAddress(dn, port) => Self::DomainName(dn, port),
        }
    }
}

impl From<&Address> for ServerAddr {
    fn from(addr: &Address) -> Self {
        match *addr {
            Address::SocketAddress(sa) => Self::SocketAddr(sa),
            Address::DomainNameAddress(ref dn, port) => Self::DomainName(dn.clone(), port),
        }
    }
}

impl From<ServerAddr> for Address {
    fn from(addr: ServerAddr) -> Self {
        match addr {
            ServerAddr::SocketAddr(sa) => Self::SocketAddress(sa),
            ServerAddr::DomainName(dn, port) => Self::DomainNameAddress(dn, port),
        }
    }
}

impl From<&ServerAddr> for Address {
    fn from(addr: &ServerAddr) -> Self {
        match *addr {
            ServerAddr::SocketAddr(sa) => Self::SocketAddress(sa),
            ServerAddr::DomainName(ref dn, port) => Self::DomainNameAddress(dn.clone(), port),
        }
    }
}

/// Policy for handling replay attack requests
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum ReplayAttackPolicy {
    /// Default strategy based on protocol
    ///
    /// SIP022 (AEAD-2022): Reject
    /// SIP004 (AEAD): Ignore
    /// Stream: Ignore
    #[default]
    Default,
    /// Ignore it completely
    Ignore,
    /// Try to detect replay attack and warn about it
    Detect,
    /// Try to detect replay attack and reject the request
    Reject,
}

impl Display for ReplayAttackPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Default => f.write_str("default"),
            Self::Ignore => f.write_str("ignore"),
            Self::Detect => f.write_str("detect"),
            Self::Reject => f.write_str("reject"),
        }
    }
}

/// Error while parsing ReplayAttackPolicy from string
#[derive(Debug, Clone, Copy)]
pub struct ReplayAttackPolicyError;

impl Display for ReplayAttackPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ReplayAttackPolicy")
    }
}

impl FromStr for ReplayAttackPolicy {
    type Err = ReplayAttackPolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" => Ok(Self::Default),
            "ignore" => Ok(Self::Ignore),
            "detect" => Ok(Self::Detect),
            "reject" => Ok(Self::Reject),
            _ => Err(ReplayAttackPolicyError),
        }
    }
}
