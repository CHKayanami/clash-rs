//! UDP socket for communicating with shadowsocks' proxy server

#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket};
use std::{
    future::poll_fn,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::{Arc, LazyLock},
    task::{Context, Poll, ready},
    time::Duration,
};

use byte_string::ByteStr;
use bytes::{Bytes, BytesMut};
use log::{info, trace};
use tokio::{io::ReadBuf, time};

use crate::{
    config::{ServerConfig, ServerUserManager},
    context::SharedContext,
    crypto::CipherKind,
    relay::{socks5::Address, udprelay::options::UdpSocketControlData},
};

use super::{
    compat::{DatagramReceive, DatagramSend, DatagramSocket},
    crypto_io::{
        ProtocolError, ProtocolResult, decrypt_client_payload, encrypt_server_payload,
    },
};
#[cfg(not(feature = "aead-cipher-2022"))]
use super::crypto_io::{decrypt_server_payload, encrypt_client_payload};
#[cfg(feature = "aead-cipher-2022")]
use super::crypto_io::{decrypt_server_payload_cached, encrypt_client_payload_cached};
#[cfg(feature = "aead-cipher-2022")]
use super::aead_2022::UdpCipherCache;

/// UDP socket type, defining whether the socket is used in Client or Server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSocketType {
    /// Socket used for `Client -> Server`
    Client,
    /// Socket used for `Server -> Client`
    Server,
}

/// `ProxySocket` error type
#[derive(thiserror::Error, Debug)]
pub enum ProxySocketError {
    /// std::io::Error
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    ProtocolError(ProtocolError),
    #[error("peer: {0}, {1}")]
    ProtocolErrorWithPeer(SocketAddr, ProtocolError),
    #[error("invalid server user identity {:?}", ByteStr::new(.0))]
    InvalidServerUser(Bytes),
}

impl From<ProxySocketError> for io::Error {
    fn from(e: ProxySocketError) -> Self {
        match e {
            ProxySocketError::IoError(err) => err,
            ProxySocketError::ProtocolError(err) => io::Error::new(ErrorKind::Other, err),
            ProxySocketError::ProtocolErrorWithPeer(.., err) => io::Error::new(ErrorKind::Other, err),
            ProxySocketError::InvalidServerUser(..) => io::Error::new(ErrorKind::Other, "invalid server user identity"),
        }
    }
}

/// `ProxySocket` result type
pub type ProxySocketResult<T> = Result<T, ProxySocketError>;

static DEFAULT_SOCKET_CONTROL: LazyLock<UdpSocketControlData> = LazyLock::new(UdpSocketControlData::default);

/// UDP client for communicating with ShadowSocks' server
#[derive(Debug)]
pub struct ProxySocket<S> {
    socket_type: UdpSocketType,
    io: S,
    method: CipherKind,
    key: Box<[u8]>,
    send_timeout: Option<Duration>,
    recv_timeout: Option<Duration>,
    context: SharedContext,
    identity_keys: Arc<Vec<Bytes>>,
    user_manager: Option<Arc<ServerUserManager>>,
    #[cfg(feature = "aead-cipher-2022")]
    cipher_cache: UdpCipherCache,
}

impl<S> ProxySocket<S> {
    /// Create a `ProxySocket` from a I/O object that impls `DatagramTransport`
    pub fn from_socket(socket_type: UdpSocketType, context: SharedContext, svr_cfg: &ServerConfig, socket: S) -> Self {
        let key = svr_cfg.key().to_vec().into_boxed_slice();
        let method = svr_cfg.method();

        Self {
            socket_type,
            io: socket,
            method,
            key,
            send_timeout: None,
            recv_timeout: None,
            context,
            identity_keys: match socket_type {
                UdpSocketType::Client => svr_cfg.clone_identity_keys(),
                UdpSocketType::Server => Arc::new(Vec::new()),
            },
            user_manager: match socket_type {
                UdpSocketType::Client => None,
                UdpSocketType::Server => svr_cfg.clone_user_manager(),
            },
            #[cfg(feature = "aead-cipher-2022")]
            cipher_cache: UdpCipherCache::new(),
        }
    }

    /// Set `send` timeout, `None` will clear timeout
    pub fn set_send_timeout(&mut self, t: Option<Duration>) {
        self.send_timeout = t;
    }

    /// Set `recv` timeout, `None` will clear timeout
    pub fn set_recv_timeout(&mut self, t: Option<Duration>) {
        self.recv_timeout = t;
    }
}

impl<S> ProxySocket<S>
where
    S: DatagramSend,
{
    fn encrypt_send_buffer(
        &self,
        addr: &Address,
        control: &UdpSocketControlData,
        identity_keys: &[Bytes],
        payload: &[u8],
        send_buf: &mut BytesMut,
    ) -> ProxySocketResult<()> {
        match self.socket_type {
            UdpSocketType::Client => {
                #[cfg(feature = "aead-cipher-2022")]
                encrypt_client_payload_cached(
                    &self.context,
                    self.method,
                    &self.key,
                    addr,
                    control,
                    identity_keys,
                    payload,
                    send_buf,
                    Some(&self.cipher_cache),
                );

                #[cfg(not(feature = "aead-cipher-2022"))]
                encrypt_client_payload(
                    &self.context,
                    self.method,
                    &self.key,
                    addr,
                    control,
                    identity_keys,
                    payload,
                    send_buf,
                );
            }
            UdpSocketType::Server => {
                let mut key = self.key.as_ref();

                if let Some(ref user) = control.user {
                    trace!("udp encrypt with {:?} identity", user);
                    key = user.key();
                }

                encrypt_server_payload(&self.context, self.method, key, addr, control, payload, send_buf)
            }
        }

        Ok(())
    }

    /// Send a UDP packet to addr through proxy `target` with `ControlData`
    pub fn poll_send_to_with_ctrl(
        &self,
        target: SocketAddr,
        addr: &Address,
        control: &UdpSocketControlData,
        payload: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<ProxySocketResult<usize>> {
        let mut send_buf = BytesMut::with_capacity(payload.len() + 256);

        self.encrypt_send_buffer(addr, control, &self.identity_keys, payload, &mut send_buf)?;

        info!(
            "UDP server client poll_send_to to {}, payload length {} bytes, packet length {} bytes",
            target,
            payload.len(),
            send_buf.len()
        );

        let n_send_buf = send_buf.len();
        match self.io.poll_send_to(cx, &send_buf, target).map_err(|x| x.into()) {
            Poll::Ready(Ok(l)) => {
                if l == n_send_buf {
                    Poll::Ready(Ok(payload.len()))
                } else {
                    Poll::Ready(Err(io::Error::from(ErrorKind::WriteZero).into()))
                }
            }
            x => x,
        }
    }

    /// Send a UDP packet to target through proxy `target`
    pub async fn send_to(&self, target: SocketAddr, addr: &Address, payload: &[u8]) -> ProxySocketResult<usize> {
        let fut = poll_fn(|cx| self.poll_send_to_with_ctrl(target, addr, &DEFAULT_SOCKET_CONTROL, payload, cx));
        match self.send_timeout {
            None => fut.await,
            Some(d) => match time::timeout(d, fut).await {
                Ok(res) => res,
                Err(..) => Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        }
    }
}

impl<S> ProxySocket<S>
where
    S: DatagramReceive,
{
    fn decrypt_recv_buffer(
        &self,
        recv_buf: &mut [u8],
        user_manager: Option<&ServerUserManager>,
    ) -> ProtocolResult<(usize, Address, Option<UdpSocketControlData>)> {
        match self.socket_type {
            UdpSocketType::Client => {
                #[cfg(feature = "aead-cipher-2022")]
                return decrypt_server_payload_cached(
                    &self.context,
                    self.method,
                    &self.key,
                    recv_buf,
                    Some(&self.cipher_cache),
                );

                #[cfg(not(feature = "aead-cipher-2022"))]
                return decrypt_server_payload(&self.context, self.method, &self.key, recv_buf);
            }
            UdpSocketType::Server => {
                decrypt_client_payload(&self.context, self.method, &self.key, recv_buf, user_manager)
            }
        }
    }

    /// Poll family function to receive decrypted packet from Shadowsocks' UDP server
    #[allow(clippy::type_complexity)]
    pub fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        recv_buf: &mut ReadBuf<'_>,
    ) -> Poll<ProxySocketResult<(usize, Address, usize)>> {
        ready!(self.io.poll_recv(cx, recv_buf))?;

        let n_recv = recv_buf.filled().len();

        match self.decrypt_recv_buffer(recv_buf.filled_mut(), self.user_manager.as_deref()) {
            Ok(x) => Poll::Ready(Ok((x.0, x.1, n_recv))),
            Err(err) => Poll::Ready(Err(ProxySocketError::ProtocolError(err))),
        }
    }

    /// Poll family function to receive packet from Shadowsocks' UDP server with source address and control
    #[allow(clippy::type_complexity)]
    pub fn poll_recv_from_with_ctrl(
        &self,
        cx: &mut Context<'_>,
        recv_buf: &mut ReadBuf<'_>,
    ) -> Poll<ProxySocketResult<(usize, SocketAddr, Address, usize, Option<UdpSocketControlData>)>> {
        let src = ready!(self.io.poll_recv_from(cx, recv_buf))?;

        let n_recv = recv_buf.filled().len();
        match self.decrypt_recv_buffer(recv_buf.filled_mut(), self.user_manager.as_deref()) {
            Ok(x) => Poll::Ready(Ok((x.0, src, x.1, n_recv, x.2))),
            Err(err) => Poll::Ready(Err(ProxySocketError::ProtocolErrorWithPeer(src, err))),
        }
    }

    /// Receive packet from Shadowsocks' UDP server with source address
    #[allow(clippy::type_complexity)]
    pub async fn recv_from(&self, recv_buf: &mut [u8]) -> ProxySocketResult<(usize, SocketAddr, Address, usize)> {
        let fut = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(recv_buf);
            match ready!(self.poll_recv_from_with_ctrl(cx, &mut read_buf)) {
                Ok((n, sa, a, rn, _)) => Poll::Ready(Ok((n, sa, a, rn))),
                Err(e) => Poll::Ready(Err(e)),
            }
        });

        match self.recv_timeout {
            None => fut.await,
            Some(d) => match time::timeout(d, fut).await {
                Ok(res) => res,
                Err(..) => Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        }
    }
}

impl<S> ProxySocket<S>
where
    S: DatagramSocket,
{
    /// Get local addr of socket
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

#[cfg(unix)]
impl<S> AsRawFd for ProxySocket<S>
where
    S: AsRawFd,
{
    /// Retrieve raw fd of the outbound socket
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}

#[cfg(unix)]
impl<S> AsFd for ProxySocket<S>
where
    S: AsFd,
{
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.io.as_fd()
    }
}

#[cfg(windows)]
impl<S> AsRawSocket for ProxySocket<S>
where
    S: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.io.as_raw_socket()
    }
}

#[cfg(windows)]
impl<S> AsSocket for ProxySocket<S>
where
    S: AsSocket,
{
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.io.as_socket()
    }
}
