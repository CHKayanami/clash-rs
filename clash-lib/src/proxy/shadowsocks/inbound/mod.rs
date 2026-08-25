mod datagram;

use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    config::internal::listener::InboundUser,
    proxy::{
        inbound::{InboundHandlerTrait, accept_tcp},
        shadowsocks::{inbound::datagram::InboundShadowsocksDatagram, map_cipher},
        utils::{new_udp_socket, try_create_dualstack_tcplistener},
    },
    session::{Network, Session, SocksAddr, Type},
};
use async_trait::async_trait;
use shadowsocks::{
    ProxySocket,
    config::{ServerConfig, ServerUser, ServerUserManager},
    context::Context,
    relay::{Address, tcprelay::proxy_stream::server::ProxyServerStream},
};
use tokio::io::{AsyncRead, AsyncWrite};

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> crate::proxy::ProxyStream
    for ProxyServerStream<S>
{
}
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tracing::{debug, info, warn};

pub struct ShadowsocksInbound {
    addr: SocketAddr,
    password: String,
    udp: bool,
    cipher: String,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    #[allow(unused)]
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
    /// Watch receiver for the user list. The manager pushes updated user lists
    /// here without restarting the listener; TCP picks them up between accepts
    /// and UDP restarts its socket gracefully.
    users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,

    udp_closer: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<u8>>>>,
}

impl Drop for ShadowsocksInbound {
    fn drop(&mut self) {
        debug!("Shadowsocks inbound listener on {} stopped", self.addr);
    }
}

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub password: String,
    pub udp: bool,
    pub cipher: String,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub authenticator: ThreadSafeAuthenticator,
    pub fw_mark: Option<u32>,
    /// Watch receiver for the live user list. Pass the receiver half of a
    /// `tokio::sync::watch::channel(initial_users)` created by the caller.
    pub users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

impl ShadowsocksInbound {
    pub fn new(opts: InboundOptions) -> Self {
        Self {
            addr: opts.addr,
            password: opts.password,
            udp: opts.udp,
            cipher: opts.cipher,
            allow_lan: opts.allow_lan,
            dispatcher: opts.dispatcher,
            authenticator: opts.authenticator,
            fw_mark: opts.fw_mark,
            users_rx: opts.users_rx,
            udp_closer: Default::default(),
        }
    }

    fn build_server_config(&self) -> std::io::Result<ServerConfig> {
        ServerConfig::new(self.addr, &self.password, map_cipher(&self.cipher)?)
            .map_err(|e| {
                new_io_error(format!("Failed to create Shadowsocks config: {e}"))
            })
    }
}

/// Build a `ServerUserManager` from a slice of `InboundUser` entries.
/// Returns `None` when the slice is empty (single-user mode).
fn build_user_manager(
    users: &[InboundUser],
    addr: SocketAddr,
) -> Option<ServerUserManager> {
    if users.is_empty() {
        return None;
    }
    let mut mgr = ServerUserManager::new();
    let mut loaded = 0usize;
    for u in users {
        match ServerUser::with_encoded_key(&u.name, &u.password) {
            Ok(user) => {
                mgr.add_user(user);
                loaded += 1;
            }
            Err(e) => warn!("Skipping invalid SS user '{}': {}", u.name, e),
        }
    }
    info!(
        "shadowsocks inbound {addr}: loaded {loaded}/{} users",
        users.len()
    );
    Some(mgr)
}

/// Index from uPSK to user name, so resolving the authenticated user after a
/// handshake is a hash lookup rather than a scan of the whole user list on
/// every connection.
fn build_user_index(
    mgr: Option<&ServerUserManager>,
) -> Arc<HashMap<Vec<u8>, String>> {
    let mut index = HashMap::new();
    if let Some(mgr) = mgr {
        for u in mgr.users_iter() {
            index.insert(u.key().to_vec(), u.name().to_owned());
        }
    }
    Arc::new(index)
}

#[async_trait]
impl InboundHandlerTrait for ShadowsocksInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        self.udp
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let context = Context::new_shared(shadowsocks::config::ServerType::Server);
        let config = self.build_server_config()?;
        let method = map_cipher(&self.cipher)?;
        let server_key_bytes: Arc<Vec<u8>> = Arc::new(config.key().to_vec());

        let raw_listener = try_create_dualstack_tcplistener(self.addr)?;

        let mut users_rx = self.users_rx.clone();
        let initial_users =
            build_user_manager(&users_rx.borrow_and_update(), self.addr);
        let mut user_index = build_user_index(initial_users.as_ref());
        let mut user_manager = initial_users.map(Arc::new);

        loop {
            tokio::select! {
                result = raw_listener.accept() => {
                    let (stream, peer_addr) = match result {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to accept Shadowsocks TCP connection: {}", e);
                            continue;
                        }
                    };

                    // Shared with the other TCP inbounds: this compares against
                    // the *accepted* socket's local address. Comparing against
                    // the listener's instead silently disabled allow-lan
                    // whenever it was bound to a wildcard address.
                    let Some(src_addr) = accept_tcp(
                        &stream,
                        peer_addr,
                        self.allow_lan,
                        "shadowsocks inbound",
                    ) else {
                        continue;
                    };

                    // Spawn immediately so the accept loop is never blocked by
                    // per-connection I/O (handshake). A stalling client
                    // only affects its own task.
                    let dispatcher = self.dispatcher.clone();
                    let context = context.clone();
                    let key_bytes = Arc::clone(&server_key_bytes);
                    let mgr = user_manager.clone();
                    let index = Arc::clone(&user_index);
                    let fw_mark = self.fw_mark;

                    tokio::spawn(async move {
                        let mut socket =
                            ProxyServerStream::from_stream_with_user_manager(
                                context,
                                stream,
                                method,
                                &key_bytes,
                                mgr,
                            );

                        let Ok(target) = socket.handshake().await else {
                            warn!("Failed to perform Shadowsocks handshake");
                            return;
                        };

                        // Resolve the authenticated user name from the key
                        // exposed by the handshake — no manual peek needed.
                        let inbound_user = socket
                            .user_key()
                            .and_then(|key| index.get(key).cloned());

                        debug!("Shadowsocks TCP connection target: {:?}", target);

                        let sess = Session {
                            network: Network::Tcp,
                            typ: Type::Shadowsocks,
                            source: src_addr,
                            so_mark: fw_mark,
                            destination: match target {
                                Address::SocketAddress(addr) => SocksAddr::Ip(addr),
                                Address::DomainNameAddress(domain, port) => {
                                    SocksAddr::Domain(domain.into(), port)
                                }
                            },
                            inbound_user,
                            ..Default::default()
                        };

                        dispatcher.dispatch_stream(sess, Box::new(socket)).await;
                    });
                }

                Ok(()) = users_rx.changed() => {
                    let users = users_rx.borrow_and_update().clone();
                    info!(
                        "shadowsocks inbound {}: TCP user list updated ({} users)",
                        self.addr,
                        users.len()
                    );
                    let mgr = build_user_manager(&users, self.addr);
                    user_index = build_user_index(mgr.as_ref());
                    user_manager = mgr.map(Arc::new);
                }
            }
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        let mut users_rx = self.users_rx.clone();

        loop {
            // Create UDP socket with the current user list.
            let context =
                Context::new_shared(shadowsocks::config::ServerType::Server);
            let mut config = self.build_server_config()?;

            {
                let users = users_rx.borrow_and_update();
                if let Some(mgr) = build_user_manager(&users, self.addr) {
                    config.set_user_manager(mgr);
                }
            }

            // Rebinding races the previous socket's close, so a failure here is
            // usually transient. Propagating it would end `listen_udp` for good
            // and take UDP down until the process restarts — retry with capped
            // backoff instead.
            let socket = {
                let mut backoff = std::time::Duration::from_millis(50);
                loop {
                    match new_udp_socket(
                        Some(self.addr),
                        None,
                        #[cfg(target_os = "linux")]
                        self.fw_mark,
                        None,
                    )
                    .await
                    {
                        Ok(s) => break s,
                        Err(e) => {
                            warn!(
                                "shadowsocks inbound {}: failed to bind UDP \
                                 socket ({}), retrying in {:?}",
                                self.addr, e, backoff
                            );
                            tokio::time::sleep(backoff).await;
                            backoff =
                                (backoff * 2).min(std::time::Duration::from_secs(5));
                        }
                    }
                }
            };

            let proxy_socket: ProxySocket<shadowsocks::net::UdpSocket> =
                ProxySocket::from_socket(
                    shadowsocks::relay::udprelay::proxy_socket::UdpSocketType::Server,
                    context,
                    &config,
                    socket.into(),
                );

            let dispatcher = self.dispatcher.clone();
            let wrapped_socket =
                Box::new(InboundShadowsocksDatagram::new(proxy_socket));
            let sess = Session {
                network: Network::Udp,
                typ: Type::Shadowsocks,
                source: self.addr,
                so_mark: self.fw_mark,
                iface: None,
                ..Default::default()
            };

            let closer = dispatcher.dispatch_datagram(sess, wrapped_socket).await;
            {
                let mut g = self.udp_closer.lock().await;
                *g = Some(closer);
            }

            // Block until the user list changes; then close the UDP socket and
            // loop to rebind with the new users.
            match users_rx.changed().await {
                Ok(()) => {
                    info!(
                        "shadowsocks inbound {}: user list changed, restarting UDP \
                         socket",
                        self.addr
                    );
                    if let Some(c) = self.udp_closer.lock().await.take() {
                        let _ = c.send(0);
                    }
                    // Brief yield so the dispatcher can drop the old socket;
                    // the bind retry above covers the case where it needs
                    // longer than this.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(_) => {
                    // Sender dropped — listener is shutting down.
                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid 32-byte base64 key (same value used in the test server config).
    const VALID_KEY: &str = "3SYJ/f8nmVuzKvKglykRQDSgg10e/ADilkdRWrrY9HU=";

    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }

    #[test]
    fn test_build_user_manager_empty_returns_none() {
        assert!(
            build_user_manager(&[], addr()).is_none(),
            "empty user list should yield single-user mode (None)"
        );
    }

    #[test]
    fn test_build_user_manager_valid_user_returns_some() {
        let users = vec![InboundUser {
            name: "user1".to_string(),
            password: VALID_KEY.to_string(),
        }];
        assert!(
            build_user_manager(&users, addr()).is_some(),
            "valid user should produce a ServerUserManager"
        );
    }

    #[test]
    fn test_build_user_manager_invalid_password_does_not_panic() {
        // Invalid base64 — should be skipped with a warning, not panic.
        let users = vec![InboundUser {
            name: "bad".to_string(),
            password: "not-valid-base64!!!".to_string(),
        }];
        // Returns Some because the users slice is non-empty, even though
        // the single entry failed to load.
        let _mgr = build_user_manager(&users, addr());
    }

    #[test]
    fn test_build_user_manager_mixes_valid_and_invalid() {
        let users = vec![
            InboundUser {
                name: "good".to_string(),
                password: VALID_KEY.to_string(),
            },
            InboundUser {
                name: "bad".to_string(),
                password: "!!!".to_string(),
            },
        ];
        // Invalid entry is skipped; valid entry is loaded — must not panic.
        assert!(build_user_manager(&users, addr()).is_some());
    }

    #[tokio::test]
    async fn test_classic_udp_inbound() -> anyhow::Result<()> {
        use crate::proxy::datagram::UdpPacket;
        use crate::proxy::shadowsocks::inbound::datagram::InboundShadowsocksDatagram;
        use futures::{SinkExt, StreamExt};
        use shadowsocks::{
            config::{ServerConfig, ServerType},
            context::Context,
            relay::udprelay::proxy_socket::{ProxySocket, UdpSocketType},
        };
        use tokio::net::UdpSocket;

        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_socket = UdpSocket::bind(server_addr).await?;
        let server_local_addr = server_socket.local_addr()?;

        let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let client_local_addr = client_socket.local_addr()?;

        let method = shadowsocks::crypto::CipherKind::AES_256_GCM;
        let password = "testpassword";

        let context = Context::new_shared(ServerType::Server);
        let config =
            ServerConfig::new(server_local_addr, password.to_owned(), method)?;

        let proxy_socket = ProxySocket::from_socket(
            UdpSocketType::Server,
            context.clone(),
            &config,
            server_socket.into(),
        );

        let mut inbound_datagram = InboundShadowsocksDatagram::new(proxy_socket);

        // Client wraps in shadowsocks client ProxySocket
        let client_context = Context::new_shared(ServerType::Local);
        let client_proxy_socket: ProxySocket<shadowsocks::net::UdpSocket> =
            ProxySocket::from_socket(
                UdpSocketType::Client,
                client_context,
                &config,
                client_socket.into(),
            );

        // Client sends packet to server
        let payload = b"hello udp";
        let target_addr = shadowsocks::relay::Address::SocketAddress(
            "1.1.1.1:53".parse().unwrap(),
        );
        client_proxy_socket
            .send_to(server_local_addr, &target_addr, payload)
            .await?;

        // Server receives packet via stream
        let received_pkt = inbound_datagram.next().await;
        assert!(received_pkt.is_some());
        let received_pkt = received_pkt.unwrap();
        assert_eq!(received_pkt.data.as_ref(), payload);
        assert_eq!(
            received_pkt.src_addr.must_into_socket_addr(),
            client_local_addr
        );

        // Server sends response back using Sink
        let response_payload = b"udp response";
        let response_pkt = UdpPacket {
            data: bytes::Bytes::from_static(response_payload),
            src_addr: SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
            dst_addr: SocksAddr::Ip(client_local_addr),
            inbound_user: None,
        };

        inbound_datagram.send(response_pkt).await?;

        // Client receives response packet
        let mut recv_buf = vec![0u8; 65535];
        let (n, physical_from_addr, logical_from_addr, ..) =
            client_proxy_socket.recv_from(&mut recv_buf).await?;
        assert_eq!(&recv_buf[..n], response_payload);
        assert_eq!(physical_from_addr, server_local_addr);
        assert_eq!(
            logical_from_addr,
            shadowsocks::relay::Address::SocketAddress(
                "1.1.1.1:53".parse().unwrap()
            )
        );

        Ok(())
    }
}
