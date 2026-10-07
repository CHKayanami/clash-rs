use crate::runner::ListenerReady;
use crate::proxy::AnyStream;
mod auth;
mod datagram;
use auth::Authentication;

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
    config::ServerConfig,
    context::Context,
    relay::{Address, tcprelay::proxy_stream::server::ProxyServerStream},
};
use tokio::io::{AsyncRead, AsyncWrite};

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> crate::proxy::ProxyStream
    for ProxyServerStream<S>
{
}
use std::{net::SocketAddr, sync::Arc};
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

#[async_trait]
impl InboundHandlerTrait for ShadowsocksInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        self.udp
    }

    async fn listen_tcp(&self, ready: ListenerReady) -> std::io::Result<()> {
        let context = Context::new_shared(shadowsocks::config::ServerType::Server);
        let config = self.build_server_config()?;
        let method = map_cipher(&self.cipher)?;
        let server_key_bytes: Arc<Vec<u8>> = Arc::new(config.key().to_vec());

        let raw_listener = try_create_dualstack_tcplistener(self.addr)?;

        let mut users_rx = self.users_rx.clone();
        let mut auth = Authentication::new(method, &users_rx.borrow_and_update())?;

        ready.notify();

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
                    let mgr = auth.manager.clone();
                    let index = Arc::clone(&auth.index);
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

                        dispatcher.dispatch_stream(sess, AnyStream::new(socket)).await;
                    });
                }

                Ok(()) = users_rx.changed() => {
                    let users = users_rx.borrow_and_update().clone();
                    match auth.update(&users) {
                        Ok(()) => info!(
                            "shadowsocks inbound {}: TCP user list updated ({} users)",
                            self.addr, users.len(),
                        ),
                        Err(e) => warn!(
                            "shadowsocks inbound {}: rejecting TCP user update: {}",
                            self.addr, e,
                        ),
                    }
                }
            }
        }
    }

    async fn listen_udp(&self, ready: ListenerReady) -> std::io::Result<()> {
        let mut ready = Some(ready);
        let mut users_rx = self.users_rx.clone();
        let mut auth = Authentication::new(
            map_cipher(&self.cipher)?, &users_rx.borrow_and_update(),
        )?;

        loop {
            // Create UDP socket with the current user list.
            let context =
                Context::new_shared(shadowsocks::config::ServerType::Server);
            let mut config = self.build_server_config()?;

            if let Some(manager) = &auth.manager {
                config.set_user_manager((**manager).clone());
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
                        Err(e) if ready.is_some() => return Err(e),
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

            let wrapped_socket = Box::new(InboundShadowsocksDatagram::new(
                proxy_socket, self.allow_lan,
            )?);
            if let Some(ready) = ready.take() {
                ready.notify();
            }

            let dispatcher = self.dispatcher.clone();
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
            loop {
                match users_rx.changed().await {
                    Ok(()) => {
                        if let Err(e) = auth.update(&users_rx.borrow_and_update()) {
                            warn!(
                                "shadowsocks inbound {}: rejecting UDP user update: {}",
                                self.addr, e,
                            );
                            continue;
                        }
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
                        break;
                    }
                    Err(_) => {
                        // Sender dropped — listener is shutting down.
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shadowsocks::config::{ServerUser, ServerUserManager};

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

        let mut inbound_datagram = InboundShadowsocksDatagram::new(proxy_socket, true)?;

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

    #[tokio::test]
    async fn test_aead2022_udp_packets_share_authenticated_user()
    -> anyhow::Result<()> {
        use crate::proxy::shadowsocks::inbound::datagram::InboundShadowsocksDatagram;
        use futures::{StreamExt, future::poll_fn};
        use shadowsocks::{
            config::ServerType,
            context::Context,
            relay::udprelay::{
                options::UdpSocketControlData, proxy_socket::UdpSocketType,
            },
        };
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let method = shadowsocks::crypto::CipherKind::AEAD2022_BLAKE3_AES_128_GCM;
        let server_key = "AAAAAAAAAAAAAAAAAAAAAA==";
        let user_key = "AQEBAQEBAQEBAQEBAQEBAQ==";
        let mut config = ServerConfig::new(address, server_key, method)?;
        let mut users = ServerUserManager::new();
        users.add_user(ServerUser::with_encoded_key("alice", user_key)?);
        config.set_user_manager(users);
        let server = ProxySocket::from_socket(
            UdpSocketType::Server,
            Context::new_shared(ServerType::Server),
            &config,
            socket.into(),
        );
        let mut inbound = InboundShadowsocksDatagram::new(server, true)?;
        let client_config =
            ServerConfig::new(address, format!("{server_key}:{user_key}"), method)?;
        let client: ProxySocket<shadowsocks::net::UdpSocket> =
            ProxySocket::from_socket(
                UdpSocketType::Client,
                Context::new_shared(ServerType::Local),
                &client_config,
                UdpSocket::bind("127.0.0.1:0").await?.into(),
            );
        let target =
            shadowsocks::relay::Address::SocketAddress("1.1.1.1:53".parse()?);
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 101;
        let mut first_user = None;
        for packet_id in 0..2 {
            control.packet_id = packet_id;
            poll_fn(|cx| {
                client.poll_send_to_with_ctrl(
                    address, &target, &control, b"request", cx,
                )
            })
            .await?;
            let packet = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                inbound.next(),
            )
            .await?
            .unwrap();
            let user = packet.inbound_user.unwrap();
            assert_eq!(user.as_ref(), "alice");
            if let Some(ref first) = first_user {
                assert!(Arc::ptr_eq(first, &user));
            } else {
                first_user = Some(user);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_aead2022_udp_sessions_and_replay_protection() -> anyhow::Result<()>
    {
        use crate::proxy::datagram::UdpPacket;
        use crate::proxy::shadowsocks::inbound::datagram::InboundShadowsocksDatagram;
        use futures::{SinkExt, StreamExt, future::poll_fn};
        use shadowsocks::{
            config::{ServerConfig, ServerType},
            context::Context,
            relay::udprelay::{
                options::UdpSocketControlData,
                proxy_socket::{ProxySocket, UdpSocketType},
            },
        };
        use tokio::{io::ReadBuf, net::UdpSocket};

        let server_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server_socket.local_addr()?;
        let method = shadowsocks::crypto::CipherKind::AEAD2022_BLAKE3_AES_128_GCM;
        let config = ServerConfig::new(
            server_addr,
            "AAAAAAAAAAAAAAAAAAAAAA==".to_owned(),
            method,
        )?;
        let server = ProxySocket::from_socket(
            UdpSocketType::Server,
            Context::new_shared(ServerType::Server),
            &config,
            server_socket.into(),
        );
        let mut inbound = InboundShadowsocksDatagram::new(server, true)?;

        let client1_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let client1_addr = client1_socket.local_addr()?;
        let client1: ProxySocket<shadowsocks::net::UdpSocket> =
            ProxySocket::from_socket(
                UdpSocketType::Client,
                Context::new_shared(ServerType::Local),
                &config,
                client1_socket.into(),
            );
        let client2_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let client2_addr = client2_socket.local_addr()?;
        let client2: ProxySocket<shadowsocks::net::UdpSocket> =
            ProxySocket::from_socket(
                UdpSocketType::Client,
                Context::new_shared(ServerType::Local),
                &config,
                client2_socket.into(),
            );
        let target = shadowsocks::relay::Address::SocketAddress(
            "1.1.1.1:53".parse().unwrap(),
        );

        let mut control1 = UdpSocketControlData::default();
        control1.client_session_id = 101;
        let mut control2 = UdpSocketControlData::default();
        control2.client_session_id = 202;
        poll_fn(|cx| {
            client1.poll_send_to_with_ctrl(
                server_addr,
                &target,
                &control1,
                b"client one",
                cx,
            )
        })
        .await?;
        poll_fn(|cx| {
            client2.poll_send_to_with_ctrl(
                server_addr,
                &target,
                &control2,
                b"client two",
                cx,
            )
        })
        .await?;

        let request1 = inbound.next().await.unwrap();
        let request2 = inbound.next().await.unwrap();
        assert_eq!(request1.data.as_ref(), b"client one");
        assert_eq!(request2.data.as_ref(), b"client two");

        inbound
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"response one"),
                src_addr: SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
                dst_addr: SocksAddr::Ip(client1_addr),
                inbound_user: None,
            })
            .await?;
        inbound
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"response two"),
                src_addr: SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
                dst_addr: SocksAddr::Ip(client2_addr),
                inbound_user: None,
            })
            .await?;

        let mut response1 = [0_u8; 2048];
        let (_, _, _, _, response_control1) = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut response1);
            client1.poll_recv_from_with_ctrl(cx, &mut buf)
        })
        .await?;
        let mut response2 = [0_u8; 2048];
        let (_, _, _, _, response_control2) = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut response2);
            client2.poll_recv_from_with_ctrl(cx, &mut buf)
        })
        .await?;
        let response_control1 = response_control1.unwrap();
        let response_control2 = response_control2.unwrap();
        assert_eq!(response_control1.client_session_id, 101);
        assert_eq!(response_control2.client_session_id, 202);
        assert_ne!(
            response_control1.server_session_id,
            response_control2.server_session_id
        );

        // The same client session may move to a new network address. Replies
        // queued against the old address must follow the session to the latest
        // validated address and keep the same server session ID.
        let migrated_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let migrated: ProxySocket<shadowsocks::net::UdpSocket> =
            ProxySocket::from_socket(
                UdpSocketType::Client,
                Context::new_shared(ServerType::Local),
                &config,
                migrated_socket.into(),
            );
        control1.packet_id = 1;
        poll_fn(|cx| {
            migrated.poll_send_to_with_ctrl(
                server_addr,
                &target,
                &control1,
                b"migrated",
                cx,
            )
        })
        .await?;
        let migrated_request = inbound.next().await.unwrap();
        assert_eq!(migrated_request.data.as_ref(), b"migrated");
        inbound
            .send(UdpPacket {
                data: bytes::Bytes::from_static(b"migrated response"),
                src_addr: SocksAddr::Ip("1.1.1.1:53".parse().unwrap()),
                dst_addr: SocksAddr::Ip(client1_addr),
                inbound_user: None,
            })
            .await?;
        let mut migrated_response = [0_u8; 2048];
        let (_, _, _, _, migrated_control) = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut migrated_response);
            migrated.poll_recv_from_with_ctrl(cx, &mut buf)
        })
        .await?;
        assert_eq!(
            migrated_control.unwrap().server_session_id,
            response_control1.server_session_id
        );

        // Invalid datagrams are per-packet failures. Even more than the socket
        // error threshold must not terminate the inbound UDP service.
        for _ in 0..64 {
            poll_fn(|cx| {
                migrated.poll_send_to_with_ctrl(
                    server_addr,
                    &target,
                    &control1,
                    b"duplicate",
                    cx,
                )
            })
            .await?;
        }
        control1.packet_id = 2;
        poll_fn(|cx| {
            migrated.poll_send_to_with_ctrl(
                server_addr,
                &target,
                &control1,
                b"after replay",
                cx,
            )
        })
        .await?;
        let after_replay = inbound.next().await.unwrap();
        assert_eq!(after_replay.data.as_ref(), b"after replay");

        Ok(())
    }
}
