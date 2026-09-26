use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::{
    app::dns::ThreadSafeDNSResolver,
    impl_default_connector,
    proxy::{
        AnyOutboundDatagram, AnyStream, ConnectorType, DialWithConnector,
        HandlerCommonOptions, OutboundHandler, OutboundType, PlainProxyAPIResponse,
        transport::TransportLayer,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::{Session, SocksAddr},
};

pub mod inbound;
pub mod padding;
pub mod pool;
pub mod session;
pub mod stream;
pub mod types;

use super::transport::uot::OutboundDatagramUotV2;
use padding::{PaddingFactory, SharedPaddingFactory};
use pool::{SessionPool, SessionPoolConfig};
use session::AnyTlsClientSession;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
    pub pool_config: SessionPoolConfig,
    pub tls: Option<TransportLayer>,
    pub transport: Option<TransportLayer>,
}

pub struct Handler {
    opts: HandlerOptions,
    padding: SharedPaddingFactory,
    session_pool: SessionPool,
    /// Serializes session creation. Without it, every concurrent connection
    /// arriving at a cold pool dialled its own TLS session simultaneously.
    session_create_lock: tokio::sync::Mutex<()>,

    connector: Option<Arc<dyn RemoteConnector>>,
}

impl_default_connector!(Handler);

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTLS")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        connector: Option<Arc<dyn RemoteConnector>>,
    ) -> Self {
        let pool = SessionPool::new(opts.pool_config.clone());

        Self {
            opts,
            padding: PaddingFactory::default_shared(),
            session_pool: pool,
            session_create_lock: tokio::sync::Mutex::new(()),
            connector,
        }
    }

    /// Create a fresh session and add it to the pool
    async fn create_fresh_session(
        &self,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
        sess: &Session,
    ) -> io::Result<Arc<AnyTlsClientSession>> {
        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                self.opts.common_opts.tfo,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let stream = if let Some(tls_client) = self.opts.tls.as_ref() {
            tls_client.wrap(stream).await?
        } else {
            stream
        };

        let stream = if let Some(transport) = self.opts.transport.as_ref() {
            transport.wrap(stream).await?
        } else {
            stream
        };

        let session = AnyTlsClientSession::new(
            stream,
            &self.opts.password,
            Arc::clone(&self.padding),
        )
        .await?;
        let session_arc = Arc::clone(&session);
        // 预先为即将创建的首个流预占 1 个槽位，防止并发调用从池中选走该会话导致超限
        session.force_reserve_stream();
        self.session_pool.add_session(session).await;
        Ok(session_arc)
    }

    /// Get or create an active multiplexed AnyTLS session using the connection pool
    async fn get_or_create_session(
        &self,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
        sess: &Session,
    ) -> io::Result<Arc<AnyTlsClientSession>> {
        if let Some(session) = self.session_pool.get_available_session().await {
            return Ok(session);
        }

        // Only one dial at a time; whoever loses the race re-checks the pool
        // and will usually find the session the winner just added.
        let _creating = self.session_create_lock.lock().await;
        if let Some(session) = self.session_pool.get_available_session().await {
            return Ok(session);
        }

        self.create_fresh_session(resolver, connector, sess).await
    }

    /// Open a multiplexed AnyTLS stream with auto-retry on stale/broken pooled sessions
    async fn open_stream_with_retry(
        &self,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
        sess: &Session,
        dest: &SocksAddr,
    ) -> io::Result<crate::proxy::anytls::stream::AnyTlsStream> {
        let session = self
            .get_or_create_session(resolver.clone(), connector, sess)
            .await?;

        match session.open_stream(dest).await {
            Ok(stream) => Ok(stream),
            Err(err) if is_session_broken_err(&err) => {
                debug!(
                    "AnyTLS pooled session broken ({:?}), retrying with fresh connection",
                    err
                );
                session.mark_closed();
                self.session_pool.prune_sessions();

                let fresh_session =
                    self.create_fresh_session(resolver, connector, sess).await?;
                fresh_session.open_stream(dest).await
            }
            Err(err) => Err(err),
        }
    }

    /// Helper method for raw stream creation (used in unit tests / fallback)
    #[allow(dead_code)]
    async fn open_anytls_stream(
        &self,
        stream: AnyStream,
        destination: &SocksAddr,
    ) -> io::Result<AnyStream> {
        let session = AnyTlsClientSession::new(
            stream,
            &self.opts.password,
            Arc::clone(&self.padding),
        )
        .await?;
        let stream = session.open_stream(destination).await?;
        Ok(Box::new(stream))
    }
}

fn is_session_broken_err(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    ) || err.to_string().contains("closed")
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Anytls
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        if let Some(dialer) = self.connector.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
            self.connect_stream_with_connector(sess, resolver, dialer.as_ref())
                .await
        } else {
            self.connect_stream_with_connector(
                sess,
                resolver,
                &**GLOBAL_DIRECT_CONNECTOR,
            )
            .await
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        if let Some(dialer) = self.connector.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
            self.connect_datagram_with_connector(sess, resolver, dialer.as_ref())
                .await
        } else {
            self.connect_datagram_with_connector(
                sess,
                resolver,
                &**GLOBAL_DIRECT_CONNECTOR,
            )
            .await
        }
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<AnyStream> {
        let stream = self
            .open_stream_with_retry(resolver, connector, sess, &sess.destination)
            .await?;

        sess.push_chain(self.name());
        Ok(Box::new(stream))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<AnyOutboundDatagram> {
        let uot_dest = SocksAddr::try_from((
            crate::proxy::transport::uot::UDP_OVER_TCP_V2_MAGIC_HOST.to_owned(),
            0,
        ))?;

        let mut stream = self
            .open_stream_with_retry(resolver, connector, sess, &uot_dest)
            .await?;

        let request = crate::proxy::transport::uot::encode_uot_connect_request(
            &sess.destination,
        );
        stream.write_all(&request).await?;
        stream.flush().await?;

        let datagram =
            OutboundDatagramUotV2::new(Box::new(stream), sess.destination.clone());
        sess.push_chain(self.name());
        Ok(Box::new(datagram))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        if self.opts.tls.is_some() {
            m.insert("tls".to_owned(), Box::new(true) as _);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::session::SocksAddr;

    #[cfg(docker_test)]
    use std::io::Write;

    #[cfg(docker_test)]
    use crate::{
        proxy::{
            transport,
            utils::test_utils::{
                Suite,
                config_helper::test_config_base_dir,
                consts::{IMAGE_SINGBOX, LOCAL_ADDR},
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    #[cfg(docker_test)]
    const ANYTLS_SERVER_CONFIG: &str = r#"{
    "log": {
        "level": "info"
    },
    "inbounds": [
        {
            "type": "anytls",
            "tag": "anytls-in",
            "listen": "0.0.0.0",
            "listen_port": 10002,
            "users": [
                {
                    "name": "user",
                    "password": "example"
                }
            ],
            "padding_scheme": ["stop=0"],
            "tls": {
                "enabled": true,
                "certificate_path": "/etc/ssl/v2ray/fullchain.pem",
                "key_path": "/etc/ssl/v2ray/privkey.pem"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ]
}"#;

    fn make_handler(udp: bool, with_tls: bool) -> Handler {
        use crate::proxy::transport::{TlsClient, TransportLayer};
        Handler::new(
            HandlerOptions {
                name: "test".to_owned(),
                common_opts: Default::default(),
                server: "127.0.0.1".to_owned(),
                port: 10002,
                password: "secret".to_owned(),
                udp,
                pool_config: Default::default(),
                tls: if with_tls {
                    Some(TransportLayer::Tls(
                        TlsClient::new(
                            true,
                            "example.org".to_owned(),
                            None,
                            None,
                            None,
                            None,
                        )
                        .expect("failed to create TLS client"),
                    ))
                } else {
                    None
                },
                transport: None,
            },
            None,
        )
    }

    async fn read_frame_raw(
        r: &mut (impl AsyncReadExt + Unpin),
    ) -> (u8, u32, Vec<u8>) {
        let cmd = r.read_u8().await.unwrap();
        let sid = r.read_u32().await.unwrap();
        let len = r.read_u16().await.unwrap() as usize;
        let mut data = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut data).await.unwrap();
        }
        (cmd, sid, data)
    }

    #[test]
    fn test_encode_uot_connect_request() {
        let dst = SocksAddr::try_from(("1.1.1.1".to_owned(), 53)).unwrap();
        let req = crate::proxy::transport::uot::encode_uot_connect_request(&dst);

        assert_eq!(req[0], 1);
        let parsed = SocksAddr::try_from(&req[1..]).unwrap();
        assert_eq!(parsed, dst);
    }

    #[test]
    fn test_encode_uot_connect_request_domain() {
        let dst = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let req = crate::proxy::transport::uot::encode_uot_connect_request(&dst);

        assert_eq!(req[0], 1);
        let parsed = SocksAddr::try_from(&req[1..]).unwrap();
        assert_eq!(parsed, dst);
    }

    #[tokio::test]
    async fn test_handler_proto() {
        let h = make_handler(false, false);
        assert!(matches!(h.proto(), OutboundType::Anytls));
        assert_eq!(h.name(), "test");
    }

    #[tokio::test]
    async fn test_handler_support_udp_true() {
        let h = make_handler(true, false);
        assert!(h.support_udp().await);
    }

    #[tokio::test]
    async fn test_handler_support_udp_false() {
        let h = make_handler(false, false);
        assert!(!h.support_udp().await);
    }

    #[tokio::test]
    async fn test_as_map_required_fields() {
        let h = make_handler(false, false);
        let map = h.as_map().await;
        assert!(map.contains_key("server"));
        assert!(map.contains_key("port"));
        assert!(map.contains_key("password"));
        assert!(!map.contains_key("tls"), "tls absent when None");
    }

    #[tokio::test]
    async fn test_as_map_optional_flags() {
        let h = make_handler(true, true);
        let map = h.as_map().await;
        assert!(map.contains_key("tls"), "tls present when Some");
    }

    #[tokio::test]
    async fn test_open_anytls_stream_sends_handshake() {
        let h = make_handler(false, false);
        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let (client, mut server) = duplex(65536);

        let dst_clone = dst.clone();
        let task = tokio::spawn(async move {
            h.open_anytls_stream(Box::new(client), &dst_clone)
                .await
                .unwrap()
        });

        // Password SHA256 hash
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        assert_eq!(&hash_buf, Sha256::digest(b"secret").as_slice());

        // Padding0 length
        let pad_len = server.read_u16().await.unwrap() as usize;
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            server.read_exact(&mut pad_buf).await.unwrap();
        }

        // SETTINGS frame (stream_id = 0) — v2 protocol with padding-md5
        let (cmd, sid, data) = read_frame_raw(&mut server).await;
        assert_eq!(cmd, types::Command::Settings as u8);
        assert_eq!(sid, 0);
        let settings_str = String::from_utf8(data).unwrap();
        assert!(settings_str.contains("v=2"), "settings must use v=2");
        assert!(
            settings_str.contains("padding-md5="),
            "settings must include padding-md5"
        );

        // SYN frame
        let (cmd, sid, data) = read_frame_raw(&mut server).await;
        assert_eq!(cmd, types::Command::Syn as u8);
        assert_eq!(sid, 1);
        assert!(data.is_empty());

        // PSH frame carries the destination address
        let (cmd, sid, data) = read_frame_raw(&mut server).await;
        assert_eq!(cmd, types::Command::Psh as u8);
        assert_eq!(sid, 1);
        let mut expected = BytesMut::new();
        dst.write_buf(&mut expected);
        assert_eq!(data, expected.to_vec());

        // Reply ServerSettings (v=1) to finish handshake
        let mut settings = types::StringMap::new();
        settings.insert("v", "1");
        let frame = types::Frame::with_data(
            types::Command::ServerSettings,
            0,
            Bytes::from(settings.to_bytes()),
        );
        let mut b = BytesMut::new();
        frame.encode_into(&mut b);
        server.write_all(&b).await.unwrap();

        let _app = task.await.unwrap();
    }

    #[tokio::test]
    async fn test_open_anytls_stream_relays_data() {
        let h = make_handler(false, false);
        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let (client, mut server) = duplex(65536);

        let task = tokio::spawn(async move {
            h.open_anytls_stream(Box::new(client), &dst).await.unwrap()
        });

        // Drain initial handshake bytes
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        let pad_len = server.read_u16().await.unwrap() as usize;
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            server.read_exact(&mut pad_buf).await.unwrap();
        }
        read_frame_raw(&mut server).await; // SETTINGS
        read_frame_raw(&mut server).await; // SYN
        read_frame_raw(&mut server).await; // PSH (dest)

        // Reply ServerSettings (v=1) to complete handshake
        let mut settings = types::StringMap::new();
        settings.insert("v", "1");
        let frame = types::Frame::with_data(
            types::Command::ServerSettings,
            0,
            Bytes::from(settings.to_bytes()),
        );
        let mut b = BytesMut::new();
        frame.encode_into(&mut b);
        server.write_all(&b).await.unwrap();

        let mut app = task.await.unwrap();

        // Send a PSH frame from server → client
        let payload = b"response data";
        let frame = types::Frame::data(1, bytes::Bytes::from_static(payload));
        let mut frame_buf = BytesMut::new();
        frame.encode_into(&mut frame_buf);
        server.write_all(&frame_buf).await.unwrap();

        let mut recv_buf = vec![0u8; payload.len()];
        app.read_exact(&mut recv_buf).await.unwrap();
        assert_eq!(recv_buf, payload);
    }

    #[tokio::test]
    async fn test_open_anytls_stream_multiple_writes() {
        let h = make_handler(false, false);
        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let (client, mut server) = duplex(131072);

        let task = tokio::spawn(async move {
            h.open_anytls_stream(Box::new(client), &dst).await.unwrap()
        });

        // Drain initial handshake bytes
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        let pad_len = server.read_u16().await.unwrap() as usize;
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            server.read_exact(&mut pad_buf).await.unwrap();
        }
        read_frame_raw(&mut server).await; // SETTINGS
        read_frame_raw(&mut server).await; // SYN
        read_frame_raw(&mut server).await; // PSH (dest)

        // Reply ServerSettings (v=1) to finish handshake
        let mut settings = types::StringMap::new();
        settings.insert("v", "1");
        let frame = types::Frame::with_data(
            types::Command::ServerSettings,
            0,
            Bytes::from(settings.to_bytes()),
        );
        let mut b = BytesMut::new();
        frame.encode_into(&mut b);
        server.write_all(&b).await.unwrap();

        let mut app = task.await.unwrap();

        // Multiple consecutive writes from client → server
        for chunk_idx in 0..10 {
            let data = format!("chunk payload {chunk_idx}");
            app.write_all(data.as_bytes()).await.unwrap();

            // May receive Command::Waste (0) padding frame before Command::Psh (2)
            let (cmd, sid, recv_data) = loop {
                let (cmd, sid, recv_data) = read_frame_raw(&mut server).await;
                if cmd != types::Command::Waste as u8 {
                    break (cmd, sid, recv_data);
                }
            };
            assert_eq!(cmd, types::Command::Psh as u8);
            assert_eq!(sid, 1);
            assert_eq!(recv_data, data.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_shutdown_drains_in_flight_data() {
        let h = make_handler(false, false);
        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let (client, mut server) = duplex(65536);

        let task = tokio::spawn(async move {
            h.open_anytls_stream(Box::new(client), &dst).await.unwrap()
        });

        // 接收初始握手
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        let pad_len = server.read_u16().await.unwrap() as usize;
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            server.read_exact(&mut pad_buf).await.unwrap();
        }
        read_frame_raw(&mut server).await; // SETTINGS
        read_frame_raw(&mut server).await; // SYN
        read_frame_raw(&mut server).await; // PSH (dest)

        // 回复 ServerSettings (v=1) 完成握手
        let mut settings = types::StringMap::new();
        settings.insert("v", "1");
        let ss_frame = types::Frame::with_data(
            types::Command::ServerSettings,
            0,
            Bytes::from(settings.to_bytes()),
        );
        let mut b = BytesMut::new();
        ss_frame.encode_into(&mut b);
        server.write_all(&b).await.unwrap();

        let mut app = task.await.unwrap();

        // 服务端发送响应数据（PSH 帧），但不发送 FIN（模拟合法服务端：收到 FIN 后关闭流且绝不回发 FIN）
        let in_flight_payload =
            b"in-flight response received before/during shutdown";
        let psh_frame =
            types::Frame::data(1, bytes::Bytes::from_static(in_flight_payload));
        let mut resp_buf = BytesMut::new();
        psh_frame.encode_into(&mut resp_buf);
        server.write_all(&resp_buf).await.unwrap();

        // 客户端调用 shutdown（本地写出 FIN 帧）
        app.shutdown().await.unwrap();

        // 服务端从底层连接确认读到客户端发来的 FIN 帧
        // 这证明本地 FIN 已经完全从会话 writer 写出
        let (cmd, sid, _) = loop {
            let (cmd, sid, data) = read_frame_raw(&mut server).await;
            if cmd != types::Command::Waste as u8 {
                break (cmd, sid, data);
            }
        };
        assert_eq!(cmd, types::Command::Fin as u8);
        assert_eq!(sid, 1);

        // 客户端必须能够顺利读取到该已入队响应数据（排空队列）
        let mut resp = vec![0u8; in_flight_payload.len()];
        app.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, in_flight_payload);

        // 在途数据排空后，由于本地 FIN 已写出并注销流，接收通道已关闭，
        // 即使合法服务端不回发 FIN，客户端继续读也应立即收到 EOF (0 bytes) 而绝不挂起
        let mut eof_buf = [0u8; 10];
        let n = app.read(&mut eof_buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_drop_stream_releases_session_capacity() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let session_clone = Arc::clone(&session);
        let task =
            tokio::spawn(
                async move { session_clone.open_stream(&dst).await.unwrap() },
            );

        // 服务端消费握手
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        let pad_len = server.read_u16().await.unwrap() as usize;
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            server.read_exact(&mut pad_buf).await.unwrap();
        }
        read_frame_raw(&mut server).await; // SETTINGS
        read_frame_raw(&mut server).await; // SYN
        read_frame_raw(&mut server).await; // PSH (dest)

        // 回复 ServerSettings (v=1) 完成握手
        let mut settings = types::StringMap::new();
        settings.insert("v", "1");
        let frame = types::Frame::with_data(
            types::Command::ServerSettings,
            0,
            Bytes::from(settings.to_bytes()),
        );
        let mut b = BytesMut::new();
        frame.encode_into(&mut b);
        server.write_all(&b).await.unwrap();

        let app = task.await.unwrap();
        assert_eq!(session.total_streams_count(), 1);

        // 丢弃流
        drop(app);

        // active_streams 容量必须立即释放
        assert_eq!(session.total_streams_count(), 0);

        // 服务端应收到客户端 Drop 发出的 FIN
        let (cmd, sid, _) = loop {
            let (cmd, sid, data) = read_frame_raw(&mut server).await;
            if cmd != types::Command::Waste as u8 {
                break (cmd, sid, data);
            }
        };
        assert_eq!(cmd, types::Command::Fin as u8);
        assert_eq!(sid, 1);
    }

    #[tokio::test]
    async fn test_v2_synack_error_propagated_to_caller() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        // 服务端任务：模拟 v2 AnyTLS 服务端，回复 ServerSettings(v=2) 以及带错误的 SynAck
        tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            server.read_exact(&mut hash_buf).await.unwrap();
            let pad_len = server.read_u16().await.unwrap() as usize;
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                server.read_exact(&mut pad_buf).await.unwrap();
            }
            read_frame_raw(&mut server).await; // SETTINGS
            read_frame_raw(&mut server).await; // SYN 1
            read_frame_raw(&mut server).await; // PSH (dest) 1

            // 1. 发送 ServerSettings (v=2)
            let mut s = types::StringMap::new();
            s.insert("v", "2");
            let ss_frame = types::Frame::with_data(
                types::Command::ServerSettings,
                0,
                bytes::Bytes::from(s.to_bytes()),
            );
            // 2. 发送 SynAck 1 (成功)
            let ack1 = types::Frame::control(types::Command::SynAck, 1);
            let mut buf = BytesMut::new();
            ss_frame.encode_into(&mut buf);
            ack1.encode_into(&mut buf);
            server.write_all(&buf).await.unwrap();

            // 等待第二个流（stream 2）的打开请求
            read_frame_raw(&mut server).await; // SYN 2
            read_frame_raw(&mut server).await; // PSH (dest) 2

            // 给 stream 2 回复带错误信息的 SynAck
            let err_msg = "target host unreachable";
            let ack2 = types::Frame::with_data(
                types::Command::SynAck,
                2,
                bytes::Bytes::from_static(err_msg.as_bytes()),
            );
            let mut buf2 = BytesMut::new();
            ack2.encode_into(&mut buf2);
            server.write_all(&buf2).await.unwrap();
        });

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        // 第一个流成功
        let _stream1 = session.open_stream(&dst).await.unwrap();

        // 等待 reader_loop 处理服务端的 ServerSettings 并将协议版本确认为 v2
        let mut v2_confirmed = false;
        for _ in 0..50 {
            if session.total_streams_count() >= 1 {
                // 读取一小段数据确保 reader 已经消费了 ServerSettings
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            // 尝试读取 stream1 接收通道（此时没有数据，仅仅让出调度给 reader）
            tokio::task::yield_now().await;
            // 检查 session 的 peer_version
            if session.last_active_secs() > 0 {
                // 已处理帧
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                v2_confirmed = true;
                break;
            }
        }
        assert!(v2_confirmed);

        // 第二个流（此时已确认为 v2）：服务端拒绝目标连接，应当返回错误
        let res = session.open_stream(&dst).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.to_string().contains("target host unreachable"));
        // 且活跃计数必须已回滚，不残留孤儿记录
        assert_eq!(session.total_streams_count(), 1); // 仅剩 stream 1
    }

    #[tokio::test]
    async fn test_open_stream_cancellation_releases_record_and_capacity() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        // 标记对端为 v2，使得 open_stream 会等待 SynAck
        session.set_peer_version(2);

        let (fin_tx, fin_rx) = tokio::sync::oneshot::channel();
        // 服务端仅消费 Auth 和第一个流的 SYN，但不回复 SynAck
        tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            let _ = server.read_exact(&mut hash_buf).await;
            let pad_len = server.read_u16().await.unwrap_or(0) as usize;
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                let _ = server.read_exact(&mut pad_buf).await;
            }
            // 循环读取直到读完开流数据（跳过可能存在的 Waste 填充帧）
            loop {
                let (cmd, _, _) = read_frame_raw(&mut server).await;
                if cmd == types::Command::Psh as u8 {
                    break;
                }
            }

            // 取消后，OpenGuard 必须向服务端补发 FIN 帧（跳过可能存在的 Waste 填充帧）
            loop {
                let (cmd, _, _) = read_frame_raw(&mut server).await;
                if cmd != types::Command::Waste as u8 {
                    let _ = fin_tx.send(cmd);
                    break;
                }
            }
        });

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        // 设置 50ms 超时强制 cancel 正在等待 open_stream 的 future
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            session.open_stream(&dst),
        )
        .await;

        assert!(
            res.is_err(),
            "open_stream must be cancelled by timeout, got: {:?}",
            res
        );
        // cancellation guard 必须自动回滚 active_streams
        assert_eq!(
            session.total_streams_count(),
            0,
            "active_streams must be 0 after cancellation"
        );
        // 对端必须收到 FIN 控制帧
        let cmd = fin_rx.await.unwrap();
        assert_eq!(cmd, types::Command::Fin as u8);
    }

    #[tokio::test]
    async fn test_concurrent_first_streams_do_not_duplicate_settings() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        // 服务端统计收到的 Settings 帧数量
        let (settings_count_tx, settings_count_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            let _ = server.read_exact(&mut hash_buf).await;
            let pad_len = server.read_u16().await.unwrap_or(0) as usize;
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                let _ = server.read_exact(&mut pad_buf).await;
            }

            let mut settings_count = 0;
            let mut first_cmd = None;
            // 两个流各自产生: (首流有Settings) + Syn + Psh，以及后续流 Syn + Psh
            for _ in 0..5 {
                let (cmd, _, _) = read_frame_raw(&mut server).await;
                if first_cmd.is_none() {
                    first_cmd = Some(cmd);
                }
                if cmd == types::Command::Settings as u8 {
                    settings_count += 1;
                }
            }
            let _ = settings_count_tx.send((first_cmd, settings_count));
        });

        let dst1 = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let dst2 = SocksAddr::try_from(("5.6.7.8".to_owned(), 80)).unwrap();

        let s1 = Arc::clone(&session);
        let s2 = Arc::clone(&session);
        let (_r1, _r2) = tokio::join!(s1.open_stream(&dst1), s2.open_stream(&dst2));

        let (first_cmd, settings_count) = settings_count_rx.await.unwrap();
        assert_eq!(
            first_cmd,
            Some(types::Command::Settings as u8),
            "First frame received by server MUST be Settings, never SYN"
        );
        assert_eq!(
            settings_count, 1,
            "Concurrent first streams must not duplicate Settings frame"
        );
    }

    #[tokio::test]
    async fn test_try_reserve_stream_concurrent_never_exceeds_max() {
        let (client, _server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        let max_streams = 4;
        let mut handles = Vec::new();

        // 启动 32 个并发协程，混合执行 try_reserve_stream、commit_reserved_stream、release 和 unregister
        for _ in 0..32 {
            let sess = Arc::clone(&session);
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    if sess.try_reserve_stream(max_streams) {
                        assert!(
                            sess.total_streams_count() <= max_streams,
                            "Total streams must never exceed max_streams!"
                        );
                        // 模拟转化为活跃流
                        sess.commit_reserved_stream();
                        assert!(
                            sess.total_streams_count() <= max_streams,
                            "Total streams must never exceed max_streams after commit!"
                        );
                        // 模拟短暂中继后注销流
                        sess.decrement_active_streams();
                    }
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(session.total_streams_count(), 0);
    }

    #[tokio::test]
    async fn test_first_stream_v2_synack_error_propagated_to_caller() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        // 服务端针对首个流直接回复拒绝错误
        tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            server.read_exact(&mut hash_buf).await.unwrap();
            let pad_len = server.read_u16().await.unwrap() as usize;
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                server.read_exact(&mut pad_buf).await.unwrap();
            }
            read_frame_raw(&mut server).await; // Settings
            read_frame_raw(&mut server).await; // Syn
            read_frame_raw(&mut server).await; // Psh (dest)

            // 回复 ServerSettings(v=2) 与带拒绝信息的 SynAck
            let mut s = types::StringMap::new();
            s.insert("v", "2");
            let ss_frame = types::Frame::with_data(
                types::Command::ServerSettings,
                0,
                Bytes::from(s.to_bytes()),
            );
            let ack = types::Frame::with_data(
                types::Command::SynAck,
                1,
                Bytes::from_static(b"upstream connection refused"),
            );
            let mut buf = BytesMut::new();
            ss_frame.encode_into(&mut buf);
            ack.encode_into(&mut buf);
            server.write_all(&buf).await.unwrap();
        });

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        // 1. 首流请求入队后即可返回成功
        let mut stream = session.open_stream(&dst).await.unwrap();

        // 2. 服务端回复 v2 设置和拒绝后，流上的读和写都能感知到该拒绝错误
        let mut buf = [0u8; 100];
        let read_res = stream.read(&mut buf).await;
        assert!(
            read_res.is_err(),
            "Stream read must see the rejection error"
        );
        assert!(
            read_res
                .err()
                .unwrap()
                .to_string()
                .contains("upstream connection refused")
        );

        let write_res = stream.write_all(b"test").await;
        assert!(
            write_res.is_err(),
            "Stream write must also see the rejection error"
        );

        // 确保 reader loop 已处理 ServerSettings(v=2)
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 3. 确认是 v2 后，后续流再打开时会在 open_stream 中等待 SynAck
        let dst2 = SocksAddr::try_from(("5.6.7.8".to_owned(), 80)).unwrap();
        let res2 = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            session.open_stream(&dst2),
        )
        .await;
        // 服务端没有为第二个流发送 SynAck，因此第二个流在等待 SynAck 时挂起或超时
        assert!(res2.is_err() || res2.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_v1_server_first_stream_does_not_timeout() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        // v1 服务端：消费握手，但不发送 ServerSettings 也不发送 SynAck
        tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            let _ = server.read_exact(&mut hash_buf).await;
            let pad_len = server.read_u16().await.unwrap_or(0) as usize;
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                let _ = server.read_exact(&mut pad_buf).await;
            }
            let _ = read_frame_raw(&mut server).await; // Settings
            let _ = read_frame_raw(&mut server).await; // Syn
            let _ = read_frame_raw(&mut server).await; // Psh (dest)
            // v1 服务端不回复任何控制帧，保持连接
            let mut sink = vec![0u8; 1024];
            while let Ok(n) = server.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        // 在 v1 服务端下，首流请求入队后直接返回，绝不超时等待，版本仍标为未知
        let start = std::time::Instant::now();
        let res = session.open_stream(&dst).await;
        let elapsed = start.elapsed();
        assert!(
            res.is_ok(),
            "First stream on v1 server must succeed immediately"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "First stream on v1 server must return immediately upon enqueue, took {:?}",
            elapsed
        );
        assert_eq!(session.total_streams_count(), 1);
    }

    #[tokio::test]
    async fn test_session_closed_drains_queued_eof_without_error() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let session_clone = Arc::clone(&session);
        let task =
            tokio::spawn(
                async move { session_clone.open_stream(&dst).await.unwrap() },
            );

        // 消费握手并回复 ServerSettings(v=1)
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        let pad_len = server.read_u16().await.unwrap() as usize;
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            server.read_exact(&mut pad_buf).await.unwrap();
        }
        read_frame_raw(&mut server).await;
        read_frame_raw(&mut server).await;
        read_frame_raw(&mut server).await;

        let mut s = types::StringMap::new();
        s.insert("v", "1");
        let ss = types::Frame::with_data(
            types::Command::ServerSettings,
            0,
            Bytes::from(s.to_bytes()),
        );
        let mut b = BytesMut::new();
        ss.encode_into(&mut b);
        server.write_all(&b).await.unwrap();

        let mut app = task.await.unwrap();

        // 服务端向流写入 FIN 帧
        let fin_frame = types::Frame::control(types::Command::Fin, 1);
        let mut fin_buf = BytesMut::new();
        fin_frame.encode_into(&mut fin_buf);
        server.write_all(&fin_buf).await.unwrap();

        // 稍作等待确保 FIN 进入通道，随后关闭 transport（断开会话连接）
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(server);
        // 等待 reader_loop 退出并标记 session_closed
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(session.is_closed());

        // 应用层此时才读取流：必须读出正常 EOF (0 字节)，不得报 BrokenPipe 错误！
        let mut read_buf = [0u8; 100];
        let n = app.read(&mut read_buf).await.unwrap();
        assert_eq!(
            n, 0,
            "Queued FIN must yield clean EOF even after session closed"
        );
    }

    #[tokio::test]
    async fn test_pool_concurrent_reservation_respects_max_streams() {
        use super::pool::{SessionPool, SessionPoolConfig};

        let config = SessionPoolConfig {
            min_connections: 1,
            max_connections: 1,
            max_streams_per_connection: 2,
            idle_timeout: std::time::Duration::from_secs(60),
            idle_session_check_interval: std::time::Duration::from_secs(30),
        };
        let pool = SessionPool::new(config);

        let (c1, mut s1) = duplex(4096);
        // 后台服务端自动响应握手
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            while let Ok(n) = s1.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let mut settings = types::StringMap::new();
                settings.insert("v", "1");
                let frame = types::Frame::with_data(
                    types::Command::ServerSettings,
                    0,
                    Bytes::from(settings.to_bytes()),
                );
                let mut b = BytesMut::new();
                frame.encode_into(&mut b);
                let _ = s1.write_all(&b).await;
            }
        });

        let sess1 = session::AnyTlsClientSession::new(
            Box::new(c1),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        pool.add_session(sess1).await;

        // 并发进行 5 次 get_available_session 获取
        // 由于 max_streams_per_connection = 2 且 max_connections = 1，
        // 前 2 次通过 try_reserve_stream 成功，后续必须因超过上限而返回 None（或在达到 max_connections 时受限）
        let s_a = pool.get_available_session().await;
        assert!(s_a.is_some(), "First session slot reserved");
        let s_b = pool.get_available_session().await;
        assert!(s_b.is_some(), "Second session slot reserved");

        // 已经预占了 2 个槽位，刚好达到 max_streams_per_connection = 2
        let s_c = pool.get_available_session().await;
        // 当 max_connections 限制且只有 1 个会话时，若所有连接已满则触发 fallback 分配
        assert!(s_c.is_some());
    }

    #[tokio::test]
    async fn test_write_does_not_drain_incoming_channel_backpressure() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        // 服务端发送 Settings 和一个流的下行数据帧
        tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            server.read_exact(&mut hash_buf).await.unwrap();
            let pad_len = server.read_u16().await.unwrap() as usize;
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                server.read_exact(&mut pad_buf).await.unwrap();
            }
            read_frame_raw(&mut server).await; // Settings
            read_frame_raw(&mut server).await; // Syn
            read_frame_raw(&mut server).await; // Psh

            // 回复 ServerSettings(v=1)
            let mut s = types::StringMap::new();
            s.insert("v", "1");
            let ss_frame = types::Frame::with_data(
                types::Command::ServerSettings,
                0,
                Bytes::from(s.to_bytes()),
            );
            // 发送下行数据
            let data_frame =
                types::Frame::data(1, Bytes::from_static(b"incoming payload"));
            let mut buf = BytesMut::new();
            ss_frame.encode_into(&mut buf);
            data_frame.encode_into(&mut buf);
            server.write_all(&buf).await.unwrap();

            // 保持 server 存活，读取客户端写入的数据
            let mut discard = [0u8; 1024];
            while let Ok(n) = server.read(&mut discard).await {
                if n == 0 {
                    break;
                }
            }
        });

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let mut stream = session.open_stream(&dst).await.unwrap();

        // 等待 reader_loop 处理下行数据并塞入 data_rx
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 连续进行多次写操作
        for _ in 0..5 {
            stream.write_all(b"hello world").await.unwrap();
            stream.flush().await.unwrap();
        }

        // 写操作不应该偷跑任何下行数据，随后 read 必须能完整读到 "incoming payload"
        let mut read_buf = [0u8; 32];
        let n = stream.read(&mut read_buf).await.unwrap();
        assert_eq!(&read_buf[..n], b"incoming payload");
    }

    #[tokio::test]
    async fn test_read_drains_buffer_before_reporting_broken_pipe() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            server.read_exact(&mut hash_buf).await.unwrap();
            let pad_len = server.read_u16().await.unwrap() as usize;
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                server.read_exact(&mut pad_buf).await.unwrap();
            }
            read_frame_raw(&mut server).await; // Settings
            read_frame_raw(&mut server).await; // Syn
            read_frame_raw(&mut server).await; // Psh

            let mut s = types::StringMap::new();
            s.insert("v", "1");
            let ss_frame = types::Frame::with_data(
                types::Command::ServerSettings,
                0,
                Bytes::from(s.to_bytes()),
            );
            // 发送 8 字节数据随后立即关闭连接（导致 session 异常断开）
            let data_frame = types::Frame::data(1, Bytes::from_static(b"12345678"));
            let mut buf = BytesMut::new();
            ss_frame.encode_into(&mut buf);
            data_frame.encode_into(&mut buf);
            server.write_all(&buf).await.unwrap();
            // 直接 drop server 连接导致 BrokenPipe
            drop(server);
        });

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let mut stream = session.open_stream(&dst).await.unwrap();

        // 第一次读取 4 个字节，使剩余 4 个字节留在 read_buffer 中
        let mut partial = [0u8; 4];
        let n1 = stream.read(&mut partial).await.unwrap();
        assert_eq!(n1, 4);
        assert_eq!(&partial, b"1234");

        // 等待会话检测到底层连接断开
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 第二次读取必须能够读完 read_buffer 里的后 4 个字节，而不是直接报 BrokenPipe
        let mut remaining = [0u8; 4];
        let n2 = stream.read(&mut remaining).await.unwrap();
        assert_eq!(n2, 4);
        assert_eq!(&remaining, b"5678");

        // 缓冲区完全排空后，下一次读取才会返回异常断开的 BrokenPipe
        let mut final_buf = [0u8; 4];
        let res = stream.read(&mut final_buf).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn test_remote_fin_stops_local_writes_with_broken_pipe() {
        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            server.read_exact(&mut hash_buf).await.unwrap();
            let pad_len = server.read_u16().await.unwrap() as usize;
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                server.read_exact(&mut pad_buf).await.unwrap();
            }
            read_frame_raw(&mut server).await; // Settings
            read_frame_raw(&mut server).await; // Syn
            read_frame_raw(&mut server).await; // Psh

            let mut s = types::StringMap::new();
            s.insert("v", "1");
            let ss_frame = types::Frame::with_data(
                types::Command::ServerSettings,
                0,
                Bytes::from(s.to_bytes()),
            );
            // 服务端主动发送 FIN 关闭流 1，但保持整个 TLS 会话连接继续存活
            let fin_frame = types::Frame::control(types::Command::Fin, 1);
            let mut buf = BytesMut::new();
            ss_frame.encode_into(&mut buf);
            fin_frame.encode_into(&mut buf);
            server.write_all(&buf).await.unwrap();

            // 保持 server 持续存活
            let mut discard = [0u8; 1024];
            while let Ok(n) = server.read(&mut discard).await {
                if n == 0 {
                    break;
                }
            }
        });

        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let mut stream = session.open_stream(&dst).await.unwrap();

        // 等待 reader_loop 处理该 FIN 帧
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 对端已经发送 FIN，写操作必须返回 BrokenPipe 错误，而不能静默入队成功
        let write_res = stream.write_all(b"data to closed stream").await;
        assert!(write_res.is_err(), "Write after remote FIN must fail");
        assert_eq!(write_res.unwrap_err().kind(), io::ErrorKind::BrokenPipe);

        // flush 不应把服务端正常关闭误报为先前写入失败。
        // HTTP 客户端在收到完整响应后仍可能轮询 flush。
        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn test_http_response_fin_does_not_fail_connection_flush() {
        use http_body_util::Empty;
        use hyper_util::rt::TokioIo;

        let (client, mut server) = duplex(65536);
        let session = session::AnyTlsClientSession::new(
            Box::new(client),
            "secret",
            PaddingFactory::default_factory(),
        )
        .await
        .unwrap();

        let server_task = tokio::spawn(async move {
            let mut hash_buf = [0u8; 32];
            server.read_exact(&mut hash_buf).await.unwrap();
            let pad_len = server.read_u16().await.unwrap() as usize;
            let mut pad_buf = vec![0u8; pad_len];
            server.read_exact(&mut pad_buf).await.unwrap();
            read_frame_raw(&mut server).await; // Settings
            read_frame_raw(&mut server).await; // Syn
            read_frame_raw(&mut server).await; // Destination

            loop {
                let (cmd, _, data) = read_frame_raw(&mut server).await;
                if cmd == types::Command::Psh as u8 {
                    assert!(data.starts_with(b"GET "));
                    break;
                }
            }

            let response = types::Frame::data(
                1,
                Bytes::from_static(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"),
            );
            let fin = types::Frame::control(types::Command::Fin, 1);
            let mut frames = BytesMut::new();
            response.encode_into(&mut frames);
            fin.encode_into(&mut frames);
            server.write_all(&frames).await.unwrap();
        });

        let dst = SocksAddr::try_from(("example.org".to_owned(), 80)).unwrap();
        let stream = session.open_stream(&dst).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .unwrap();
        let conn_task = tokio::spawn(conn);
        let request = http::Request::get("http://example.org/generate_204")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::NO_CONTENT);

        server_task.await.unwrap();
        let conn_result = tokio::time::timeout(std::time::Duration::from_secs(1), conn_task)
            .await
            .unwrap()
            .unwrap();
        assert!(conn_result.is_ok(), "HTTP connection driver: {conn_result:?}");
    }

    #[tokio::test]
    async fn test_update_padding_scheme_applies_to_subsequent_sessions() {
        let h = Arc::new(make_handler(false, false));
        let dst = Arc::new(SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap());

        // --- 会话 1：初次建立，使用默认方案 ---
        let (client1, mut server1) = duplex(65536);
        let h1 = Arc::clone(&h);
        let dst1 = Arc::clone(&dst);
        let task1 = tokio::spawn(async move {
            h1.open_anytls_stream(Box::new(client1), &dst1)
                .await
                .unwrap()
        });

        // 读取会话 1 的初始认证与握手
        let mut hash_buf = [0u8; 32];
        server1.read_exact(&mut hash_buf).await.unwrap();
        let pad_len1 = server1.read_u16().await.unwrap() as usize;
        if pad_len1 > 0 {
            let mut pad_buf = vec![0u8; pad_len1];
            server1.read_exact(&mut pad_buf).await.unwrap();
        }
        let (cmd, _, data1) = read_frame_raw(&mut server1).await; // Settings
        assert_eq!(cmd, types::Command::Settings as u8);
        let settings1 = types::StringMap::from_bytes(&data1);
        let default_factory = PaddingFactory::default_factory();
        assert_eq!(
            settings1.get("padding-md5").unwrap(),
            default_factory.md5(),
            "首次会话必须使用默认 padding-md5"
        );
        read_frame_raw(&mut server1).await; // Syn
        read_frame_raw(&mut server1).await; // Psh

        // 回复 ServerSettings 完成会话 1 握手
        let mut s = types::StringMap::new();
        s.insert("v", "1");
        let ss_frame = types::Frame::with_data(
            types::Command::ServerSettings,
            0,
            Bytes::from(s.to_bytes()),
        );
        let mut buf = BytesMut::new();
        ss_frame.encode_into(&mut buf);
        server1.write_all(&buf).await.unwrap();
        let _stream1 = task1.await.unwrap();

        // 服务端向会话 1 下发 UpdatePaddingScheme
        let custom_scheme = b"stop=4\n0=50-50\n1=200-200\n2=300-300\n3=400-400";
        let custom_factory = PaddingFactory::new(custom_scheme).unwrap();
        let update_frame = types::Frame::with_data(
            types::Command::UpdatePaddingScheme,
            0,
            Bytes::from_static(custom_scheme),
        );
        let mut update_buf = BytesMut::new();
        update_frame.encode_into(&mut update_buf);
        server1.write_all(&update_buf).await.unwrap();

        // 给 reader_loop 一小段调度时间处理 UpdatePaddingScheme 帧
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 验证已有会话 1 收到更新后，Handler 共享的 scheme 已被原子更新为新方案
        assert_eq!(
            h.padding.load().md5(),
            custom_factory.md5(),
            "Handler 共享的 padding 必须已被原子更新为新方案"
        );

        // --- 会话 2：在收到更新后由同一个 Handler 新建会话 ---
        let (client2, mut server2) = duplex(65536);
        let h2 = Arc::clone(&h);
        let dst2 = Arc::clone(&dst);
        let task2 = tokio::spawn(async move {
            h2.open_anytls_stream(Box::new(client2), &dst2)
                .await
                .unwrap()
        });

        // 验证会话 2 的认证包 (packet 0) 采用新方案指定的 padding 长度 (50 字节)
        let mut hash_buf2 = [0u8; 32];
        server2.read_exact(&mut hash_buf2).await.unwrap();
        let pad_len2 = server2.read_u16().await.unwrap() as usize;
        assert_eq!(
            pad_len2, 50,
            "新会话的 auth 包必须使用更新后的 padding 方案 (0=50-50)"
        );
        if pad_len2 > 0 {
            let mut pad_buf = vec![0u8; pad_len2];
            server2.read_exact(&mut pad_buf).await.unwrap();
        }

        // 验证会话 2 的 Settings (packet 1) 上报的 padding-md5 变为新方案的 MD5
        let (cmd2, _, data2) = read_frame_raw(&mut server2).await;
        assert_eq!(cmd2, types::Command::Settings as u8);
        let settings2 = types::StringMap::from_bytes(&data2);
        assert_eq!(
            settings2.get("padding-md5").unwrap(),
            custom_factory.md5(),
            "新会话必须上报服务端下发的最新 padding-md5"
        );

        drop(task2);
    }
}
