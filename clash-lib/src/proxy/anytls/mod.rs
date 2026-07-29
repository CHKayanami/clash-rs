use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram, ChainedStream,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::transport::TransportLayer,
    session::{Session, SocksAddr},
};

use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType, PlainProxyAPIResponse,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};

mod datagram;
pub mod inbound;
pub mod padding;
pub mod pool;
pub mod session;
pub mod stream;
pub mod types;

use datagram::OutboundDatagramAnytls;
use padding::PaddingFactory;
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
    padding: Arc<PaddingFactory>,
    session_pool: SessionPool,
    /// Serializes session creation. Without it, every concurrent connection
    /// arriving at a cold pool dialled its own TLS session simultaneously.
    session_create_lock: tokio::sync::Mutex<()>,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
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
    const UDP_OVER_TCP_V2_MAGIC_ADDR: &str = "sp.v2.udp-over-tcp.arpa";

    pub fn new(opts: HandlerOptions) -> Self {
        let pool = SessionPool::new(opts.pool_config.clone());

        Self {
            opts,
            padding: PaddingFactory::default_factory(),
            session_pool: pool,
            session_create_lock: tokio::sync::Mutex::new(()),
            connector: Default::default(),
        }
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
        self.session_pool.add_session(session).await;
        Ok(session_arc)
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

    fn encode_uot_connect_request(dst_addr: &SocksAddr) -> BytesMut {
        let mut request = BytesMut::new();
        request.put_u8(1); // isConnect = true (UoT v2 connect mode)
        dst_addr.write_buf(&mut request);
        request
    }
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
    ) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&*GLOBAL_DIRECT_CONNECTOR)
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_datagram_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&*GLOBAL_DIRECT_CONNECTOR)
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let session = self
            .get_or_create_session(resolver, connector, sess)
            .await?;
        let stream = session.open_stream(&sess.destination).await?;

        let chained =
            crate::app::dispatcher::ChainedStreamWrapper::new(Box::new(stream));
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let uot_dest =
            SocksAddr::try_from((Self::UDP_OVER_TCP_V2_MAGIC_ADDR.to_owned(), 0))?;

        let session = self
            .get_or_create_session(resolver, connector, sess)
            .await?;
        let mut stream = session.open_stream(&uot_dest).await?;

        let request = Self::encode_uot_connect_request(&sess.destination);
        stream.write_all(&request).await?;
        stream.flush().await?;

        let datagram =
            OutboundDatagramAnytls::new(Box::new(stream), sess.destination.clone());
        let chained = crate::app::dispatcher::ChainedDatagramWrapper::new(datagram);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
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
    use bytes::BytesMut;
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
        Handler::new(HandlerOptions {
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
        })
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
        let req = Handler::encode_uot_connect_request(&dst);

        assert_eq!(req[0], 1);
        let parsed = SocksAddr::try_from(&req[1..]).unwrap();
        assert_eq!(parsed, dst);
    }

    #[test]
    fn test_encode_uot_connect_request_domain() {
        let dst = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let req = Handler::encode_uot_connect_request(&dst);

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

        let _app = h.open_anytls_stream(Box::new(client), &dst).await.unwrap();

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
    }

    #[tokio::test]
    async fn test_open_anytls_stream_relays_data() {
        let h = make_handler(false, false);
        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let (client, mut server) = duplex(65536);

        let mut app = h.open_anytls_stream(Box::new(client), &dst).await.unwrap();

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
}
