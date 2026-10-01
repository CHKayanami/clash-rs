//! DNS over HTTP/3 (DoH3).

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use h3_quinn::Connection as H3QuinnConnection;
use quinn::ClientConfig;
use tokio::sync::Mutex;

use super::body::{DnsMessageBody, doh_content_length};
use super::doh_message::{build_doh_request, finish_doh_response};
use super::lifecycle::LifecycleSlot;
use super::owned_task::OwnedTask;
use super::quic::{SharedQuicEndpoint, dns_quic_config, quic_connect_endpoint};
use super::retry::exchange_with_retry;
use crate::app::dns::endpoint::DnsEndpoint;

type H3Sender = SendRequest<h3_quinn::OpenStreams, Bytes>;

struct H3Session {
    sender: Mutex<Option<H3Sender>>,
    connection: quinn::Connection,
    driver: OwnedTask,
}

pub struct Doh3Client {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    dial_timeout: Duration,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    session: LifecycleSlot<H3Session>,
    active_tasks: Arc<AtomicUsize>,
}

impl Doh3Client {
    pub async fn new(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        dial_timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_tracked(
            endpoint,
            query_timeout,
            dial_timeout,
            Arc::new(AtomicUsize::new(0)),
        )
        .await
    }

    pub async fn new_tracked(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        dial_timeout: Duration,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_with_options(
            endpoint,
            query_timeout,
            dial_timeout,
            active_tasks,
            SharedQuicEndpoint::new(),
        )
        .await
    }

    pub async fn new_with_dial(
        dial: super::dial::DialContext,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_with_options(
            dial.endpoint.clone(),
            dial.query_timeout,
            dial.dial_timeout,
            Arc::clone(&active_tasks),
            SharedQuicEndpoint::with_dial(dial, active_tasks),
        )
        .await
    }

    async fn new_with_options(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        dial_timeout: Duration,
        active_tasks: Arc<AtomicUsize>,
        quic_ep: SharedQuicEndpoint,
    ) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"h3"]).await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            dial_timeout,
            quic_config,
            quic_ep,
            session: LifecycleSlot::new(),
            active_tasks,
        }))
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let timeout = self.query_timeout + self.dial_timeout;
        tokio::time::timeout(
            timeout,
            exchange_with_retry("DoH3", || self.exchange_once(raw_query)),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("DoH3 query budget exhausted after {timeout:?}")
        })?
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let session = self.get_session().await?;
        let mut sender = session
            .sender
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("DoH3 sender closed"))?;
        let result = tokio::time::timeout(self.query_timeout, async {
            let orig_id = if raw_query.len() >= 2 {
                u16::from_be_bytes([raw_query[0], raw_query[1]])
            } else {
                0
            };
            let mut wire = raw_query.to_vec();
            if wire.len() >= 2 {
                wire[0..2].copy_from_slice(&[0, 0]);
            }

            let req = build_doh_request(&self.endpoint, None, "DoH3")?;

            let mut stream = sender
                .send_request(req)
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 send_request: {e}"))?;

            stream
                .send_data(Bytes::from(wire))
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 send_data: {e}"))?;

            stream
                .finish()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 finish: {e}"))?;

            let response = stream
                .recv_response()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 recv_response: {e}"))?;

            let status = response.status();
            let content_length = doh_content_length("DoH3", response.headers())?;
            let mut buf = DnsMessageBody::new("DoH3", content_length)?;
            while let Some(mut chunk) = stream
                .recv_data()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 recv_data: {e}"))?
            {
                while chunk.has_remaining() {
                    let slice = chunk.chunk();
                    buf.push(slice)?;
                    let len = slice.len();
                    chunk.advance(len);
                }
            }

            finish_doh_response("DoH3", status, buf.into_bytes(), orig_id)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("DoH3 query timed out after {:?}", self.query_timeout)
        })?;
        if result.is_err() && session.connection.close_reason().is_some() {
            self.session
                .close_if(&session, |session| async move {
                    session.connection.close(0_u32.into(), b"failed");
                    session.driver.shutdown(Duration::ZERO).await;
                })
                .await;
            return result
                .map_err(|error| super::retry::ConnectionFailure(error).into());
        }
        result
    }

    async fn get_session(&self) -> anyhow::Result<Arc<H3Session>> {
        let session = self.session.acquire(|| self.dial_session()).await?;
        if session.connection.close_reason().is_some() {
            self.session
                .close_if(&session, |session| async move {
                    session.connection.close(0_u32.into(), b"closed");
                    session.driver.shutdown(Duration::ZERO).await;
                })
                .await;
            return self.session.acquire(|| self.dial_session()).await;
        }
        Ok(session)
    }

    async fn dial_session(&self) -> anyhow::Result<H3Session> {
        let deadline = tokio::time::Instant::now() + self.dial_timeout;
        let connection = quic_connect_endpoint(
            &self.quic_ep,
            &self.quic_config,
            &self.endpoint,
            deadline,
            "DoH3",
        )
        .await?;

        let h3_conn = H3QuinnConnection::new(connection.clone());
        let (driver, sender) =
            tokio::time::timeout_at(deadline, h3::client::new(h3_conn))
                .await
                .map_err(|_| anyhow::anyhow!("DoH3 client setup timed out"))?
                .map_err(|e| anyhow::anyhow!("DoH3 client setup: {e}"))?;

        let driver_task = OwnedTask::spawn(
            async move {
                let mut driver = driver;
                let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                tracing::debug!("DoH3 driver closed: {err:?}");
            },
            Arc::clone(&self.active_tasks),
        );

        Ok(H3Session {
            sender: Mutex::new(Some(sender)),
            connection,
            driver: driver_task,
        })
    }

    async fn close_session(&self) {
        self.session
            .close(|session| async move {
                let _ = session.sender.lock().await.take();
                session.connection.close(0_u32.into(), b"closed");
                session.driver.shutdown(Duration::from_millis(100)).await;
            })
            .await;
    }

    pub async fn close(&self) {
        self.close_session().await;
        self.quic_ep.close(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::quic_test_support::{self, SocksProxy};
    use super::*;
    use crate::app::dns::endpoint::DnsProtocol;
    use crate::app::dns::query::{DnsName, QType, build_dns_query_wire_with_id};
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn doh3_queries_use_socks5_udp_and_reuse_connection() {
        let (server, client_config) = quic_test_support::server(b"h3");
        let proxy = SocksProxy::new().await;
        let relay = proxy.relay_address;
        let server_endpoint = server.clone();
        let server_task = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            assert_eq!(connection.remote_address(), relay);
            let mut h3 = h3::server::Connection::<_, Bytes>::new(
                H3QuinnConnection::new(connection),
            )
            .await
            .unwrap();
            let mut handled = tokio::task::JoinSet::new();
            while let Ok(Some(request)) = h3.accept().await {
                handled.spawn(async move {
                    let (request, mut stream) =
                        request.resolve_request().await.unwrap();
                    assert_eq!(request.uri().path(), "/dns-query");
                    let mut query = Vec::new();
                    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                        while chunk.has_remaining() {
                            let bytes = chunk.chunk();
                            query.extend_from_slice(bytes);
                            let length = bytes.len();
                            chunk.advance(length);
                        }
                    }
                    assert_eq!(query[..2], [0, 0]);
                    query[2] |= 0x80;
                    stream
                        .send_response(
                            http::Response::builder().status(200).body(()).unwrap(),
                        )
                        .await
                        .unwrap();
                    stream.send_data(Bytes::from(query)).await.unwrap();
                    stream.finish().await.unwrap();
                });
            }
            let mut count = 0;
            while let Some(result) = handled.join_next().await {
                result.unwrap();
                count += 1;
            }
            count
        });
        let active = Arc::new(AtomicUsize::new(0));
        let mut client = Doh3Client::new_with_dial(
            proxy.dial(server.local_addr().unwrap(), DnsProtocol::H3),
            active.clone(),
        )
        .await
        .unwrap();
        Arc::get_mut(&mut client).unwrap().quic_config = client_config;
        for id in [0x1234, 0x5678] {
            let query = build_dns_query_wire_with_id(
                id,
                &DnsName::from_domain("proxy.test").unwrap(),
                QType::A,
            );
            let response = client.exchange(&query).await.unwrap();
            assert_eq!(response[..2], id.to_be_bytes());
        }
        assert_eq!(proxy.associations.load(Ordering::SeqCst), 1);
        assert!(proxy.forwarded.load(Ordering::SeqCst) > 0);
        assert_eq!(client.session.init_count(), 1);
        assert_eq!(active.load(Ordering::SeqCst), 3);
        client.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server_task)
                .await
                .unwrap()
                .unwrap(),
            2
        );
        server.close(0_u32.into(), b"test finished");
    }
}
