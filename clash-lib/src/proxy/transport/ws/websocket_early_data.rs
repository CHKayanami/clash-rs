use std::{
    cmp,
    fmt::{self, Debug},
    future::Future,
    io,
    mem::take,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::ready;
use http::{HeaderValue, Request, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{
        handshake::{
            client::{Response, generate_request},
            derive_accept_key,
            machine::TryParse,
        },
        protocol::{Role, WebSocketConfig},
    },
};

use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};

use super::websocket::WebsocketConn;

type UpgradeFuture =
    Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send + Sync>>;

pub struct WebsocketEarlyDataConn {
    stream: Option<AnyStream>,
    req: Option<Request<()>>,
    stream_future: Option<UpgradeFuture>,
    early_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    ws_config: Option<WebSocketConfig>,
    early_data_header_name: String,
    max_early_data: usize,
    write_committed: usize,
    early_data_flushed: bool,
    upgrade_error: Option<io::Error>,
    closing_without_upgrade: bool,
}

impl crate::proxy::ProxyStream for WebsocketEarlyDataConn {}

impl Debug for WebsocketEarlyDataConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebsocketEarlyDataConn")
            .field("req", &self.req)
            .field("early_waker", &self.early_waker)
            .field("flush_waker", &self.flush_waker)
            .field("ws_config", &self.ws_config)
            .field("early_data_header_name", &self.early_data_header_name)
            .field("max_early_data", &self.max_early_data)
            .field("write_committed", &self.write_committed)
            .field("early_data_flushed", &self.early_data_flushed)
            .field("upgrade_in_progress", &self.stream_future.is_some())
            .field("upgrade_error", &self.upgrade_error)
            .field("closing_without_upgrade", &self.closing_without_upgrade)
            .finish()
    }
}

impl WebsocketEarlyDataConn {
    pub fn new(
        stream: AnyStream,
        req: Request<()>,
        ws_config: Option<WebSocketConfig>,
        early_data_header_name: String,
        max_early_data: usize,
    ) -> Self {
        Self {
            stream: Some(stream),
            req: Some(req),
            stream_future: None,
            early_waker: None,
            flush_waker: None,
            ws_config,
            early_data_header_name,
            max_early_data,
            write_committed: 0,
            early_data_flushed: false,
            upgrade_error: None,
            closing_without_upgrade: false,
        }
    }

    fn wake_upgrade_waiters(&mut self) {
        if let Some(waker) = self.early_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
    }

    fn check_upgrade_error(&self) -> io::Result<()> {
        match &self.upgrade_error {
            Some(error) => Err(io::Error::new(error.kind(), error.to_string())),
            None => Ok(()),
        }
    }

    fn poll_upgrade(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let future = self.stream_future.as_mut().expect("Upgrade started");
        let result = ready!(future.as_mut().poll(cx));
        self.stream_future = None;
        match result {
            Ok(stream) => {
                self.stream = Some(stream);
                self.early_data_flushed = true;
            }
            Err(error) => self.upgrade_error = Some(error),
        }
        self.wake_upgrade_waiters();
        Poll::Ready(self.check_upgrade_error())
    }

    fn proxy_stream(
        stream: AnyStream,
        req: Request<()>,
        config: Option<WebSocketConfig>,
        early_data_subprotocol: bool,
    ) -> UpgradeFuture {
        async fn run(
            mut stream: AnyStream,
            req: Request<()>,
            config: Option<WebSocketConfig>,
            early_data_subprotocol: bool,
        ) -> io::Result<AnyStream> {
            // This header carries proxy early data, not a negotiated WebSocket
            // subprotocol. Servers need not echo it in the upgrade response.
            if early_data_subprotocol {
                let early_data = req.headers().get("Sec-WebSocket-Protocol").cloned();
                let (request, key) = generate_request(req).map_err(map_io_error)?;
                stream.write_all(&request).await?;
                stream.flush().await?;
                let mut response = Vec::new();
                let (size, resp) = loop {
                    if let Some(parsed) = Response::try_parse(&response)
                        .map_err(map_io_error)?
                    {
                        break parsed;
                    }
                    if response.len() >= 64 * 1024 {
                        return Err(new_io_error("websocket response headers too large"));
                    }
                    let mut buf = [0; 1024];
                    let len = stream.read(&mut buf).await?;
                    if len == 0 {
                        return Err(new_io_error("websocket handshake ended before response"));
                    }
                    response.extend_from_slice(&buf[..len]);
                };
                validate_early_data_response(&resp, &key)?;
                if let Some(protocol) = resp.headers().get("Sec-WebSocket-Protocol")
                    && Some(protocol) != early_data.as_ref()
                {
                    return Err(new_io_error("unexpected websocket subprotocol"));
                }
                let stream = WebSocketStream::from_partially_read(
                    stream, response.split_off(size), Role::Client, config,
                ).await;
                return Ok(AnyStream::new(WebsocketConn::from_websocket(stream)));
            }
            let (stream, resp) = client_async_with_config(req, stream, config)
                .await
                .map_err(map_io_error)?;
            if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(new_io_error(
                    "msg: websocket early data handshake failed",
                ));
            }
            let rv = WebsocketConn::from_websocket(stream);
            Ok(AnyStream::new(rv))
        }

        Box::pin(run(stream, req, config, early_data_subprotocol))
    }
}

fn validate_early_data_response(resp: &Response, key: &str) -> io::Result<()> {
    let headers = resp.headers();
    let upgrade = headers.get("Upgrade").and_then(|v| v.to_str().ok());
    let connection = headers.get("Connection").and_then(|v| v.to_str().ok());
    let accept = derive_accept_key(key.as_bytes());
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS
        || !upgrade.is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        || !connection.is_some_and(|v| {
            v.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        || !headers.get("Sec-WebSocket-Accept").is_some_and(|v| v == accept.as_str())
        || headers.contains_key("Sec-WebSocket-Extensions")
    {
        return Err(new_io_error("invalid websocket early data upgrade response"));
    }
    Ok(())
}

impl AsyncRead for WebsocketEarlyDataConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 || self.closing_without_upgrade {
            return Poll::Ready(Ok(()));
        }
        self.check_upgrade_error()?;
        if !self.early_data_flushed {
            self.early_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WebsocketEarlyDataConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.check_upgrade_error()?;
        if self.closing_without_upgrade {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(mut req) = self.req.take() {
            if let Some(value) = req.headers_mut().get_mut(&self.early_data_header_name) {
                self.write_committed = cmp::min(self.max_early_data, buf.len());
                let encoded = URL_SAFE_NO_PAD.encode(&buf[..self.write_committed]);
                *value = HeaderValue::from_str(&encoded).expect("bad header value");
            }
            let stream = self.stream.take().expect("transport before Upgrade");
            let config = self.ws_config.take();
            let subprotocol = self.early_data_header_name
                .eq_ignore_ascii_case("Sec-WebSocket-Protocol");
            self.stream_future = Some(Self::proxy_stream(stream, req, config, subprotocol));
        }
        if self.stream_future.is_some() {
            ready!(self.poll_upgrade(cx))?;
        }
        // An intervening flush may already have sent the bytes in the Upgrade.
        if self.write_committed != 0 {
            return Poll::Ready(Ok(take(&mut self.write_committed)));
        }

        match &mut self.as_mut().stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.check_upgrade_error()?;
        if self.req.is_some() || self.closing_without_upgrade {
            // A flush without a write must preserve the early data opportunity.
            return Poll::Ready(Ok(()));
        }
        if self.stream_future.is_some() {
            self.flush_waker = Some(cx.waker().clone());
            ready!(self.poll_upgrade(cx))?;
        }
        match &mut self.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.check_upgrade_error()?;
        if self.req.take().is_some() {
            self.closing_without_upgrade = true;
            self.wake_upgrade_waiters();
        } else if !self.closing_without_upgrade && !self.early_data_flushed {
            ready!(self.poll_upgrade(cx))?;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::pending, time::Duration};
    use futures::{SinkExt, StreamExt, task::noop_waker};
    use http::Response as HttpResponse;
    use tokio::io::{DuplexStream, duplex};
    use tokio::time::timeout;
    use tokio_test::task::spawn;
    use tokio_tungstenite::{accept_hdr_async, tungstenite::Message};
    use crate::proxy::transport::ws::Client;

    fn early_data_pair() -> (WebsocketEarlyDataConn, DuplexStream) {
        let (client, server) = duplex(4096);
        let header = "Sec-WebSocket-Protocol";
        let config = Client::new(
            "localhost".to_owned(), 80, "/".to_owned(),
            [("Host".to_owned(), "localhost".to_owned())].into(), None, 2560,
            header.to_owned(),
        );
        let conn = WebsocketEarlyDataConn::new(
            AnyStream::new(client), config.req(), None, header.to_owned(), 2560,
        );
        (conn, server)
    }

    #[tokio::test]
    async fn failed_upgrade_wakes_reader_and_flusher_and_stays_failed() {
        let (mut conn, peer) = early_data_pair();
        let mut reader = spawn(pending::<()>());
        let mut flusher = spawn(pending::<()>());
        let mut writer = spawn(pending::<()>());
        let mut bytes = [0; 1];
        reader.enter(|cx, _| {
            assert!(Pin::new(&mut conn).poll_read(cx, &mut ReadBuf::new(&mut bytes)).is_pending());
        });
        writer.enter(|cx, _| {
            assert!(Pin::new(&mut conn).poll_write(cx, b"hello").is_pending());
        });
        flusher.enter(|cx, _| {
            assert!(Pin::new(&mut conn).poll_flush(cx).is_pending());
        });
        drop(peer);

        let error = conn.write(b"hello").await.unwrap_err();
        assert!(reader.is_woken());
        assert!(flusher.is_woken());
        assert_eq!(conn.read(&mut bytes).await.unwrap_err().kind(), error.kind());
        assert_eq!(conn.flush().await.unwrap_err().kind(), error.kind());
        assert_eq!(conn.write(b"hello").await.unwrap_err().to_string(), error.to_string());
    }

    #[tokio::test]
    async fn idle_flush_and_shutdown_do_not_start_an_upgrade() {
        let (mut conn, mut peer) = early_data_pair();
        let mut reader = spawn(pending::<()>());
        reader.enter(|cx, _| {
            let mut bytes = [0; 1];
            assert!(Pin::new(&mut conn).poll_read(cx, &mut ReadBuf::new(&mut bytes)).is_pending());
        });
        timeout(Duration::from_secs(2), async {
            assert_eq!(conn.write(b"").await.unwrap(), 0);
            conn.flush().await.unwrap();
            conn.shutdown().await.unwrap();
            assert!(reader.is_woken());
            assert_eq!(conn.read(&mut [0; 1]).await.unwrap(), 0);
            assert_eq!(peer.read_to_end(&mut Vec::new()).await.unwrap(), 0);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn flush_completes_upgrade_without_resending_early_data() {
        let (mut conn, peer) = early_data_pair();
        conn.max_early_data = 5;
        let payload = b"hellotail";
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut conn).poll_write(&mut cx, payload).is_pending());

        let send = async {
            conn.flush().await.unwrap();
            assert_eq!(conn.write(b"").await.unwrap(), 0);
            let consumed = conn.write(payload).await.unwrap();
            assert_eq!(consumed, 5);
            conn.write_all(&payload[consumed..]).await.unwrap();
            conn.flush().await.unwrap();
        };
        let receive = async {
            let mut ws = accept_hdr_async(peer, |req: &Request<()>, resp| {
                assert_eq!(req.headers()["Sec-WebSocket-Protocol"], "aGVsbG8");
                Ok(resp)
            }).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap().into_data().as_ref(), b"tail");
        };
        timeout(Duration::from_secs(2), async {
            tokio::join!(send, receive);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn early_data_without_subprotocol_response() {
        let (mut conn, server) = early_data_pair();
        let server = tokio::spawn(async move {
            let mut ws = accept_hdr_async(server, |req: &Request<()>, resp| {
                assert_eq!(req.headers()["Sec-WebSocket-Protocol"], "aGVsbG8");
                Ok(resp)
            }).await.unwrap();
            ws.send(Message::Binary(b"reply".to_vec().into())).await.unwrap();
        });
        conn.write_all(b"hello").await.unwrap();
        let mut reply = [0; 5];
        conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        server.await.unwrap();
    }

    #[test]
    fn early_data_rejects_invalid_upgrade() {
        let key = "test-key";
        let response = HttpResponse::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Accept", derive_accept_key(key.as_bytes()))
            .body(None).unwrap();
        assert!(validate_early_data_response(&response, key).is_ok());
        for header in ["Upgrade", "Connection", "Sec-WebSocket-Accept"] {
            let mut invalid = response.clone();
            invalid.headers_mut().insert(header, HeaderValue::from_static("invalid"));
            assert!(validate_early_data_response(&invalid, key).is_err());
        }
        let mut invalid = response.clone();
        *invalid.status_mut() = StatusCode::OK;
        assert!(validate_early_data_response(&invalid, key).is_err());
        let mut invalid = response;
        invalid.headers_mut().insert(
            "Sec-WebSocket-Extensions", HeaderValue::from_static("permessage-deflate"),
        );
        assert!(validate_early_data_response(&invalid, key).is_err());
    }
}
