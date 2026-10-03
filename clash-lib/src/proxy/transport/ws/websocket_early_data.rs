use std::{
    cmp,
    fmt::Debug,
    pin::Pin,
    task::{Poll, Waker},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{Future, ready};
use http::{HeaderValue, Request, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

pub struct WebsocketEarlyDataConn {
    stream: Option<AnyStream>,
    req: Option<Request<()>>,
    stream_future: Option<
        Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<AnyStream>>
                    + Send
                    + Sync,
            >,
        >,
    >,
    early_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    ws_config: Option<WebSocketConfig>,
    early_data_header_name: String,
    early_data_len: usize,
    early_data_flushed: bool,
}

impl crate::proxy::ProxyStream for WebsocketEarlyDataConn {}

impl Debug for WebsocketEarlyDataConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketEarlyDataConn")
            .field("req", &self.req)
            .field("early_waker", &self.early_waker)
            .field("flush_waker", &self.flush_waker)
            .field("ws_config", &self.ws_config)
            .field("early_data_header_name", &self.early_data_header_name)
            .field("early_data_len", &self.early_data_len)
            .field("early_data_flushed", &self.early_data_flushed)
            .finish()
    }
}

impl WebsocketEarlyDataConn {
    pub fn new(
        stream: AnyStream,
        req: Request<()>,
        ws_config: Option<WebSocketConfig>,
        early_data_header_name: String,
        early_data_len: usize,
    ) -> Self {
        Self {
            stream: Some(stream),
            req: Some(req),
            stream_future: None,
            early_waker: None,
            flush_waker: None,
            ws_config,
            early_data_header_name,
            early_data_len,
            early_data_flushed: false,
        }
    }

    fn proxy_stream(
        stream: AnyStream,
        req: Request<()>,
        config: Option<WebSocketConfig>,
        early_data_subprotocol: bool,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<AnyStream>>
                + Send
                + Sync,
        >,
    > {
        async fn run(
            mut stream: AnyStream,
            req: Request<()>,
            config: Option<WebSocketConfig>,
            early_data_subprotocol: bool,
        ) -> std::io::Result<AnyStream> {
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

fn validate_early_data_response(resp: &Response, key: &str) -> std::io::Result<()> {
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
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.early_data_flushed {
            if self.early_waker.is_none() {
                self.as_mut().early_waker = Some(cx.waker().clone());
            }
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
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.early_data_flushed {
            loop {
                match &mut self.as_mut().stream_future {
                    Some(fut) => {
                        let stream = ready!(Pin::new(fut).poll(cx))?;

                        self.as_mut().stream = Some(stream);
                        self.as_mut().early_data_flushed = true;

                        if let Some(w) = self.as_mut().early_waker.take() {
                            w.wake();
                        }
                        if let Some(w) = self.as_mut().flush_waker.take() {
                            w.wake();
                        }
                        return Poll::Ready(Ok(self.as_mut().early_data_len));
                    }
                    _ => {
                        let mut req =
                            self.as_mut().req.take().expect("req must be present");
                        if let Some(v) = req
                            .headers_mut()
                            .get_mut(&self.as_mut().early_data_header_name)
                        {
                            self.as_mut().early_data_len =
                                cmp::min(self.as_mut().early_data_len, buf.len());
                            let header_value = URL_SAFE_NO_PAD
                                .encode(&buf[..self.as_mut().early_data_len]);
                            *v = HeaderValue::from_str(&header_value)
                                .expect("bad header value");
                        }

                        let stream =
                            self.as_mut().stream.take().expect("msg: bad state");
                        let config = self.as_mut().ws_config.take();
                        let early_data_subprotocol = self.early_data_header_name
                            .eq_ignore_ascii_case("Sec-WebSocket-Protocol");
                        self.as_mut().stream_future =
                            Some(Self::proxy_stream(
                                stream, req, config, early_data_subprotocol,
                            ));
                    }
                }
            }
        }

        match &mut self.as_mut().stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.early_data_flushed {
            if self.as_mut().flush_waker.is_none() {
                self.as_mut().flush_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        match &mut self.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.early_data_flushed {
            ready!(self.as_mut().poll_flush(cx))?;
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
    use futures::SinkExt;
    use http::Response as HttpResponse;
    use tokio_tungstenite::{accept_hdr_async, tungstenite::Message};
    use crate::proxy::transport::ws::Client;

    #[tokio::test]
    async fn early_data_without_subprotocol_response() {
        let (client, server) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut ws = accept_hdr_async(server, |req: &Request<()>, resp| {
                assert_eq!(req.headers()["Sec-WebSocket-Protocol"], "aGVsbG8");
                Ok(resp)
            }).await.unwrap();
            ws.send(Message::Binary(b"reply".to_vec().into())).await.unwrap();
        });
        let client_config = Client::new(
            "localhost".to_owned(), 80, "/".to_owned(),
            [("Host".to_owned(), "localhost".to_owned())].into(), None, 2560,
            "Sec-WebSocket-Protocol".to_owned(),
        );
        let mut conn = WebsocketEarlyDataConn::new(
            AnyStream::new(client), client_config.req(), None,
            "Sec-WebSocket-Protocol".to_owned(), 2560,
        );
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
