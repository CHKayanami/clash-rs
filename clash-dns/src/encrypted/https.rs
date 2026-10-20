use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{rt::{TokioExecutor, TokioIo, TokioTimer}, server::conn::auto::Builder};
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tracing::debug;
use crate::{DnsIngress, DnsMessageExchanger, handler::TCP_REQUEST_TIMEOUT};
use super::http::{Service, QueryBody, failure, prepare};
use super::write_deadline::{ResponseBody, WriteDeadline};

async fn handle_request<X: DnsMessageExchanger>(
    request: Request<Incoming>, service: Arc<Service<X>>, peer: SocketAddr,
    deadline: Arc<WriteDeadline>,
) -> Response<ResponseBody> {
    let Ok(permit) = service.permits.clone().try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE).map(|body| deadline.body(body, None));
    };
    let response = timeout(TCP_REQUEST_TIMEOUT, async {
        let (parts, mut body) = request.into_parts();
        let request = Request::from_parts(parts, ());
        let query = match prepare(&request, service.hostname.as_ref()) {
            Ok(query) => query,
            Err(status) => return failure(status),
        };
        let mut received = QueryBody::new(query);
        while let Some(frame) = body.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(_) => return failure(StatusCode::BAD_REQUEST),
            };
            if let Ok(data) = frame.into_data() {
                if let Err(status) = received.push(&data) { return failure(status); }
            }
        }
        let query = match received.finish() {
            Ok(query) => query,
            Err(status) => return failure(status),
        };
        service.exchange(query, peer.ip(), DnsIngress::Doh).await
    }).await.unwrap_or_else(|_| failure(StatusCode::GATEWAY_TIMEOUT));
    response.map(|body| deadline.body(body, Some(permit)))
}

pub(super) async fn serve<X: DnsMessageExchanger + 'static>(
    stream: TlsStream<TcpStream>, peer: SocketAddr, service: Arc<Service<X>>,
) {
    let http2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    serve_connection(stream, peer, service, http2, TCP_REQUEST_TIMEOUT).await;
}

pub(super) async fn serve_connection<S, X>(
    stream: S, peer: SocketAddr, service: Arc<Service<X>>, http2: bool, write_timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: DnsMessageExchanger,
{
    let deadline = WriteDeadline::new(write_timeout);
    let stream = deadline.io(stream);
    let mut builder = Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new())
        .header_read_timeout(TCP_REQUEST_TIMEOUT).max_buf_size(65536);
    builder.http2().timer(TokioTimer::new()).max_concurrent_streams(64).max_header_list_size(16384)
        .initial_stream_window_size(65536).initial_connection_window_size(1024 * 1024)
        .keep_alive_interval(Some(TCP_REQUEST_TIMEOUT)).keep_alive_timeout(TCP_REQUEST_TIMEOUT);
    let builder = if http2 {
        builder.http2_only()
    } else { builder.http1_only() };
    let response_deadline = deadline.clone();
    let handler = service_fn(move |request| {
        let service = service.clone();
        let deadline = response_deadline.clone();
        async move { Ok::<_, Infallible>(handle_request(request, service, peer, deadline).await) }
    });
    tokio::select! {
        result = builder.serve_connection(TokioIo::new(stream), handler) => {
            if let Err(error) = result { debug!(%peer, %error, "DoH connection closed"); }
        }
        _ = deadline.expired() => debug!(%peer, "DoH response write timed out"),
    }
}
