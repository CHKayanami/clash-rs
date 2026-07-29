use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

/// Bound on how long an accepted connection may take to deliver a request head.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

use bytes::Bytes;
use futures::{TryFutureExt, future::BoxFuture};

use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Method, Request, Response, Uri, body::Incoming, server::conn::http1};

use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use tracing::{instrument, warn};

use crate::{
    app::dispatcher::Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::map_io_error},
    proxy::{AnyStream, ProxyError},
    session::{Network, Session, SocksAddr, Type},
};

use super::{auth::authenticate_req, connector::Connector};

pub fn maybe_socks_addr(r: &Uri) -> Option<SocksAddr> {
    let port = r.port_u16().unwrap_or(
        match r.scheme().map(|s| s.as_str()).unwrap_or("http") {
            "http" => 80 as _,
            "https" => 443 as _,
            _ => return None,
        },
    );

    r.host().map(|x| {
        if let Ok(ip) = x.parse::<IpAddr>() {
            SocksAddr::Ip((ip, port).into())
        } else {
            SocksAddr::Domain(x.to_string(), port)
        }
    })
}

/// Hop-by-hop headers, which a proxy must consume rather than forward
/// (RFC 9110 §7.6.1). `proxy-authorization` in particular carries this proxy's
/// own credentials and must never reach the origin server.
const HOP_BY_HOP_HEADERS: &[hyper::header::HeaderName] = &[
    hyper::header::CONNECTION,
    hyper::header::PROXY_AUTHENTICATE,
    hyper::header::PROXY_AUTHORIZATION,
    hyper::header::TE,
    hyper::header::TRAILER,
    hyper::header::TRANSFER_ENCODING,
    hyper::header::UPGRADE,
];

/// Strip hop-by-hop headers, including any the `Connection` header names.
fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    // `Connection: foo, bar` marks foo and bar as hop-by-hop too
    let connection_named: Vec<hyper::header::HeaderName> = headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| name.trim().parse::<hyper::header::HeaderName>().ok())
        .collect();

    for name in connection_named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    // not in the RFC list, but universally treated as hop-by-hop
    headers.remove("proxy-connection");
    headers.remove("keep-alive");
}

async fn proxy(
    mut req: Request<hyper::body::Incoming>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
    client: ProxyClient,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, ProxyError> {
    if authenticator.enabled()
        && let Some(res) = authenticate_req(&req, authenticator)
    {
        return Ok(res);
    }

    // TODO: handle other upgrades: https://github.com/hyperium/hyper/blob/master/examples/upgrades.rs
    if req.method() == Method::CONNECT {
        match maybe_socks_addr(req.uri()) {
            Some(addr) => {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            let sess = Session {
                                network: Network::Tcp,
                                typ: Type::HttpConnect,
                                source: src,
                                destination: addr,
                                so_mark: fw_mark,

                                ..Default::default()
                            };

                            dispatcher
                                .dispatch_stream(
                                    sess,
                                    Box::new(TokioIo::new(upgraded)),
                                )
                                .await
                        }
                        Err(e) => warn!("HTTP handshake failure, {}", e),
                    }
                });

                Ok(Response::new(Empty::new().map_err(map_io_error).boxed()))
            }
            _ => Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(
                    Full::new(format!("invalid request uri: {}", req.uri()).into())
                        .map_err(map_io_error)
                        .boxed(),
                )
                .unwrap()),
        }
    } else {
        strip_hop_by_hop(req.headers_mut());

        match client
            .request(req)
            .map_err(|x| ProxyError::General(x.to_string()))
            .await
        {
            Ok(mut res) => {
                strip_hop_by_hop(res.headers_mut());
                Ok(res.map(|b| b.map_err(map_io_error).boxed()))
            }
            Err(e) => {
                warn!("http proxy error: {}", e);
                Ok(Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .body(Empty::new().map_err(map_io_error).boxed())
                    .unwrap())
            }
        }
    }
}

type ProxyClient = Client<Connector, Incoming>;

struct ProxyService {
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
    /// Built once per accepted connection. Building it per request threw away
    /// the connection pool on every call.
    client: ProxyClient,
}

impl hyper::service::Service<Request<hyper::body::Incoming>> for ProxyService {
    type Error = ProxyError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    type Response = Response<BoxBody<Bytes, std::io::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        Box::pin(proxy(
            req,
            self.src,
            self.dispatcher.clone(),
            self.authenticator.clone(),
            self.fw_mark,
            self.client.clone(),
        ))
    }
}

#[instrument(skip(stream, dispatcher, authenticator))]
pub async fn handle(
    stream: TokioIo<AnyStream>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
) {
    let client = Client::builder(TokioExecutor::new())
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build(Connector::new(src, dispatcher.clone(), fw_mark));

    let result = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        // bound how long a connection may sit without sending a complete
        // request head
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(
            stream,
            ProxyService {
                src,
                dispatcher,
                authenticator,
                fw_mark,
                client,
            },
        )
        .with_upgrades()
        .await;

    if let Err(http_err) = result {
        warn!("Error while serving HTTP connection: {}", http_err);
    }
}
