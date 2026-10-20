use std::{net::SocketAddr, sync::Arc};
use bytes::{Buf, Bytes};
use h3::{error::Code, server::RequestStream};
use h3_quinn::Connection as H3Connection;
use http::{Request, Response, StatusCode};
use quinn::{Connection, Endpoint};
use tokio::{task::JoinSet, time::timeout};
use tracing::debug;
use crate::{DnsIngress, DnsMessageExchanger, handler::{MAX_TCP_CONNECTIONS, TCP_REQUEST_TIMEOUT}};
use super::http::{Service, QueryBody, failure, prepare};

type Stream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn respond(stream: &mut Stream, response: Response<Bytes>) {
    let (parts, body) = response.into_parts();
    if stream.send_response(Response::from_parts(parts, ())).await.is_ok() {
        if !body.is_empty() && stream.send_data(body).await.is_err() { return; }
        let _ = stream.finish().await;
    }
}

async fn request<X: DnsMessageExchanger>(
    request: Request<()>, mut stream: Stream, service: Arc<Service<X>>, peer: SocketAddr,
) {
    let Ok(_permit) = service.permits.clone().try_acquire_owned() else {
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        let _ = timeout(TCP_REQUEST_TIMEOUT, respond(&mut stream, failure(StatusCode::SERVICE_UNAVAILABLE))).await;
        return;
    };
    let result = timeout(TCP_REQUEST_TIMEOUT, async {
        let query = match prepare(&request, service.hostname.as_ref()) {
            Ok(query) => query,
            Err(status) => {
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                respond(&mut stream, failure(status)).await;
                return;
            }
        };
        let mut body = QueryBody::new(query);
        loop {
            let mut chunk = match stream.recv_data().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(_) => {
                    stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                    return;
                }
            };
            while chunk.has_remaining() {
                let bytes = chunk.chunk();
                if let Err(status) = body.push(bytes) {
                    stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                    respond(&mut stream, failure(status)).await;
                    return;
                }
                let len = bytes.len();
                chunk.advance(len);
            }
        }
        let query = match body.finish() {
            Ok(query) => query,
            Err(_) => {
                stream.stop_stream(Code::H3_MESSAGE_ERROR);
                return;
            }
        };
        let response = service.exchange(query, peer.ip(), DnsIngress::Doh3).await;
        respond(&mut stream, response).await;
    }).await;
    if result.is_err() {
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
    }
}

async fn connection<X: DnsMessageExchanger + 'static>(connection: Connection, service: Arc<Service<X>>) {
    let peer = connection.remote_address();
    let mut builder = h3::server::builder();
    builder.max_field_section_size(16384);
    let mut http = match timeout(TCP_REQUEST_TIMEOUT, builder.build(H3Connection::new(connection.clone()))).await {
        Ok(Ok(http)) => http,
        _ => return,
    };
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            Some(_) = requests.join_next(), if !requests.is_empty() => {}
            result = http.accept() => {
                let resolver = match result { Ok(Some(resolver)) => resolver, _ => break };
                if requests.len() >= 64 {
                    connection.close(0x107_u32.into(), b"too many DNS requests");
                    break;
                }
                let service = service.clone();
                requests.spawn(async move {
                    if let Ok(Ok((message, stream))) = timeout(TCP_REQUEST_TIMEOUT, resolver.resolve_request()).await {
                        request(message, stream, service, peer).await;
                    }
                });
            }
        }
    }
}

pub(super) async fn serve<X: DnsMessageExchanger + 'static>(endpoint: Endpoint, service: Arc<Service<X>>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if connections.len() >= MAX_TCP_CONNECTIONS {
                    incoming.refuse();
                    continue;
                }
                let service = service.clone();
                connections.spawn(async move {
                    match timeout(TCP_REQUEST_TIMEOUT, incoming).await {
                        Ok(Ok(conn)) => connection(conn, service).await,
                        Ok(Err(error)) => debug!(%error, "DoH3 handshake failed"),
                        Err(_) => debug!("DoH3 handshake timed out"),
                    }
                });
            }
        }
    }
}
