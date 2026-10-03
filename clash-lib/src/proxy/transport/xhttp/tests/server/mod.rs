mod metadata;
mod session;

use std::{collections::HashMap, convert::Infallible, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::BodyExt;
use hyper::{body::{Body, Incoming}, server::conn::{http1, http2}, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use tokio::{io::duplex, time::sleep};
use crate::{config::internal::proxy::XHttpOpt, proxy::AnyStream};
use super::super::{body::RequestBody, connection::{ConnectionFactory, Tasks}};
use self::session::Session;

pub(super) struct Capture {
    pub(super) method: Method,
    pub(super) uri: Uri,
    pub(super) headers: HeaderMap,
    pub(super) version: Version,
    pub(super) sequence: Option<u64>,
    pub(super) body: Bytes,
}

pub(super) struct Server {
    pub(super) captures: Mutex<Vec<Capture>>,
    sessions: Arc<Mutex<HashMap<String, Arc<Session>>>>,
    pub(super) options: XHttpOpt,
    expected: usize,
    pub(super) get_status: StatusCode,
    pub(super) post_status: StatusCode,
    pub(super) post_delay: Duration,
    pub(super) delay_first_packet: bool,
    pub(super) delay_headers: bool,
    pub(super) close_post: bool,
    pub(super) connections: AtomicUsize,
    pub(super) max_uploads: AtomicUsize,
    pub(super) h2_streams: u32,
    uploads: AtomicUsize,
    tasks: Mutex<Tasks>,
}
impl Server {
    pub(super) fn new(expected: usize) -> Self {
        Self {
            captures: Mutex::new(Vec::new()), sessions: Arc::new(Mutex::new(HashMap::new())),
            options: XHttpOpt { path: Some("/test".into()), ..Default::default() },
            expected, get_status: StatusCode::OK, post_status: StatusCode::OK,
            post_delay: Duration::ZERO, delay_first_packet: false, delay_headers: false, close_post: false,
            connections: AtomicUsize::new(0), max_uploads: AtomicUsize::new(0), uploads: AtomicUsize::new(0),
            h2_streams: 100,
            tasks: Mutex::new(Tasks::new()),
        }
    }

    pub(super) fn share_sessions(&mut self, other: &Self) { self.sessions = other.sessions.clone(); }

    async fn request(self: Arc<Self>, request: Request<Incoming>) -> Result<Response<RequestBody>, Infallible> {
        let (parts, mut body) = request.into_parts();
        let (id, sequence) = metadata::extract(&self.options, &parts.uri, &parts.headers);
        let stream_one = self.options.mode.as_deref() == Some("stream-one");
        let download = parts.method == Method::GET && sequence.is_none() && body.is_end_stream();
        let data = metadata::data(&self.options, &parts.headers);
        let capture = {
            let mut captures = self.captures.lock();
            let index = captures.len();
            captures.push(Capture { method: parts.method, uri: parts.uri, headers: parts.headers,
                version: parts.version, sequence, body: Bytes::new() });
            index
        };
        let status = if download { self.get_status } else { self.post_status };
        if status != StatusCode::OK {
            return Ok(Response::builder().status(status).body(RequestBody::empty()).unwrap());
        }
        let id = if stream_one { format!("one-{capture}") } else { id };
        let session = self.sessions.lock().entry(id).or_insert_with(|| Arc::new(Session::new(self.expected))).clone();
        if download {
            if self.delay_headers { session.wait_for_data().await; }
            return Ok(Response::new(session.body()));
        }
        if stream_one {
            if self.delay_headers && let Some(Ok(frame)) = body.frame().await {
                if let Ok(data) = frame.into_data() { session.echo(data).await; }
            }
            let reply = session.body();
            self.tasks.lock().push(tokio::spawn(async move {
                while let Some(Ok(frame)) = body.frame().await {
                    if let Ok(data) = frame.into_data() { session.echo(data).await; }
                }
            }));
            return Ok(Response::new(reply));
        }
        let uploads = self.uploads.fetch_add(1, Ordering::AcqRel) + 1;
        self.max_uploads.fetch_max(uploads, Ordering::AcqRel);
        sleep(if self.delay_first_packet && sequence == Some(0) { Duration::from_millis(50) } else { self.post_delay }).await;
        let mut packet = Vec::new();
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(data) = frame.into_data() {
                if sequence.is_none() { session.echo(data).await; }
                else { packet.extend_from_slice(&data); }
            }
        }
        if let Some(sequence) = sequence {
            let payload = Bytes::from(data.unwrap_or(packet));
            self.captures.lock()[capture].body = payload.clone();
            session.packet(sequence, payload).await;
        }
        self.uploads.fetch_sub(1, Ordering::AcqRel);
        let mut response = Response::new(RequestBody::empty());
        if self.close_post { response.headers_mut().insert("connection", "close".parse().unwrap()); }
        Ok(response)
    }

    pub(super) fn factory(self: &Arc<Self>, h2: bool) -> ConnectionFactory {
        let state = self.clone();
        let key = format!("{:p}/{h2}", Arc::as_ptr(self));
        ConnectionFactory { key, dial: Arc::new(move || {
            let state = state.clone();
            Box::pin(async move {
                state.connections.fetch_add(1, Ordering::AcqRel);
                let (client, server) = duplex(4096);
                let handler = state.clone();
                let h2_streams = state.h2_streams;
                state.tasks.lock().push(tokio::spawn(async move {
                    let service = service_fn(move |request| handler.clone().request(request));
                    if h2 {
                        let _ = http2::Builder::new(TokioExecutor::new()).max_header_list_size(1_048_576)
                            .max_concurrent_streams(h2_streams).serve_connection(TokioIo::new(server), service).await;
                    } else {
                        let _ = http1::Builder::new().max_headers(4096).max_buf_size(1_048_576).serve_connection(TokioIo::new(server), service).await;
                    }
                }));
                Ok(AnyStream::new(client))
            })
        }) }
    }
}
