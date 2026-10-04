mod capacity;
mod http2;
mod response_body;

use std::{future::poll_fn, io, sync::Arc, time::Duration};
use bytes::Bytes;
use futures::future::BoxFuture;
use http::{Request, Response, Version};
use h2::client::SendRequest;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tracing::debug;
use tokio::{sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore}, task::JoinHandle, time::timeout};

use crate::proxy::{AnyStream, transport::h2_common::{ConnectionDriver, client_builder}};
use super::{body::RequestBody, options::{HttpVersion, Mode, Options}, range::invalid};
use self::{capacity::Capacity, http2::{UploadTask, send as send_h2}, response_body::IncomingBody};
pub(super) use self::response_body::ResponseBody;

pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
type ResponseFuture = BoxFuture<'static, io::Result<Response<IncomingBody>>>;
pub(crate) type DialFuture = BoxFuture<'static, io::Result<AnyStream>>;

#[derive(Clone)]
pub(crate) struct ConnectionFactory {
    pub(crate) key: String,
    pub(crate) dial: Arc<dyn Fn() -> DialFuture + Send + Sync>,
}

pub(super) struct Tasks(Vec<JoinHandle<()>>);
impl Tasks {
    pub(super) fn new() -> Self { Self(Vec::new()) }
    pub(super) fn push(&mut self, task: JoinHandle<()>) { self.0.push(task); }
}
impl Drop for Tasks {
    fn drop(&mut self) { for task in &self.0 { task.abort(); } }
}

enum Sender {
    Http1(http1::SendRequest<RequestBody>),
    Http2(SendRequest<Bytes>),
}
impl Sender {
    async fn ready(&mut self) -> io::Result<()> {
        match self {
            Self::Http1(sender) => sender.ready().await.map_err(io::Error::other),
            Self::Http2(sender) => poll_fn(|cx| sender.poll_ready(cx)).await.map_err(io::Error::other),
        }
    }
    fn send(&mut self, request: Request<RequestBody>) -> io::Result<(ResponseFuture, Option<UploadTask>)> {
        match self {
            Self::Http1(sender) => {
                let reply = sender.send_request(request);
                Ok((Box::pin(async move {
                    let response = reply.await.map_err(io::Error::other)?;
                    let (parts, body) = response.into_parts();
                    Ok(Response::from_parts(parts, IncomingBody::Http1(body)))
                }), None))
            }
            Self::Http2(sender) => send_h2(sender, request),
        }
    }
}

enum Driver { Http1 { _tasks: Tasks }, Http2 { _driver: ConnectionDriver } }

struct Connection {
    sender: AsyncMutex<Sender>,
    capacity: Arc<Capacity>,
    version: Version,
    _driver: Driver,
}

pub(super) struct ConnectionLease {
    connection: Arc<Connection>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for ConnectionLease {
    fn drop(&mut self) { self.connection.capacity.release(); }
}

pub(super) struct Reply {
    future: ResponseFuture,
    lease: ConnectionLease,
    upload: Option<UploadTask>,
}

impl Reply {
    pub(super) async fn body(mut self) -> io::Result<ResponseBody> {
        let response = if let Some(upload) = &mut self.upload {
            tokio::select! {
                response = &mut self.future => response?,
                result = upload.result() => {
                    result?;
                    self.upload = None;
                    self.future.await?
                }
            }
        } else { self.future.await? };
        if response.status() != 200 {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused,
                format!("XHTTP server returned {}", response.status())));
        }
        Ok(ResponseBody { body: response.into_body(), _lease: self.lease, _upload: self.upload })
    }
}

pub(super) async fn response(reply: Reply) -> io::Result<ResponseBody> {
    timeout(REQUEST_TIMEOUT, reply.body()).await.map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, "XHTTP response timed out")
    })?
}

pub(super) async fn drain(mut body: ResponseBody) -> io::Result<()> {
    while let Some(data) = body.data().await { data?; }
    Ok(())
}

pub(super) struct HttpTransport {
    options: Arc<Options>,
    factory: ConnectionFactory,
    connections: Mutex<Vec<Arc<Connection>>>,
    creating: AsyncMutex<()>,
    slots: Arc<Semaphore>,
    download_slots: Arc<Semaphore>,
    keep_alive: Option<Duration>,
}

impl HttpTransport {
    pub(super) fn new(options: Arc<Options>, factory: ConnectionFactory, keep_alive: Option<Duration>) -> Self {
        Self { options, factory, connections: Mutex::new(Vec::new()), creating: AsyncMutex::new(()),
            slots: Arc::new(Semaphore::new(32)), download_slots: Arc::new(Semaphore::new(32)), keep_alive }
    }

    fn available(&self, download: bool) -> Option<Arc<Connection>> {
        let mut connections = self.connections.lock();
        connections.retain(|connection| !connection.capacity.closed());
        connections.iter().find(|connection| self.reserve(&connection.capacity, connection.version, download)).cloned()
    }

    fn reserve(&self, capacity: &Capacity, version: Version, download: bool) -> bool {
        capacity.reserve(download && version == Version::HTTP_2
            && self.options.mode != Mode::StreamOne)
    }

    async fn acquire(&self, download: bool) -> io::Result<ConnectionLease> {
        // Long-lived downloads must not consume the permits needed to upload
        // the bytes which make those downloads progress.
        let slots = if download { &self.download_slots } else { &self.slots };
        let permit = slots.clone().acquire_owned().await.map_err(io::Error::other)?;
        if let Some(connection) = self.available(download) { return Ok(ConnectionLease { connection, _permit: permit }); }
        let _creating = self.creating.lock().await;
        if let Some(connection) = self.available(download) { return Ok(ConnectionLease { connection, _permit: permit }); }
        let stream = timeout(REQUEST_TIMEOUT, (self.factory.dial)()).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP dial timed out"))??;
        let version = version(&self.options, &stream)?;
        debug!(?version, "XHTTP starting HTTP connection");
        let (sender, capacity, driver) = if version == Version::HTTP_2 {
            let mut builder = client_builder();
            builder.max_header_list_size(1_048_576).initial_max_send_streams(0);
            let (sender, connection) = builder.handshake(stream).await.map_err(io::Error::other)?;
            let driver = ConnectionDriver::spawn(connection, self.keep_alive);
            let capacity = Arc::new(Capacity::new(driver.state()));
            timeout(REQUEST_TIMEOUT, capacity.initialized()).await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP HTTP/2 settings timed out"))??;
            debug!("XHTTP HTTP/2 stream capacity initialized");
            (Sender::Http2(sender), capacity, Driver::Http2 { _driver: driver })
        } else {
            let capacity = Arc::new(Capacity::default());
            let driver_capacity = capacity.clone();
            let (sender, connection) = http1::handshake(TokioIo::new(stream)).await.map_err(io::Error::other)?;
            let mut driver = Tasks::new();
            driver.push(tokio::spawn(async move {
                let _ = connection.await;
                driver_capacity.close();
            }));
            capacity.update(1);
            (Sender::Http1(sender), capacity, Driver::Http1 { _tasks: driver })
        };
        if !self.reserve(&capacity, version, download) { return Err(io::ErrorKind::BrokenPipe.into()); }
        let connection = Arc::new(Connection { sender: AsyncMutex::new(sender), capacity,
            version, _driver: driver });
        self.connections.lock().push(connection.clone());
        Ok(ConnectionLease { connection, _permit: permit })
    }

    pub(super) async fn start<F>(&self, request: F) -> io::Result<Reply>
    where F: FnOnce(Version) -> io::Result<Request<RequestBody>>,
    {
        self.dispatch(request, false).await
    }

    pub(super) async fn download<F>(&self, request: F) -> io::Result<Reply>
    where F: FnOnce(Version) -> io::Result<Request<RequestBody>>,
    {
        self.dispatch(request, true).await
    }

    async fn dispatch<F>(&self, request: F, download: bool) -> io::Result<Reply>
    where F: FnOnce(Version) -> io::Result<Request<RequestBody>>,
    {
        // Only retry readiness failures: after dispatch, replaying an upload
        // could duplicate bytes which the server has already accepted.
        let mut request = Some(request);
        for attempt in 0..2 {
            let lease = self.acquire(download).await?;
            let mut sender = lease.connection.sender.lock().await;
            if let Err(error) = sender.ready().await {
                lease.connection.capacity.close();
                if attempt == 1 { return Err(error); }
                continue;
            }
            let (future, upload) = sender.send(request.take().expect("undispatched XHTTP request")(lease.connection.version)?)?;
            drop(sender);
            return Ok(Reply { future, lease, upload });
        }
        unreachable!()
    }
}

fn version(options: &Options, stream: &AnyStream) -> io::Result<Version> {
    let alpn = match stream {
        AnyStream::Tls(tls) => tls.get_ref().1.alpn_protocol(),
        AnyStream::BoringTls(tls) => tls.ssl().selected_alpn_protocol(),
        _ => None,
    };
    let negotiated = match alpn {
        Some(b"h2") => Some(HttpVersion::Http2),
        Some(b"http/1.1") => Some(HttpVersion::Http1),
        Some(_) => return Err(invalid("unsupported XHTTP ALPN")),
        None => None,
    };
    let selected = match options.version {
        HttpVersion::Auto => negotiated.unwrap_or_else(|| {
            if options.reality || (!options.secure && options.mode == Mode::StreamOne) { HttpVersion::Http2 }
            else { HttpVersion::Http1 }
        }),
        configured if negotiated.is_some_and(|version| version != configured) => {
            return Err(invalid("XHTTP HTTP version conflicts with negotiated ALPN"));
        }
        configured => configured,
    };
    if selected == HttpVersion::Http1 && options.mode == Mode::StreamOne {
        return Err(invalid("XHTTP stream-one requires HTTP/2"));
    }
    Ok(if selected == HttpVersion::Http2 { Version::HTTP_2 } else { Version::HTTP_11 })
}
