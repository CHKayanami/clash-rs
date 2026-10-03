mod body;
mod connection;
mod metadata;
mod options;
mod padding;
mod payload;
mod pool;
mod range;
mod session;
mod stream;
mod upload;
#[cfg(test)]
mod tests;

use std::{io, sync::Arc};
use async_trait::async_trait;
use tokio::{sync::{mpsc, oneshot}, time::timeout};
use crate::{config::internal::proxy::XHttpOpt, proxy::AnyStream};
use super::{Transport, TransportDialer, dial::TransportSecurity};
use self::{
    body::RequestBody,
    connection::{REQUEST_TIMEOUT, Tasks, drain, response},
    options::{Mode, Options},
    pool::Pool,
    range::invalid,
    stream::Shared,
    upload::{Packets, Upload},
};
pub(crate) use connection::{ConnectionFactory, DialFuture};
pub(crate) use stream::XHttpStream;

struct Download {
    server: String,
    port: u16,
    security: Option<TransportSecurity>,
    options: Arc<Options>,
    pool: Pool,
}

pub struct Client {
    options: Arc<Options>,
    pool: Pool,
    download: Option<Download>,
    needs_download: bool,
}
impl Client {
    pub fn new(
        opts: &XHttpOpt, host: &str, secure: bool, reality: bool, alpn: Option<&[String]>,
    ) -> io::Result<Self> {
        Ok(Self { options: Arc::new(Options::new(opts, host, secure, reality, alpn)?),
            pool: Pool::new(opts.reuse_settings.as_ref())?, download: None,
            needs_download: opts.download_settings.is_some() })
    }

    pub(crate) fn configure_download(
        &mut self, opts: &XHttpOpt, server: String, port: u16,
        security: Option<TransportSecurity>, alpn: Option<&[String]>,
    ) -> io::Result<()> {
        let secure = security.is_some();
        let reality = matches!(security, Some(TransportSecurity::Reality(_)));
        self.download = Some(Download { options: Arc::new(Options::new(opts, &server, secure, reality, alpn)?),
            pool: Pool::new(opts.reuse_settings.as_ref())?, server, port, security });
        Ok(())
    }

    pub(crate) async fn dial(&self, dialer: &TransportDialer<'_>) -> io::Result<AnyStream> {
        let upload = dialer.factory()?;
        let download = self.download.as_ref().map(|download| {
            dialer.endpoint_factory(&download.server, download.port, download.security.clone())
        }).transpose()?;
        self.connect_with_factories(upload, download).await
    }

    async fn connect_with_factories(
        &self, upload: ConnectionFactory, download: Option<ConnectionFactory>,
    ) -> io::Result<AnyStream> {
        timeout(REQUEST_TIMEOUT, self.connect(upload, download)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP connection setup timed out"))?
            .map(AnyStream::new)
    }

    async fn connect(&self, upload: ConnectionFactory, download: Option<ConnectionFactory>) -> io::Result<XHttpStream> {
        if self.needs_download && self.download.is_none() {
            return Err(invalid("XHTTP download-settings requires a configured download endpoint"));
        }
        let shared = Arc::new(Shared::default());
        let mut tasks = Tasks::new();
        let upload_lease = self.pool.acquire(self.options.clone(), upload).await;
        let upload_transport = upload_lease.transport();
        let mut leases = vec![upload_lease];
        let (download_transport, download_options) = match (&self.download, download) {
            (Some(settings), Some(factory)) => {
                let lease = settings.pool.acquire(settings.options.clone(), factory).await;
                let transport = lease.transport();
                leases.push(lease);
                (transport, settings.options.clone())
            }
            (None, None) => (upload_transport.clone(), self.options.clone()),
            _ => return Err(invalid("XHTTP download connection factory is missing")),
        };
        let session = if self.options.mode == Mode::StreamOne { String::new() } else { self.options.session() };
        let (commands, mut receiver) = mpsc::channel(8);
        let (uploader, download) = if self.options.mode == Mode::StreamOne {
            let (body_sender, body_receiver) = mpsc::channel(1);
            let download = upload_transport.download(|version| self.options.request("", None,
                Some(RequestBody::Stream(body_receiver)), version)).await?;
            (Upload::Stream(body_sender), download)
        } else {
            let download = download_transport.download(|version| download_options.request(&session, None, None, version)).await?;
            let uploader = match self.options.mode {
                Mode::StreamUp => {
                    let (body_sender, body_receiver) = mpsc::channel(1);
                    let reply = upload_transport.start(|version| self.options.request(&session, None,
                        Some(RequestBody::Stream(body_receiver)), version)).await?;
                    let shared = shared.clone();
                    tasks.push(tokio::spawn(async move {
                        // HTTP/1.1 can withhold upload headers until request EOF.
                        if let Err(error) = async { drain(reply.body().await?).await }.await { shared.fail(error); }
                    }));
                    Upload::Stream(body_sender)
                }
                Mode::PacketUp => Upload::Packets(Packets::new(upload_transport, self.options.clone(), session)),
                Mode::StreamOne => unreachable!(),
            };
            (uploader, download)
        };
        let upload_shared = shared.clone();
        tasks.push(tokio::spawn(async move { uploader.run(&mut receiver, &upload_shared).await; }));
        let (body_sender, body_receiver) = oneshot::channel();
        let download_shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            match response(download).await {
                Ok(body) => { let _ = body_sender.send(body); }
                Err(error) => { download_shared.fail(error); }
            }
        }));
        Ok(XHttpStream::new(body_receiver, commands, shared, tasks, leases))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, _stream: AnyStream) -> io::Result<AnyStream> {
        Err(invalid("XHTTP requires a connection factory"))
    }
}
