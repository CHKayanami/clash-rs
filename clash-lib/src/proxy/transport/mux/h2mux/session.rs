use bytes::Bytes;
use h2::client::{Builder, SendRequest};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::Mutex;
use tracing::debug;

use super::{
    protocol::{SessionRequest, StreamRequest, build_h2_connect_request},
    stream::{H2MuxStream, StreamCloser},
};
use crate::{
    common::errors::map_io_error,
    proxy::{AnyStream, transport::mux::MuxOption},
    session::SocksAddr,
};

struct SessionCloser {
    active_streams: Arc<AtomicUsize>,
}

impl StreamCloser for SessionCloser {
    fn on_close(&self) {
        self.active_streams.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct H2MuxSession {
    send_request: Mutex<SendRequest<Bytes>>,
    active_streams: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    opt: MuxOption,
}

impl H2MuxSession {
    pub async fn new(mut carrier: AnyStream, opt: MuxOption) -> io::Result<Arc<Self>> {
        // Send sing-box session request header over raw carrier stream
        let session_req = SessionRequest::new_h2mux(opt.padding);
        session_req.write(&mut carrier).await?;

        let mut builder = Builder::new();
        builder.initial_window_size(4 * 1024 * 1024);
        builder.initial_connection_window_size(16 * 1024 * 1024);
        builder.max_concurrent_streams(1024);
        builder.enable_push(false);

        let (send_request, connection) =
            builder.handshake(carrier).await.map_err(map_io_error)?;

        let closed = Arc::new(AtomicBool::new(false));
        let closed_clone = closed.clone();

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("h2mux connection closed: {}", e);
            }
            closed_clone.store(true, Ordering::SeqCst);
        });

        Ok(Arc::new(Self {
            send_request: Mutex::new(send_request),
            active_streams: Arc::new(AtomicUsize::new(0)),
            closed,
            opt,
        }))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::SeqCst)
    }

    pub fn is_available(&self) -> bool {
        if self.is_closed() {
            return false;
        }
        let active = self.active_streams();
        if self.opt.max_streams > 0 && active >= self.opt.max_streams {
            return false;
        }
        true
    }

    pub async fn open_stream(
        self: &Arc<Self>,
        destination: &SocksAddr,
        is_udp: bool,
    ) -> io::Result<AnyStream> {
        let req = build_h2_connect_request()?;
        let (resp, send_stream) = {
            let sender = {
                let guard = self.send_request.lock().await;
                guard.clone()
            };
            let mut ready_sender = sender.ready().await.map_err(map_io_error)?;
            ready_sender.send_request(req, false).map_err(map_io_error)?
        };

        self.active_streams.fetch_add(1, Ordering::SeqCst);

        let closer: Arc<dyn StreamCloser> = Arc::new(SessionCloser {
            active_streams: self.active_streams.clone(),
        });

        let stream_req = StreamRequest::new(destination.clone(), is_udp);

        let stream = H2MuxStream::new(
            resp,
            send_stream,
            stream_req,
            Some(closer),
        )?;

        Ok(Box::new(stream))
    }
}
