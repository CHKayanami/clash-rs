use std::{future::poll_fn, io, pin::Pin, task::{Context, Poll}};
use bytes::Bytes;
use futures::ready;
use h2::RecvStream;
use hyper::body::{Body, Incoming};
use super::{ConnectionLease, http2::{UploadTask, poll_data}};

pub(super) enum IncomingBody {
    Http1(Incoming),
    Http2(RecvStream),
}

impl IncomingBody {
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Bytes>>> {
        match self {
            Self::Http1(body) => loop {
                match ready!(Pin::new(&mut *body).poll_frame(cx)) {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() { return Poll::Ready(Some(Ok(data))); }
                    }
                    Some(Err(error)) => return Poll::Ready(Some(Err(io::Error::other(error)))),
                    None => return Poll::Ready(None),
                }
            },
            Self::Http2(body) => poll_data(body, cx),
        }
    }
}

pub(in super::super) struct ResponseBody {
    pub(super) body: IncomingBody,
    pub(super) _lease: ConnectionLease,
    pub(super) _upload: Option<UploadTask>,
}

impl ResponseBody {
    pub(in super::super) fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Bytes>>> {
        if let Some(upload) = &mut self._upload
            && let Poll::Ready(result) = upload.poll_result(cx) {
            self._upload = None;
            if let Err(error) = result { return Poll::Ready(Some(Err(error))); }
        }
        self.body.poll_data(cx)
    }

    pub(in super::super) async fn data(&mut self) -> Option<io::Result<Bytes>> {
        poll_fn(|cx| self.poll_data(cx)).await
    }
}
