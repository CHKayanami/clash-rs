use std::{convert::Infallible, io, pin::Pin, task::{Context, Poll}};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::{mpsc, oneshot};

pub(super) struct BodyChunk {
    pub(super) data: Bytes,
    pub(super) consumed: oneshot::Sender<()>,
}

pub(super) enum RequestBody {
    Full(Full<Bytes>),
    Stream(mpsc::Receiver<BodyChunk>),
}

impl RequestBody {
    pub(super) fn empty() -> Self {
        Self::Full(Full::new(Bytes::new()))
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Self::Full(body) => Pin::new(body).poll_frame(cx).map(|frame| {
                frame.map(|frame: Result<Frame<Bytes>, Infallible>| {
                    frame.map_err(|never| match never {})
                })
            }),
            Self::Stream(receiver) => receiver.poll_recv(cx).map(|chunk| {
                chunk.map(|chunk| {
                    let _ = chunk.consumed.send(());
                    Ok(Frame::data(chunk.data))
                })
            }),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Full(body) => body.is_end_stream(),
            Self::Stream(receiver) => receiver.is_closed() && receiver.is_empty(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(body) => body.size_hint(),
            Self::Stream(_) => SizeHint::default(),
        }
    }
}
